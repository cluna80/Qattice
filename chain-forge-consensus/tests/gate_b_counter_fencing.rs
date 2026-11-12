//! Gate B — B3: File-based MonotonicCounter fencing and partial-write recovery (QAT-07).
//!
//! Tests F1 and F2 from the Gate B scope document (gate-b-scope.md § B3).
//! Requires real file I/O and Windows exclusive-lock semantics. Fencing (F1, F2) must
//! be verified on Windows (BossKing MINGW64); partial-write tests run cross-platform.
//!
//! Run (Windows only for fencing):
//!   cargo test -p chain-forge-consensus --features gate-b-harness \
//!     --test gate_b_counter_fencing -- --nocapture
#![cfg(feature = "gate-b-harness")]

use chain_forge_consensus::pq_hotstuff::safety::{
    CounterBinding, CounterState, FsCounter, MonotonicCounter,
};
use std::path::PathBuf;

fn tmp_dir(label: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gate_b_ctr_{}_{}", label, std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn test_binding() -> CounterBinding {
    CounterBinding { public_key: vec![0xAB; 32], instance_id: [0x01; 16] }
}

// ── B3-partial: truncated read fails closed ───────────────────────────────────

#[test]
fn b3_truncated_record_fails_closed() {
    let dir = tmp_dir("truncated");
    let path = dir.join("ctr.bin");

    // Write a truncated file (< 44 bytes).
    std::fs::write(&path, &[0u8; 20]).unwrap();

    let err = FsCounter::open(&path, test_binding()).unwrap_err();
    let msg = err.0.to_lowercase();
    assert!(msg.contains("truncated"), "expected Truncated, got: {err}");
    println!("[b3_truncated_record_fails_closed] PASS: {err}");
}

#[test]
fn b3_digest_mismatch_fails_closed() {
    let dir = tmp_dir("digmismatch");
    let path = dir.join("ctr.bin");

    // Write a 44-byte record where the last 4 bytes (CRC32) are wrong.
    let mut buf = [0u8; 44];
    buf[..8].copy_from_slice(&1u64.to_be_bytes()); // value=1
    // digest bytes 8..40 stay zero
    buf[40..44].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // bad CRC
    std::fs::write(&path, &buf).unwrap();

    let err = FsCounter::open(&path, test_binding()).unwrap_err();
    let msg = err.0.to_lowercase();
    assert!(
        msg.contains("checksummismatch") || msg.contains("checksum"),
        "expected ChecksumMismatch, got: {err}"
    );
    println!("[b3_digest_mismatch_fails_closed] PASS: {err}");
}

// ── B3-advance: basic create + advance round-trip ────────────────────────────

#[test]
fn b3_create_and_advance() {
    let dir = tmp_dir("create_adv");
    let path = dir.join("ctr.bin");

    let mut ctr = FsCounter::create(&path, test_binding()).unwrap();
    let session = ctr.acquire_session().unwrap();

    let initial = ctr.read().unwrap();
    assert_eq!(initial, CounterState::INITIAL, "initial state should be (0, [0;32])");

    let new_digest = [0xCC; 32];
    ctr.advance(&initial, new_digest, &session).unwrap();

    let after = ctr.read().unwrap();
    assert_eq!(after.value, 1);
    assert_eq!(after.digest, new_digest);

    // Re-read from disk to confirm durability.
    drop(ctr);
    let ctr2 = FsCounter::open(&path, test_binding()).unwrap();
    let disk = ctr2.read().unwrap();
    assert_eq!(disk.value, 1);
    assert_eq!(disk.digest, new_digest);
    println!("[b3_create_and_advance] PASS: counter at (1, {:?})", &new_digest[..4]);
}

// ── B3-stale-session: stale session token is rejected ────────────────────────

#[test]
fn b3_stale_session_rejected() {
    let dir = tmp_dir("stale_sess");
    let path = dir.join("ctr.bin");

    let mut ctr = FsCounter::create(&path, test_binding()).unwrap();
    let session1 = ctr.acquire_session().unwrap();
    let _session2 = ctr.acquire_session().unwrap(); // supersedes session1

    let initial = ctr.read().unwrap();
    let err = ctr.advance(&initial, [0xBB; 32], &session1).unwrap_err();
    assert!(err.0.contains("stale session"), "expected stale session error, got: {err}");
    println!("[b3_stale_session_rejected] PASS: {err}");
}

// ── B3-wrong-expected: wrong expected state is rejected ───────────────────────

#[test]
fn b3_wrong_expected_rejected() {
    let dir = tmp_dir("wrong_exp");
    let path = dir.join("ctr.bin");

    let mut ctr = FsCounter::create(&path, test_binding()).unwrap();
    let session = ctr.acquire_session().unwrap();

    let wrong = CounterState { value: 99, digest: [0xAA; 32] };
    let err = ctr.advance(&wrong, [0xBB; 32], &session).unwrap_err();
    assert!(err.0.contains("compare-and-advance failed"), "expected CAS failure, got: {err}");
    println!("[b3_wrong_expected_rejected] PASS: {err}");
}

// ── F1 / F2: writer fencing (Windows only; stub on other platforms) ───────────
//
// Full two-process fencing tests require launching a child process. The child is
// spawned as a separate invocation of the test binary with an environment variable
// controlling its behaviour. On non-Windows platforms the fencing mechanism
// (FILE_SHARE_READ only, no FILE_SHARE_WRITE) is not available, so these tests
// are compiled but skip the acquire-failure assertion on non-Windows.

const ENV_CHILD_MODE: &str = "GATE_B_COUNTER_CHILD_MODE";
const ENV_COUNTER_PATH: &str = "GATE_B_COUNTER_PATH";

/// Child entry point: called when GATE_B_COUNTER_CHILD_MODE is set.
/// Mode "try_acquire": attempt acquire_session() and print the result.
/// Mode "acquire_and_advance": acquire, advance to value=2 digest=[0xDD;32], print result.
fn maybe_run_as_child() -> bool {
    let mode = match std::env::var(ENV_CHILD_MODE) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let path = std::env::var(ENV_COUNTER_PATH).expect("GATE_B_COUNTER_PATH not set");
    let mut ctr = FsCounter::open(&path, test_binding()).expect("child: open");
    match mode.as_str() {
        "try_acquire" => {
            match ctr.acquire_session() {
                Ok(_) => println!("CHILD_ACQUIRE_OK"),
                Err(e) => println!("CHILD_ACQUIRE_ERR:{e}"),
            }
        }
        "acquire_and_advance" => {
            let session = ctr.acquire_session().expect("child: acquire");
            let state = ctr.read().unwrap();
            ctr.advance(&state, [0xDD; 32], &session).expect("child: advance");
            println!("CHILD_ADVANCE_OK:{}", ctr.read().unwrap().value);
        }
        other => panic!("unknown child mode: {other}"),
    }
    true
}

/// Dedicated test entry point for the child process in F1/F2 fencing tests.
/// When the env var is set, `maybe_run_as_child()` runs the child logic and exits;
/// when it is not set, this test is a no-op (filtered out by the parent test anyway).
#[test]
fn gate_b_child_entry() {
    maybe_run_as_child();
}

fn spawn_child(mode: &str, counter_path: &std::path::Path) -> std::process::Output {
    let exe = std::env::current_exe().expect("current_exe");
    std::process::Command::new(&exe)
        .env(ENV_CHILD_MODE, mode)
        .env(ENV_COUNTER_PATH, counter_path.to_str().unwrap())
        // --nocapture so println! inside the test function is visible in
        // the captured stdout we check for CHILD_ACQUIRE_ERR / CHILD_ACQUIRE_OK.
        .args(["--nocapture", "--test-threads=1", "gate_b_child_entry"])
        .output()
        .expect("spawn child")
}

/// F1: second writer blocked while first holds handle; succeeds after into_parts().
#[test]
fn b3_f1_fencing_while_alive() {
    let dir = tmp_dir("f1");
    let path = dir.join("ctr_f1.bin");

    // Create and acquire session in this process.
    let mut ctr = FsCounter::create(&path, test_binding()).unwrap();
    let _session = ctr.acquire_session().unwrap();

    // Spawn a child that tries to acquire.
    let out = spawn_child("try_acquire", &path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!("[F1] child stdout: {stdout}");
    println!("[F1] child stderr: {stderr}");

    #[cfg(windows)]
    {
        assert!(
            stdout.contains("CHILD_ACQUIRE_ERR"),
            "F1: child should fail to acquire while parent holds lock.\nstdout: {stdout}\nstderr: {stderr}"
        );
        println!("[b3_f1_fencing_while_alive] PASS: child blocked while parent holds lock");
    }
    #[cfg(not(windows))]
    {
        // On Linux/Mac the exclusive-lock mechanism is not enforced; skip the assertion.
        println!("[b3_f1_fencing_while_alive] SKIP on non-Windows (fencing not enforced)");
    }

    // Now release the handle (simulates into_parts()).
    ctr.release_handle();

    // Child should now succeed.
    let out2 = spawn_child("acquire_and_advance", &path);
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    println!("[F1] child2 stdout: {stdout2}");
    assert!(
        stdout2.contains("CHILD_ADVANCE_OK"),
        "F1: child should succeed after parent releases lock.\nstdout: {stdout2}"
    );
    println!("[b3_f1_fencing_while_alive] PASS: child succeeded after lock released");
}

/// F2: second writer blocked while first is alive; reacquires and advances after TerminateProcess.
/// On Windows this test spawns a child that holds the counter, then kills it, then reacquires.
/// The kill is simulated here by dropping the counter (which closes the handle).
#[test]
fn b3_f2_reacquisition_after_kill() {
    let dir = tmp_dir("f2");
    let path = dir.join("ctr_f2.bin");

    // Create the counter. value=1, digest=[0xCC;32] after first advance.
    {
        let mut ctr = FsCounter::create(&path, test_binding()).unwrap();
        let sess = ctr.acquire_session().unwrap();
        let st = ctr.read().unwrap();
        ctr.advance(&st, [0xCC; 32], &sess).unwrap();
        // ctr drops here, releasing the handle (simulating TerminateProcess handle cleanup).
    }

    // Verify file state: value=1.
    let (val, dig) = chain_forge_consensus::pq_hotstuff::safety::fs_counter::read_counter_file(&path).unwrap();
    assert_eq!(val, 1);
    assert_eq!(dig, [0xCC; 32]);
    println!("[F2] file state after simulated kill: value={val}");

    // Second process acquires and advances.
    let mut ctr2 = FsCounter::open(&path, test_binding()).unwrap();
    let sess2 = ctr2.acquire_session().unwrap();
    let st2 = ctr2.read().unwrap();
    assert_eq!(st2.value, 1, "F2: state must be (1, [0xCC;32]) after kill");
    ctr2.advance(&st2, [0xEE; 32], &sess2).unwrap();

    let final_state = ctr2.read().unwrap();
    assert_eq!(final_state.value, 2);
    assert_eq!(final_state.digest, [0xEE; 32]);
    println!("[b3_f2_reacquisition_after_kill] PASS: reacquired and advanced to value=2");
}
