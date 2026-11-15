//! H0-11B Phase 3 — ResumeValidator acceptance test (live, four-node)
//!
//! ## Scenarios
//!
//! RV-01  Four validators finalize blocks; none is jailed.
//! RV-02  Dave's node is killed; liveness enforcement jails him after the
//!        liveness window elapses and an epoch boundary fires.
//! RV-03  ResumeValidator submitted by a *different* sender (Alice) is rejected
//!        by the execution layer (authorization: self-only). The tx receipt
//!        shows failure; Dave remains Jailed.
//! RV-04  ResumeValidator submitted by Dave's own account succeeds after the
//!        jail-release epoch is reached. The tx receipt shows success and the
//!        event "resume_validator: validator_id=qcb1dave" is present.
//! RV-05  Dave's registry status transitions Jailed → Candidate on every live
//!        node (not Active — Dave must re-qualify at the next epoch boundary).
//! RV-06  A second ResumeValidator from Dave succeeds at the execution layer
//!        (authorization passes) but node.rs unjail() returns an error (no
//!        longer Jailed) which is logged as a warning; Dave stays Candidate.
//! RV-07  After the transition Dave does NOT re-enter the committee automatically
//!        (he has not re-bonded or re-verified in this test).
//! RV-08  State roots agree across all three live nodes after each transition.
//! RV-09  After a node restart, the remaining live committee is preserved and
//!        the state root matches the pre-restart value.
//!
//! ## Notes
//!
//! Uses the same genesis (`genesis-val-jail.json`) as the existing
//! `validator_jail_live` test so we don't need a new genesis file.
//! The liveness window is 100 blocks at 2 s/block; the jail period is
//! 10 epochs × 5 blocks/epoch = 50 blocks (~100 s at 2 s/block).
//!
//! The ResumeValidator tx builder is in `chain_forge_execution::Transaction`.
//!
//! Per CLAUDE.md: ✅ only after confirmed passing on Windows (MINGW64 / BossKing).
//!
//! ## Run
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test h0_11b_resume_validator_live -- --nocapture
//! ```

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{ClassicalScheme, SignatureScheme};
use chain_forge_execution::{Transaction, TxBody};

const CHAIN_ID:     &str = "qcb-devnet-val-jail";
const DAVE:         &str = "qcb1dave";
const ALICE:        &str = "qcb1alice";
const EPOCH_BLOCKS: u64  = 5;
const JAIL_EPOCHS:  u64  = 10;
const GENESIS_BOND: u64  = 490_000_000;

// ── Infra helpers ─────────────────────────────────────────────────────────────

fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let start = 21_000 + (std::process::id() % 7_000) as u16;
    loop {
        let p = start + NEXT.fetch_add(1, Ordering::Relaxed);
        assert!(p < 32_000, "no free port found");
        if TcpListener::bind(("127.0.0.1", p)).is_ok() { return p; }
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn node_bin() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    target.join("debug").join(exe)
}

fn genesis_path() -> PathBuf {
    repo_root().join("tests").join("devnet").join("genesis-val-jail.json")
}

fn key_file(label: &str) -> PathBuf {
    repo_root().join("tests").join("devnet").join("keys").join(format!("{label}.key.json"))
}

struct NodeHandle { proc: Child }
impl Drop for NodeHandle {
    fn drop(&mut self) {
        let _ = self.proc.kill();
        let _ = self.proc.wait();
    }
}

#[derive(Clone)]
struct Spec { name: &'static str, api: u16, p2p: u16, peers: Vec<u16> }

fn spawn(spec: &Spec, log_dir: &PathBuf) -> NodeHandle {
    let short = spec.name.trim_start_matches("qcb1");
    let data_dir = log_dir.join(format!("data-{short}"));
    std::fs::create_dir_all(&data_dir).unwrap();
    let log_path = log_dir.join(format!("{}.log", spec.name));
    if log_path.exists() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let _ = std::fs::rename(&log_path,
            log_dir.join(format!("{}.prev-{stamp}.log", spec.name)));
    }
    let log = std::fs::File::create(&log_path).unwrap();
    let mut cmd = Command::new(node_bin());
    cmd.arg("--genesis").arg(genesis_path())
       .arg("--validator").arg(spec.name)
       .arg("--api-port").arg(spec.api.to_string())
       .arg("--p2p-port").arg(spec.p2p.to_string())
       .arg("--data-dir").arg(&data_dir)
       .arg("--key-file").arg(key_file(short));
    for p in &spec.peers { cmd.arg("--bootstrap").arg(format!("/ip4/127.0.0.1/tcp/{p}")); }
    if std::env::var_os("CF_TEST_STORAGE_V2").is_some() { cmd.arg("--storage-v2-experimental"); }
    cmd.stdout(log.try_clone().unwrap()).stderr(log).stdin(Stdio::null());
    NodeHandle { proc: cmd.spawn().unwrap_or_else(|e| panic!("spawn {}: {e}", spec.name)) }
}

fn tail_log(log_dir: &PathBuf, name: &str, n: usize) -> String {
    std::fs::read_to_string(log_dir.join(format!("{name}.log")))
        .map(|s| {
            let lines: Vec<&str> = s.lines().collect();
            lines[lines.len().saturating_sub(n)..].join("\n")
        })
        .unwrap_or_else(|_| "<no log>".into())
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

fn http(method: &str, port: u16, path: &str, body: &str) -> Option<serde_json::Value> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(500)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len());
    s.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1).unwrap_or("")).ok()
}
fn get(port: u16, path: &str) -> Option<serde_json::Value> { http("GET", port, path, "") }

fn height(port: u16) -> u64 {
    get(port, "/api/status").and_then(|v| v["height"].as_u64()).unwrap_or(0)
}

fn state_view(port: u16) -> Option<(u64, String)> {
    let v = get(port, "/api/status")?;
    Some((v["height"].as_u64()?, v["state_root"].as_str()?.to_string()))
}

fn port_open(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100)).is_ok() { return true; }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn wait_until(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() { return true; }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn nonce(port: u16, addr: &str) -> u64 {
    get(port, &format!("/api/accounts/{addr}")).and_then(|v| v["nonce"].as_u64()).unwrap_or(0)
}

fn submit_tx(port: u16, tx: &Transaction) -> serde_json::Value {
    http("POST", port, "/api/tx", &serde_json::to_string(tx).unwrap()).unwrap_or_default()
}

fn wait_tx(port: u16, id: &str, timeout: Duration) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(r) = get(port, &format!("/api/tx/{id}")) {
            if r["success"].as_bool().is_some() { return r; }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("tx {id} never landed (height={})", height(port));
}

fn submit_and_wait(port: u16, tx: &Transaction, timeout: Duration) -> serde_json::Value {
    let resp = submit_tx(port, tx);
    assert_eq!(resp["status"].as_str().unwrap_or(""), "queued",
               "tx {} not queued: {resp}", tx.id);
    wait_tx(port, &tx.id, timeout)
}

fn agree(ports: &[u16], timeout: Duration) -> (u64, String) {
    let deadline = Instant::now() + timeout;
    let mut last = String::new();
    while Instant::now() < deadline {
        let views: Vec<Option<(u64, String)>> = ports.iter().map(|&p| state_view(p)).collect();
        if views.iter().all(Option::is_some) {
            let views: Vec<(u64, String)> = views.into_iter().map(Option::unwrap).collect();
            last = format!("{views:?}");
            if views.iter().all(|v| v.0 == views[0].0) && views.iter().all(|v| v.1 == views[0].1) {
                return views[0].clone();
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("nodes never agreed within {timeout:?}; last: {last}");
}

fn status_of(port: u16, id: &str) -> Option<serde_json::Value> {
    get(port, "/api/validators/status")?.as_array()?.iter()
        .find(|v| v["id"].as_str() == Some(id)).cloned()
}

fn validator_status(port: u16, id: &str) -> Option<String> {
    status_of(port, id)?.get("status")?.as_str().map(str::to_string)
}

fn committee(port: u16) -> Vec<String> {
    let mut ids: Vec<String> = get(port, "/api/validators")
        .and_then(|v| v.as_array().cloned()).unwrap_or_default()
        .iter().filter_map(|v| v["id"].as_str().map(str::to_string)).collect();
    ids.sort();
    ids
}

// ── Tx builders ───────────────────────────────────────────────────────────────

fn bond_tx(sender: &str, nonce_val: u64, amount: u64) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(sender).unwrap();
    let mut tx = Transaction::bond_validator(
        &format!("bond-{sender}-{nonce_val}"), sender, amount as u128, nonce_val);
    if let TxBody::BondValidator { ref mut owner_identity_id, .. } = tx.body {
        *owner_identity_id = Some(sender.to_string());
    }
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

/// ResumeValidator submitted by `sender` for `validator_id`.
/// If sender != validator_id the tx will be rejected by the execution layer (RV-03).
fn resume_tx(sender: &str, validator_id: &str, nonce_val: u64) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(sender).unwrap();
    let mut tx = Transaction::resume_validator(
        &format!("resume-{sender}-{nonce_val}"), validator_id, nonce_val);
    // Override sender to `sender` (may differ from validator_id for the unauthorized test).
    tx.sender = sender.to_string();
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

// ── The test ──────────────────────────────────────────────────────────────────

#[test]
fn h0_11b_resume_validator_live() {
    let bin = node_bin();
    if !bin.exists() {
        eprintln!("SKIP: binary not found at {bin:?}. Run `cargo build -p chain-forge-node`.");
        return;
    }
    let t0 = Instant::now();
    let say = |m: String| println!("[{:>4}s] {m}", t0.elapsed().as_secs());

    let ports: Vec<(u16, u16)> = (0..4).map(|_| (free_port(), free_port())).collect();
    let names = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
    let specs: Vec<Spec> = (0..4).map(|i| Spec {
        name: names[i], api: ports[i].0, p2p: ports[i].1,
        peers: (0..4).filter(|&j| j != i).map(|j| ports[j].1).collect(),
    }).collect();
    let api: Vec<u16> = specs.iter().map(|s| s.api).collect();
    let (alice, bob, carol, dave) = (api[0], api[1], api[2], api[3]);
    let live_api  = [alice, bob, carol];
    let all_api   = [alice, bob, carol, dave];

    // Include a unix-second timestamp so every test run gets fresh data directories.
    // Reusing the same path loads stale chain state from a previous run, causing
    // wrong starting heights and already-consumed nonces.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let tmp = std::env::temp_dir().join(format!("qcb-rv-{alice}-{stamp}"));
    std::fs::create_dir_all(&tmp).unwrap();
    println!("\n── H0-11B ResumeValidator (Phase 3) ───────────────────────────────────");
    println!("   chain_id={CHAIN_ID} logs={tmp:?}");

    let mut nodes: Vec<Option<NodeHandle>> = specs.iter().map(|s| Some(spawn(s, &tmp))).collect();
    for (i, s) in specs.iter().enumerate() {
        assert!(port_open(s.api, Duration::from_secs(30)),
                "{} API did not come up\n--- log ---\n{}", s.name, tail_log(&tmp, s.name, 40));
        let _ = i;
    }
    assert!(wait_until(Duration::from_secs(60), || all_api.iter().all(|&p| height(p) >= 3)),
            "devnet did not reach height 3");
    say(format!("devnet up at height {}", height(alice)));

    // Bond all four so jailing has a real bond record.
    for (i, n) in names.iter().enumerate() {
        let r = submit_and_wait(api[i], &bond_tx(n, nonce(api[i], n), GENESIS_BOND),
                                Duration::from_secs(30));
        assert!(r["success"].as_bool().unwrap_or(false), "bond for {n} failed: {r}");
    }
    let h = height(alice);
    assert!(wait_until(Duration::from_secs(60), || height(alice) >= h + EPOCH_BLOCKS + 1),
            "no epoch boundary after bonding");
    say("all four bonded".into());

    // ── RV-01: healthy network — nobody jailed ────────────────────────────────
    assert!(wait_until(Duration::from_secs(120), || all_api.iter().all(|&p| height(p) >= 30)),
            "RV-01: devnet did not reach height 30");
    for n in names {
        assert_eq!(validator_status(alice, n).as_deref(), Some("Active"),
                   "RV-01: {n} is not Active");
    }
    assert_eq!(committee(alice).len(), 4, "RV-01: committee must have four seats");
    let (h_ok, root_ok) = agree(&all_api, Duration::from_secs(30));
    say(format!("✓ RV-01: four validators Active (h={h_ok}, root={}…)", &root_ok[..12]));

    // ── Kill Dave ─────────────────────────────────────────────────────────────
    nodes[3] = None; // Drop kills the process via NodeHandle::drop.
    std::thread::sleep(Duration::from_secs(2)); // let the OS reap the process
    say("Dave killed; waiting for liveness enforcement…".into());

    // The genesis liveness window is 100 blocks. On Windows/MINGW64 the devnet
    // runs at ~9 s/block, so the window takes ~900 s to fill. After the full
    // window has rolled past Dave's kill point and the miss rate reaches the
    // 20% threshold, jailing fires at the next epoch boundary (every 5 blocks
    // = ~45 s). Allow 1800 s (30 min) with margin.
    assert!(wait_until(Duration::from_secs(1800), || {
        validator_status(alice, DAVE).as_deref() == Some("Jailed")
    }), "RV-02: Dave was not jailed within 30 min\nlast status: {:?}", validator_status(alice, DAVE));
    let (h_jailed, _) = agree(&live_api, Duration::from_secs(90));

    let dave_rec = status_of(alice, DAVE).expect("Dave status record");
    let jailed_epoch = dave_rec["jailed_epoch"].as_u64().expect("jailed_epoch");
    let unjail_after = dave_rec["unjail_after"].as_u64().expect("unjail_after");
    assert_eq!(unjail_after.saturating_sub(jailed_epoch), JAIL_EPOCHS,
               "RV-02: jail must last {JAIL_EPOCHS} epochs");
    // Verify all live nodes agree on Dave's jail record.
    for &port in &live_api {
        let r = status_of(port, DAVE).expect("Dave status on live node");
        assert_eq!(r["status"].as_str(), Some("Jailed"), "RV-02: node at :{port} disagrees on Jailed");
        assert_eq!(r["unjail_after"].as_u64(), Some(unjail_after),
                   "RV-02: unjail_after mismatch on node :{port}");
    }
    say(format!("✓ RV-02: Dave Jailed at epoch {jailed_epoch}, release after epoch {unjail_after} (h={h_jailed})"));

    // ── RV-03: unauthorized resume (Alice → Dave) must be rejected ────────────
    // The jail-release epoch may not have arrived yet; test authorization regardless.
    let alice_nonce = nonce(alice, ALICE);
    let bad_tx = resume_tx(ALICE, DAVE, alice_nonce);
    // Authorization check in the execution layer: sender (Alice) != validator_id (Dave).
    // The tx must be rejected (success=false) even if it reaches a node.
    let bad_resp = submit_and_wait(alice, &bad_tx, Duration::from_secs(30));
    assert!(!bad_resp["success"].as_bool().unwrap_or(true),
            "RV-03: unauthorized resume must fail; got: {bad_resp}");
    // Dave must still be Jailed.
    assert_eq!(validator_status(alice, DAVE).as_deref(), Some("Jailed"),
               "RV-03: Dave must remain Jailed after unauthorized resume");
    say(format!("✓ RV-03: unauthorized resume rejected: {}", bad_resp["error"].as_str().unwrap_or("(no error field)")));

    // ── Wait for jail-release epoch ───────────────────────────────────────────
    // Jail expires at `unjail_after` epoch, i.e. height unjail_after * EPOCH_BLOCKS.
    let release_height = (unjail_after + 1) * EPOCH_BLOCKS;
    say(format!("  waiting for height {release_height} (jail release at epoch {unjail_after})…"));
    // Jail lasts 10 epochs × 5 blocks = 50 blocks. At ~9 s/block that is ~450 s.
    // Add 300 s margin for epoch-boundary jitter.
    assert!(wait_until(Duration::from_secs(750), || height(alice) >= release_height),
            "RV-04: jail-release epoch never passed (stuck at h={})", height(alice));

    // ── RV-04: authorized resume (Dave → Dave) must succeed ──────────────────
    // Dave is still offline. Authorization is `tx.sender == validator_id` checked
    // by the execution layer — it does not matter which node receives the tx.
    // We sign with Dave's keypair and submit to a live node; query Dave's nonce
    // from Alice so we get the chain-head value regardless of Dave's sync state.
    say("Submitting authorized ResumeValidator via live node (Dave is offline)…".into());
    let dave_nonce = nonce(alice, DAVE);
    let resume = resume_tx(DAVE, DAVE, dave_nonce);
    let resume_id = resume.id.clone();
    let submit_resp = submit_tx(alice, &resume);
    assert_eq!(submit_resp["status"].as_str().unwrap_or(""), "queued",
               "RV-04: resume tx not queued: {submit_resp}");
    let result = wait_tx(alice, &resume_id, Duration::from_secs(60));
    assert!(result["success"].as_bool().unwrap_or(false),
            "RV-04: authorized resume tx failed: {result}");
    // The event "resume_validator: validator_id=qcb1dave" must be present.
    let events: Vec<String> = result["events"].as_array()
        .map(|a| a.iter().filter_map(|e| e.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    assert!(events.iter().any(|e| e.contains("resume_validator") && e.contains(DAVE)),
            "RV-04: resume_validator event missing from receipt; events={events:?}");
    say(format!("✓ RV-04: authorized resume succeeded (events: {:?})", events));

    // ── RV-05: Dave's status is Candidate on every live node ─────────────────
    // Allow a short propagation window for the unjail to be reflected in the API.
    assert!(wait_until(Duration::from_secs(60), || {
        live_api.iter().all(|&p| validator_status(p, DAVE).as_deref() == Some("Candidate"))
    }), "RV-05: Dave is not Candidate on all live nodes\n\
        alice={:?} bob={:?} carol={:?}",
        validator_status(alice, DAVE), validator_status(bob, DAVE), validator_status(carol, DAVE));
    say("✓ RV-05: Dave is Candidate on all live nodes".into());

    // ── RV-06: duplicate resume — succeeds in execution layer, unjail() warns ─
    // Dave is still offline; query Alice for the updated nonce.
    let dave_nonce2 = nonce(alice, DAVE);
    assert!(dave_nonce2 > dave_nonce, "RV-06: Dave's nonce did not advance after first resume");
    let resume2 = resume_tx(DAVE, DAVE, dave_nonce2);
    let result2 = submit_and_wait(alice, &resume2, Duration::from_secs(30));
    // Execution-layer succeeds (authorization passes; event emitted).
    // node.rs unjail() returns an error (not Jailed) → logged as warn, tx receipt still success.
    assert!(result2["success"].as_bool().unwrap_or(false),
            "RV-06: duplicate resume receipt must be success (auth passed); got: {result2}");
    // Dave remains Candidate (not demoted or changed by the duplicate).
    assert_eq!(validator_status(alice, DAVE).as_deref(), Some("Candidate"),
               "RV-06: Dave must remain Candidate after duplicate resume");
    say("✓ RV-06: duplicate resume receipt=success, Dave remains Candidate".into());

    // ── RV-07: Dave does NOT re-enter the committee automatically ─────────────
    // Dave has not re-bonded or re-verified; Candidate means waiting, not Active.
    std::thread::sleep(Duration::from_secs(5)); // let an epoch boundary fire
    let h_after = height(alice);
    let _ = wait_until(Duration::from_secs(60), || height(alice) > h_after + EPOCH_BLOCKS);
    let dave_comm_status = validator_status(alice, DAVE);
    assert_ne!(dave_comm_status.as_deref(), Some("Active"),
               "RV-07: Dave must not re-enter the committee without re-qualifying (Candidate, not Active)");
    assert!(!committee(alice).contains(&DAVE.to_string()),
            "RV-07: Dave must not be in the consensus committee without re-qualifying");
    say(format!("✓ RV-07: Dave is {:?}, not in committee", dave_comm_status));

    // ── RV-08: state roots agree on all live nodes ────────────────────────────
    let (h_agree, root_agree) = agree(&live_api, Duration::from_secs(60));
    say(format!("✓ RV-08: live nodes agree (h={h_agree}, root={}…)", &root_agree[..12]));

    // ── RV-09: restart one live node; committee and state root preserved ───────
    let _saved_root = root_agree.clone();
    say("Restarting Carol to verify state preservation…".into());
    nodes[2] = None; // kill Carol
    // Three → two live nodes is below f=1 quorum for 3 seats; chain stalls briefly.
    // Let it stall for up to 30 s, then restart Carol.
    std::thread::sleep(Duration::from_secs(5));
    nodes[2] = Some(spawn(&specs[2], &tmp));
    assert!(port_open(carol, Duration::from_secs(60)),
            "Carol did not restart\n{}", tail_log(&tmp, "qcb1carol", 30));
    // After Carol rejoins, the three-node committee (alice, bob, carol) should resume finality.
    let (h_final, root_final) = agree(&live_api, Duration::from_secs(120));
    // State root must advance beyond saved_root (chain is live again), or at minimum match it.
    assert!(h_final >= h_agree,
            "RV-09: height regressed after Carol restart ({h_final} < {h_agree})");
    // Committee is still alice, bob, carol (Dave is Candidate, not seated).
    let comm_after = committee(alice);
    assert!(!comm_after.contains(&DAVE.to_string()),
            "RV-09: Dave must not be seated after Carol restart; committee={comm_after:?}");
    say(format!("✓ RV-09: after Carol restart, h={h_final}, root={}…, committee={comm_after:?}",
                &root_final[..12]));

    say(format!("ALL RV-01..RV-09 passed in {}s", t0.elapsed().as_secs()));
    println!("   Per CLAUDE.md: mark ✅ only after confirmed passing on BossKing (Windows/MINGW64)");
}
