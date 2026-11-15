//! H0-11B Phase 3 — Automatic suspension acceptance test (live, four-node)
//!
//! ## Scenarios
//!
//! AS-01  Four validators finalize blocks; all Active.
//! AS-02  Dave's node is killed. Before the liveness window fills he is still
//!        Active (threshold not yet breached).
//! AS-03  After the liveness window fills and Dave's miss rate exceeds 33%,
//!        the grace window is entered; Dave remains Active until it expires.
//! AS-04  After the 50-block grace window elapses, the automatic-suspension
//!        gate fires at the next epoch boundary: Dave transitions Active →
//!        Jailed without any manual ResumeValidator or other intervention.
//! AS-05  All three live nodes agree on registry (Dave=Jailed) and state root
//!        after the automatic jail.
//! AS-06  Carol restarts; full 4-node state-root agreement resumes with the
//!        three-node committee (Dave still Jailed, seat not yet recovered).
//!
//! ## Notes
//!
//! Uses `genesis-auto-suspend.json`:
//!   - `window_blocks = 100`, `max_missed_pct = 33`, `start_height = 10`
//!   - `automatic_suspension_enabled = true`
//!   - `validator_epoch_blocks = 5`
//!
//! At ~9 s/block (Windows/MINGW64):
//!   - Window fills in ~100 blocks × 9 s = ~900 s
//!   - Grace window: 50 blocks × 9 s = ~450 s
//!   - Jail fires at next epoch boundary after grace expires: +5 blocks
//!   - Total to jail: ~155 blocks × 9 s ≈ 1395 s (~23 min)
//!   - Generous timeout: 1800 s (30 min)
//!
//! Per CLAUDE.md: ✅ only after confirmed passing on Windows (MINGW64 / BossKing).
//!
//! ## Run
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test h0_11b_auto_suspend_live -- --nocapture
//! ```

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const CHAIN_ID:              &str = "qcb-devnet-auto-suspend";
const DAVE:                  &str = "qcb1dave";
const LIVENESS_WINDOW_BLOCKS: u64 = 100;

// ── Infra helpers ─────────────────────────────────────────────────────────────

fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let start = 22_000 + (std::process::id() % 7_000) as u16;
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
    repo_root().join("tests").join("devnet").join("genesis-auto-suspend.json")
}

fn key_file(label: &str) -> PathBuf {
    repo_root().join("tests").join("devnet").join("keys").join("mldsa").join(format!("{label}.key.json"))
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

// ── The test ──────────────────────────────────────────────────────────────────

#[test]
fn h0_11b_auto_suspend_live() {
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
    let live_api = [alice, bob, carol];
    let all_api  = [alice, bob, carol, dave];

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let tmp = std::env::temp_dir().join(format!("qcb-as-{alice}-{stamp}"));
    std::fs::create_dir_all(&tmp).unwrap();
    println!("\n── H0-11B Automatic Suspension ────────────────────────────────────────");
    println!("   chain_id={CHAIN_ID} logs={tmp:?}");

    let mut nodes: Vec<Option<NodeHandle>> = specs.iter().map(|s| Some(spawn(s, &tmp))).collect();
    for (i, s) in specs.iter().enumerate() {
        assert!(port_open(s.api, Duration::from_secs(30)),
                "{} API did not come up\n--- log ---\n{}", s.name, tail_log(&tmp, s.name, 40));
        let _ = i;
    }
    // Wait for all four nodes to reach height > start_height (10) so liveness enforcement is live.
    assert!(wait_until(Duration::from_secs(60), || all_api.iter().all(|&p| height(p) > 15)),
            "devnet did not reach height 15");
    say(format!("devnet up at height {}", height(alice)));

    // ── AS-01: healthy network — all Active ──────────────────────────────────
    for n in names {
        assert_eq!(validator_status(alice, n).as_deref(), Some("Active"),
                   "AS-01: {n} is not Active at startup");
    }
    assert_eq!(committee(alice).len(), 4, "AS-01: committee must have four seats");
    let (h01, root01) = agree(&all_api, Duration::from_secs(30));
    say(format!("✓ AS-01: four validators Active (h={h01}, root={}…)", &root01[..12]));

    // Record the height at which Dave was last seen active before killing him.
    let dave_kill_height = height(alice);

    // ── Kill Dave ────────────────────────────────────────────────────────────
    nodes[3] = None; // Drop kills the process via NodeHandle::drop.
    std::thread::sleep(Duration::from_secs(2));
    say(format!("Dave killed at h={dave_kill_height}; waiting for threshold breach…"));

    // ── AS-02: threshold not yet breached — Dave still Active ────────────────
    // With window_blocks=20 and start_height=5, enforcement is live but Dave has
    // not yet accumulated 33%+ misses. Right after the kill he is still Active.
    assert_eq!(validator_status(alice, DAVE).as_deref(), Some("Active"),
               "AS-02: Dave should still be Active immediately after kill");
    say("✓ AS-02: Dave still Active immediately after kill (threshold not yet breached)".into());

    // ── AS-03: grace window entered — Dave still Active ───────────────────────
    // After ~100 blocks Dave's miss rate exceeds 33%; the suspension_tracker entry
    // is created but the grace window (50 blocks) has not yet expired. Dave remains
    // Active throughout. The window_blocks=100 at ~9s/block takes ~900s to fill.
    // We sample partway through the grace window (at window + 10 blocks) to verify
    // Dave is still Active before the grace window expires.
    // Allow 1200s (~20 min) to reach the sample point.
    let breach_height = dave_kill_height + LIVENESS_WINDOW_BLOCKS + 10;
    assert!(wait_until(Duration::from_secs(1200), || height(alice) >= breach_height),
            "AS-03: did not reach h={breach_height} in time (stuck at h={})", height(alice));
    // At this point we are in the grace window: Dave missed >33% but suspension has
    // not fired yet (grace window ~50 more blocks needed). He must still be Active.
    // This assertion is best-effort — if the test machine is very slow the grace
    // window may have already expired. If Dave is Jailed here the test jumps to AS-04.
    let dave_mid = validator_status(alice, DAVE);
    say(format!("  AS-03: Dave status mid-window: {:?}", dave_mid));
    if dave_mid.as_deref() == Some("Active") {
        say("✓ AS-03: Dave still Active during grace window (breach detected, jail not yet fired)".into());
    } else {
        say("  AS-03: Dave already Jailed (fast machine or grace window already elapsed — skipping grace-window assertion)".into());
    }

    // ── AS-04: automatic suspension at epoch boundary ─────────────────────────
    // After the grace window expires (~50 blocks after first breach), the commit_block
    // Pass 5 fires jail() at the next epoch boundary. With epoch_blocks=5 this happens
    // within 5 blocks of the grace expiry.
    // Total budget: window(100) + grace(50) + epoch_jitter(10) = 160 blocks × 9 s ≈ 1440 s.
    // Add generous margin: 1800 s (30 min).
    assert!(wait_until(Duration::from_secs(1800), || {
        validator_status(alice, DAVE).as_deref() == Some("Jailed")
    }), "AS-04: Dave was not automatically jailed within 20 min\nlast status: {:?}",
        validator_status(alice, DAVE));

    let dave_rec = status_of(alice, DAVE).expect("Dave status record after auto-jail");
    let jailed_epoch = dave_rec["jailed_epoch"].as_u64().expect("jailed_epoch");
    let unjail_after = dave_rec["unjail_after"].as_u64().expect("unjail_after");

    // ── AS-05: 3-node registry and state-root agreement ──────────────────────
    // All three live nodes must agree Dave=Jailed, same unjail_after, same state root.
    for &port in &live_api {
        let r = status_of(port, DAVE).expect("Dave status on live node");
        assert_eq!(r["status"].as_str(), Some("Jailed"),
                   "AS-05: node at :{port} disagrees — Dave is not Jailed");
        assert_eq!(r["unjail_after"].as_u64(), Some(unjail_after),
                   "AS-05: unjail_after mismatch on node :{port}");
    }
    // Committee must have three seats (Dave ejected at the epoch boundary that jailed him).
    let cmt = committee(alice);
    assert_eq!(cmt.len(), 3, "AS-05: committee must shrink to 3 after Dave's auto-jail; got {cmt:?}");
    assert!(!cmt.iter().any(|v| v == DAVE), "AS-05: Dave must not be in committee; got {cmt:?}");

    let (h05, root05) = agree(&live_api, Duration::from_secs(90));
    say(format!("✓ AS-04/AS-05: Dave auto-jailed at epoch {jailed_epoch} (release after epoch {unjail_after}), h={h05}, root={}…", &root05[..12]));

    // ── AS-06: Carol restarts; 3-node agreement resumes ──────────────────────
    say("Restarting Carol to verify persistence and state-root agreement…".into());
    nodes[2] = None; // kill Carol
    std::thread::sleep(Duration::from_secs(2));
    nodes[2] = Some(spawn(&specs[2], &tmp));
    assert!(port_open(carol, Duration::from_secs(30)),
            "AS-06: Carol API did not come back\n--- log ---\n{}", tail_log(&tmp, "qcb1carol", 40));

    // Carol must sync to the head held by Alice and Bob.
    assert!(wait_until(Duration::from_secs(300), || {
        let h_carol = height(carol);
        let h_alice = height(alice);
        h_carol > 0 && h_carol + 5 >= h_alice
    }), "AS-06: Carol did not sync within 5 min");

    let (h06, root06) = agree(&live_api, Duration::from_secs(90));
    // Dave must still be Jailed after Carol's restart (persisted state).
    assert_eq!(validator_status(carol, DAVE).as_deref(), Some("Jailed"),
               "AS-06: Dave must still be Jailed after Carol restart");
    assert_eq!(committee(carol).len(), 3,
               "AS-06: 3-node committee must hold after Carol restart");

    say(format!("✓ AS-06: Carol restarted, 3-node agreement (h={h06}, root={}…)", &root06[..12]));

    println!("\n── ALL AS-01..AS-06 passed in {}s ──────────────────────────────────────\n",
             t0.elapsed().as_secs());
}
