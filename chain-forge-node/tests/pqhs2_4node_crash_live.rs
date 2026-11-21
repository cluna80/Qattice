//! PQ-HotStuff-2 validator-crash / TC-quorum integration test (JL-08).
//!
//! Starts four `chain-forge-node` processes against `genesis-4node-pqhs2.json`
//! (ML-DSA-65 consensus keys, `bft_variant = "pq-hotstuff"`).
//!
//! Scenario:
//!   Phase 1 — all 4 nodes commit to height `PHASE1_HEIGHT` (baseline).
//!   Phase 2 — Dave (index 3) is killed; the remaining 3 nodes (Alice, Bob,
//!             Carol) must continue committing via TC nil-vote quorum
//!             (2f+1 = 3 of 4).  They must reach `PHASE2_HEIGHT`.
//!   Phase 3 — block-hash agreement check on the 3 surviving nodes.
//!
//! This validates JL-08: when a validator exits mid-consensus the surviving
//! quorum can resynchronise round advancement via timeout certificates and
//! commit new blocks without a live proposer on every round.
//!
//! Run (Windows/Linux):
//!   cargo build -p chain-forge-node --features pq-hotstuff
//!   cargo test -p chain-forge-node --features pq-hotstuff \
//!     --test pqhs2_4node_crash_live -- --nocapture
//!
//! Environment variables:
//!   DEVNET_TIMEOUT_SECS   (default 120)  total test timeout
//!   PHASE1_HEIGHT         (default 3)    baseline all-4-node height
//!   PHASE2_HEIGHT         (default 6)    target height for 3-node quorum

use std::{
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const VALIDATORS: &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
const API_PORTS:  &[u16]  = &[19090, 19091, 19092, 19093];
const P2P_PORTS:  &[u16]  = &[28008, 28009, 28010, 28011];

const GENESIS_FILE: &str = "genesis-4node-pqhs2.json";
const KEY_DIR:      &str = "keys/mldsa";

// ── Path helpers ──────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().to_path_buf()
}

fn node_binary() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe   = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    let debug   = target.join("debug").join(&exe);
    let release = target.join("release").join(&exe);
    match (debug.metadata().and_then(|m| m.modified()),
           release.metadata().and_then(|m| m.modified())) {
        (Ok(dt), Ok(rt)) => if dt >= rt { debug } else { release },
        (Ok(_), Err(_))  => debug,
        (Err(_), Ok(_))  => release,
        (Err(_), Err(_)) => debug,
    }
}

fn genesis_path() -> PathBuf {
    repo_root().join("tests").join("devnet").join(GENESIS_FILE)
}

// ── Network helpers ───────────────────────────────────────────────────────────

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() { return true; }
        if Instant::now() >= deadline { return false; }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn http_get_body(api_port: u16, path: &str) -> Option<String> {
    use std::io::{BufRead, Write};
    let mut stream = TcpStream::connect(format!("127.0.0.1:{api_port}")).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{api_port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut body = String::new();
    let reader = std::io::BufReader::new(stream);
    let mut past_headers = false;
    for line in reader.lines() {
        let line = line.ok()?;
        if past_headers { body.push_str(&line); }
        else if line.is_empty() { past_headers = true; }
    }
    Some(body)
}

fn poll_height(api_port: u16) -> Option<u64> {
    let body = http_get_body(api_port, "/api/status")?;
    body.split("\"height\":")
        .nth(1)
        .and_then(|s| s.split([',', '}']).next())
        .and_then(|s| s.trim().parse().ok())
}

fn fetch_block_field(api_port: u16, height: u64, field: &str) -> Option<String> {
    let body = http_get_body(api_port, &format!("/api/blocks/{height}"))?;
    if body.contains("\"error\"") || body.trim().is_empty() { return None; }
    let needle = format!("\"{}\":\"", field);
    body.split(&needle)
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| s.to_string())
}

fn read_peer_id(log_path: &PathBuf, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let text = std::fs::read_to_string(log_path).unwrap_or_default();
        let clean: String = {
            let mut out = String::with_capacity(text.len());
            let mut in_esc = false;
            for c in text.chars() {
                if c == '\x1b' { in_esc = true; continue; }
                if in_esc { if c == 'm' { in_esc = false; } continue; }
                out.push(c);
            }
            out
        };
        if let Some(id) = clean.lines()
            .filter(|l| l.contains("P2P listening"))
            .find_map(|l| l.split("peer=").nth(1))
            .map(|rest| rest.split_whitespace().next().unwrap_or("").to_string())
            .filter(|id| id.starts_with("12D3"))
        {
            return id;
        }
        assert!(Instant::now() < deadline, "no libp2p peer id in {log_path:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ── RAII process guard ────────────────────────────────────────────────────────

struct NodeProcess {
    validator: &'static str,
    child:     Option<Child>,
    api_port:  u16,
}

impl NodeProcess {
    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn is_alive(&mut self) -> bool {
        match self.child.as_mut() {
            None => false,
            Some(c) => c.try_wait().map(|s| s.is_none()).unwrap_or(false),
        }
    }
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

// ── Spawn ─────────────────────────────────────────────────────────────────────

fn spawn_node(
    bin:       &PathBuf,
    validator: &'static str,
    api_port:  u16,
    p2p_port:  u16,
    data_dir:  &PathBuf,
    log_path:  &PathBuf,
    bootstrap: Option<&str>,
) -> NodeProcess {
    let genesis = genesis_path();
    let log_file = std::fs::File::create(log_path)
        .unwrap_or_else(|e| panic!("cannot create log {log_path:?}: {e}"));

    let short_name = validator.strip_prefix("qcb1").unwrap_or(validator);
    let key_file = repo_root()
        .join("tests").join("devnet").join(KEY_DIR)
        .join(format!("{short_name}.key.json"));

    std::fs::create_dir_all(data_dir).unwrap();

    let mut cmd = Command::new(bin);
    cmd.args([
        "--genesis",   genesis.to_str().unwrap(),
        "--validator", validator,
        "--key-file",  key_file.to_str().unwrap(),
        "--api-port",  &api_port.to_string(),
        "--p2p-port",  &p2p_port.to_string(),
        "--data-dir",  data_dir.to_str().unwrap(),
    ]);
    if let Some(b) = bootstrap {
        cmd.args(["--bootstrap", b]);
    }
    let child = cmd
        .stdout(log_file.try_clone().unwrap())
        .stderr(log_file)
        .stdin(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {validator}: {e}"));

    NodeProcess { validator, child: Some(child), api_port }
}

// ── Poll helpers ──────────────────────────────────────────────────────────────

/// Poll the given subset of nodes until all report height >= target.
/// Dead nodes (child already killed) are excluded from the check.
fn poll_subset_until_height(
    nodes:   &mut [NodeProcess],
    target:  u64,
    timeout: Duration,
    log_dir: &PathBuf,
) {
    println!("   Polling /api/status (target: height >= {target})...\n");
    let start = Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            println!("\nTIMEOUT after {elapsed:.1?}");
            for node in nodes.iter() {
                if node.child.is_none() { continue; }
                let log_path = log_dir.join(format!("{}.log", node.validator));
                println!("\n── {} log (last 40 lines) ──────────────────────────", node.validator);
                if let Ok(content) = std::fs::read_to_string(&log_path) {
                    let lines: Vec<_> = content.lines().collect();
                    for line in lines.iter().rev().take(40).collect::<Vec<_>>().into_iter().rev() {
                        println!("{line}");
                    }
                }
            }
            panic!("devnet did not reach height {target} within {timeout:?}");
        }

        let mut all_reached = true;
        let mut status = String::new();
        for node in nodes.iter_mut() {
            if node.child.is_none() {
                status.push_str(&format!("  {}=DEAD", node.validator));
                continue;
            }
            if let Some(ref mut child) = node.child {
                if let Ok(Some(exit)) = child.try_wait().map_err(|_| ()) {
                    panic!("{} exited unexpectedly with status {exit}", node.validator);
                }
            }
            let h = poll_height(node.api_port).unwrap_or(0);
            status.push_str(&format!("  {}={h}", node.validator));
            if h < target { all_reached = false; }
        }

        print!("\r   [{:>4.1}s]{status}   ", elapsed.as_secs_f32());
        std::io::Write::flush(&mut std::io::stdout()).ok();

        if all_reached {
            println!("\n\n── Nodes reached height {target} in {:.1?} ──", start.elapsed());
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ── Test ─────────────────────────────────────────────────────────────────────

/// PQ-HotStuff-2: surviving quorum (3-of-4) continues after one validator crash.
///
/// Validates JL-08 (TC nil-vote quorum): when Dave exits mid-consensus, Alice,
/// Bob and Carol (the 2f+1 = 3 survivors) can resynchronise round advancement
/// via timeout-certificate quorum and commit new blocks.
#[test]
#[cfg_attr(not(feature = "pq-hotstuff"), ignore = "requires pq-hotstuff feature")]
fn pqhs2_4node_crash_survivor_quorum() {
    let bin = node_binary();
    if !bin.exists() {
        println!(
            "SKIP: node binary not found at {bin:?}. \
             Run `cargo build -p chain-forge-node --features pq-hotstuff` first."
        );
        return;
    }

    let genesis = genesis_path();
    if !genesis.exists() {
        println!("SKIP: genesis file not found at {genesis:?}");
        return;
    }

    let phase1_height: u64 = std::env::var("PHASE1_HEIGHT")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let phase2_height: u64 = std::env::var("PHASE2_HEIGHT")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(phase1_height + 3);
    let timeout_secs: u64 = std::env::var("DEVNET_TIMEOUT_SECS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(120);
    let timeout = Duration::from_secs(timeout_secs);

    let log_dir = std::env::temp_dir().join("pqhs2_crash_logs");
    let dat_dir = std::env::temp_dir().join("pqhs2_crash_data");
    let _ = std::fs::remove_dir_all(&log_dir);
    let _ = std::fs::remove_dir_all(&dat_dir);
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::create_dir_all(&dat_dir).unwrap();

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  PQ-HotStuff-2 · 4-node crash / TC-quorum test      ║");
    println!("╚══════════════════════════════════════════════════════╝\n");
    println!("   binary:        {bin:?}");
    println!("   genesis:       {genesis:?}");
    println!("   logs:          {log_dir:?}");
    println!("   phase1_height: {phase1_height}  (all 4 nodes)");
    println!("   phase2_height: {phase2_height}  (3 survivors via TC quorum)");
    println!("   timeout:       {timeout_secs}s\n");

    // ── Spawn node 0 (Alice) first to get its peer-id ────────────────────────
    let alice_data = dat_dir.join("alice");
    let alice_log  = log_dir.join("qcb1alice.log");
    let alice = spawn_node(
        &bin, VALIDATORS[0],
        API_PORTS[0], P2P_PORTS[0],
        &alice_data, &alice_log, None,
    );
    assert!(wait_for_port(API_PORTS[0], Duration::from_secs(15)),
        "alice API port :{} never opened", API_PORTS[0]);
    let peer_id  = read_peer_id(&alice_log, Duration::from_secs(15));
    let bootstrap = format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer_id}", P2P_PORTS[0]);
    println!("   bootstrap: {bootstrap}");

    let mut nodes: Vec<NodeProcess> = vec![alice];
    for (i, &validator) in VALIDATORS[1..].iter().enumerate() {
        let idx      = i + 1;
        let data_dir = dat_dir.join(validator.strip_prefix("qcb1").unwrap_or(validator));
        let log_path = log_dir.join(format!("{validator}.log"));
        let node = spawn_node(
            &bin, validator,
            API_PORTS[idx], P2P_PORTS[idx],
            &data_dir, &log_path,
            Some(&bootstrap),
        );
        assert!(wait_for_port(API_PORTS[idx], Duration::from_secs(15)),
            "{validator} API port :{} never opened", API_PORTS[idx]);
        nodes.push(node);
    }

    // ── Phase 1: all 4 nodes reach baseline ──────────────────────────────────
    println!("\n── Phase 1: all 4 nodes → height {phase1_height} ──────────────────────────────");
    // Phase 1 uses half the timeout; phase 2 uses the remaining half.
    let phase_timeout = timeout / 2;
    poll_subset_until_height(&mut nodes, phase1_height, phase_timeout, &log_dir);

    println!("\n   ✓ All 4 nodes at height {phase1_height}");

    // ── Kill Dave (index 3) ───────────────────────────────────────────────────
    println!("\n── Killing Dave (index 3) — testing TC-quorum with 3-of-4 survivors ──");
    nodes[3].kill();
    println!("   Dave killed.");

    // ── Phase 2: 3 survivors advance via TC nil-vote quorum ──────────────────
    println!("\n── Phase 2: 3 survivors → height {phase2_height} via TC quorum ─────────────────");
    // Poll only the first 3 nodes; Dave's slot has child=None and is printed DEAD.
    poll_subset_until_height(&mut nodes, phase2_height, phase_timeout, &log_dir);

    // ── Phase 3: agreement on 3 surviving nodes ───────────────────────────────
    println!("\n── Phase 3: block-hash agreement on 3 survivors at height {phase2_height} ──");
    let mut hashes: Vec<(&str, String)> = Vec::new();
    for node in nodes.iter().take(3) {
        let block_hash = fetch_block_field(node.api_port, phase2_height, "block_hash")
            .unwrap_or_else(|| format!("<unavailable from {}>", node.validator));
        let state_root = fetch_block_field(node.api_port, phase2_height, "state_root")
            .unwrap_or_else(|| format!("<unavailable from {}>", node.validator));
        println!("   {}  block_hash={}  state_root={}", node.validator, block_hash, state_root);
        hashes.push((node.validator, block_hash));
    }
    let (_, ref ref_hash) = hashes[0];
    for (validator, hash) in &hashes[1..] {
        assert_eq!(
            hash, ref_hash,
            "AGREEMENT FAILURE: {validator} block_hash {hash} != {} block_hash {ref_hash} at height {phase2_height}",
            hashes[0].0
        );
    }
    println!("   ✓ 3 survivors agree on block_hash={ref_hash}");

    println!("\n[pqhs2_4node_crash_survivor_quorum] PASS");
}
