//! PQ-HotStuff-2 four-node authenticated epoch-change integration test.
//!
//! Starts four `chain-forge-node` processes against `genesis-4node-pqhs2-epoch.json`.
//! The genesis configures an epoch-change at height 2 (same 4 validators, epoch 0 → 1).
//! The proposer at height 2 injects a typed `PQHS-EC1:` epoch-change payload; the engine
//! runs `verify_handoff_proof` with real ML-DSA-65 signatures (epoch-transition feature).
//! The engine starts at epoch 0; the first transition produces epoch 1.
//!
//! Timeline:
//!   Height 2: epoch-change block committed in epoch 0 (on_commit fires, epoch → 1)
//!   Height 3: first block committed after the epoch transition (epoch 1)
//!   Height 4: continued finalization in epoch 1
//!   Height 5: epoch 1 is stable
//!
//! Assertions:
//!   - All 4 nodes agree on block_hash + state_root at heights 2-5
//!   - epoch field = 0 at height 2 (epoch-change block committed under epoch 0)
//!   - epoch field = 1 at heights 3, 4, and 5 (committed after the epoch transition)
//!
//! Run (Windows/Linux):
//!   cargo build -p chain-forge-node --features pq-hotstuff
//!   cargo test -p chain-forge-node --features pq-hotstuff \
//!     --test pqhs2_4node_epoch_live -- --nocapture

use std::{
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// serde_json is a workspace dev-dependency used for structured block JSON parsing
// in `fetch_last_commit`.
use serde_json;

const VALIDATORS: &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];

// Each test gets its own port range so they can run in parallel without conflicts.
const API_PORTS_EPOCH:    &[u16] = &[19090, 19091, 19092, 19093];
const P2P_PORTS_EPOCH:    &[u16] = &[28010, 28011, 28012, 28013];
const API_PORTS_BOUNDARY: &[u16] = &[19094, 19095, 19096, 19097];
const P2P_PORTS_BOUNDARY: &[u16] = &[28014, 28015, 28016, 28017];

const GENESIS_FILE: &str = "genesis-4node-pqhs2-epoch.json";
const KEY_DIR:      &str = "keys/mldsa";

// ── Path helpers ─────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().to_path_buf()
}

fn node_binary() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
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
    let needle = format!("\"{}\":\"", field);
    body.split(&needle)
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| s.to_string())
}

fn fetch_block_epoch(api_port: u16, height: u64) -> Option<u64> {
    let body = http_get_body(api_port, &format!("/api/blocks/{height}"))?;
    body.split("\"epoch\":")
        .nth(1)
        .and_then(|s| s.split([',', '}']).next())
        .and_then(|s| s.trim().parse().ok())
}

struct LastCommitInfo {
    height: u64,
    epoch:  u64,
    /// Epochs from the constituent precommit votes.
    vote_epochs: Vec<u64>,
}

/// Fetch and parse `last_commit` from `/api/blocks/{height}` using structured
/// JSON decoding. Returns `None` if the block is unavailable or has no
/// `last_commit` field.
fn fetch_last_commit(api_port: u16, height: u64) -> Option<LastCommitInfo> {
    let body = http_get_body(api_port, &format!("/api/blocks/{height}"))?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let lc = v.get("last_commit")?;
    let cert_height = lc.get("height")?.as_u64()?;
    let cert_epoch  = lc.get("epoch")?.as_u64()?;
    let vote_epochs: Vec<u64> = lc
        .get("precommits")
        .and_then(|a| a.as_array())
        .map(|votes| votes.iter()
            .filter_map(|vote| vote.get("epoch")?.as_u64())
            .collect())
        .unwrap_or_default();
    Some(LastCommitInfo { height: cert_height, epoch: cert_epoch, vote_epochs })
}

// ── RAII process guard ────────────────────────────────────────────────────────

struct NodeProcess {
    validator: &'static str,
    child:     Child,
    api_port:  u16,
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Peer-id reader ────────────────────────────────────────────────────────────

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

// ── Spawn ─────────────────────────────────────────────────────────────────────

fn spawn_nodes(
    bin: &PathBuf,
    log_dir: &PathBuf,
    api_ports: &[u16],
    p2p_ports: &[u16],
) -> Vec<NodeProcess> {
    let genesis = genesis_path();
    let mut nodes: Vec<NodeProcess> = Vec::new();
    let mut bootstrap: Option<String> = None;

    for (i, &validator) in VALIDATORS.iter().enumerate() {
        let api_port = api_ports[i];
        let p2p_port = p2p_ports[i];
        let log_path = log_dir.join(format!("{validator}.log"));
        let log_file = std::fs::File::create(&log_path)
            .unwrap_or_else(|e| panic!("cannot create log {log_path:?}: {e}"));

        println!("   Starting {validator}  api=:{api_port}  p2p=:{p2p_port}  log={log_path:?}");

        let short_name = validator.strip_prefix("qcb1").unwrap_or(validator);
        let key_file = repo_root()
            .join("tests").join("devnet").join(KEY_DIR)
            .join(format!("{short_name}.key.json"));

        let mut cmd = Command::new(bin);
        cmd.args([
            "--genesis",   genesis.to_str().unwrap(),
            "--validator", validator,
            "--key-file",  key_file.to_str().unwrap(),
            "--api-port",  &api_port.to_string(),
            "--p2p-port",  &p2p_port.to_string(),
        ]);
        if let Some(b) = &bootstrap {
            cmd.args(["--bootstrap", b]);
        }
        let child = cmd
            .stdout(log_file.try_clone().unwrap())
            .stderr(log_file)
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {validator}: {e}"));

        nodes.push(NodeProcess { validator, child, api_port });

        if i == 0 {
            let peer = read_peer_id(&log_path, Duration::from_secs(15));
            bootstrap = Some(format!("/ip4/127.0.0.1/tcp/{p2p_port}/p2p/{peer}"));
            println!("   bootstrap: {}", bootstrap.as_deref().unwrap());
        }
    }

    println!("\n   Waiting for API ports to bind...");
    for node in &nodes {
        assert!(
            wait_for_port(node.api_port, Duration::from_secs(15)),
            "{} API port :{} never opened", node.validator, node.api_port
        );
        println!("   {} API is up on :{}", node.validator, node.api_port);
    }
    println!();
    nodes
}

// ── Poll until height ─────────────────────────────────────────────────────────

fn poll_until_height(
    nodes: &mut Vec<NodeProcess>,
    target: u64,
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
                let log_path = log_dir.join(format!("{}.log", node.validator));
                println!("\n── {} log (last 40 lines) ──────────────────────────", node.validator);
                if let Ok(content) = std::fs::read_to_string(&log_path) {
                    let lines: Vec<_> = content.lines().collect();
                    for line in lines.iter().rev().take(40).collect::<Vec<_>>().into_iter().rev() {
                        println!("{line}");
                    }
                }
            }
            panic!("epoch-change devnet did not reach height {target} within {timeout:?}");
        }

        let mut all_reached = true;
        let mut status = String::new();
        for node in nodes.iter_mut() {
            if let Ok(Some(exit)) = node.child.try_wait().map_err(|_| ()) {
                panic!("{} exited unexpectedly: {exit}", node.validator);
            }
            let h = poll_height(node.api_port).unwrap_or(0);
            status.push_str(&format!("  {}={h}", node.validator));
            if h < target { all_reached = false; }
        }

        print!("\r   [{:>4.1}s]{status}   ", elapsed.as_secs_f32());
        std::io::Write::flush(&mut std::io::stdout()).ok();

        if all_reached {
            println!("\n\n── All 4 nodes reached height {target} in {:.1?} ──", start.elapsed());
            println!("{status}");
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ── Agreement + epoch checks ──────────────────────────────────────────────────

fn assert_agreement_and_epoch(nodes: &[NodeProcess], height: u64, expected_epoch: u64) {
    println!("\n── Height {height} (expected epoch {expected_epoch}) ──────────────────────────────────");
    let mut hashes: Vec<(&str, String, String, u64)> = Vec::new();
    for node in nodes {
        let block_hash = fetch_block_field(node.api_port, height, "block_hash")
            .unwrap_or_else(|| format!("<unavailable from {}>", node.validator));
        let state_root = fetch_block_field(node.api_port, height, "state_root")
            .unwrap_or_else(|| format!("<unavailable from {}>", node.validator));
        let epoch = fetch_block_epoch(node.api_port, height).unwrap_or(0);
        println!("   {}  block_hash={}  state_root={}  epoch={epoch}",
            node.validator, block_hash, state_root);
        hashes.push((node.validator, block_hash, state_root, epoch));
    }

    let (_, ref ref_hash, ref ref_root, ref_epoch) = hashes[0];
    for (validator, hash, root, epoch) in &hashes[1..] {
        assert_eq!(hash, ref_hash,
            "FORK: {} block_hash {} != {} block_hash {} at height {}",
            validator, hash, hashes[0].0, ref_hash, height);
        assert_eq!(root, ref_root,
            "STATE DIVERGENCE: {} state_root {} != {} state_root {} at height {}",
            validator, root, hashes[0].0, ref_root, height);
        assert_eq!(*epoch, ref_epoch,
            "EPOCH MISMATCH: {} epoch {} != {} epoch {} at height {}",
            validator, epoch, hashes[0].0, ref_epoch, height);
    }

    assert_eq!(ref_epoch, expected_epoch,
        "EPOCH WRONG at height {height}: all nodes report epoch={ref_epoch}, expected {expected_epoch}");

    println!("   ✓ height {height}: block_hash={ref_hash}  state_root={ref_root}  epoch={ref_epoch}");
}

// ── Test ─────────────────────────────────────────────────────────────────────

/// PQ-HotStuff-2 four-node authenticated epoch-change devnet.
///
/// Uses `genesis-4node-pqhs2-epoch.json` (same 4 ML-DSA-65 validators, epoch-change
/// at height 2). Verifies the authenticated handoff path (`verify_handoff_proof`) and
/// continued finalization in epoch 2.
#[test]
fn pqhs2_4node_epoch_change_reaches_new_epoch() {
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

    let timeout_secs: u64 = std::env::var("DEVNET_TIMEOUT_SECS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(90);
    let timeout = Duration::from_secs(timeout_secs);

    let log_dir = std::env::temp_dir().join("pqhs2_4node_epoch_live");
    std::fs::create_dir_all(&log_dir).expect("create log dir");

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  PQ-HotStuff-2 · epoch-change devnet · ML-DSA-65    ║");
    println!("╚══════════════════════════════════════════════════════╝\n");
    println!("   binary:  {bin:?}");
    println!("   genesis: {genesis:?}");
    println!("   logs:    {log_dir:?}");
    println!("   epoch-change: height 2 (epoch 0 → 1)");
    println!("   target:  height >= 5  timeout: {timeout_secs}s\n");

    let mut nodes = spawn_nodes(&bin, &log_dir, API_PORTS_EPOCH, P2P_PORTS_EPOCH);
    // Target height 5: heights 2–4 cover the boundary; 5 confirms epoch 2 is stable
    poll_until_height(&mut nodes, 5, timeout, &log_dir);

    // Epoch-change block: committed in epoch 0; on_commit fires immediately → epoch=1
    assert_agreement_and_epoch(&nodes, 2, 0);
    // First block after the transition: on_commit already incremented epoch to 1
    assert_agreement_and_epoch(&nodes, 3, 1);
    // Continued finalization in epoch 1
    assert_agreement_and_epoch(&nodes, 4, 1);
    // Epoch 1 is stable
    assert_agreement_and_epoch(&nodes, 5, 1);

    println!("\n[pqhs2_4node_epoch_change_reaches_new_epoch] PASS");
}

// ── QC cert-epoch boundary assertion ─────────────────────────────────────────

/// Check that every node's `last_commit` certificate at `block_height`:
///   - certifies `expected_cert_height`
///   - carries `expected_cert_epoch` on the CommitCertificate.epoch field
///   - has all constituent precommit votes carrying the same epoch
fn assert_cert_epoch(
    nodes: &[NodeProcess],
    block_height: u64,
    expected_cert_height: u64,
    expected_cert_epoch: u64,
) {
    println!(
        "\n── Cert check: block {block_height} → last_commit for h{expected_cert_height} \
         (expected cert epoch {expected_cert_epoch}) ──"
    );
    for node in nodes {
        let lc = fetch_last_commit(node.api_port, block_height)
            .unwrap_or_else(|| panic!(
                "{} block {block_height} last_commit unavailable", node.validator
            ));
        println!(
            "   {}  last_commit.height={}  cert.epoch={}  vote_epochs={:?}",
            node.validator, lc.height, lc.epoch, lc.vote_epochs
        );
        assert_eq!(
            lc.height, expected_cert_height,
            "{} block {block_height}: last_commit.height={}, expected {expected_cert_height}",
            node.validator, lc.height
        );
        assert_eq!(
            lc.epoch, expected_cert_epoch,
            "{} block {block_height}: CommitCertificate.epoch={}, expected {expected_cert_epoch}",
            node.validator, lc.epoch
        );
        for (i, &ve) in lc.vote_epochs.iter().enumerate() {
            assert_eq!(
                ve, expected_cert_epoch,
                "{} block {block_height}: precommits[{i}].epoch={ve}, expected {expected_cert_epoch}",
                node.validator
            );
        }
    }
    println!(
        "   ✓ block {block_height}: last_commit certifies h{expected_cert_height} epoch={expected_cert_epoch}"
    );
}

/// PQ-HotStuff-2 QC cert-epoch boundary test.
///
/// Same devnet as `pqhs2_4node_epoch_change_reaches_new_epoch` (epoch-change at h2,
/// epoch 0 → 1). Additionally asserts the **certificate** epochs carried in each
/// block's `last_commit` field.
///
/// `last_commit` for block H is the CommitCertificate for block H itself
/// (the QC passed to commit_block by the two-chain rule).
///
/// Two-chain commit semantics: block H is committed when QC(H+1) with the
/// consecutive round exists. QC(H) is assembled at the time QC(H+1) triggers
/// the commit. CommitCertificate.epoch is derived from the constituent votes'
/// epoch field (which is set at vote-signing time, before on_commit fires).
///
///   Block h2: QC votes cast at epoch 0 → cert.epoch = 0
///   Block h3: QC votes cast at epoch 0 (before on_commit(h2) advances epoch)
///             → cert.epoch = 0
///   Block h4: QC votes cast at epoch 1 (after the transition) → cert.epoch = 1
///
/// This confirms ML-DSA-65 signatures are bound to the vote-signing epoch and
/// the boundary (epoch flip from 0 to 1 in cert.epoch) is between h3 and h4.
#[test]
fn pqhs2_4node_qc_cert_epoch_boundary() {
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

    let timeout_secs: u64 = std::env::var("DEVNET_TIMEOUT_SECS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(90);
    let timeout = Duration::from_secs(timeout_secs);

    let log_dir = std::env::temp_dir().join("pqhs2_4node_qc_epoch_boundary");
    std::fs::create_dir_all(&log_dir).expect("create log dir");

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  PQ-HotStuff-2 · QC cert-epoch boundary · ML-DSA-65 ║");
    println!("╚══════════════════════════════════════════════════════╝\n");
    println!("   binary:  {bin:?}");
    println!("   genesis: {genesis:?}");
    println!("   logs:    {log_dir:?}");
    println!("   epoch-change: height 2 (epoch 0 → 1)");
    println!("   target:  height >= 5  timeout: {timeout_secs}s\n");

    let mut nodes = spawn_nodes(&bin, &log_dir, API_PORTS_BOUNDARY, P2P_PORTS_BOUNDARY);
    poll_until_height(&mut nodes, 5, timeout, &log_dir);

    // Block-epoch assertions (same as the companion test)
    assert_agreement_and_epoch(&nodes, 2, 0);
    assert_agreement_and_epoch(&nodes, 3, 1);
    assert_agreement_and_epoch(&nodes, 4, 1);
    assert_agreement_and_epoch(&nodes, 5, 1);

    // QC cert-epoch boundary assertions.
    // CommitCertificate.epoch = epoch of the precommit votes (set at signing time).
    //
    //   h2: votes cast before on_commit(h2) → cert.epoch = 0
    assert_cert_epoch(&nodes, 2, 2, 0);
    //   h3: votes cast before on_commit(h2) (h3's QC triggers h2's commit)
    //       → cert.epoch = 0  (the epoch flip is here, between h3 and h4)
    assert_cert_epoch(&nodes, 3, 3, 0);
    //   h4: votes cast after the epoch transition → cert.epoch = 1
    assert_cert_epoch(&nodes, 4, 4, 1);

    println!("\n[pqhs2_4node_qc_cert_epoch_boundary] PASS");
}
