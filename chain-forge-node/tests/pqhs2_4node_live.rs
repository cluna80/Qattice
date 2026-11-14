//! PQ-HotStuff-2 four-node devnet integration test (QAT-07, `pq-hotstuff` feature).
//!
//! Spawns four `chain-forge-node` processes (Alice, Bob, Carol, Dave) against
//! `tests/devnet/genesis-4node-pqhs2-fips204.json` (FIPS 204 ML-DSA-65 consensus keys,
//! `bft_variant = "pq-hotstuff"`), then polls each node's `/api/status`
//! endpoint until all four report `height >= 3` or the test times out.
//!
//! This validates:
//!   - `PqHotStuffEngine` is selected when `bft_variant = "pq-hotstuff"` in genesis
//!   - Message dispatch (propose / receive_vote / on_timeout) works over TCP
//!   - Peer handshake completes and gossip propagates votes to all four nodes
//!   - Four nodes commit at least 3 blocks using genuine FIPS 204 ML-DSA-65 consensus keys
//!   - At least one emitted vote carries a valid FIPS 204 ML-DSA-65 signature
//!     (verified independently via `chain_forge_consensus::pq_hotstuff::safety::decode_record`
//!     + `Fips204Verifier` over `CTX_VOTE` and the canonical `VoteMessage` encoding)
//!
//! Run (Windows/Linux):
//!   cargo build -p chain-forge-node --features pq-hotstuff
//!   cargo test -p chain-forge-node --features pq-hotstuff \
//!     --test pqhs2_4node_live -- --nocapture
//!
//! Environment variables:
//!   DEVNET_TIMEOUT_SECS   (default 60)   seconds to wait for all nodes to reach target height
//!   DEVNET_TARGET_HEIGHT  (default 3)    minimum height all nodes must reach

use std::{
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const VALIDATORS: &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
const API_PORTS: &[u16] = &[19080, 19081, 19082, 19083];
const P2P_PORTS: &[u16] = &[28000, 28001, 28002, 28003];

const GENESIS_FILE: &str = "genesis-4node-pqhs2-fips204.json";
const KEY_DIR: &str = "keys/fips204";

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

fn poll_height(api_port: u16) -> Option<u64> {
    use std::io::{BufRead, Write};
    let mut stream = TcpStream::connect(format!("127.0.0.1:{api_port}")).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    let request = format!(
        "GET /api/status HTTP/1.0\r\nHost: 127.0.0.1:{api_port}\r\nConnection: close\r\n\r\n"
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
    body.split("\"height\":")
        .nth(1)
        .and_then(|s| s.split([',', '}']).next())
        .and_then(|s| s.trim().parse().ok())
}

/// Fetch a JSON field value from `/api/blocks/{height}` on a node.
fn fetch_block_field(api_port: u16, height: u64, field: &str) -> Option<String> {
    use std::io::{BufRead, Write};
    let mut stream = TcpStream::connect(format!("127.0.0.1:{api_port}")).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let request = format!(
        "GET /api/blocks/{height} HTTP/1.0\r\nHost: 127.0.0.1:{api_port}\r\nConnection: close\r\n\r\n"
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
    let needle = format!("\"{}\":\"", field);
    body.split(&needle)
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| s.to_string())
}

/// Assert all four nodes agree on `block_hash` and `state_root` at the given height.
fn assert_four_node_agreement(nodes: &[NodeProcess], height: u64) {
    println!("\n── Block agreement check at height {height} ──────────────────────────────────");
    let mut hashes: Vec<(&str, String, String)> = Vec::new();
    for node in nodes {
        let block_hash = fetch_block_field(node.api_port, height, "block_hash")
            .unwrap_or_else(|| format!("<unavailable from {}>", node.validator));
        let state_root = fetch_block_field(node.api_port, height, "state_root")
            .unwrap_or_else(|| format!("<unavailable from {}>", node.validator));
        println!("   {}  block_hash={}  state_root={}", node.validator, block_hash, state_root);
        hashes.push((node.validator, block_hash, state_root));
    }
    let (_, ref ref_hash, ref ref_root) = hashes[0];
    for (validator, hash, root) in &hashes[1..] {
        assert_eq!(
            hash, ref_hash,
            "AGREEMENT FAILURE: {} block_hash {} != {} block_hash {} at height {}",
            validator, hash, hashes[0].0, ref_hash, height
        );
        assert_eq!(
            root, ref_root,
            "AGREEMENT FAILURE: {} state_root {} != {} state_root {} at height {}",
            validator, root, hashes[0].0, ref_root, height
        );
    }
    println!("   ✓ All 4 nodes agree: block_hash={ref_hash}  state_root={ref_root}");
}

// ── RAII process guard ────────────────────────────────────────────────────────

struct NodeProcess {
    validator: &'static str,
    child: Child,
    api_port: u16,
    data_dir: PathBuf,
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

fn spawn_nodes(bin: &PathBuf, log_dir: &PathBuf) -> Vec<NodeProcess> {
    let genesis = genesis_path();
    let mut nodes: Vec<NodeProcess> = Vec::new();
    let mut bootstrap: Option<String> = None;

    for (i, &validator) in VALIDATORS.iter().enumerate() {
        let api_port = API_PORTS[i];
        let p2p_port = P2P_PORTS[i];
        let log_path = log_dir.join(format!("{validator}.log"));
        let log_file = std::fs::File::create(&log_path)
            .unwrap_or_else(|e| panic!("cannot create log {log_path:?}: {e}"));

        println!("   Starting {validator}  api=:{api_port}  p2p=:{p2p_port}  log={log_path:?}");

        let short_name = validator.strip_prefix("qcb1").unwrap_or(validator);
        let key_file = repo_root()
            .join("tests").join("devnet").join(KEY_DIR)
            .join(format!("{short_name}.key.json"));
        let data_dir = log_dir.join(format!("{validator}-data"));
        std::fs::create_dir_all(&data_dir)
            .unwrap_or_else(|e| panic!("cannot create data dir {data_dir:?}: {e}"));

        let mut cmd = Command::new(bin);
        cmd.args([
            "--genesis",   genesis.to_str().unwrap(),
            "--validator", validator,
            "--key-file",  key_file.to_str().unwrap(),
            "--api-port",  &api_port.to_string(),
            "--p2p-port",  &p2p_port.to_string(),
            "--data-dir",  data_dir.to_str().unwrap(),
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

        nodes.push(NodeProcess { validator, child, api_port, data_dir });

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
            "{} API port :{} never opened",
            node.validator, node.api_port
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
                println!("\n── {} log (last 40 lines) ─────────────────────────────", node.validator);
                if let Ok(content) = std::fs::read_to_string(&log_path) {
                    let lines: Vec<_> = content.lines().collect();
                    for line in lines.iter().rev().take(40).collect::<Vec<_>>().into_iter().rev() {
                        println!("{line}");
                    }
                }
            }
            panic!("PQ-HotStuff-2 devnet did not reach height {target} within {timeout:?}");
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
            println!("\n\n── All 4 PQ-HotStuff-2 nodes reached height {target} in {:.1?} ──", start.elapsed());
            println!("{status}");
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ── FIPS 204 wire-vote verification ─────────────────────────────────────────

/// Read a node's persisted safety record and independently verify the last
/// signed vote with the FIPS 204 backend.
///
/// The node must have been started with `--data-dir`; the safety store is at
/// `<data_dir>/pq-safety/<validator>/safety_state.cbor`.
///
/// Returns `Some(description)` on success, `None` if the record path does not
/// exist or no vote has been signed yet (record is in `Fresh` state).
fn verify_fips204_last_vote(validator: &str, data_dir: &PathBuf) -> Option<String> {
    use chain_forge_consensus::pq_hotstuff::{
        safety::{ConsensusVerifier, CTX_VOTE, Fips204Verifier, decode_record, STATE_FILE},
        wire::{AlgId, VoteMessage},
    };

    let safety_dir = data_dir.join("pq-safety").join(validator);
    let record_path = safety_dir.join(STATE_FILE);

    if !record_path.exists() {
        return None;
    }

    let cbor = std::fs::read(&record_path)
        .unwrap_or_else(|e| panic!(
            "cannot read safety record for {validator} at {record_path:?}: {e}"
        ));

    let rec = decode_record(&cbor).unwrap_or_else(|e| {
        panic!("decode_record for {validator} failed: {e:?}")
    });

    let item = rec.last_vote.as_ref()?;
    let sig  = &item.envelope.signature;

    let vm = VoteMessage::decode(&item.message, AlgId::MLDSA65_FIPS204).unwrap_or_else(|e| {
        panic!("VoteMessage::decode for {validator} failed: {e:?}")
    });

    let ok = Fips204Verifier.verify(&rec.public_key, CTX_VOTE, &item.message, sig);

    assert!(
        ok,
        "FIPS 204 vote signature FAILED for {validator} — \
         chain={} epoch={} round={} sig_len={}",
        vm.chain_id, vm.epoch, vm.round, sig.len()
    );

    Some(format!(
        "{validator}: FIPS 204 vote signature VALID — \
         chain={} epoch={} round={} block_id={}",
        vm.chain_id, vm.epoch, vm.round,
        hex::encode(&vm.block_id[..8])
    ))
}

// ── Test ─────────────────────────────────────────────────────────────────────

/// PQ-HotStuff-2 four-node devnet: message dispatch and peer handshake with
/// ML-DSA-65 signatures over TCP.
///
/// Validates that `PqHotStuffEngine` is selected from genesis `bft_variant =
/// "pq-hotstuff"`, peers connect, votes are gossipped, and all four nodes commit
/// at least `DEVNET_TARGET_HEIGHT` (default 3) blocks.
#[test]
fn pqhs2_4node_reaches_target_height() {
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

    let target: u64 = std::env::var("DEVNET_TARGET_HEIGHT")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let timeout_secs: u64 = std::env::var("DEVNET_TIMEOUT_SECS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(60);
    let timeout = Duration::from_secs(timeout_secs);

    let log_dir = std::env::temp_dir().join("pqhs2_4node_live");
    std::fs::create_dir_all(&log_dir).expect("create log dir");

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  PQ-HotStuff-2 · 4-node devnet · ML-DSA-65 keys     ║");
    println!("╚══════════════════════════════════════════════════════╝\n");
    println!("   binary:  {bin:?}");
    println!("   genesis: {genesis:?}");
    println!("   logs:    {log_dir:?}");
    println!("   target:  height >= {target}  timeout: {timeout_secs}s\n");

    let mut nodes = spawn_nodes(&bin, &log_dir);
    poll_until_height(&mut nodes, target, timeout, &log_dir);

    // Cross-node agreement: all 4 nodes must have the same block_hash and
    // state_root at the target height. This catches forks and state divergence.
    assert_four_node_agreement(&nodes, target);

    // FIPS 204 wire-vote verification: collect data-dir paths, drop nodes
    // (which kills and waits for each child so safety stores are fully flushed),
    // then read back the persisted records and verify independently.
    println!("\n── FIPS 204 vote signature verification ─────────────────────────────────────");
    let data_dirs: Vec<(&str, PathBuf)> = nodes.iter()
        .map(|n| (n.validator, n.data_dir.clone()))
        .collect();
    drop(nodes); // kills and waits for all four node processes

    let mut verified = 0usize;
    for (validator, data_dir) in &data_dirs {
        match verify_fips204_last_vote(validator, data_dir) {
            Some(msg) => { println!("   ✓ {msg}"); verified += 1; }
            None => { println!("   - {validator}: no safety record found or Fresh state — skipping"); }
        }
    }

    assert!(
        verified >= 1,
        "FIPS 204 verification: at least 1 node must have a signed vote in its safety store"
    );
    println!("\n   {verified}/4 validators had their FIPS 204 vote signatures verified.");

    println!("\n[pqhs2_4node_reaches_target_height] PASS");
}
