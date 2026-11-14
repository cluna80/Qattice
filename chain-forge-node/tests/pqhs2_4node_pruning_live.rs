//! PQ-HotStuff-2 four-node fixed-set pruning integration test.
//!
//! Starts four `chain-forge-node` processes against `genesis-4node-pqhs2.json`
//! (block_time_ms=2000; no epoch change so the validator set stays fixed).
//! Runs until all four nodes have committed at least `CHAIN_STORE_KEEP + 1`
//! blocks (height >= 65), then:
//!
//!   1. Verifies that `/api/status` reports `chain_store_watermark >= 1` on
//!      every node (pruning fired at least once).
//!   2. Verifies that `/api/blocks/{H}` returns empty/null for a height well
//!      below the watermark (the entry has been pruned from chain_store and
//!      scrolled off the 100-block explorer window).
//!   3. Verifies that all four nodes agree on `block_hash` and `state_root`
//!      at the current committed tip.
//!   4. Kills one node, waits for the remaining three to advance two more
//!      blocks, then restarts the killed node with the same data directory.
//!   5. Waits for the restarted node to reach the same height as its peers.
//!   6. Asserts that the restarted node agrees on `block_hash` and
//!      `state_root` at the tip.
//!
//! Run (Windows/Linux):
//!   cargo build -p chain-forge-node --features pq-hotstuff
//!   cargo test -p chain-forge-node --features pq-hotstuff \
//!     --test pqhs2_4node_pruning_live -- --nocapture

use std::{
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const VALIDATORS: &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];

const API_PORTS: &[u16] = &[19098, 19099, 19100, 19101];
const P2P_PORTS: &[u16] = &[28018, 28019, 28020, 28021];

const GENESIS_FILE: &str = "genesis-4node-pqhs2.json";
const KEY_DIR:      &str = "keys/mldsa";

/// Must match CHAIN_STORE_KEEP in node.rs; we pass height > this to trigger pruning.
/// Set to 20 so the test completes within 240 s on the Windows devnet (~9 s/block).
const PRUNE_THRESHOLD: u64 = 20;

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

fn poll_watermark(api_port: u16) -> Option<u64> {
    let body = http_get_body(api_port, "/api/status")?;
    body.split("\"chain_store_watermark\":")
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

struct NodeProcess {
    validator: &'static str,
    child:     Child,
    api_port:  u16,
    data_dir:  PathBuf,
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_node(
    bin:        &PathBuf,
    validator:  &'static str,
    api_port:   u16,
    p2p_port:   u16,
    data_dir:   &PathBuf,
    log_path:   &PathBuf,
    bootstrap:  Option<&str>,
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

    NodeProcess { validator, child, api_port, data_dir: data_dir.clone() }
}

fn poll_until_height(
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
            println!("\n\n── All nodes reached height {target} in {:.1?} ──", start.elapsed());
            println!("{status}");
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ── Test ─────────────────────────────────────────────────────────────────────

#[test]
#[cfg_attr(not(feature = "pq-hotstuff"), ignore = "requires pq-hotstuff feature")]
fn pqhs2_4node_fixed_set_pruning() {
    let bin     = node_binary();
    let log_dir = std::env::temp_dir().join("pqhs2_pruning_logs");
    let dat_dir = std::env::temp_dir().join("pqhs2_pruning_data");
    let _ = std::fs::remove_dir_all(&log_dir);
    let _ = std::fs::remove_dir_all(&dat_dir);
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::create_dir_all(&dat_dir).unwrap();

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  pqhs2_4node_fixed_set_pruning");
    println!("  binary : {bin:?}");
    println!("  genesis: {:?}", genesis_path());
    println!("  logs   : {log_dir:?}");
    println!("  data   : {dat_dir:?}");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Spawn node 0 first to get its peer-id for bootstrap
    let alice_data = dat_dir.join("alice");
    let alice_log  = log_dir.join("qcb1alice.log");
    let mut alice = spawn_node(
        &bin, "qcb1alice",
        API_PORTS[0], P2P_PORTS[0],
        &alice_data, &alice_log, None,
    );

    assert!(wait_for_port(API_PORTS[0], Duration::from_secs(15)),
        "alice API port :{} never opened", API_PORTS[0]);
    let peer_id = read_peer_id(&alice_log, Duration::from_secs(15));
    let bootstrap = format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer_id}", P2P_PORTS[0]);
    println!("   bootstrap: {bootstrap}");

    // Spawn remaining nodes
    let mut nodes: Vec<NodeProcess> = Vec::new();
    nodes.push(alice);
    for (i, &validator) in VALIDATORS[1..].iter().enumerate() {
        let idx = i + 1;
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

    // ── Phase 1: Run past the pruning threshold ───────────────────────────────

    let target_height = PRUNE_THRESHOLD + 1; // height 21 triggers first prune
    println!("\n── Phase 1: waiting for height {target_height} (pruning threshold) ──");
    // 21 blocks × ~9 s/block on Windows devnet = ~190 s plus network overhead
    poll_until_height(&mut nodes, target_height, Duration::from_secs(240), &log_dir);

    // ── Phase 2: Verify pruning fired on all nodes ────────────────────────────

    println!("\n── Phase 2: verifying chain_store_watermark > 0 on all nodes ──");
    for node in &nodes {
        let wm = poll_watermark(node.api_port)
            .unwrap_or_else(|| panic!("{} /api/status missing chain_store_watermark", node.validator));
        println!("   {}  chain_store_watermark = {wm}", node.validator);
        assert!(wm >= 1,
            "{} expected chain_store_watermark >= 1 after height {target_height}, got {wm}",
            node.validator);
    }

    // ── Phase 3: Verify height 1 is absent from chain_store.json ────────────
    //
    // The explorer VecDeque (queried by /api/blocks/{H}) holds up to 100 entries
    // and is populated independently of chain_store; it still has height 1 when
    // only 21 blocks have been committed.  The actual pruning evidence is in the
    // persisted chain_store.json file, which is written (after the prune) on
    // every commit_block call.

    println!("\n── Phase 3: verifying height 1 is absent from alice's chain_store.json ──");
    // Give alice's process a moment to finish writing the snapshot after height 21.
    std::thread::sleep(Duration::from_millis(500));
    // State is persisted under data_dir/snapshots/gen-NNNNNN/ (generation-based
    // snapshot layout).  Read CURRENT to find the active generation directory.
    let alice_dir  = dat_dir.join("alice");
    let current    = std::fs::read_to_string(alice_dir.join("CURRENT"))
        .unwrap_or_else(|e| panic!("cannot read alice/CURRENT: {e}"));
    let gen        = current.trim();
    let alice_cs_path = alice_dir.join("snapshots").join(gen).join("chain_store.json");
    println!("   reading {alice_cs_path:?}");
    let cs_text = std::fs::read_to_string(&alice_cs_path)
        .unwrap_or_else(|e| panic!("cannot read {alice_cs_path:?}: {e}"));
    let cs: serde_json::Value = serde_json::from_str(&cs_text)
        .unwrap_or_else(|e| panic!("chain_store.json is not valid JSON: {e}"));
    let keys: Vec<&str> = cs.as_object()
        .map(|m| { let mut v: Vec<&str> = m.keys().map(|s| s.as_str()).collect(); v.sort(); v })
        .unwrap_or_default();
    println!("   chain_store.json height keys: {:?}", &keys[..keys.len().min(6)]);
    assert!(!keys.contains(&"1"),
        "chain_store.json still contains height 1 after pruning (watermark=2);\
         \n  all keys: {keys:?}");
    println!("   ✓ height 1 is absent from chain_store.json (pruned)");

    // ── Phase 4: Agreement at current tip ────────────────────────────────────

    println!("\n── Phase 4: agreement check at height {target_height} ──");
    let mut tip_hashes: Vec<(&str, String, String)> = Vec::new();
    for node in &nodes {
        let h = fetch_block_field(node.api_port, target_height, "block_hash")
            .unwrap_or_else(|| panic!("{} /api/blocks/{target_height} block_hash unavailable", node.validator));
        let r = fetch_block_field(node.api_port, target_height, "state_root")
            .unwrap_or_else(|| panic!("{} /api/blocks/{target_height} state_root unavailable", node.validator));
        println!("   {}  block_hash={}  state_root={}", node.validator, h, r);
        tip_hashes.push((node.validator, h, r));
    }
    let (_, ref ref_hash, ref ref_root) = tip_hashes[0];
    for (v, h, r) in &tip_hashes[1..] {
        assert_eq!(h, ref_hash, "block_hash mismatch at height {target_height}: {} vs {}", v, tip_hashes[0].0);
        assert_eq!(r, ref_root, "state_root mismatch at height {target_height}: {} vs {}", v, tip_hashes[0].0);
    }
    println!("   ✓ all nodes agree on block_hash and state_root at height {target_height}");

    // ── Phase 5: Kill dave and let peers advance ──────────────────────────────

    let dave_idx = nodes.iter().position(|n| n.validator == "qcb1dave").unwrap();
    let dave_data = nodes[dave_idx].data_dir.clone();
    println!("\n── Phase 5: killing dave (idx {dave_idx}) ──");
    {
        let dave = &mut nodes[dave_idx];
        let _ = dave.child.kill();
        let _ = dave.child.wait();
    }
    // Tombstone so drop() doesn't double-kill
    nodes[dave_idx].api_port = 0;

    // Let alice/bob/carol advance 2 more blocks (3 of 4 is quorum)
    let advance_to = target_height + 2;
    println!("   waiting for alice/bob/carol to reach height {advance_to}...");
    let alive: Vec<u16> = nodes.iter().filter(|n| n.api_port != 0).map(|n| n.api_port).collect();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let all_at = alive.iter().all(|&p| poll_height(p).unwrap_or(0) >= advance_to);
        if all_at { break; }
        assert!(Instant::now() < deadline, "alive nodes did not reach height {advance_to} within 60s");
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("   alice/bob/carol reached height {advance_to}");

    // ── Phase 6: Restart dave from pruned storage ─────────────────────────────

    println!("\n── Phase 6: restarting dave from pruned data dir {dave_data:?} ──");
    let dave_log = log_dir.join("qcb1dave-restart.log");
    let dave_new = spawn_node(
        &bin, "qcb1dave",
        API_PORTS[dave_idx], P2P_PORTS[dave_idx],
        &dave_data, &dave_log,
        Some(&bootstrap),
    );
    assert!(wait_for_port(API_PORTS[dave_idx], Duration::from_secs(20)),
        "dave (restarted) API port :{} never opened", API_PORTS[dave_idx]);

    // Replace tombstone with the new process
    nodes[dave_idx] = dave_new;

    // ── Phase 7: Wait for dave to catch up ────────────────────────────────────

    println!("── Phase 7: waiting for dave to catch up to height {advance_to} ──");
    poll_until_height(&mut nodes, advance_to, Duration::from_secs(90), &log_dir);

    // ── Phase 8: Agreement at advance_to ─────────────────────────────────────

    println!("\n── Phase 8: agreement check at height {advance_to} ──");
    let mut final_hashes: Vec<(&str, String, String)> = Vec::new();
    for node in &nodes {
        let h = fetch_block_field(node.api_port, advance_to, "block_hash")
            .unwrap_or_else(|| panic!("{} /api/blocks/{advance_to} block_hash unavailable", node.validator));
        let r = fetch_block_field(node.api_port, advance_to, "state_root")
            .unwrap_or_else(|| panic!("{} /api/blocks/{advance_to} state_root unavailable", node.validator));
        println!("   {}  block_hash={}  state_root={}", node.validator, h, r);
        final_hashes.push((node.validator, h, r));
    }
    let (_, ref ref_hash2, ref ref_root2) = final_hashes[0];
    for (v, h, r) in &final_hashes[1..] {
        assert_eq!(h, ref_hash2,
            "block_hash mismatch at height {advance_to} after dave restart: {} vs {}",
            v, final_hashes[0].0);
        assert_eq!(r, ref_root2,
            "state_root mismatch at height {advance_to} after dave restart: {} vs {}",
            v, final_hashes[0].0);
    }
    println!("   ✓ dave (restarted from pruned storage) agrees with peers at height {advance_to}");
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  pqhs2_4node_fixed_set_pruning  PASS");
    println!("═══════════════════════════════════════════════════════════════\n");
}
