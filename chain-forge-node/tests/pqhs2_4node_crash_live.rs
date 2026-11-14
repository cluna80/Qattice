//! Phase 0.5 crash injection — PQ-HotStuff-2 ML-DSA-65 signing safety under node kill/restart.
//!
//! ## What is tested
//!
//! CJ-1 (`crash_proposer_before_commit`):
//!   Kill the proposer for height H before its proposal forms a QC.  The 3
//!   surviving nodes time out, advance to round 2, elect a new proposer, and
//!   commit at H with round=2.  The killed node is restarted; it reopens its
//!   SafetyStore, honours the persisted floor, and catches up without
//!   equivocation.  Verified: no "FloorViolation" or "violates the persisted
//!   floor" log line on the restarted node; all 4 nodes agree on state_root at
//!   the final height.
//!
//! CJ-2 (`crash_voter_after_prevote`):
//!   Kill a non-proposer after it has been running (and therefore signed at
//!   least one vote).  The remaining 3 nodes form a quorum and commit.  The
//!   killed node is restarted; it reopens its SafetyStore; floors prevent any
//!   attempt to sign below the recorded view.  Verified: no FloorViolation log
//!   line; all 4 nodes agree on state_root at the final height.
//!
//! CJ-3 (`crash_during_pruning`):
//!   Run the network past PRUNE_THRESHOLD (height > 20) so the prune watermark
//!   advances on all nodes, then kill one node.  Restart it from the pruned
//!   data dir; it must catch up to its peers and the prune watermark must be
//!   consistent (≥ PRUNE_THRESHOLD).  Verified: all 4 nodes agree on state_root.
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node --features pq-hotstuff
//! cargo test -p chain-forge-node --features pq-hotstuff \
//!   --test pqhs2_4node_crash_live -- --nocapture
//! ```
//!
//! Per CLAUDE.md: ✅ only after confirmed passing on Windows (MINGW64).

use std::{
    io::{BufRead, Write as _},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// ── Constants ──────────────────────────────────────────────────────────────────

const VALIDATORS: &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];

// Each test gets its own port block so the three tests can run in parallel
// without port collisions.  Phase 0 DIS-TX suite uses 19200-19203/29200-29203.
//   CJ-1: 19210-19213 / 29210-29213
//   CJ-2: 19220-19223 / 29220-29223
//   CJ-3: 19230-19233 / 29230-29233
const CJ1_API: &[u16] = &[19210, 19211, 19212, 19213];
const CJ1_P2P: &[u16] = &[29210, 29211, 29212, 29213];
const CJ2_API: &[u16] = &[19220, 19221, 19222, 19223];
const CJ2_P2P: &[u16] = &[29220, 29221, 29222, 29223];
const CJ3_API: &[u16] = &[19230, 19231, 19232, 19233];
const CJ3_P2P: &[u16] = &[29230, 29231, 29232, 29233];

const GENESIS_TEMPLATE: &str = "genesis-4node-pqhs2-fips204.json";
const KEY_DIR:           &str = "keys/fips204";

/// Proposer at height H, round R (1-based): (H + R - 1) % 4.
/// alice=0, bob=1, carol=2, dave=3.
fn proposer_index(height: u64, round: u64) -> usize {
    ((height + round - 1) % 4) as usize
}

/// Must match CHAIN_STORE_KEEP in node.rs.
const PRUNE_THRESHOLD: u64 = 20;

// ── Path helpers ──────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().to_path_buf()
}

fn node_binary() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe     = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    let debug   = target.join("debug").join(&exe);
    let release = target.join("release").join(&exe);
    match (
        debug.metadata().and_then(|m| m.modified()),
        release.metadata().and_then(|m| m.modified()),
    ) {
        (Ok(dt), Ok(rt)) => if dt >= rt { debug } else { release },
        (Ok(_), Err(_))  => debug,
        (Err(_), Ok(_))  => release,
        (Err(_), Err(_)) => debug,
    }
}

fn key_file(short: &str) -> PathBuf {
    repo_root().join("tests").join("devnet").join(KEY_DIR)
        .join(format!("{short}.key.json"))
}

// ── Genesis builder ───────────────────────────────────────────────────────────

/// Build a patched genesis for the given chain_id (one per test to avoid port/state collisions).
fn genesis_for(chain_id: &str) -> PathBuf {
    let template = repo_root().join("tests").join("devnet").join(GENESIS_TEMPLATE);
    let text = std::fs::read_to_string(&template)
        .unwrap_or_else(|e| panic!("read genesis template {template:?}: {e}"));
    let mut g: serde_json::Value = serde_json::from_str(&text)
        .expect("parse genesis template JSON");

    g["chain_id"] = serde_json::Value::String(chain_id.to_string());
    g["consensus"]["block_time_ms"] = serde_json::Value::Number(10_000.into());

    let dir = std::env::temp_dir()
        .join(format!("pqhs2_crash_genesis_{}_{}", std::process::id(), chain_id));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("genesis.json");
    let tmp = dir.join("genesis.json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(&g).unwrap()).unwrap();
    std::fs::rename(&tmp, &out).unwrap();
    out
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn http_raw(port: u16, method: &str, path: &str, body: Option<&str>)
    -> Option<(u16, String)>
{
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let content = body.unwrap_or("");
    let req = if body.is_some() {
        format!(
            "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{content}",
            content.len()
        )
    } else {
        format!("{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
    };
    stream.write_all(req.as_bytes()).ok()?;
    let reader = std::io::BufReader::new(stream);
    let mut lines = reader.lines();
    let status_line = lines.next()?.ok()?;
    let status_code: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    for line in lines.by_ref() {
        if line.ok()?.is_empty() { break; }
    }
    let mut resp = String::new();
    for line in lines {
        if let Ok(l) = line { resp.push_str(&l); }
    }
    Some((status_code, resp))
}

fn api_get(port: u16, path: &str) -> Option<serde_json::Value> {
    let (_, body) = http_raw(port, "GET", path, None)?;
    serde_json::from_str(&body).ok()
}

fn height_of(port: u16) -> u64 {
    api_get(port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0)
}

fn state_root_of(port: u16) -> String {
    api_get(port, "/api/status")
        .and_then(|v| v["state_root"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn watermark_of(port: u16) -> Option<u64> {
    api_get(port, "/api/status")
        .and_then(|v| v["chain_store_watermark"].as_u64())
}

fn wait_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() { return true; }
        if Instant::now() >= deadline { return false; }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_port_gone(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_err() { return true; }
        if Instant::now() >= deadline { return false; }
        std::thread::sleep(Duration::from_millis(100));
    }
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

/// Returns true if the log file for `validator` contains any FloorViolation line.
fn log_has_floor_violation(log_dir: &PathBuf, validator: &str) -> bool {
    let path = log_dir.join(format!("{validator}.log"));
    std::fs::read_to_string(path)
        .map(|s| {
            s.contains("FloorViolation")
                || s.contains("violates the persisted floor")
                || s.contains("floor violation")
        })
        .unwrap_or(false)
}

// ── Node lifecycle ────────────────────────────────────────────────────────────

struct NodeProcess {
    validator: &'static str,
    child:     Child,
    api_port:  u16,
    data_dir:  PathBuf,
    log_path:  PathBuf,
}

impl NodeProcess {
    fn log_tail(&self, n: usize) -> String {
        std::fs::read_to_string(&self.log_path)
            .map(|s| {
                let lines: Vec<_> = s.lines().collect();
                lines.iter().rev().take(n).collect::<Vec<_>>()
                    .into_iter().rev()
                    .map(|l| l.to_string()).collect::<Vec<_>>().join("\n")
            })
            .unwrap_or_default()
    }

    /// Kill this node and wait for the process to exit.
    fn kill_and_wait(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_node_with_genesis(
    bin:       &PathBuf,
    genesis:   &PathBuf,
    validator: &'static str,
    api_port:  u16,
    p2p_port:  u16,
    data_dir:  &PathBuf,
    log_path:  &PathBuf,
    bootstrap: Option<&str>,
    append_log: bool,
) -> NodeProcess {
    let log_file = if append_log {
        std::fs::OpenOptions::new().create(true).append(true).open(log_path)
            .unwrap_or_else(|e| panic!("cannot open log {log_path:?}: {e}"))
    } else {
        std::fs::File::create(log_path)
            .unwrap_or_else(|e| panic!("cannot create log {log_path:?}: {e}"))
    };

    let short = validator.strip_prefix("qcb1").unwrap_or(validator);
    let key   = key_file(short);

    std::fs::create_dir_all(data_dir).unwrap();

    let mut cmd = Command::new(bin);
    cmd.args([
        "--genesis",   genesis.to_str().unwrap(),
        "--validator", validator,
        "--key-file",  key.to_str().unwrap(),
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
        .unwrap_or_else(|e| panic!("spawn {validator}: {e}"));

    NodeProcess {
        validator,
        child,
        api_port,
        data_dir: data_dir.clone(),
        log_path: log_path.clone(),
    }
}

fn wait_height_subset(
    nodes:   &mut [&mut NodeProcess],
    target:  u64,
    timeout: Duration,
    label:   &str,
) {
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            for node in nodes.iter() {
                println!("\n── {} log (last 20 lines) ──", node.validator);
                println!("{}", node.log_tail(20));
            }
            panic!("{label}: nodes did not reach height {target} within {timeout:?}");
        }

        let mut all = true;
        let mut status = String::new();
        for node in nodes.iter_mut() {
            if let Ok(Some(exit)) = node.child.try_wait().map_err(|_| ()) {
                panic!("{} exited unexpectedly: {exit}", node.validator);
            }
            let h = height_of(node.api_port);
            status.push_str(&format!("  {}={h}", node.validator));
            if h < target { all = false; }
        }

        print!("\r   [{label} {:.1}s]{status}   ", start.elapsed().as_secs_f32());
        std::io::stdout().flush().ok();

        if all {
            println!("\n── {label}: all reached height {target} in {:.1?}", start.elapsed());
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn wait_height(nodes: &mut Vec<NodeProcess>, target: u64, timeout: Duration, label: &str) {
    let mut refs: Vec<&mut NodeProcess> = nodes.iter_mut().collect();
    wait_height_subset(&mut refs, target, timeout, label);
}

// ── CJ-1: Kill proposer before commit ────────────────────────────────────────

#[test]
#[cfg_attr(not(feature = "pq-hotstuff"), ignore = "requires pq-hotstuff feature")]
fn crash_proposer_before_commit() {
    let bin = node_binary();
    if !bin.exists() {
        eprintln!("SKIP: binary not found at {bin:?}");
        return;
    }

    let chain_id = "qcb-devnet-cj1-crash-proposer";
    let genesis  = genesis_for(chain_id);

    let log_dir = std::env::temp_dir().join("pqhs2_cj1_logs");
    let dat_dir = std::env::temp_dir().join("pqhs2_cj1_data");
    let _ = std::fs::remove_dir_all(&log_dir);
    let _ = std::fs::remove_dir_all(&dat_dir);
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::create_dir_all(&dat_dir).unwrap();

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  CJ-1  crash_proposer_before_commit");
    println!("  binary : {bin:?}");
    println!("  genesis: {genesis:?}");
    println!("═══════════════════════════════════════════════════════════════\n");

    // ── Phase 1: Bring up all 4 nodes ────────────────────────────────────────

    println!("── Phase 1: start 4-node devnet ──");

    let alice_log  = log_dir.join("qcb1alice.log");
    let alice_data = dat_dir.join("alice");
    let mut alice  = spawn_node_with_genesis(
        &bin, &genesis, "qcb1alice",
        CJ1_API[0], CJ1_P2P[0],
        &alice_data, &alice_log, None, false,
    );
    assert!(wait_port(CJ1_API[0], Duration::from_secs(30)),
        "alice API never opened");
    let peer_id   = read_peer_id(&alice_log, Duration::from_secs(20));
    let bootstrap = format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer_id}", CJ1_P2P[0]);
    println!("   bootstrap: {bootstrap}");

    let mut bob   = spawn_node_with_genesis(
        &bin, &genesis, "qcb1bob",
        CJ1_API[1], CJ1_P2P[1],
        &dat_dir.join("bob"), &log_dir.join("qcb1bob.log"),
        Some(&bootstrap), false,
    );
    let mut carol = spawn_node_with_genesis(
        &bin, &genesis, "qcb1carol",
        CJ1_API[2], CJ1_P2P[2],
        &dat_dir.join("carol"), &log_dir.join("qcb1carol.log"),
        Some(&bootstrap), false,
    );
    let mut dave  = spawn_node_with_genesis(
        &bin, &genesis, "qcb1dave",
        CJ1_API[3], CJ1_P2P[3],
        &dat_dir.join("dave"), &log_dir.join("qcb1dave.log"),
        Some(&bootstrap), false,
    );
    for (port, name) in [(CJ1_API[1], "bob"), (CJ1_API[2], "carol"), (CJ1_API[3], "dave")] {
        assert!(wait_port(port, Duration::from_secs(30)), "{name} API never opened");
    }

    let mut all = vec![alice, bob, carol, dave];
    wait_height(&mut all, 3, Duration::from_secs(300), "Phase1");

    // ── Phase 2: Determine proposer for height 5 and kill it ─────────────────

    // Height 5, round 1 → proposer index = (5+1-1) % 4 = 1 → "qcb1bob".
    // We kill bob BEFORE height 5 commits so the surviving 3 must timeout and
    // elect a new proposer at round 2.
    let kill_target_height: u64 = 5;
    let kill_idx    = proposer_index(kill_target_height, 1);
    let kill_name   = VALIDATORS[kill_idx];
    let kill_port   = CJ1_API[kill_idx];
    println!("\n── Phase 2: kill proposer for height {kill_target_height} ({kill_name}, port {kill_port}) ──");

    // Wait until height 4 is committed on all nodes before killing, so the
    // kill happens exactly when height 5 round 1 begins.
    wait_height(&mut all, kill_target_height - 1, Duration::from_secs(300), "pre-kill");

    // Kill the target node.
    all[kill_idx].kill_and_wait();
    assert!(
        wait_port_gone(kill_port, Duration::from_secs(15)),
        "{kill_name} port {kill_port} still open after kill"
    );
    println!("   {kill_name} killed (port {kill_port} closed)");

    // ── Phase 3: Remaining 3 nodes commit at round 2 ─────────────────────────

    println!("\n── Phase 3: surviving 3 nodes must commit height {kill_target_height} ──");
    let target_height = kill_target_height + 2;
    {
        let (left, right) = all.split_at_mut(kill_idx);
        let mut survivors_ref: Vec<&mut NodeProcess> =
            left.iter_mut().chain(right[1..].iter_mut()).collect();
        wait_height_subset(&mut survivors_ref, target_height, Duration::from_secs(300), "Phase3-survivors");
    }
    println!("   survivors reached height {target_height}");

    // ── Phase 4: Restart killed node ─────────────────────────────────────────

    println!("\n── Phase 4: restart {kill_name} from same data dir ──");

    let restart_log = log_dir.join(format!("{kill_name}.log"));
    let restart_data = dat_dir.join(VALIDATORS[kill_idx].strip_prefix("qcb1").unwrap());

    // Append restart output to same log so we can scan the whole log for FloorViolation.
    let restarted = spawn_node_with_genesis(
        &bin, &genesis, VALIDATORS[kill_idx],
        CJ1_API[kill_idx], CJ1_P2P[kill_idx],
        &restart_data, &restart_log,
        Some(&bootstrap), true,
    );
    assert!(
        wait_port(CJ1_API[kill_idx], Duration::from_secs(30)),
        "{kill_name} API did not reopen after restart"
    );
    all[kill_idx] = restarted;

    // ── Phase 5: All 4 catch up and agree ────────────────────────────────────

    let final_height = target_height + 3;
    println!("\n── Phase 5: wait for all 4 to reach height {final_height} ──");
    wait_height(&mut all, final_height, Duration::from_secs(300), "Phase5");

    // ── Phase 6: Verify safety ────────────────────────────────────────────────

    println!("\n── Phase 6: safety checks ──");

    // No FloorViolation on the restarted node.
    assert!(
        !log_has_floor_violation(&log_dir, kill_name),
        "FloorViolation detected in {kill_name} log after crash+restart — signing safety violated!"
    );
    println!("   no FloorViolation in {kill_name} log ✓");

    // All 4 nodes agree on state_root.
    let roots: Vec<String> = all.iter().map(|n| state_root_of(n.api_port)).collect();
    println!("   state roots: {roots:?}");
    for (i, root) in roots.iter().enumerate() {
        assert_eq!(
            root, &roots[0],
            "{} state_root {:?} differs from alice {:?}",
            VALIDATORS[i], root, roots[0]
        );
    }
    println!("   all 4 nodes agree on state_root ✓");

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  CJ-1  PASS");
    println!("═══════════════════════════════════════════════════════════════\n");
}

// ── CJ-2: Kill a voter after it has signed ───────────────────────────────────

#[test]
#[cfg_attr(not(feature = "pq-hotstuff"), ignore = "requires pq-hotstuff feature")]
fn crash_voter_after_prevote() {
    let bin = node_binary();
    if !bin.exists() {
        eprintln!("SKIP: binary not found at {bin:?}");
        return;
    }

    let chain_id = "qcb-devnet-cj2-crash-voter";
    let genesis  = genesis_for(chain_id);

    let log_dir = std::env::temp_dir().join("pqhs2_cj2_logs");
    let dat_dir = std::env::temp_dir().join("pqhs2_cj2_data");
    let _ = std::fs::remove_dir_all(&log_dir);
    let _ = std::fs::remove_dir_all(&dat_dir);
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::create_dir_all(&dat_dir).unwrap();

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  CJ-2  crash_voter_after_prevote");
    println!("  binary : {bin:?}");
    println!("  genesis: {genesis:?}");
    println!("═══════════════════════════════════════════════════════════════\n");

    // ── Phase 1: Start all 4 nodes ────────────────────────────────────────────

    println!("── Phase 1: start 4-node devnet ──");

    let alice_log  = log_dir.join("qcb1alice.log");
    let alice_data = dat_dir.join("alice");
    let alice = spawn_node_with_genesis(
        &bin, &genesis, "qcb1alice",
        CJ2_API[0], CJ2_P2P[0],
        &alice_data, &alice_log, None, false,
    );
    assert!(wait_port(CJ2_API[0], Duration::from_secs(30)), "alice API never opened");
    let peer_id   = read_peer_id(&alice_log, Duration::from_secs(20));
    let bootstrap = format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer_id}", CJ2_P2P[0]);

    let bob   = spawn_node_with_genesis(&bin, &genesis, "qcb1bob",
        CJ2_API[1], CJ2_P2P[1], &dat_dir.join("bob"),
        &log_dir.join("qcb1bob.log"), Some(&bootstrap), false);
    let carol = spawn_node_with_genesis(&bin, &genesis, "qcb1carol",
        CJ2_API[2], CJ2_P2P[2], &dat_dir.join("carol"),
        &log_dir.join("qcb1carol.log"), Some(&bootstrap), false);
    let dave  = spawn_node_with_genesis(&bin, &genesis, "qcb1dave",
        CJ2_API[3], CJ2_P2P[3], &dat_dir.join("dave"),
        &log_dir.join("qcb1dave.log"), Some(&bootstrap), false);
    for (port, name) in [(CJ2_API[1], "bob"), (CJ2_API[2], "carol"), (CJ2_API[3], "dave")] {
        assert!(wait_port(port, Duration::from_secs(30)), "{name} API never opened");
    }

    let mut all = vec![alice, bob, carol, dave];

    // Let all nodes run for a while so each has signed multiple votes.
    wait_height(&mut all, 5, Duration::from_secs(300), "Phase1-establish");

    // ── Phase 2: Kill the non-proposer at height 5 (carol = index 2) ─────────
    // At height 5, round 1 → proposer = (5+1-1) % 4 = 1 (bob).
    // Kill carol (index 2), a voter that has already signed at heights 1-5.
    let kill_idx  = 2; // carol
    let kill_name = VALIDATORS[kill_idx];
    let kill_port = CJ2_API[kill_idx];

    println!("\n── Phase 2: kill voter {kill_name} ──");
    all[kill_idx].kill_and_wait();
    assert!(wait_port_gone(kill_port, Duration::from_secs(15)),
        "{kill_name} port still open");
    println!("   {kill_name} killed ✓");

    // ── Phase 3: Remaining 3 commit more blocks ───────────────────────────────

    let commit_height = 10;
    println!("\n── Phase 3: surviving 3 commit to height {commit_height} ──");
    {
        // kill_idx == 2 (carol): split at 2 → left=[alice,bob], right=[carol,dave][1..]=[dave]
        let (left, right) = all.split_at_mut(kill_idx);
        let mut survivors_ref: Vec<&mut NodeProcess> =
            left.iter_mut().chain(right[1..].iter_mut()).collect();
        wait_height_subset(&mut survivors_ref, commit_height, Duration::from_secs(300), "Phase3");
    }

    // ── Phase 4: Restart carol ────────────────────────────────────────────────

    println!("\n── Phase 4: restart {kill_name} ──");
    let restarted = spawn_node_with_genesis(
        &bin, &genesis, VALIDATORS[kill_idx],
        CJ2_API[kill_idx], CJ2_P2P[kill_idx],
        &dat_dir.join("carol"), &log_dir.join("qcb1carol.log"),
        Some(&bootstrap), true,
    );
    assert!(wait_port(CJ2_API[kill_idx], Duration::from_secs(30)),
        "{kill_name} API did not reopen");
    all[kill_idx] = restarted;

    // ── Phase 5: All 4 agree ──────────────────────────────────────────────────

    let final_height = commit_height + 3;
    println!("\n── Phase 5: all 4 to height {final_height} ──");
    wait_height(&mut all, final_height, Duration::from_secs(300), "Phase5");

    // ── Phase 6: Safety checks ────────────────────────────────────────────────

    println!("\n── Phase 6: safety checks ──");
    assert!(
        !log_has_floor_violation(&log_dir, kill_name),
        "FloorViolation detected in {kill_name} log after crash+restart!"
    );
    println!("   no FloorViolation in {kill_name} log ✓");

    let roots: Vec<String> = all.iter().map(|n| state_root_of(n.api_port)).collect();
    println!("   state roots: {roots:?}");
    for (i, root) in roots.iter().enumerate() {
        assert_eq!(root, &roots[0],
            "{} state_root differs from alice", VALIDATORS[i]);
    }
    println!("   all 4 nodes agree on state_root ✓");

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  CJ-2  PASS");
    println!("═══════════════════════════════════════════════════════════════\n");
}

// ── CJ-3: Kill during pruning, restart from pruned data ──────────────────────

#[test]
#[cfg_attr(not(feature = "pq-hotstuff"), ignore = "requires pq-hotstuff feature")]
fn crash_during_pruning() {
    let bin = node_binary();
    if !bin.exists() {
        eprintln!("SKIP: binary not found at {bin:?}");
        return;
    }

    let chain_id = "qcb-devnet-cj3-crash-prune";
    let genesis  = genesis_for(chain_id);

    let log_dir = std::env::temp_dir().join("pqhs2_cj3_logs");
    let dat_dir = std::env::temp_dir().join("pqhs2_cj3_data");
    let _ = std::fs::remove_dir_all(&log_dir);
    let _ = std::fs::remove_dir_all(&dat_dir);
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::create_dir_all(&dat_dir).unwrap();

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  CJ-3  crash_during_pruning");
    println!("  binary : {bin:?}");
    println!("  genesis: {genesis:?}");
    println!("  PRUNE_THRESHOLD: {PRUNE_THRESHOLD}");
    println!("═══════════════════════════════════════════════════════════════\n");

    // ── Phase 1: Start all 4 nodes ────────────────────────────────────────────

    println!("── Phase 1: start 4-node devnet ──");

    let alice_log  = log_dir.join("qcb1alice.log");
    let alice_data = dat_dir.join("alice");
    let alice = spawn_node_with_genesis(
        &bin, &genesis, "qcb1alice",
        CJ3_API[0], CJ3_P2P[0],
        &alice_data, &alice_log, None, false,
    );
    assert!(wait_port(CJ3_API[0], Duration::from_secs(30)), "alice API never opened");
    let peer_id   = read_peer_id(&alice_log, Duration::from_secs(20));
    let bootstrap = format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer_id}", CJ3_P2P[0]);

    let bob   = spawn_node_with_genesis(&bin, &genesis, "qcb1bob",
        CJ3_API[1], CJ3_P2P[1], &dat_dir.join("bob"),
        &log_dir.join("qcb1bob.log"), Some(&bootstrap), false);
    let carol = spawn_node_with_genesis(&bin, &genesis, "qcb1carol",
        CJ3_API[2], CJ3_P2P[2], &dat_dir.join("carol"),
        &log_dir.join("qcb1carol.log"), Some(&bootstrap), false);
    let dave  = spawn_node_with_genesis(&bin, &genesis, "qcb1dave",
        CJ3_API[3], CJ3_P2P[3], &dat_dir.join("dave"),
        &log_dir.join("qcb1dave.log"), Some(&bootstrap), false);
    for (port, name) in [(CJ3_API[1], "bob"), (CJ3_API[2], "carol"), (CJ3_API[3], "dave")] {
        assert!(wait_port(port, Duration::from_secs(30)), "{name} API never opened");
    }

    let mut all = vec![alice, bob, carol, dave];

    // ── Phase 2: Run past prune threshold ────────────────────────────────────

    // +2 is enough to verify the watermark advanced; +5 risks a timeout when
    // 12 node processes run in parallel in a debug build on Windows (~29s/block).
    let past_prune = PRUNE_THRESHOLD + 2;
    println!("── Phase 2: run to height {past_prune} (past PRUNE_THRESHOLD={PRUNE_THRESHOLD}) ──");
    wait_height(&mut all, past_prune, Duration::from_secs(900), "Phase2-prune");

    // Verify at least one node has a watermark ≥ PRUNE_THRESHOLD.
    let watermarks: Vec<Option<u64>> = all.iter()
        .map(|n| watermark_of(n.api_port)).collect();
    println!("   watermarks: {watermarks:?}");
    let any_pruned = watermarks.iter().any(|w| w.map_or(false, |v| v >= PRUNE_THRESHOLD));
    assert!(any_pruned, "no node has chain_store_watermark >= {PRUNE_THRESHOLD}; got {watermarks:?}");

    // ── Phase 3: Kill dave (index 3) ─────────────────────────────────────────

    let kill_idx  = 3; // dave
    let kill_name = VALIDATORS[kill_idx];
    let kill_port = CJ3_API[kill_idx];

    println!("\n── Phase 3: kill {kill_name} at height {past_prune} ──");
    all[kill_idx].kill_and_wait();
    assert!(wait_port_gone(kill_port, Duration::from_secs(15)),
        "{kill_name} port still open");
    println!("   {kill_name} killed ✓");

    // ── Phase 4: Survivors continue ───────────────────────────────────────────

    let commit_height = past_prune + 3;
    println!("\n── Phase 4: surviving 3 commit to height {commit_height} ──");
    {
        // kill_idx == 3 (dave): split at 3 → left=[alice,bob,carol], right=[dave][1..]=[]
        let (left, _right) = all.split_at_mut(kill_idx);
        let mut survivors_ref: Vec<&mut NodeProcess> = left.iter_mut().collect();
        wait_height_subset(&mut survivors_ref, commit_height, Duration::from_secs(300), "Phase4");
    }

    // ── Phase 5: Restart dave from pruned data dir ────────────────────────────

    println!("\n── Phase 5: restart {kill_name} from pruned data dir ──");
    let restarted = spawn_node_with_genesis(
        &bin, &genesis, VALIDATORS[kill_idx],
        CJ3_API[kill_idx], CJ3_P2P[kill_idx],
        &dat_dir.join("dave"), &log_dir.join("qcb1dave.log"),
        Some(&bootstrap), true,
    );
    assert!(wait_port(CJ3_API[kill_idx], Duration::from_secs(30)),
        "{kill_name} API did not reopen");
    all[kill_idx] = restarted;

    // ── Phase 6: All 4 agree ──────────────────────────────────────────────────

    let final_height = commit_height + 3;
    println!("\n── Phase 6: all 4 to height {final_height} ──");
    wait_height(&mut all, final_height, Duration::from_secs(300), "Phase6");

    // ── Phase 7: Verify ───────────────────────────────────────────────────────

    println!("\n── Phase 7: verification ──");

    // Restarted node must have watermark ≥ PRUNE_THRESHOLD (it picked it up from peers).
    let dave_wm = watermark_of(CJ3_API[kill_idx]);
    println!("   {kill_name} watermark: {dave_wm:?}");
    assert!(
        dave_wm.map_or(false, |v| v >= PRUNE_THRESHOLD),
        "{kill_name} watermark after restart must be >= {PRUNE_THRESHOLD}, got {dave_wm:?}"
    );
    println!("   {kill_name} watermark consistent ✓");

    // No floor violation on the restarted node.
    assert!(
        !log_has_floor_violation(&log_dir, kill_name),
        "FloorViolation detected in {kill_name} log after crash+restart!"
    );
    println!("   no FloorViolation in {kill_name} log ✓");

    // All 4 agree on state_root.
    let roots: Vec<String> = all.iter().map(|n| state_root_of(n.api_port)).collect();
    println!("   state roots: {roots:?}");
    for (i, root) in roots.iter().enumerate() {
        assert_eq!(root, &roots[0],
            "{} state_root differs from alice", VALIDATORS[i]);
    }
    println!("   all 4 nodes agree on state_root ✓");

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  CJ-3  PASS");
    println!("═══════════════════════════════════════════════════════════════\n");
}
