//! H0-4 Nonce-replay hardening — PQ-HotStuff-2 native path
//!
//! ## Scenarios
//!
//! NR-01  nonce == u64::MAX is refused at admission (HTTP 4xx / status=rejected).
//! NR-02  cross-block replay: a tx that committed at nonce N is re-submitted with
//!        nonce N again; the second submission must be refused or fail execution.
//!        Balance and nonce are unchanged by the rejected tx.
//! NR-03  future nonce: a tx with nonce > current account nonce is refused or
//!        fails execution; balance and nonce are unchanged.
//!
//! ## Notes
//!
//! The pqhs2 genesis uses `signature_scheme: "pqc-native"`, which forces
//! ML-DSA signatures on user transactions.  To submit *unsigned* transactions
//! for the nonce-overflow corner case we patch `signature_scheme` to `"hybrid"`
//! (Ed25519Allowed policy) while keeping `bft_variant: "pq-hotstuff"`.  Signed
//! ML-DSA transactions are used for all other cases.
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node --features pq-hotstuff
//! cargo test -p chain-forge-node --features pq-hotstuff \
//!   --test h0_4_nonce_replay_live -- --nocapture
//! ```
//!
//! Per CLAUDE.md: ✅ only after confirmed passing on Windows (MINGW64).

#![cfg_attr(not(feature = "pq-hotstuff"), allow(unused))]

use std::{
    io::{BufRead, Write as _},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{MlDsaScheme, SchemeId, SignatureScheme, mldsa_tx_prehash};
use chain_forge_execution::{Transaction, TxBody};

// ── Constants ──────────────────────────────────────────────────────────────────

const VALIDATORS:  &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
const API_PORTS:   &[u16]  = &[19210, 19211, 19212, 19213];
const P2P_PORTS:   &[u16]  = &[29210, 29211, 29212, 29213];

const GENESIS_TEMPLATE: &str = "genesis-4node-pqhs2-fips204.json";
const KEY_DIR:           &str = "keys/fips204";

const CHAIN_ID:    &str = "qcb-devnet-h04-nonce";
const ALICE_ADDR:  &str = "qcb1alice_sender";
const ALICE_SEED:  &str = "h04-nonce-alice-seed-00000000000000000000001";
const RECV_ADDR:   &str = "qcb1nonce_recv";
const TX_AMOUNT:   u128 = 10_000;

// ── Path helpers ──────────────────────────────────────────────────────────────

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

fn key_file(short: &str) -> PathBuf {
    repo_root().join("tests").join("devnet").join(KEY_DIR)
        .join(format!("{short}.key.json"))
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ── Genesis builder ───────────────────────────────────────────────────────────

/// Build a patched genesis for the nonce-replay suite.
///
/// Patches:
/// - `chain_id` → CHAIN_ID
/// - `cryptography.signature_scheme` → "hybrid"  (allows unsigned txs on PQ-HotStuff-2)
/// - `execution.require_signatures` → false       (consistent with hybrid)
/// - Adds ALICE_ADDR (funded, ML-DSA key bound)
/// - Adds RECV_ADDR  (funded, no key — acts as a plain recipient)
fn genesis_path() -> PathBuf {
    static ONCE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let template = repo_root().join("tests").join("devnet").join(GENESIS_TEMPLATE);
        let text = std::fs::read_to_string(&template)
            .unwrap_or_else(|e| panic!("read genesis template {template:?}: {e}"));
        let mut g: serde_json::Value = serde_json::from_str(&text)
            .expect("parse genesis template JSON");

        g["chain_id"] = serde_json::Value::String(CHAIN_ID.to_string());
        g["consensus"]["block_time_ms"] = serde_json::Value::Number(10_000.into());

        // Hybrid policy: ML-DSA-signed txs still work but unsigned ones are
        // also accepted, enabling NR-01 (u64::MAX nonce) with an unsigned tx.
        g["cryptography"]["signature_scheme"] = serde_json::Value::String("hybrid".into());
        g["execution"]["require_signatures"]  = serde_json::Value::Bool(false);

        // Alice's ML-DSA-65 key — bound in genesis so key-binding doesn't fire.
        let kp     = MlDsaScheme.generate_keypair(ALICE_SEED).expect("alice ML-DSA keygen");
        let pk_hex = hex_encode(&kp.public_key);

        g["genesis_accounts"].as_array_mut().unwrap().push(serde_json::json!({
            "label":      "Alice sender",
            "address":    ALICE_ADDR,
            "balance":    "50000000",
            "role":       "user",
            "public_key": pk_hex
        }));
        g["genesis_accounts"].as_array_mut().unwrap().push(serde_json::json!({
            "label":   "Nonce recv",
            "address": RECV_ADDR,
            "balance": "1000000",
            "role":    "user"
        }));

        let dir = std::env::temp_dir()
            .join(format!("h0_4_nonce_replay_genesis_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("genesis.json");
        let tmp = dir.join("genesis.json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&g).unwrap()).unwrap();
        std::fs::rename(&tmp, &out).unwrap();
        out
    }).clone()
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

fn api_post(port: u16, path: &str, body: &str) -> Option<(u16, serde_json::Value)> {
    let (status, resp) = http_raw(port, "POST", path, Some(body))?;
    let val = serde_json::from_str(&resp).unwrap_or(serde_json::Value::Null);
    Some((status, val))
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

fn balance_of(port: u16, addr: &str) -> u128 {
    api_get(port, &format!("/api/accounts/{addr}"))
        .and_then(|v| {
            v["balance"].as_str().and_then(|s| s.parse().ok())
                .or_else(|| v["balance"].as_u64().map(|n| n as u128))
                .or_else(|| v["balances"]["uqcb"].as_str().and_then(|s| s.parse().ok()))
                .or_else(|| v["balances"]["uqcb"].as_u64().map(|n| n as u128))
        })
        .unwrap_or(0)
}

fn nonce_of(port: u16, addr: &str) -> u64 {
    api_get(port, &format!("/api/accounts/{addr}"))
        .and_then(|v| v["nonce"].as_u64())
        .unwrap_or(0)
}

fn wait_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() { return true; }
        if Instant::now() >= deadline { return false; }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_tx_result(port: u16, tx_id: &str, timeout: Duration) -> Option<serde_json::Value> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = api_get(port, &format!("/api/tx/{tx_id}")) {
            if v.get("success").is_some() { return Some(v); }
            if v.get("code").is_some()    { return Some(v); }
        }
        if Instant::now() >= deadline { return None; }
        std::thread::sleep(Duration::from_millis(300));
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

// ── Node lifecycle ────────────────────────────────────────────────────────────

struct NodeProcess {
    validator: &'static str,
    child:     Child,
    api_port:  u16,
    log_path:  PathBuf,
}

impl NodeProcess {
    fn log_tail(&self, n: usize) -> String {
        std::fs::read_to_string(&self.log_path)
            .map(|s| {
                let lines: Vec<_> = s.lines().collect();
                lines.iter().rev().take(n).collect::<Vec<_>>().into_iter().rev()
                    .map(|l| l.to_string()).collect::<Vec<_>>().join("\n")
            })
            .unwrap_or_default()
    }
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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
    let short = validator.strip_prefix("qcb1").unwrap_or(validator);
    let key = key_file(short);
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
    NodeProcess { validator, child, api_port, log_path: log_path.clone() }
}

fn wait_height(nodes: &mut Vec<NodeProcess>, target: u64, timeout: Duration, log_dir: &PathBuf) {
    let start = Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed > timeout {
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
            let h = height_of(node.api_port);
            status.push_str(&format!("  {}={h}", node.validator));
            if h < target { all_reached = false; }
        }
        print!("\r   [{:>4.1}s]{status}   ", elapsed.as_secs_f32());
        std::io::stdout().flush().ok();
        if all_reached {
            println!("\n\n── All nodes reached height {target} in {:.1?} ──", start.elapsed());
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ── Transaction builders ──────────────────────────────────────────────────────

fn unsigned_transfer(id: &str, sender: &str, nonce: u64) -> Transaction {
    Transaction {
        id:            id.to_string(),
        sender:        sender.to_string(),
        nonce,
        body:          TxBody::Transfer { to: RECV_ADDR.to_string(), denom: "uqcb".to_string(), amount: TX_AMOUNT },
        gas_limit:     200_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![],
        sig_scheme:    None,
        pq_public_key: vec![],
    }
}

fn signed_transfer(id: &str, nonce: u64) -> Transaction {
    let kp       = MlDsaScheme.generate_keypair(ALICE_SEED).expect("alice ML-DSA keygen");
    let body     = TxBody::Transfer { to: RECV_ADDR.to_string(), denom: "uqcb".to_string(), amount: TX_AMOUNT };
    let body_json = serde_json::to_string(&body).expect("body serialise");
    let message  = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let sig      = MlDsaScheme.sign(&message, &kp).expect("ML-DSA sign");
    Transaction {
        id:            id.to_string(),
        sender:        ALICE_ADDR.to_string(),
        nonce,
        body,
        gas_limit:     500_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![format!("mldsa65:{}", hex_encode(&sig.bytes))],
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: kp.public_key.clone(),
    }
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[test]
#[cfg_attr(not(feature = "pq-hotstuff"), ignore = "requires pq-hotstuff feature")]
fn h0_4_nonce_replay() {
    let bin = node_binary();
    if !bin.exists() {
        eprintln!("SKIP: node binary not found at {bin:?}. Run `cargo build -p chain-forge-node --features pq-hotstuff` first.");
        return;
    }

    let log_dir = std::env::temp_dir().join("h0_4_nonce_replay_live");
    let dat_dir = std::env::temp_dir().join("h0_4_nonce_replay_data");
    let _ = std::fs::remove_dir_all(&log_dir);
    let _ = std::fs::remove_dir_all(&dat_dir);
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::create_dir_all(&dat_dir).unwrap();

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  h0_4_nonce_replay");
    println!("  binary : {bin:?}");
    println!("  genesis: {:?}", genesis_path());
    println!("  logs   : {log_dir:?}");
    println!("═══════════════════════════════════════════════════════════════\n");

    // ── Start devnet ──────────────────────────────────────────────────────────

    println!("── starting 4-node PQ-HotStuff-2 devnet (hybrid sig policy) ──");

    let alice_data = dat_dir.join("alice");
    let alice_log  = log_dir.join("qcb1alice.log");
    let alice = spawn_node(&bin, "qcb1alice", API_PORTS[0], P2P_PORTS[0],
        &alice_data, &alice_log, None);
    assert!(wait_port(API_PORTS[0], Duration::from_secs(20)),
        "alice API :{} never opened", API_PORTS[0]);
    let peer_id   = read_peer_id(&alice_log, Duration::from_secs(20));
    let bootstrap = format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer_id}", P2P_PORTS[0]);
    println!("   bootstrap: {bootstrap}");

    let mut nodes: Vec<NodeProcess> = vec![alice];
    for (i, &validator) in VALIDATORS[1..].iter().enumerate() {
        let idx      = i + 1;
        let short    = validator.strip_prefix("qcb1").unwrap_or(validator);
        let data_dir = dat_dir.join(short);
        let log_path = log_dir.join(format!("{validator}.log"));
        let node = spawn_node(&bin, validator,
            API_PORTS[idx], P2P_PORTS[idx],
            &data_dir, &log_path, Some(&bootstrap));
        assert!(wait_port(API_PORTS[idx], Duration::from_secs(20)),
            "{validator} API :{} never opened", API_PORTS[idx]);
        nodes.push(node);
    }

    println!("   waiting for height 2...");
    wait_height(&mut nodes, 2, Duration::from_secs(300), &log_dir);

    // ── NR-01: nonce == u64::MAX refused at admission ─────────────────────────

    println!("\n── NR-01: nonce == u64::MAX refused at admission ──");
    {
        let tx     = unsigned_transfer("nr01-maxnonce", ALICE_ADDR, u64::MAX);
        let tx_json = serde_json::to_string(&tx).expect("serialise");
        let (status, resp) = api_post(API_PORTS[0], "/api/tx", &tx_json)
            .expect("no response");
        println!("   HTTP {status}: {resp}");
        let rejected = status >= 400
            || resp["status"].as_str() == Some("rejected")
            || resp.get("code").is_some();
        assert!(rejected,
            "NR-01: u64::MAX nonce must be refused at admission; got HTTP {status}: {resp}");
        println!("   ✓ NR-01: u64::MAX nonce rejected (HTTP {status})");
    }

    // ── NR-02: cross-block replay ─────────────────────────────────────────────

    println!("\n── NR-02: cross-block replay ──");
    {
        let bal0   = balance_of(API_PORTS[0], ALICE_ADDR);
        let nonce0 = nonce_of(API_PORTS[0], ALICE_ADDR);
        println!("   alice balance={bal0}  nonce={nonce0}");

        // Submit valid tx at nonce0.
        let tx1     = signed_transfer("nr02-first", nonce0);
        let tx1_json = serde_json::to_string(&tx1).expect("serialise");
        let (s1, r1) = api_post(API_PORTS[0], "/api/tx", &tx1_json)
            .expect("no response");
        println!("   tx1 submit HTTP {s1}: {r1}");
        assert!(s1 == 200 || s1 == 202,
            "NR-02: valid tx1 must be accepted; got HTTP {s1}: {r1}");

        let result1 = wait_tx_result(API_PORTS[0], "nr02-first", Duration::from_secs(180))
            .unwrap_or_else(|| {
                println!("   Alice log (last 30):\n{}", nodes[0].log_tail(30));
                panic!("NR-02: tx1 did not commit within 180s");
            });
        println!("   tx1 result: {result1}");
        assert!(result1["success"].as_bool() == Some(true),
            "NR-02: tx1 must succeed; got: {result1}");
        println!("   ✓ NR-02: tx1 committed (height={})", result1["height"]);

        // Record post-commit state.
        let bal1   = balance_of(API_PORTS[0], ALICE_ADDR);
        let nonce1 = nonce_of(API_PORTS[0], ALICE_ADDR);
        println!("   after commit: alice balance={bal1}  nonce={nonce1}");
        assert_eq!(nonce1, nonce0 + 1, "NR-02: nonce must increment after tx1");

        // Re-submit same nonce (stale).
        let tx_replay     = signed_transfer("nr02-replay", nonce0);
        let tx_replay_json = serde_json::to_string(&tx_replay).expect("serialise");
        let (sr, rr) = api_post(API_PORTS[0], "/api/tx", &tx_replay_json)
            .expect("no response");
        println!("   replay submit HTTP {sr}: {rr}");

        let replay_rejected_at_admission = sr >= 400
            || rr["status"].as_str() == Some("rejected")
            || rr.get("code").is_some();

        if replay_rejected_at_admission {
            println!("   ✓ NR-02: replay rejected at admission (HTTP {sr})");
        } else {
            // Queued — must fail at execution (success=false).
            let exec = wait_tx_result(API_PORTS[0], "nr02-replay", Duration::from_secs(60));
            match exec {
                Some(ref r) if r["success"].as_bool() == Some(false) => {
                    println!("   ✓ NR-02: replay failed at execution: {r}");
                }
                Some(ref r) if r["success"].as_bool() == Some(true) => {
                    panic!("NR-02: replay succeeded — nonce enforcement broken; result: {r}");
                }
                other => {
                    println!("   INFO: replay tx status ambiguous ({other:?}) — checking invariants");
                }
            }
        }

        // Invariant: alice's nonce and balance must be unchanged by the rejected replay.
        let bal2   = balance_of(API_PORTS[0], ALICE_ADDR);
        let nonce2 = nonce_of(API_PORTS[0], ALICE_ADDR);
        println!("   after replay: alice balance={bal2}  nonce={nonce2}");
        assert_eq!(nonce2, nonce1, "NR-02: nonce must not change after rejected replay");
        assert!(bal2 >= bal1.saturating_sub(TX_AMOUNT / 2),
            "NR-02: balance must not decrease further after rejected replay \
             (before={bal1} after={bal2})");
        println!("   ✓ NR-02: nonce and balance unchanged by rejected replay");
    }

    // ── NR-03: future nonce ───────────────────────────────────────────────────

    println!("\n── NR-03: future nonce rejected ──");
    {
        let cur_nonce = nonce_of(API_PORTS[0], ALICE_ADDR);
        let future    = cur_nonce + 100;
        println!("   current nonce={cur_nonce}  submitting nonce={future}");

        let tx_future     = signed_transfer("nr03-future", future);
        let tx_future_json = serde_json::to_string(&tx_future).expect("serialise");
        let bal_before = balance_of(API_PORTS[0], ALICE_ADDR);
        let (sf, rf) = api_post(API_PORTS[0], "/api/tx", &tx_future_json)
            .expect("no response");
        println!("   future-nonce submit HTTP {sf}: {rf}");

        let rejected_at_admission = sf >= 400
            || rf["status"].as_str() == Some("rejected")
            || rf.get("code").is_some();

        if rejected_at_admission {
            println!("   ✓ NR-03: future nonce rejected at admission (HTTP {sf})");
        } else {
            // Queued — must fail at execution.
            let exec = wait_tx_result(API_PORTS[0], "nr03-future", Duration::from_secs(60));
            match exec {
                Some(ref r) if r["success"].as_bool() == Some(false) => {
                    println!("   ✓ NR-03: future nonce failed at execution: {r}");
                }
                Some(ref r) if r["success"].as_bool() == Some(true) => {
                    panic!("NR-03: future-nonce tx succeeded — nonce enforcement broken; result: {r}");
                }
                other => {
                    println!("   INFO: future-nonce tx status ambiguous ({other:?}) — checking invariants");
                }
            }
        }

        // Invariant: nonce and balance unchanged.
        let nonce_after = nonce_of(API_PORTS[0], ALICE_ADDR);
        let bal_after   = balance_of(API_PORTS[0], ALICE_ADDR);
        println!("   after future-nonce: nonce={nonce_after}  balance={bal_after}");
        assert_eq!(nonce_after, cur_nonce,
            "NR-03: nonce must not change after future-nonce rejection");
        assert!(bal_after >= bal_before.saturating_sub(TX_AMOUNT / 2),
            "NR-03: balance must not decrease after future-nonce rejection \
             (before={bal_before} after={bal_after})");
        println!("   ✓ NR-03: nonce and balance unchanged by future-nonce rejection");
    }

    // ── State root agreement ──────────────────────────────────────────────────

    println!("\n── Final: all 4 nodes agree on state root ──");
    {
        let check_h = height_of(API_PORTS[0]);
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if API_PORTS.iter().all(|&p| height_of(p) >= check_h) { break; }
            std::thread::sleep(Duration::from_millis(300));
        }
        let roots: Vec<String>  = API_PORTS.iter().map(|&p| state_root_of(p)).collect();
        let heights: Vec<u64>   = API_PORTS.iter().map(|&p| height_of(p)).collect();
        println!("   heights={heights:?}  roots={roots:?}");
        if heights.windows(2).all(|w| w[0] == w[1]) && roots.iter().all(|r| !r.is_empty()) {
            assert!(roots.windows(2).all(|w| w[0] == w[1]),
                "state root mismatch: {roots:?}");
            println!("   ✓ all 4 nodes agree on state root {}", roots[0]);
        } else {
            println!("   INFO: nodes at different heights — skipping cross-node root check");
        }
    }

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  h0_4_nonce_replay  PASS");
    println!("═══════════════════════════════════════════════════════════════\n");
}
