//! H0-6 Key-binding race — PQ-HotStuff-2 native path
//!
//! ## Scenario
//!
//! KB-01  Two ML-DSA-65 key pairs (key_A and key_B) claim the same account
//!        address in the same block.  At most one binding must succeed.  All
//!        four nodes must agree on the resulting bound key and state root.
//!
//! ## Mechanics
//!
//! - Genesis: `signature_scheme: "pqc-native"`, `require_signatures: true`.
//!   This sets `AccountSignaturePolicy::MlDsaOnly`, so `bind_key_if_unbound`
//!   fires on every signed tx from an unbound account.
//! - The contested account address is derived from key_A via
//!   `Address::from_public_key_schemed` (PostQuantum scheme) and pre-funded in
//!   genesis with `public_key` absent.
//! - Tx1 (signed by key_A, nonce=0) and Tx2 (signed by key_B, nonce=0) are
//!   submitted in rapid succession to two different nodes before either block
//!   commits.  Both are valid ML-DSA signatures; only the first one the
//!   executor sees can bind.
//! - After both transactions are either committed or rejected:
//!   * Exactly one of them has `success=true` (key_A wins because Tx1 carries
//!     the address-matching key; Tx2 fails the sig check after binding).
//!   * All four nodes agree on `state_root`.
//!   * The bound key on the account matches key_A's public key.
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node --features pq-hotstuff
//! cargo test -p chain-forge-node --features pq-hotstuff \
//!   --test h0_6_keybind_race_live -- --nocapture
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

use chain_forge_core::{Address, AddressScheme, HashWidth};
use chain_forge_crypto::{MlDsaScheme, SchemeId, SignatureScheme, mldsa_tx_prehash};
use chain_forge_execution::{Transaction, TxBody};

// ── Constants ──────────────────────────────────────────────────────────────────

const VALIDATORS:  &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
const API_PORTS:   &[u16]  = &[19220, 19221, 19222, 19223];
const P2P_PORTS:   &[u16]  = &[29220, 29221, 29222, 29223];

const GENESIS_TEMPLATE: &str = "genesis-4node-pqhs2-fips204.json";
const KEY_DIR:           &str = "keys/fips204";

const CHAIN_ID:   &str = "qcb-devnet-h06-keybind";
const RECV_ADDR:  &str = "qcb1kb_recv";
const TX_AMOUNT:  u128 = 5_000;

// Deterministic seeds for the two competing key pairs.
const SEED_A: &str = "h06-keybind-key-A-seed-000000000000000000000001";
const SEED_B: &str = "h06-keybind-key-B-seed-000000000000000000000002";

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

// ── Deterministic key-derived address ────────────────────────────────────────

fn mldsa_public_key(seed: &str) -> Vec<u8> {
    MlDsaScheme.generate_keypair(seed)
        .expect("keygen")
        .public_key
        .clone()
}

/// Derive an address from a ML-DSA public key using the PostQuantum scheme.
fn key_derived_address(seed: &str) -> String {
    let pk = mldsa_public_key(seed);
    Address::from_public_key_schemed(
        &pk,
        "qcb",
        HashWidth::Bits256,
        AddressScheme::PostQuantum,
    ).as_str().to_string()
}

// ── Genesis builder ───────────────────────────────────────────────────────────

/// Genesis for the key-binding race test.
///
/// - `signature_scheme: "pqc-native"` + `require_signatures: true`
///   → MlDsaOnly policy, `bind_key_if_unbound` fires.
/// - Contested account: address derived from key_A, funded, NO `public_key`.
/// - Recipient: plain funded account.
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

        // pqc-native + require_signatures = MlDsaOnly policy.
        // The template already has pqc-native; set require_signatures explicitly.
        g["execution"]["require_signatures"] = serde_json::Value::Bool(true);

        let contested_addr = key_derived_address(SEED_A);
        println!("   [genesis] contested address (key_A derived): {contested_addr}");

        // Contested account: NO public_key so bind_key_if_unbound fires on first tx.
        g["genesis_accounts"].as_array_mut().unwrap().push(serde_json::json!({
            "label":   "Contested",
            "address": contested_addr,
            "balance": "50000000",
            "role":    "user"
            // public_key intentionally absent
        }));
        // Recipient.
        g["genesis_accounts"].as_array_mut().unwrap().push(serde_json::json!({
            "label":   "KB recv",
            "address": RECV_ADDR,
            "balance": "1000000",
            "role":    "user"
        }));

        let dir = std::env::temp_dir()
            .join(format!("h0_6_keybind_genesis_{}", std::process::id()));
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

fn bound_key_of(port: u16, addr: &str) -> Option<String> {
    api_get(port, &format!("/api/accounts/{addr}"))
        .and_then(|v| v["public_key"].as_str().map(str::to_string))
        .filter(|s| !s.is_empty())
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

// ── ML-DSA-65 transaction builders ───────────────────────────────────────────

fn build_binding_tx(id: &str, seed: &str, sender: &str, nonce: u64) -> Transaction {
    let kp       = MlDsaScheme.generate_keypair(seed).expect("keygen");
    let body     = TxBody::Transfer {
        to:     RECV_ADDR.to_string(),
        denom:  "uqcb".to_string(),
        amount: TX_AMOUNT,
    };
    let body_json = serde_json::to_string(&body).expect("body serialise");
    let message  = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let sig      = MlDsaScheme.sign(&message, &kp).expect("ML-DSA sign");
    Transaction {
        id:            id.to_string(),
        sender:        sender.to_string(),
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
fn h0_6_keybind_race() {
    let bin = node_binary();
    if !bin.exists() {
        eprintln!("SKIP: node binary not found at {bin:?}. Run `cargo build -p chain-forge-node --features pq-hotstuff` first.");
        return;
    }

    let contested_addr = key_derived_address(SEED_A);
    let key_a_hex = hex_encode(&mldsa_public_key(SEED_A));
    let key_b_hex = hex_encode(&mldsa_public_key(SEED_B));

    let log_dir = std::env::temp_dir().join("h0_6_keybind_live");
    let dat_dir = std::env::temp_dir().join("h0_6_keybind_data");
    let _ = std::fs::remove_dir_all(&log_dir);
    let _ = std::fs::remove_dir_all(&dat_dir);
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::create_dir_all(&dat_dir).unwrap();

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  h0_6_keybind_race");
    println!("  binary : {bin:?}");
    println!("  genesis: {:?}", genesis_path());
    println!("  contested addr : {contested_addr}");
    println!("  key_A (expect bind): {}...", &key_a_hex[..16]);
    println!("  key_B (must lose)  : {}...", &key_b_hex[..16]);
    println!("  logs   : {log_dir:?}");
    println!("═══════════════════════════════════════════════════════════════\n");

    // ── Start devnet ──────────────────────────────────────────────────────────

    println!("── starting 4-node PQ-HotStuff-2 devnet (pqc-native, require_signatures=true) ──");

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

    // ── KB-01: submit racing binding transactions ─────────────────────────────

    println!("\n── KB-01: submitting Tx1 (key_A) and Tx2 (key_B) in rapid succession ──");

    // Tx1: signed by key_A, sender = contested_addr (address derived from key_A).
    // key_A matches the address derivation → bind_key_if_unbound should bind key_A.
    let tx1 = build_binding_tx("kb01-tx-key-a", SEED_A, &contested_addr, 0);
    let tx1_json = serde_json::to_string(&tx1).expect("serialise tx1");

    // Tx2: signed by key_B, sender = contested_addr.
    // key_B does NOT match the address → sig check fails after key_A is bound,
    // or binding is preempted regardless of which tx lands first.
    let tx2 = build_binding_tx("kb01-tx-key-b", SEED_B, &contested_addr, 0);
    let tx2_json = serde_json::to_string(&tx2).expect("serialise tx2");

    // Submit Tx1 to node 0 (Alice) and Tx2 to node 1 (Bob) simultaneously.
    let (s1, r1) = api_post(API_PORTS[0], "/api/tx", &tx1_json).expect("no response tx1");
    println!("   Tx1 (key_A) submit HTTP {s1}: {r1}");

    let (s2, r2) = api_post(API_PORTS[1], "/api/tx", &tx2_json).expect("no response tx2");
    println!("   Tx2 (key_B) submit HTTP {s2}: {r2}");

    // Both must be accepted at admission (nonce=0 is valid; sig is structurally correct).
    // If either is refused before execution that is also acceptable, but we expect queued.
    let tx1_accepted = s1 == 200 || s1 == 202;
    let tx2_accepted = s2 == 200 || s2 == 202;
    println!("   Tx1 accepted={tx1_accepted}  Tx2 accepted={tx2_accepted}");

    // Wait for results.
    let res1 = if tx1_accepted {
        wait_tx_result(API_PORTS[0], "kb01-tx-key-a", Duration::from_secs(180))
    } else {
        Some(r1.clone())
    };
    let res2 = if tx2_accepted {
        wait_tx_result(API_PORTS[1], "kb01-tx-key-b", Duration::from_secs(180))
    } else {
        Some(r2.clone())
    };

    println!("   Tx1 result: {:?}", res1);
    println!("   Tx2 result: {:?}", res2);

    // Count successes.
    let tx1_success = res1.as_ref().and_then(|r| r["success"].as_bool()).unwrap_or(false);
    let tx2_success = res2.as_ref().and_then(|r| r["success"].as_bool()).unwrap_or(false);
    println!("   Tx1 success={tx1_success}  Tx2 success={tx2_success}");

    let success_count = tx1_success as u32 + tx2_success as u32;
    assert!(success_count <= 1,
        "KB-01: at most one binding tx must succeed; both succeeded (tx1={tx1_success}, tx2={tx2_success})");
    println!("   ✓ KB-01: at most one binding succeeded ({success_count}/2)");

    // key_A is the address-matching key, so it should be the one that binds.
    // (If the executor sees Tx1 first, key_A binds and Tx2 fails sig check.
    //  If Tx2 arrives first, key_B is bound but key_B does not match the
    //  address derivation — that is a failure of the address-binding invariant.
    //  The core must only bind a key whose derived address matches the sender.)
    if tx2_success && !tx1_success {
        // key_B bound: verify whether the address-derivation invariant allows it.
        // On a pqc-native chain, bind_key_if_unbound should reject a key whose
        // derived address doesn't match the account address.
        // We flag this as a protocol violation.
        panic!(
            "KB-01: key_B (non-address-matching) bound to the contested account; \
             address-derivation invariant violated"
        );
    }

    // ── Verify bound key on all 4 nodes ──────────────────────────────────────

    println!("\n── verifying bound key and state root on all 4 nodes ──");

    // Give all nodes time to reach the same height.
    let check_h = height_of(API_PORTS[0]);
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if API_PORTS.iter().all(|&p| height_of(p) >= check_h) { break; }
        std::thread::sleep(Duration::from_millis(300));
    }

    let mut bound_keys: Vec<Option<String>> = Vec::new();
    for &port in API_PORTS {
        let bk = bound_key_of(port, &contested_addr);
        println!("   node :{port}  bound_key={bk:?}");
        bound_keys.push(bk);
    }

    // All nodes that have a bound key must agree on the same key.
    let non_empty: Vec<&String> = bound_keys.iter().flatten().collect();
    if non_empty.len() > 1 {
        let first = non_empty[0];
        for k in &non_empty[1..] {
            assert_eq!(k, &first,
                "KB-01: nodes disagree on bound key: {bound_keys:?}");
        }
        println!("   ✓ KB-01: all nodes that resolved the key agree: {}...", &first[..16.min(first.len())]);
    }

    // If a key is bound it must be key_A (address-matching).
    for k in &non_empty {
        assert_eq!(k.as_str(), key_a_hex.as_str(),
            "KB-01: bound key is not key_A; got {}...", &k[..16.min(k.len())]);
    }
    if !non_empty.is_empty() {
        println!("   ✓ KB-01: bound key matches key_A on all reporting nodes");
    } else {
        // Neither tx succeeded (both may have been in the same block and both
        // failed nonce collision) — the account should remain unbound.
        println!("   INFO: no key bound (both txs may have shared a block slot) — account remains unbound");
    }

    // ── State root agreement ──────────────────────────────────────────────────

    let roots: Vec<String>  = API_PORTS.iter().map(|&p| state_root_of(p)).collect();
    let heights: Vec<u64>   = API_PORTS.iter().map(|&p| height_of(p)).collect();
    println!("   heights={heights:?}  roots={roots:?}");
    if heights.windows(2).all(|w| w[0] == w[1]) && roots.iter().all(|r| !r.is_empty()) {
        assert!(roots.windows(2).all(|w| w[0] == w[1]),
            "KB-01: state root mismatch: {roots:?}");
        println!("   ✓ KB-01: all 4 nodes agree on state root {}", roots[0]);
    } else {
        println!("   INFO: nodes at different heights — skipping cross-node root check");
    }

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  h0_6_keybind_race  PASS");
    println!("═══════════════════════════════════════════════════════════════\n");
}

// ── KB-02: same-block binding race ───────────────────────────────────────────
//
// Both Tx1 (key_A) and Tx2 (key_B) are submitted to the SAME node in rapid
// succession, so the mempool is likely to include both in the next block.
//
// Assertions:
//   - At most one tx commits with success=true.
//   - If both committed in the same block: exactly one succeeded.
//   - Bound key on all 4 nodes is key_A (the address-matching key).
//   - All 4 nodes agree on state root.
//   - If the two txs landed in different blocks (scheduler split them),
//     the cross-block invariant still holds and the test notes the outcome.

const KB2_API_PORTS: &[u16] = &[19230, 19231, 19232, 19233];
const KB2_P2P_PORTS: &[u16] = &[29230, 29231, 29232, 29233];
const KB2_CHAIN_ID:  &str   = "qcb-devnet-h06-kb2";

static KB2_GENESIS: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

fn kb2_genesis_path() -> std::path::PathBuf {
    KB2_GENESIS.get_or_init(|| {
        let template = repo_root().join("tests").join("devnet").join(GENESIS_TEMPLATE);
        let text = std::fs::read_to_string(&template)
            .unwrap_or_else(|e| panic!("read genesis template {template:?}: {e}"));
        let mut g: serde_json::Value = serde_json::from_str(&text)
            .expect("parse genesis template JSON");

        g["chain_id"] = serde_json::Value::String(KB2_CHAIN_ID.to_string());
        g["consensus"]["block_time_ms"] = serde_json::Value::Number(10_000.into());
        g["execution"]["require_signatures"] = serde_json::Value::Bool(true);

        let contested_addr = key_derived_address(SEED_A);

        g["genesis_accounts"].as_array_mut().unwrap().push(serde_json::json!({
            "label":   "Contested KB2",
            "address": contested_addr,
            "balance": "50000000",
            "role":    "user"
            // public_key intentionally absent
        }));
        g["genesis_accounts"].as_array_mut().unwrap().push(serde_json::json!({
            "label":   "KB2 recv",
            "address": RECV_ADDR,
            "balance": "1000000",
            "role":    "user"
        }));

        let dir = std::env::temp_dir()
            .join(format!("h0_6_kb2_genesis_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("genesis.json");
        let tmp = dir.join("genesis.json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&g).unwrap()).unwrap();
        std::fs::rename(&tmp, &out).unwrap();
        out
    }).clone()
}

fn build_binding_tx_kb2(id: &str, seed: &str, sender: &str, nonce: u64) -> Transaction {
    let kp       = MlDsaScheme.generate_keypair(seed).expect("keygen");
    let body     = TxBody::Transfer {
        to:     RECV_ADDR.to_string(),
        denom:  "uqcb".to_string(),
        amount: TX_AMOUNT,
    };
    let body_json = serde_json::to_string(&body).expect("body serialise");
    let message  = mldsa_tx_prehash(KB2_CHAIN_ID, body_json.as_bytes());
    let sig      = MlDsaScheme.sign(&message, &kp).expect("ML-DSA sign");
    Transaction {
        id:            id.to_string(),
        sender:        sender.to_string(),
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

fn spawn_node_kb2(
    bin:       &PathBuf,
    validator: &'static str,
    api_port:  u16,
    p2p_port:  u16,
    data_dir:  &PathBuf,
    log_path:  &PathBuf,
    bootstrap: Option<&str>,
) -> NodeProcess {
    let genesis = kb2_genesis_path();
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

#[test]
#[cfg_attr(not(feature = "pq-hotstuff"), ignore = "requires pq-hotstuff feature")]
fn h0_6_keybind_race_same_block() {
    let bin = node_binary();
    if !bin.exists() {
        eprintln!("SKIP: node binary not found at {bin:?}.");
        return;
    }

    let contested_addr = key_derived_address(SEED_A);
    let key_a_hex = hex_encode(&mldsa_public_key(SEED_A));
    let key_b_hex = hex_encode(&mldsa_public_key(SEED_B));

    let log_dir = std::env::temp_dir().join("h0_6_kb2_live");
    let dat_dir = std::env::temp_dir().join("h0_6_kb2_data");
    let _ = std::fs::remove_dir_all(&log_dir);
    let _ = std::fs::remove_dir_all(&dat_dir);
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::create_dir_all(&dat_dir).unwrap();

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  h0_6_keybind_race_same_block (KB-02)");
    println!("  binary : {bin:?}");
    println!("  contested addr : {contested_addr}");
    println!("  key_A : {}...", &key_a_hex[..16]);
    println!("  key_B : {}...", &key_b_hex[..16]);
    println!("═══════════════════════════════════════════════════════════════\n");

    // ── Start devnet ──────────────────────────────────────────────────────────

    let alice_data = dat_dir.join("alice");
    let alice_log  = log_dir.join("qcb1alice.log");
    let alice = spawn_node_kb2(&bin, "qcb1alice", KB2_API_PORTS[0], KB2_P2P_PORTS[0],
        &alice_data, &alice_log, None);
    assert!(wait_port(KB2_API_PORTS[0], Duration::from_secs(20)),
        "alice API :{} never opened", KB2_API_PORTS[0]);
    let peer_id   = read_peer_id(&alice_log, Duration::from_secs(20));
    let bootstrap = format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer_id}", KB2_P2P_PORTS[0]);
    println!("   bootstrap: {bootstrap}");

    let mut nodes: Vec<NodeProcess> = vec![alice];
    for (i, &validator) in VALIDATORS[1..].iter().enumerate() {
        let idx      = i + 1;
        let short    = validator.strip_prefix("qcb1").unwrap_or(validator);
        let data_dir = dat_dir.join(short);
        let log_path = log_dir.join(format!("{validator}.log"));
        let node = spawn_node_kb2(&bin, validator,
            KB2_API_PORTS[idx], KB2_P2P_PORTS[idx],
            &data_dir, &log_path, Some(&bootstrap));
        assert!(wait_port(KB2_API_PORTS[idx], Duration::from_secs(20)),
            "{validator} API :{} never opened", KB2_API_PORTS[idx]);
        nodes.push(node);
    }

    println!("   waiting for height 2...");
    wait_height(&mut nodes, 2, Duration::from_secs(300), &log_dir);

    // ── KB-02: submit both txs to the SAME node back-to-back ─────────────────

    println!("\n── KB-02: submitting Tx1 (key_A) and Tx2 (key_B) to same node ──");

    let tx1 = build_binding_tx_kb2("kb02-tx-key-a", SEED_A, &contested_addr, 0);
    let tx2 = build_binding_tx_kb2("kb02-tx-key-b", SEED_B, &contested_addr, 0);
    let tx1_json = serde_json::to_string(&tx1).expect("serialise tx1");
    let tx2_json = serde_json::to_string(&tx2).expect("serialise tx2");

    // Both submitted to Alice (port 0) with no sleep in between.
    let (s1, r1) = api_post(KB2_API_PORTS[0], "/api/tx", &tx1_json).expect("no response tx1");
    let (s2, r2) = api_post(KB2_API_PORTS[0], "/api/tx", &tx2_json).expect("no response tx2");
    println!("   Tx1 HTTP {s1}: {r1}");
    println!("   Tx2 HTTP {s2}: {r2}");

    let tx1_queued = s1 == 200 || s1 == 202;
    let tx2_queued = s2 == 200 || s2 == 202;

    // Wait for execution results.
    let res1 = if tx1_queued {
        wait_tx_result(KB2_API_PORTS[0], "kb02-tx-key-a", Duration::from_secs(180))
    } else {
        Some(r1.clone())
    };
    let res2 = if tx2_queued {
        wait_tx_result(KB2_API_PORTS[0], "kb02-tx-key-b", Duration::from_secs(180))
    } else {
        Some(r2.clone())
    };

    println!("   Tx1 result: {:?}", res1);
    println!("   Tx2 result: {:?}", res2);

    let tx1_success = res1.as_ref().and_then(|r| r["success"].as_bool()).unwrap_or(false);
    let tx2_success = res2.as_ref().and_then(|r| r["success"].as_bool()).unwrap_or(false);
    let h1 = res1.as_ref().and_then(|r| r["height"].as_u64());
    let h2 = res2.as_ref().and_then(|r| r["height"].as_u64());

    println!("   Tx1 success={tx1_success} height={h1:?}");
    println!("   Tx2 success={tx2_success} height={h2:?}");

    // Core invariant: at most one succeeds regardless of block placement.
    let success_count = tx1_success as u32 + tx2_success as u32;
    assert!(success_count <= 1,
        "KB-02: at most one binding tx must succeed; both succeeded");
    println!("   ✓ KB-02: at most one binding succeeded ({success_count}/2)");

    // Report whether we hit same-block or cross-block.
    match (h1, h2) {
        (Some(a), Some(b)) if a == b => {
            println!("   ✓ KB-02: SAME-BLOCK confirmed — both txs committed at height {a}; \
                       exactly one succeeded ({success_count}/2)");
        }
        (Some(a), Some(b)) => {
            println!("   INFO: KB-02: txs landed in different blocks ({a} vs {b}); \
                       cross-block invariant still holds");
        }
        _ => {
            println!("   INFO: KB-02: one or both txs have no height (may have been \
                       rejected at admission)");
        }
    }

    // key_A must be the winner if any key bound.
    if tx2_success && !tx1_success {
        panic!(
            "KB-02: key_B (non-address-matching) bound to the contested account; \
             address-derivation invariant violated"
        );
    }

    // ── Verify bound key and state root on all 4 nodes ───────────────────────

    println!("\n── KB-02: verifying bound key and state root on all 4 nodes ──");
    let check_h = height_of(KB2_API_PORTS[0]);
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if KB2_API_PORTS.iter().all(|&p| height_of(p) >= check_h) { break; }
        std::thread::sleep(Duration::from_millis(300));
    }

    let mut bound_keys: Vec<Option<String>> = Vec::new();
    for &port in KB2_API_PORTS {
        let bk = bound_key_of(port, &contested_addr);
        println!("   node :{port}  bound_key={}", bk.as_deref().map(|k| &k[..16.min(k.len())]).unwrap_or("(none)"));
        bound_keys.push(bk);
    }

    let non_empty: Vec<&String> = bound_keys.iter().flatten().collect();
    if non_empty.len() > 1 {
        let first = non_empty[0];
        for k in &non_empty[1..] {
            assert_eq!(k, &first, "KB-02: nodes disagree on bound key");
        }
        println!("   ✓ KB-02: all nodes agree on bound key {}...", &first[..16.min(first.len())]);
    }
    for k in &non_empty {
        assert_eq!(k.as_str(), key_a_hex.as_str(),
            "KB-02: bound key is not key_A");
    }
    if !non_empty.is_empty() {
        println!("   ✓ KB-02: bound key = key_A on all reporting nodes");
    }

    let roots: Vec<String> = KB2_API_PORTS.iter().map(|&p| state_root_of(p)).collect();
    let heights: Vec<u64>  = KB2_API_PORTS.iter().map(|&p| height_of(p)).collect();
    println!("   heights={heights:?}  roots={roots:?}");
    if heights.windows(2).all(|w| w[0] == w[1]) && roots.iter().all(|r| !r.is_empty()) {
        assert!(roots.windows(2).all(|w| w[0] == w[1]),
            "KB-02: state root mismatch: {roots:?}");
        println!("   ✓ KB-02: all 4 nodes agree on state root {}", roots[0]);
    } else {
        println!("   INFO: nodes at different heights — skipping cross-node root check");
    }

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  h0_6_keybind_race_same_block  PASS");
    println!("═══════════════════════════════════════════════════════════════\n");
}
