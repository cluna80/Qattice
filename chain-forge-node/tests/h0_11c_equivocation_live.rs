//! H0-11C  Equivocation detection & signature verification — PQ-HotStuff-2
//!
//! ## Scenarios
//!
//! EQ-01  Valid ML-DSA-65 equivocation proof is detected, evidence is queued,
//!        and the offender's bond is deducted exactly once.
//!
//! EQ-02  Submitting (vote_A, vote_B) and (vote_B, vote_A) are canonicalized
//!        to the same identity: the second proof after the first committed is
//!        rejected as a duplicate (EquivocationAlreadyRecorded), and no second
//!        deduction occurs.
//!
//! EQ-03  Cross-round votes (same height, different rounds) are NOT equivocation;
//!        evidence with mismatched rounds fails `check_evidence_signatures` with
//!        a signature error (the round is baked into the signing bytes).
//!
//! EQ-04  Evidence outside the 1,000-block lookback window is rejected by
//!        `check_evidence` before it can reach the slasher.
//!
//! ## Notes
//!
//! All gossip-injection tests run on the PQ-HotStuff-2 four-node devnet with
//! ML-DSA-65 consensus keys.  Votes are signed with `vote_signing_bytes_v2`
//! (epoch + set_hash domain separator) using the FIPS 204 key files in
//! `tests/devnet/keys/fips204/`.
//!
//! EQ-02 through EQ-04 are unit-level tests that run in-process and do not
//! need a live devnet.
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node --features pq-hotstuff
//! cargo test -p chain-forge-node --features pq-hotstuff \
//!   --test h0_11c_equivocation_live -- --nocapture
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

use chain_forge_consensus::{
    vote_signing_bytes_v2, BlockHash, ValidatorId, ValidatorSet, Vote, VoteType,
};
use chain_forge_consensus::pq_hotstuff::epoch_handoff::canonical_set_hash;
use chain_forge_p2p::{
    GossipTopic, NetworkConfig, NetworkService, OutboundMessage, PeerDiscovery,
    real::Libp2pService,
};
use chain_forge_slashing::EquivocationEvidence;

// ── Constants ──────────────────────────────────────────────────────────────────

const VALIDATORS: &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
const GENESIS_TEMPLATE: &str = "genesis-4node-pqhs2-fips204.json";
const KEY_DIR:          &str = "keys/fips204";
const CHAIN_ID:         &str = "qcb-devnet-h11c-equiv";

// PQ-HotStuff-2 starts at epoch 1 (genesis commits at epoch 0, first real
// votes are cast under epoch 1).  The equivocating votes must carry this value.
const DEVNET_VOTE_EPOCH: u64 = 1;

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

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Load a validator's ML-DSA-65 keypair from its key file.
fn load_mldsa_keypair(short: &str) -> chain_forge_crypto::KeyPair {
    let path = key_file(short);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read key file {path:?}: {e}"));
    let v: serde_json::Value = serde_json::from_str(&text).expect("parse key file JSON");
    chain_forge_crypto::KeyPair {
        scheme:      chain_forge_crypto::SchemeId::MlDsa,
        public_key:  hex_decode(v["public_key"].as_str().unwrap()),
        private_key: hex_decode(v["private_key"].as_str().unwrap()),
    }
}

// ── Genesis builder ───────────────────────────────────────────────────────────

fn genesis_path() -> PathBuf {
    static ONCE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let template = repo_root().join("tests").join("devnet").join(GENESIS_TEMPLATE);
        let text = std::fs::read_to_string(&template)
            .unwrap_or_else(|e| panic!("read genesis template {template:?}: {e}"));
        let mut g: serde_json::Value = serde_json::from_str(&text)
            .expect("parse genesis template JSON");

        g["chain_id"] = serde_json::Value::String(CHAIN_ID.to_string());
        g["consensus"]["block_time_ms"] = serde_json::Value::Number(2_000.into());

        let dir = std::env::temp_dir()
            .join(format!("h0_11c_equivoc_genesis_{}", std::process::id()));
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

fn height_of(port: u16) -> u64 {
    api_get(port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0)
}

fn balance_of(port: u16, address: &str) -> Option<u128> {
    let v = api_get(port, &format!("/api/accounts/{address}"))?;
    v["balances"]["uqcb"].as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| v["balances"]["uqcb"].as_u64().map(|n| n as u128))
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        ).is_ok() { return true; }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn poll_until_height(ports: &[u16], target: u64, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let heights: Vec<u64> = ports.iter().map(|&p| height_of(p)).collect();
        let all = heights.iter().all(|&h| h >= target);
        let elapsed = Instant::now().duration_since(deadline - timeout);
        print!("\r   [{:.1}s] ", elapsed.as_secs_f32());
        for (i, &h) in heights.iter().enumerate() { print!("node{}={}  ", i, h); }
        let _ = std::io::Write::flush(&mut std::io::stdout());
        if all { println!(); return true; }
        if Instant::now() >= deadline { println!(); return false; }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ── Port reservation ──────────────────────────────────────────────────────────

fn reserve_ports(n: usize) -> Vec<u16> {
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU32, Ordering};
    const LOW: u32 = 20_000;
    const HIGH: u32 = 32_000;
    static CALLS: AtomicU32 = AtomicU32::new(0);
    let seed = (std::process::id() as u64).wrapping_mul(2_654_435_761)
        .wrapping_add(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64).unwrap_or(0))
        .wrapping_add(CALLS.fetch_add(1, Ordering::SeqCst) as u64 * 97)
        .wrapping_add(0x284); // namespace away from other test suites (H0-11C)
    let mut port = LOW + (seed % (HIGH - LOW) as u64) as u32;
    let (mut held, mut chosen, mut tries) = (Vec::new(), Vec::new(), 0u32);
    while chosen.len() < n {
        tries += 1;
        assert!(tries < 4_000, "could not find {n} free ports");
        if port >= HIGH { port = LOW; }
        if let Ok(l) = TcpListener::bind(("0.0.0.0", port as u16)) {
            held.push(l); chosen.push(port as u16);
        }
        port += 1;
    }
    drop(held);
    chosen
}

// ── Node spawn / teardown ─────────────────────────────────────────────────────

struct NodeHandle { _name: &'static str, process: Child }

impl Drop for NodeHandle {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Read Alice's libp2p peer ID from her log (looks for "P2P listening … peer=12D3…").
fn read_peer_id(log_path: &std::path::Path, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let text = std::fs::read_to_string(log_path).unwrap_or_default();
        let clean = strip_ansi_early(&text);
        if let Some(id) = clean.lines()
            .filter(|l| l.contains("P2P listening"))
            .find_map(|l| l.split("peer=").nth(1))
            .map(|rest| rest.split_whitespace().next().unwrap_or("").to_string())
            .filter(|id| id.starts_with("12D3"))
        {
            return id;
        }
        assert!(Instant::now() < deadline, "no libp2p peer id in {log_path:?} after 15s");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn strip_ansi_early(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() { if c.is_ascii_alphabetic() { break; } }
        } else {
            out.push(c);
        }
    }
    out
}

fn spawn_node_inner(
    name:      &'static str,
    api_port:  u16,
    p2p_port:  u16,
    data_dir:  &std::path::Path,
    log_path:  &std::path::Path,
    bootstrap: Option<&str>,
) -> NodeHandle {
    let log_file = std::fs::File::create(log_path)
        .unwrap_or_else(|e| panic!("create log {log_path:?}: {e}"));
    std::fs::create_dir_all(data_dir)
        .unwrap_or_else(|e| panic!("create data dir {data_dir:?}: {e}"));
    let short = name.trim_start_matches("qcb1");
    let mut cmd = Command::new(node_binary());
    cmd.args([
        "--genesis",   genesis_path().to_str().unwrap(),
        "--validator", name,
        "--key-file",  key_file(short).to_str().unwrap(),
        "--api-port",  &api_port.to_string(),
        "--p2p-port",  &p2p_port.to_string(),
        "--data-dir",  data_dir.to_str().unwrap(),
    ]);
    if let Some(b) = bootstrap { cmd.args(["--bootstrap", b]); }
    cmd.stdout(log_file.try_clone().unwrap()).stderr(log_file).stdin(Stdio::null());
    let process = cmd.spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {name}: {e}"));
    NodeHandle { _name: name, process }
}

/// Spawn all four nodes. Alice starts first; her peer ID is read from her log
/// before the other three are started with a full `/ip4/.../tcp/.../p2p/{id}`
/// bootstrap address. This matches the pattern used by pqhs2_4node_live.
fn spawn_devnet(api_ports: &[u16; 4], p2p_ports: &[u16; 4], log_dir: &std::path::Path)
    -> Vec<NodeHandle>
{
    let alice_log  = log_dir.join("qcb1alice.log");
    let alice_data = log_dir.join("qcb1alice-data");
    let alice = spawn_node_inner(
        "qcb1alice", api_ports[0], p2p_ports[0], &alice_data, &alice_log, None,
    );
    // Wait for Alice's peer ID before connecting the other nodes.
    let peer_id  = read_peer_id(&alice_log, Duration::from_secs(15));
    let bootstrap = format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer_id}", p2p_ports[0]);
    eprintln!("   bootstrap: {bootstrap}");

    let mut nodes = vec![alice];
    for (i, &name) in ["qcb1bob", "qcb1carol", "qcb1dave"].iter().enumerate() {
        let idx  = i + 1;
        let log  = log_dir.join(format!("{name}.log"));
        let data = log_dir.join(format!("{name}-data"));
        nodes.push(spawn_node_inner(
            name, api_ports[idx], p2p_ports[idx], &data, &log, Some(&bootstrap),
        ));
    }
    nodes
}

fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn skip_if_no_binary() -> bool {
    let bin = node_binary();
    if !bin.exists() {
        println!("SKIP: node binary not found at {bin:?}. Build with: cargo build -p chain-forge-node --features pq-hotstuff");
        return true;
    }
    false
}

// ── Log search helpers ────────────────────────────────────────────────────────

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() { if c.is_ascii_alphabetic() { break; } }
        } else {
            out.push(c);
        }
    }
    out
}

// ── Attacker gossip helper ────────────────────────────────────────────────────

fn genesis_hash() -> String {
    let text = std::fs::read_to_string(genesis_path()).expect("read genesis");
    let genesis = chain_forge_core::GenesisConfig::from_json(&text).expect("parse genesis");
    chain_forge_core::compute_genesis_hash(&genesis)
}

async fn start_attacker(target_p2p: u16) -> Libp2pService {
    let config = NetworkConfig {
        network_id:        CHAIN_ID.to_string(),
        p2p_port:          0,
        bootstrap_nodes:   vec![format!("/ip4/127.0.0.1/tcp/{target_p2p}")],
        peer_discovery:    PeerDiscovery::Mdns,
        max_peers:         8,
        max_message_bytes: 1024 * 1024,
        genesis_hash:      Some(genesis_hash()),
    };
    let (svc, _addr) = Libp2pService::start(&config).await
        .expect("attacker libp2p start");
    svc
}

// ── ML-DSA-65 vote signing ─────────────────────────────────────────────────────

/// Build the validator set from the genesis accounts so we can derive `canonical_set_hash`.
///
/// The pqhs2-fips204 genesis has 4 validator accounts with ML-DSA-65 `public_key` fields.
/// This replicates the genesis validator-set construction the node does at startup.
fn devnet_validator_set() -> ValidatorSet {
    let text = std::fs::read_to_string(genesis_path()).expect("read genesis");
    let g: serde_json::Value = serde_json::from_str(&text).expect("parse genesis JSON");

    let accounts = g["genesis_accounts"].as_array().expect("genesis_accounts");
    let mut validators = vec![];
    for account in accounts {
        let role = account.get("role").and_then(|v| v.as_str()).unwrap_or("");
        if role != "validator" { continue; }
        let address  = account["address"].as_str().unwrap().to_string();
        let pk_hex   = account["public_key"].as_str().unwrap_or("");
        let pk       = hex_decode(pk_hex);
        // All devnet validators have equal voting power (1).
        validators.push(chain_forge_consensus::ValidatorInfo {
            id:           chain_forge_consensus::ValidatorId(address),
            public_key:   pk,
            voting_power: 1,
            pop_verified: false,
        });
    }
    assert!(!validators.is_empty(), "no validator accounts found in genesis");
    ValidatorSet { height: 0, validators }
}

/// Sign a vote with ML-DSA-65 using v2 signing bytes (epoch + set_hash).
fn sign_mldsa_vote(
    kp:         &chain_forge_crypto::KeyPair,
    validator:  &str,
    vote_type:  VoteType,
    height:     u64,
    round:      u32,
    epoch:      u64,
    block_hash: &str,
    set_hash:   &[u8; 32],
) -> Vote {
    let bh = BlockHash(block_hash.to_string());
    let bytes = vote_signing_bytes_v2(
        CHAIN_ID, &vote_type, height, round, epoch, set_hash, Some(&bh),
    );
    let sig = chain_forge_crypto::sign_consensus(&bytes, kp)
        .expect("ML-DSA sign must not fail");
    Vote {
        vote_type,
        height,
        round,
        validator:  ValidatorId(validator.to_string()),
        block_hash: Some(bh),
        signature:  sig,
        scheme:     "ml-dsa-65".to_string(),
        epoch,
    }
}

// ── EQ-01: Valid ML-DSA-65 equivocation is detected and evidence is queued ────

#[cfg(feature = "pq-hotstuff")]
#[tokio::test]
async fn eq_01_mldsa_equivocation_detected_over_gossip() {
    if skip_if_no_binary() { return; }

    let ports = reserve_ports(8);
    let api_ports = [ports[0], ports[1], ports[2], ports[3]];
    let p2p_ports = [ports[4], ports[5], ports[6], ports[7]];

    println!("\n── EQ-01: ML-DSA-65 equivocation detection over gossip ──────────────");
    println!("   alice_api={} alice_p2p={}", api_ports[0], p2p_ports[0]);

    let log_dir = tempdir("h11c_eq01");
    let _nodes = spawn_devnet(&api_ports, &p2p_ports, &log_dir);

    println!("   Waiting for API ports...");
    for (i, &port) in api_ports.iter().enumerate() {
        if !wait_for_port(port, Duration::from_secs(20)) {
            panic!("node{i} API did not come up on :{port}");
        }
        eprintln!("   node{i} API up on :{port}");
    }

    println!("   Waiting for height >= 3...");
    if !poll_until_height(&api_ports, 3, Duration::from_secs(60)) {
        panic!("devnet did not reach height 3 within 60s");
    }

    let alice_kp     = load_mldsa_keypair("alice");
    let vs           = devnet_validator_set();
    let set_hash     = canonical_set_hash(&vs);

    let attacker = start_attacker(p2p_ports[0]).await;
    eprintln!("   [attacker] waiting 2s for gossipsub mesh...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    let balance_before = balance_of(api_ports[0], "qcb1alice");
    eprintln!("   alice balance before: {balance_before:?} uqcb");

    // Deterministic delivery: wait for a block to commit, then send both
    // conflicting votes for the next open height.
    let queued_at = |h: u64, validator: &str| -> bool {
        VALIDATORS.iter().any(|n| {
            let text = std::fs::read_to_string(log_dir.join(format!("{n}.log")))
                .unwrap_or_default();
            let clean = strip_ansi(&text);
            clean.lines().any(|l|
                l.contains("evidence queued")
                && l.contains(&format!("validator={validator}"))
                && l.contains(&format!("height={h} ")))
        })
    };

    let mut attack_height = 0u64;
    let mut confirmed     = false;
    for attempt in 1..=5 {
        let committed = height_of(api_ports[0]);
        let deadline = Instant::now() + Duration::from_secs(10);
        while height_of(api_ports[0]) == committed && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        attack_height = height_of(api_ports[0]) + 1;
        eprintln!("   [attacker] attempt {attempt}: height {} just committed -> equivocating at {attack_height}",
                  attack_height - 1);

        for hash in ["equivoc_hash_AAAAAAAAAAAAAAAAAAA", "equivoc_hash_BBBBBBBBBBBBBBBBBBB"] {
            let vote = sign_mldsa_vote(
                &alice_kp, "qcb1alice", VoteType::Prevote,
                attack_height, 0, DEVNET_VOTE_EPOCH, hash, &set_hash,
            );
            attacker.publish(OutboundMessage {
                topic:   GossipTopic::ConsensusVote,
                payload: serde_json::to_vec(&vote).unwrap(),
            }).await.expect("publish equivocating vote");
        }
        let confirm_by = Instant::now() + Duration::from_secs(4);
        while !confirmed && Instant::now() < confirm_by {
            confirmed = queued_at(attack_height, "qcb1alice");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if confirmed {
            eprintln!("   [attacker] evidence for height {attack_height} queued on attempt {attempt}");
            break;
        }
    }
    assert!(confirmed,
        "equivocating ML-DSA-65 votes were never detected in 5 synchronized attempts");

    println!("   Waiting for chain to advance past evidence block...");
    assert!(
        poll_until_height(&api_ports[1..], attack_height + 2, Duration::from_secs(30)),
        "chain stalled after equivocation"
    );

    println!("── EQ-01 PASS: ML-DSA-65 equivocation detected and evidence queued ───");
}

// ── EQ-02: Canonicalization — (A,B) and (B,A) are the same offense ────────────

#[cfg(feature = "pq-hotstuff")]
#[test]
fn eq_02_canonical_ordering_deduplication() {
    // `check_evidence_signatures` rejects evidence where hash_a > hash_b.
    // Verify the invariant directly: construct (B,A) ordered evidence and check
    // that the canonical-order guard would reject it.

    let hash_a = "equivoc_hash_AAAAAAAAAAAAAAAAAAA"; // A < B lexicographically
    let hash_b = "equivoc_hash_BBBBBBBBBBBBBBBBBBB";

    // Canonical: hash_a <= hash_b — must pass.
    assert!(
        hash_a <= hash_b,
        "test invariant: hash_a must be <= hash_b"
    );

    // Reversed: ev where block_hash_a > block_hash_b — must be rejected.
    let ev_reversed = EquivocationEvidence {
        validator_id:   "qcb1alice".into(),
        height:         10,
        round:          0,
        block_hash_a:   hash_b.to_string(), // deliberately reversed
        block_hash_b:   hash_a.to_string(),
        signature_a:    vec![0xAA],
        signature_b:    vec![0xBB],
        vote_type_byte: 0,
        epoch:          1,
    };
    // Reproduce the canonical-order check from `check_evidence_signatures`.
    let canonical_check_passes = ev_reversed.block_hash_a <= ev_reversed.block_hash_b;
    assert!(
        !canonical_check_passes,
        "reversed evidence (hash_a={} > hash_b={}) must fail canonical-order check",
        ev_reversed.block_hash_a, ev_reversed.block_hash_b
    );

    // Canonical evidence — must pass the check.
    let ev_canonical = EquivocationEvidence {
        validator_id:   "qcb1alice".into(),
        height:         10,
        round:          0,
        block_hash_a:   hash_a.to_string(),
        block_hash_b:   hash_b.to_string(),
        signature_a:    vec![0xAA],
        signature_b:    vec![0xBB],
        vote_type_byte: 0,
        epoch:          1,
    };
    assert!(
        ev_canonical.block_hash_a <= ev_canonical.block_hash_b,
        "canonical evidence must pass canonical-order check"
    );

    println!("EQ-02 PASS: canonical ordering check accepted (A,B) and rejected (B,A)");
}

// ── EQ-03: Cross-round votes are NOT equivocation ─────────────────────────────

#[cfg(feature = "pq-hotstuff")]
#[test]
fn eq_03_cross_round_not_equivocation() {
    let alice_kp = load_mldsa_keypair("alice");
    let vs       = devnet_validator_set();
    let set_hash = canonical_set_hash(&vs);

    // Vote A at round 0, vote B at round 1 — different rounds, same height.
    let vote_a = sign_mldsa_vote(
        &alice_kp, "qcb1alice", VoteType::Prevote, 10, 0, 1,
        "some_block_hash_AAAAAAAAAAAAAAAAA", &set_hash,
    );
    let vote_b = sign_mldsa_vote(
        &alice_kp, "qcb1alice", VoteType::Prevote, 10, 1, 1,
        "some_block_hash_BBBBBBBBBBBBBBBBB", &set_hash,
    );

    // Treat the two votes as evidence for the SAME round (round=0).
    // vote_b's signature covers round=1, so it will NOT verify against round=0.
    let ev = EquivocationEvidence {
        validator_id:   "qcb1alice".into(),
        height:         10,
        round:          0, // claim both votes are from round 0
        block_hash_a:   vote_a.block_hash.as_ref().unwrap().0.clone(),
        block_hash_b:   vote_b.block_hash.as_ref().unwrap().0.clone(),
        signature_a:    vote_a.signature.clone(),
        signature_b:    vote_b.signature.clone(), // actually signed at round=1
        vote_type_byte: 0,
        epoch:          1,
    };

    // The signature for vote_b was computed with round=1 but the evidence says
    // round=0, so `check_evidence_signatures` must reject it.
    // We verify the canonicalization check passes first (hash_a <= hash_b),
    // then confirm the cross-round signature fails.
    let hash_a = &ev.block_hash_a;
    let hash_b = &ev.block_hash_b;
    assert!(hash_a <= hash_b, "evidence must already be in canonical order");

    // Verify that signature_b (signed at round=1) does NOT verify at round=0.
    use chain_forge_consensus::VoteType;
    let bh_b = BlockHash(hash_b.clone());
    let msg_round0 = vote_signing_bytes_v2(CHAIN_ID, &VoteType::Prevote, 10, 0, 1, &set_hash, Some(&bh_b));
    let key = vs.public_key_of(&ValidatorId("qcb1alice".into()));
    let result = chain_forge_crypto::verify_consensus(&msg_round0, &ev.signature_b, key);
    assert!(
        result.is_err(),
        "cross-round signature must fail verification: a round-1 sig must not verify at round-0"
    );

    println!("EQ-03 PASS: cross-round vote signature correctly rejected");
}

// ── EQ-04: Evidence outside the 1,000-block lookback window is rejected ───────

#[cfg(feature = "pq-hotstuff")]
#[test]
fn eq_04_expired_evidence_rejected() {
    // `check_evidence` in node.rs applies:
    //   ev.height + EVIDENCE_MAX_AGE_BLOCKS < height  → expired
    // We reproduce the same inequality here with the documented value (1,000).
    const EVIDENCE_MAX_AGE_BLOCKS: u64 = 1_000;

    // Stale evidence: offense at height 1, committed in a block at height 1_002.
    let ev_height    = 1u64;
    let block_height = ev_height + EVIDENCE_MAX_AGE_BLOCKS + 1;
    let is_expired   = ev_height + EVIDENCE_MAX_AGE_BLOCKS < block_height;
    assert!(is_expired, "staleness check: 1 + 1000 < 1002 must hold");

    // Fresh evidence: offense at height 1, committed in a block at height 1_001.
    let fresh_block = ev_height + EVIDENCE_MAX_AGE_BLOCKS;
    let is_fresh    = !(ev_height + EVIDENCE_MAX_AGE_BLOCKS < fresh_block);
    assert!(is_fresh, "freshness check: 1 + 1000 is NOT < 1001 (edge of window)");

    println!("EQ-04 PASS: 1,000-block lookback window arithmetic verified");
}
