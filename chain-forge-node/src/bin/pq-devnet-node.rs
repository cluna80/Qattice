//! PQ-HotStuff-2 devnet node (feature `pq-devnet`). **DEVNET ONLY. NOT FOR PRODUCTION.** See `chain_forge_node::pq_devnet` for what is and
//! is not provided (devnet-only key file, non-production counter, unauthenticated local transport, devnet-interim payloads and application).
//!
//!   pq-devnet-node keygen   --dir DIR
//!   pq-devnet-node assemble --out FILE --chain-id ID (--base-port PORT | --ports P0,P1,P2,P3) --dirs DIR0,DIR1,DIR2,DIR3
//!   pq-devnet-node run      --config FILE --dir DIR [--tick-ms 20]
//!
//! `run` writes `DIR/status.json` every 250 ms and re-reads `DIR/partition.txt` (peer indices to cut off) every 200 ms.
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chain_forge_consensus::pq_hotstuff::blockstore::BlockStore;
use chain_forge_consensus::pq_hotstuff::driver::{Driver, DriverError, Outbound};
use chain_forge_consensus::pq_hotstuff::engine::Engine;
use chain_forge_consensus::pq_hotstuff::exec::InterimApp;
use chain_forge_consensus::pq_hotstuff::safety::{Expected, Fips204Verifier, FreshInit, FsStorage, ParticipationEvidence, SafetyStore, Storage, MARKER_FILE, STATE_FILE};
use chain_forge_node::pq_devnet::*;

fn flag(args: &[String], name: &str) -> Option<String> { args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned() }
fn need(args: &[String], name: &str) -> Result<String, String> { flag(args, name).ok_or_else(|| format!("missing {name}")) }

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(String::as_str) {
        Some("keygen") => need(&args, "--dir").and_then(|d| keygen(Path::new(&d)).map(|pk| println!("public key written to {d}/{PUB_FILE} ({} bytes); the seed stays in {d}/{SEED_FILE} and is never printed", pk.len()))),
        Some("assemble") => assemble(&args),
        Some("run") => run(&args),
        _ => Err("usage: pq-devnet-node keygen|assemble|run (see the file header)".into()),
    };
    if let Err(e) = r { eprintln!("pq-devnet-node: {e}"); std::process::exit(2); }
}

fn assemble(args: &[String]) -> Result<(), String> {
    let out = need(args, "--out")?;
    let chain_id = need(args, "--chain-id")?;
    let dirs = need(args, "--dirs")?;
    let ports: Vec<u16> = match flag(args, "--ports") {
        Some(p) => p.split(',').map(|x| x.parse().map_err(|_| "bad --ports".to_string())).collect::<Result<_, _>>()?,
        None => { let base: u16 = need(args, "--base-port")?.parse().map_err(|_| "bad --base-port")?; (0..dirs.split(',').count() as u16).map(|i| base + i).collect() }
    };
    if ports.len() != dirs.split(',').count() { return Err("--ports and --dirs must have the same length".into()); }
    let mut validators = vec![];
    for (i, d) in dirs.split(',').enumerate() {
        let pk = std::fs::read_to_string(Path::new(d).join(PUB_FILE)).map_err(|e| format!("{d}: {e}"))?;
        validators.push(DevnetValidator { address: format!("pqdev-{i}"), public_key: pk.trim().to_string(), power: 1, endpoint: format!("127.0.0.1:{}", ports[i]) });
    }
    let cfg = DevnetConfig {
        label: DEVNET_LABEL.into(), chain_id, protocol_profile: "qattice-pq-hotstuff-2-v2".into(), validators,
        max_block_payload_bytes: 65_536, max_message_bytes: chain_forge_consensus::pq_hotstuff::netmsg::MAX_MESSAGE_SIZE, max_sync_blocks: 8,
        pacemaker_base_ms: 1500, pacemaker_max_ms: 12_000, min_propose_gap_ms: 150,
    };
    std::fs::write(&out, serde_json::to_vec_pretty(&cfg).unwrap()).map_err(|e| e.to_string())?;
    println!("wrote {out} (genesis hash = SHA3-256 of this file; give every node the identical file)");
    Ok(())
}

fn status_json(d: &Driver<FsStorage, DevnetFileCounter, chain_forge_consensus::pq_hotstuff::safety::Fips204Signer, Fips204Verifier, FsStorage, InterimApp<FsStorage>>, index: usize, fatal: Option<String>) -> String {
    let s = d.status();
    let cur = |c: &chain_forge_consensus::pq_hotstuff::exec::ExecCursor| serde_json::json!({"height": c.height, "block_id": hex::encode(c.block_id), "state_digest": hex::encode(c.state_digest)});
    serde_json::json!({
        "index": index, "label": DEVNET_LABEL, "round": s.round, "high_qc_round": s.high_qc_round, "committed_height": s.committed_height,
        "committed_tip": hex::encode(s.committed_tip), "exec": cur(&s.exec), "recent": s.recent.iter().map(cur).collect::<Vec<_>>(),
        "malformed": s.stats.malformed, "bad_sync": s.stats.bad_sync, "sync_requests": s.stats.sync_requests, "unsolicited_sync": s.stats.unsolicited_sync, "fatal": fatal,
    }).to_string()
}

fn write_atomic(path: &Path, text: &str) { let tmp = path.with_extension("tmp"); if std::fs::write(&tmp, text).is_ok() { let _ = std::fs::rename(&tmp, path); } }

fn dispatch(t: &Transport, outs: Vec<Outbound>) { for o in outs { match o.to { Some(to) => t.send(to, o.bytes), None => t.broadcast(&o.bytes) } } }

fn run(args: &[String]) -> Result<(), String> {
    let dir = PathBuf::from(need(args, "--dir")?);
    let tick_ms: u64 = flag(args, "--tick-ms").map(|v| v.parse().map_err(|_| "bad --tick-ms")).transpose()?.unwrap_or(20);
    let _lock = chain_forge_node::dirlock::DataDirLock::acquire(&dir).map_err(|e| e.to_string())?;
    let (cfg, genesis_hash) = DevnetConfig::load(Path::new(&need(args, "--config")?))?;
    let signer = load_signer(&dir)?;
    let pk = chain_forge_consensus::pq_hotstuff::safety::ConsensusSigner::public_key(&signer).to_vec();
    let (ecfg, me) = cfg.engine_config(&pk, genesis_hash)?;
    let dcfg = cfg.driver_config();
    for sub in ["safety", "blocks", "app"] { std::fs::create_dir_all(dir.join(sub)).map_err(|e| e.to_string())?; }

    // signing safety: open the existing state, or initialize once. Missing or mismatched pieces are refused, never repaired or reset.
    let storage = FsStorage::new(dir.join("safety")).map_err(|e| e.0)?;
    let ctr_path = dir.join("counter");
    let have_state = storage.read(STATE_FILE).map_err(|e| e.0)?.is_some() || storage.read(MARKER_FILE).map_err(|e| e.0)?.is_some();
    let store = if have_state {
        let counter = DevnetFileCounter::open(&ctr_path, &pk).map_err(|e| format!("signing-safety state exists but its counter cannot be opened ({}); refusing to start", e.0))?;
        let exp = Expected { protocol_profile: &ecfg.protocol_profile, chain_id: &ecfg.chain_id, public_key: &pk };
        SafetyStore::open(storage, counter, &exp, &Fips204Verifier, &ParticipationEvidence::default()).map_err(|e| format!("signing-safety state refused: {e}"))?
    } else {
        if ctr_path.exists() { return Err("a counter file exists but the signing-safety state is missing; refusing to reset signing safety".into()); }
        let counter = DevnetFileCounter::create(&ctr_path, &pk).map_err(|e| e.0)?;
        let init = FreshInit { protocol_profile: &ecfg.protocol_profile, chain_id: &ecfg.chain_id, public_key: &pk, instance_id: counter.instance_id(), epoch: 0 };
        SafetyStore::initialize_fresh(storage, counter, &init, &ParticipationEvidence::default()).map_err(|e| format!("cannot initialize signing safety: {e}"))?
    };
    let engine = Engine::new(ecfg, store, signer, Fips204Verifier).map_err(|e| e.to_string())?;
    let blocks = BlockStore::new(FsStorage::new(dir.join("blocks")).map_err(|e| e.0)?);
    let app = InterimApp::open(FsStorage::new(dir.join("app")).map_err(|e| e.0)?, genesis_hash).map_err(|e| e.to_string())?;

    let t0 = Instant::now();
    let now = || t0.elapsed().as_millis() as u64 + 1;
    let payload: chain_forge_consensus::pq_hotstuff::driver::PayloadSource = Box::new(|round, idx| format!("devnet-interim:{idx}:{round}").into_bytes());
    let (mut drv, first) = Driver::start(dcfg, engine, blocks, app, payload, now()).map_err(|e: DriverError| format!("start refused: {e}"))?;
    let t = Transport::start(me, cfg.endpoints()?, cfg.max_message_bytes, 256, Some(dir.join("partition.txt"))).map_err(|e| format!("transport: {e}"))?;
    eprintln!("pq-devnet-node {me}: {DEVNET_LABEL}; committed height {}, executed height {}", drv.status().committed_height, drv.status().exec.height);
    dispatch(&t, first);

    let status_path = dir.join("status.json");
    let mut last_status = Instant::now() - Duration::from_secs(1);
    loop {
        let fatal = |e: DriverError, drv: &_| -> String { let m = e.to_string(); write_atomic(&status_path, &status_json(drv, me, Some(m.clone()))); m };
        if let Some((from, bytes)) = t.recv(Duration::from_millis(tick_ms)) {
            let mut next = Some((from, bytes));
            let mut n = 0;
            while let Some((f, b)) = next.take() {
                match drv.on_bytes(f, &b, now()) { Ok(o) => dispatch(&t, o), Err(e) => return Err(fatal(e, &drv)) }
                n += 1;
                if n < 64 { next = t.recv(Duration::from_millis(0)); }
            }
        }
        match drv.tick(now()) { Ok(o) => dispatch(&t, o), Err(e) => return Err(fatal(e, &drv)) }
        if last_status.elapsed() >= Duration::from_millis(250) { write_atomic(&status_path, &status_json(&drv, me, None)); last_status = Instant::now(); }
    }
}
