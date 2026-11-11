//! PQ-HotStuff-2 devnet node (feature `pq-devnet`). **DEVNET ONLY. NOT FOR PRODUCTION.** See `chain_forge_node::pq_devnet` for what is and
//! is not provided (devnet-only key file, non-production counter, unauthenticated local transport, devnet-interim payloads and application).
//!
//!   pq-devnet-node keygen   --dir DIR
//!   pq-devnet-node assemble --out FILE --chain-id ID (--base-port PORT | --ports P0,P1,P2,P3) --dirs DIR0,DIR1,DIR2,DIR3
//!   pq-devnet-node inspect  --dir DIR            (read-only: block set, QCs, seed evidence and safety floors of a data directory)
//!   pq-devnet-node run      --config FILE --dir DIR [--tick-ms 20] [--exec-log FILE]
//!   (profile v3, OFF by default) assemble ... --checkpoint-interval K --checkpoint-max-age A [--checkpoint-margin M]
//!   (profile v3, operator-staged, OFFLINE; NOT network installation) pq-devnet-node stage-snapshot --config FILE --donor DIR --dir DIR [--back N] [--lag K]
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
use chain_forge_consensus::pq_hotstuff::checkpoint::PROFILE_V3;
use chain_forge_consensus::pq_hotstuff::engine::Msg;
use chain_forge_consensus::pq_hotstuff::netmsg::{decode as net_decode, MessageLimits, NetMsg};

fn flag(args: &[String], name: &str) -> Option<String> { args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned() }
fn need(args: &[String], name: &str) -> Result<String, String> { flag(args, name).ok_or_else(|| format!("missing {name}")) }

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(String::as_str) {
        Some("keygen") => need(&args, "--dir").and_then(|d| keygen(Path::new(&d)).map(|pk| println!("public key written to {d}/{PUB_FILE} ({} bytes); the seed stays in {d}/{SEED_FILE} and is never printed", pk.len()))),
        Some("assemble") => assemble(&args),
        Some("run") => run(&args),
        Some("stage-snapshot") => stage(&args),
        Some("inspect") => inspect(&args),
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
    // profile v3 is OFF unless a checkpoint interval is given; without it this writes exactly the v2 config it always wrote
    let checkpoint = match flag(args, "--checkpoint-interval") {
        None => None,
        Some(k) => Some(DevnetCheckpoint {
            interval: k.parse().map_err(|_| "bad --checkpoint-interval")?,
            max_age: need(args, "--checkpoint-max-age")?.parse().map_err(|_| "bad --checkpoint-max-age")?,
            margin: flag(args, "--checkpoint-margin").map(|v| v.parse().map_err(|_| "bad --checkpoint-margin")).transpose()?.unwrap_or(2),
            omit_rotations: 1, alarm_age_intervals: 8,
        }),
    };
    let cfg = DevnetConfig {
        label: DEVNET_LABEL.into(), chain_id, protocol_profile: if checkpoint.is_some() { PROFILE_V3.into() } else { "qattice-pq-hotstuff-2-v2".into() }, validators,
        max_block_payload_bytes: 65_536, max_message_bytes: chain_forge_consensus::pq_hotstuff::netmsg::MAX_MESSAGE_SIZE, max_sync_blocks: 8,
        pacemaker_base_ms: 1500, pacemaker_max_ms: 12_000, min_propose_gap_ms: 150, checkpoint,
    };
    cfg.checkpoint_config()?; // refuse an inconsistent file before writing it
    std::fs::write(&out, serde_json::to_vec_pretty(&cfg).unwrap()).map_err(|e| e.to_string())?;
    println!("wrote {out} (genesis hash = SHA3-256 of this file; give every node the identical file)");
    Ok(())
}

type Drv = Driver<FsStorage, DevnetFileCounter, chain_forge_consensus::pq_hotstuff::safety::Fips204Signer, Fips204Verifier, FsStorage, LoggedApp<InterimApp<FsStorage>>>;

fn status_json(d: &Drv, index: usize, fatal: Option<String>, violation: bool, resent: bool) -> String {
    let s = d.status();
    let cur = |c: &chain_forge_consensus::pq_hotstuff::exec::ExecCursor| serde_json::json!({"height": c.height, "block_id": hex::encode(c.block_id), "state_digest": hex::encode(c.state_digest)});
    let mut j = serde_json::json!({
        "index": index, "label": DEVNET_LABEL, "round": s.round, "high_qc_round": s.high_qc_round, "committed_height": s.committed_height,
        "committed_tip": hex::encode(s.committed_tip), "exec": cur(&s.exec), "recent": s.recent.iter().map(cur).collect::<Vec<_>>(),
        "recovering": d.engine().is_recovering(), "base": d.engine().base().map(|b| serde_json::json!({"height": b.height, "id": hex::encode(b.id)})),
        "safety": {"hvr": d.engine().store().record().hvr, "hqr": d.engine().store().record().hqr, "counter": d.engine().store().record().counter},
        "is_leader": d.engine().is_leader(), "propose_refused_while_recovering": s.stats.propose_refused_while_recovering, "timeout_refused_while_recovering": s.stats.timeout_refused_while_recovering,
        "signed_while_recovering": violation, "sent_signed_while_recovering": resent, "below_base_served": s.stats.below_base_served, "below_base_advice": s.stats.below_base_advice,
        "malformed": s.stats.malformed, "bad_sync": s.stats.bad_sync, "sync_requests": s.stats.sync_requests, "unsolicited_sync": s.stats.unsolicited_sync, "fatal": fatal,
    });
    // only when the node opted in: with serving off the status document is exactly what it always was
    #[cfg(feature = "pq-snapshot-transfer")]
    if let Some(c) = d.snapshot_serving() {
        j["snapshot_serving"] = serde_json::json!({"captured": c.captured, "capture_deferred": c.capture_deferred, "capture_other_error": c.capture_other_error, "retained": c.retained, "retained_bytes": c.retained_bytes, "pinned_now": c.pinned_now, "requests": c.requests, "malformed": c.malformed, "unsolicited_responses": c.unsolicited_responses, "replies_busy_for_pins": c.replies_busy_for_pins, "pins_released_idle": c.pins_released_idle, "gate_concurrent": c.gate_concurrent});
    }
    j.to_string()
}

fn write_atomic(path: &Path, text: &str) { let tmp = path.with_extension("tmp"); if std::fs::write(&tmp, text).is_ok() { let _ = std::fs::rename(&tmp, path); } }

/// How many of `outs` are messages SIGNED BY THIS NODE (its own vote, timeout or proposal) - new or a re-send of a stored one.
fn signed_by_me(lim: &MessageLimits, me: usize, outs: &[Outbound]) -> usize {
    outs.iter().filter(|o| match net_decode(&o.bytes, lim) {
        Ok(NetMsg::Consensus(Msg::Vote(v))) => v.voter == me,
        Ok(NetMsg::Consensus(Msg::Timeout(t))) => t.voter == me,
        Ok(NetMsg::Consensus(Msg::Proposal(b))) => b.proposer == me,
        _ => false,
    }).count()
}

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
    let app = LoggedApp::new(InterimApp::open(FsStorage::new(dir.join("app")).map_err(|e| e.0)?, genesis_hash).map_err(|e| e.to_string())?, flag(args, "--exec-log").map(PathBuf::from));

    let t0 = Instant::now();
    let now = || t0.elapsed().as_millis() as u64 + 1;
    let payload: chain_forge_consensus::pq_hotstuff::driver::PayloadSource = Box::new(|round, idx| format!("devnet-interim:{idx}:{round}").into_bytes());
    let (mut drv, first) = Driver::start(dcfg, engine, blocks, app, payload, now()).map_err(|e: DriverError| format!("start refused: {e}"))?;
    // S-2b, OFF by default: snapshot capture and serving needs the `pq-snapshot-transfer` build feature AND this explicit flag. It serves; it never installs, imports signing state or prunes.
    if args.iter().any(|a| a == "--serve-snapshots") {
        #[cfg(feature = "pq-snapshot-transfer")]
        { enable_serving(&mut drv, args, &cfg, genesis_hash, &dir, now())?; }
        #[cfg(not(feature = "pq-snapshot-transfer"))]
        { return Err("--serve-snapshots needs a build with the pq-snapshot-transfer feature (this build has it off)".into()); }
    }
    let t = Transport::start(me, cfg.endpoints()?, cfg.max_message_bytes, 256, Some(dir.join("partition.txt"))).map_err(|e| format!("transport: {e}"))?;
    eprintln!("pq-devnet-node {me}: {DEVNET_LABEL}; committed height {}, executed height {}", drv.status().committed_height, drv.status().exec.height);
    let lim = *drv.limits();
    // a node that starts Recovering must not even re-send what it signed before
    let mut resent = drv.engine().is_recovering() && signed_by_me(&lim, me, &first) > 0;
    dispatch(&t, first);

    // Defensive pruning watermark (pq-anchored-evidence, off by default).
    // PRUNE_KEEP: retain the most recent N committed block payloads; delete everything older.
    // The anchor gate guards against pruning before genesis-rooted audit completes.
    #[cfg(feature = "pq-anchored-evidence")]
    const PRUNE_KEEP: u64 = 64;
    #[cfg(feature = "pq-anchored-evidence")]
    let mut pruned_watermark: u64 = drv.block_store().pruned_watermark().map_err(|e| format!("pruned_watermark at start: {e}"))?;
    #[cfg(feature = "pq-anchored-evidence")]
    if pruned_watermark > 0 { eprintln!("pq-devnet-node {me}: pruning watermark at startup = {pruned_watermark}"); }

    let status_path = dir.join("status.json");
    let mut last_status = Instant::now() - Duration::from_secs(1);
    // runtime monitor: while the engine is Recovering the signing counter must not move. A violation stops the node and is reported.
    let mut violation = false;
    let counter_of = |d: &Drv| d.engine().store().record().counter;
    write_atomic(&status_path, &status_json(&drv, me, None, false, resent)); // the state right after start, before any message or tick
    loop {
        let fatal = |e: DriverError, drv: &Drv| -> String { let m = e.to_string(); write_atomic(&status_path, &status_json(drv, me, Some(m.clone()), false, false)); m };
        if let Some((from, bytes)) = t.recv(Duration::from_millis(tick_ms)) {
            let mut next = Some((from, bytes));
            let mut n = 0;
            while let Some((f, b)) = next.take() {
                let (was, c0) = (drv.engine().is_recovering(), counter_of(&drv));
                match drv.on_bytes(f, &b, now()) { Ok(o) => { if was && drv.engine().is_recovering() && signed_by_me(&lim, me, &o) > 0 { resent = true; } dispatch(&t, o) } Err(e) => return Err(fatal(e, &drv)) }
                if was && drv.engine().is_recovering() && counter_of(&drv) != c0 { violation = true; }
                n += 1;
                if n < 64 { next = t.recv(Duration::from_millis(0)); }
            }
        }
        let (was, c0) = (drv.engine().is_recovering(), counter_of(&drv));
        match drv.tick(now()) { Ok(o) => { if was && drv.engine().is_recovering() && signed_by_me(&lim, me, &o) > 0 { resent = true; } dispatch(&t, o) } Err(e) => return Err(fatal(e, &drv)) }
        if was && drv.engine().is_recovering() && counter_of(&drv) != c0 { violation = true; }
        if violation || resent {
            let m = if violation { "SAFETY: the signing counter moved while recovering" } else { "SAFETY: a message signed by this node was sent while recovering" };
            write_atomic(&status_path, &status_json(&drv, me, Some(m.into()), violation, resent)); return Err(m.into());
        }
        // Advance pruning watermark when finality is ahead of the keep window and the anchor gate is clear.
        #[cfg(feature = "pq-anchored-evidence")]
        {
            let committed = drv.status().committed_height;
            if committed > pruned_watermark + PRUNE_KEEP && !drv.anchor_pending() {
                let new_below = committed - PRUNE_KEEP;
                match drv.prune_below(new_below) {
                    Ok(deleted) => {
                        pruned_watermark = new_below;
                        eprintln!("pq-devnet-node {me}: pruned payloads below height {new_below} ({deleted} files deleted); watermark = {pruned_watermark}");
                    }
                    Err(e) => eprintln!("pq-devnet-node {me}: prune_below({new_below}) error: {e}"),
                }
            }
        }
        if last_status.elapsed() >= Duration::from_millis(250) {
            #[cfg(feature = "pq-anchored-evidence")]
            { let mut s = status_json(&drv, me, None, false, false); if let Ok(mut j) = serde_json::from_str::<serde_json::Value>(&s) { j["pruned_watermark"] = pruned_watermark.into(); s = j.to_string(); } write_atomic(&status_path, &s); }
            #[cfg(not(feature = "pq-anchored-evidence"))]
            write_atomic(&status_path, &status_json(&drv, me, None, false, false));
            last_status = Instant::now();
        }
    }
}

/// Offline, operator-staged snapshot (profile v3). Refuses a target whose data directory is locked by a running node.
fn stage(args: &[String]) -> Result<(), String> {
    let target = PathBuf::from(need(args, "--dir")?);
    let donor = PathBuf::from(need(args, "--donor")?);
    let back: usize = flag(args, "--back").map(|v| v.parse().map_err(|_| "bad --back")).transpose()?.unwrap_or(1);
    let (cfg, genesis_hash) = DevnetConfig::load(Path::new(&need(args, "--config")?))?;
    let _lock = chain_forge_node::dirlock::DataDirLock::acquire(&target).map_err(|e| format!("the target is in use: {e}"))?;
    let lag: usize = flag(args, "--lag").map(|v| v.parse().map_err(|_| "bad --lag")).transpose()?.unwrap_or(0);
    let st = stage_snapshot(&cfg, genesis_hash, &donor, &target, back, lag)?;
    println!("{}", serde_json::json!({"staged": true, "height": st.reference.height, "block_id": hex::encode(st.reference.block_id), "state_root": hex::encode(st.reference.state_root), "evidence_bytes": st.evidence_bytes, "note": "operator-staged, offline; NOT network installation"}));
    Ok(())
}

/// Read-only diagnostics of a node's data directory (devnet only): what the block store holds, what the high QC/TC are, the stored seed evidence, and the safety floors.
fn inspect(args: &[String]) -> Result<(), String> {
    use chain_forge_consensus::pq_hotstuff::safety::{decode_record, STATE_FILE};
    use chain_forge_consensus::pq_hotstuff::seed::{SeedEvidence, MAX_EVIDENCE_HEADERS};
    let dir = PathBuf::from(need(args, "--dir")?);
    let bs = BlockStore::new(FsStorage::new(dir.join("blocks")).map_err(|e| e.0)?);
    let loaded = bs.load().map_err(|e| e.to_string())?;
    let mut heights: Vec<(u64, u64)> = loaded.blocks.iter().map(|b| (b.height, b.round)).collect();
    heights.sort();
    let evidence = match bs.load_seed_evidence().map_err(|e| e.to_string())? {
        None => serde_json::Value::Null,
        Some((h, id, bytes)) => {
            let ev = SeedEvidence::decode(&bytes, MAX_EVIDENCE_HEADERS).map_err(|e| e.to_string())?;
            serde_json::json!({"height": h, "block_id": hex::encode(id), "headers": ev.headers.len(), "high_qc_round": ev.high_qc.round(), "high_qc_block": hex::encode(ev.high_qc.block_id()),
                "final_qc_round": ev.final_qc.as_ref().map(|c| c.round()), "has_tc": ev.high_tc.is_some(), "last_header_round": ev.headers.last().map(|h| h.round), "last_header_height": ev.headers.last().map(|h| h.height)})
        }
    };
    let storage = FsStorage::new(dir.join("safety")).map_err(|e| e.0)?;
    let rec = storage.read(STATE_FILE).map_err(|e| e.0)?.map(|b| decode_record(&b).map_err(|e| e.to_string())).transpose()?;
    println!("{}", serde_json::json!({
        "seeded_height": loaded.seeded_height, "blocks": heights.len(), "block_heights_and_rounds": heights,
        "committed_markers": loaded.committed.len(), "committed_last": loaded.committed.last().map(|c| c.0),
        "high_qc": loaded.high_qc.as_ref().map(|c| serde_json::json!({"round": c.round(), "block": hex::encode(c.block_id())})),
        "high_tc_round": loaded.high_tc.as_ref().map(|t| t.round), "damaged_blocks": loaded.damaged_blocks, "damaged_hints": loaded.damaged_hints,
        "seed_evidence": evidence,
        "safety": rec.map(|r| serde_json::json!({"hvr": r.hvr, "hqr": r.hqr, "counter": r.counter, "last_vote_round": r.last_vote.as_ref().map(|v| v.round), "last_timeout_round": r.last_timeout.as_ref().map(|t| t.round), "last_proposal_round": r.last_proposal.as_ref().map(|p| p.round)})),
    }));
    Ok(())
}

/// Validate the per-node retention and serving settings (refusing locally, before any network use), open the snapshot cache and opt the driver in.
#[cfg(feature = "pq-snapshot-transfer")]
fn enable_serving(drv: &mut Drv, args: &[String], cfg: &DevnetConfig, genesis_hash: [u8; 32], dir: &Path, now: u64) -> Result<(), String> {
    use chain_forge_consensus::pq_hotstuff::recovery::{codec::CodecLimits, requests::ServeConfig, retention::{RetentionConfig, SnapshotStore}, tree::StdTreeFs};
    use chain_forge_consensus::pq_hotstuff::serving::{ServingConfig, SnapshotServing};
    let num = |name: &str, default: u64| -> Result<u64, String> { flag(args, name).map(|v| v.parse().map_err(|_| format!("bad {name}"))).transpose().map(|o| o.unwrap_or(default)) };
    let retention = RetentionConfig { max_snapshots: num("--snapshot-count", 3)? as usize, disk_budget_bytes: num("--snapshot-budget-bytes", 64 << 20)?, max_snapshot_bytes: num("--snapshot-max-bytes", 16 << 20)? };
    retention.validate().map_err(|e| format!("snapshot retention refused: {e}"))?;
    let limit = cfg.max_message_bytes as u64;
    let lim = *drv.limits();
    let codec = CodecLimits { transport: lim.transport, n: cfg.endpoints()?.len(), max_headers: 64, max_chunk_size: 262_144, max_chunk_count: 65_536, max_snapshot_bytes: retention.max_snapshot_bytes };
    // the minimum spacing is what throttles a flood of SMALL requests (the byte buckets refund what a small answer did not use)
    let serve = ServeConfig { limit, burst: 2 * limit, refill_per_s: limit / 2, aggregate_per_s: 8 * limit, max_concurrent: 16, per_peer_outstanding: 4, min_spacing_ms: num("--snapshot-min-spacing-ms", 20)?, chunk_size: 262_144 };
    let scfg = ServingConfig { serve, codec, genesis_hash, chunk_size: 262_144, max_candidates: 8, pin_idle_ms: num("--snapshot-pin-idle-ms", 60_000)?, max_pins_per_peer: 1, max_pins_total: 4 };
    let snap_dir = flag(args, "--snapshot-dir").map(PathBuf::from).unwrap_or_else(|| dir.join("snapshot-cache"));
    std::fs::create_dir_all(&snap_dir).map_err(|e| format!("snapshot directory: {e}"))?;
    let fs = StdTreeFs::new(snap_dir).map_err(|e| e.0)?;
    let store = SnapshotStore::open(fs, retention, codec, genesis_hash).map_err(|e| format!("snapshot cache refused: {e}"))?;
    let svc = SnapshotServing::new(store, scfg, now).map_err(|e| format!("snapshot serving refused: {e}"))?;
    drv.enable_snapshot_serving(Box::new(svc));
    eprintln!("pq-devnet-node: snapshot serving ENABLED (opt-in); retention {} snapshots, budget {} bytes; installation stays operator-initiated", retention.max_snapshots, retention.disk_budget_bytes);
    Ok(())
}
