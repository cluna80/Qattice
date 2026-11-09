
// ============================================================================================================================
// Persisted, re-authenticated seed evidence; base-aware driver and block store; explicit below-base sync answers; and a LIVE (in-process, driver-level) profile-v3
// recovery network. DRAFT; disabled; nothing in a node calls this. "Live" here means four real drivers exchanging real encoded messages over the harness network with
// real execution and storage models (real ML-DSA-65 in the fips204 run) - it is NOT the TCP devnet, which does not run profile v3.
// ============================================================================================================================
use chain_forge_consensus::pq_hotstuff::seed::{SeedEvidence, MAX_EVIDENCE_HEADERS};
use chain_forge_consensus::pq_hotstuff::checkpoint::Evidence;
use chain_forge_consensus::pq_hotstuff::sync::BelowBase;

fn drv_chain(d: &Drv) -> Vec<Block> {
    let all: BTreeMap<BlockId, Block> = d.engine().known_blocks().into_iter().map(|b| (id3(b), b.clone())).collect();
    let Cert::Qc(q) = d.engine().high_qc().clone() else { return vec![] };
    let (mut cur, mut out) = (q.block_id, vec![]);
    while let Some(b) = all.get(&cur) { out.push(b.clone()); cur = b.parent_id; }
    out.reverse();
    out
}
/// Evidence a healthy driver can give: its whole chain to its high QC, naming the `from_end`-th newest reference that authenticates.
fn evidence_from(d: &Drv, from_end: usize) -> (SeedEvidence, CheckpointRef) {
    let chain = drv_chain(d);
    let hq = d.engine().high_qc().clone();
    let mut refs: Vec<CheckpointRef> = vec![];
    for b in &chain { if let Some(r) = b.checkpoint { if refs.last() != Some(&r) { refs.push(r); } } }
    let mk = |r: CheckpointRef| SeedEvidence { headers: headers_of(&chain), final_qc: Some(hq.clone()), cref: r, high_qc: hq.clone(), high_tc: None };
    let ok: Vec<CheckpointRef> = refs.into_iter().filter(|r| d.engine().authenticate_evidence(&mk(*r)).is_ok()).collect();
    assert!(ok.len() > from_end, "{} authenticating references", ok.len());
    let r = ok[ok.len() - 1 - from_end];
    (mk(r), r)
}
/// The application state a snapshot would carry at `upto`: the interim application after executing the finalized blocks 1..=upto.
fn snapshot_app(d: &Drv, upto: u64) -> MemStorage {
    let mut app = InterimApp::open(mem(), GENESIS_HASH).unwrap();
    for c in d.engine().committed_after(0).into_iter().filter(|c| c.height <= upto) { app.apply(&c).unwrap(); }
    assert_eq!(app.cursor().height, upto);
    app.into_inner()
}
fn store_with(ev: &SeedEvidence) -> BlockStore<MemStorage> {
    let mut bs = BlockStore::new(mem());
    bs.put_seed_evidence(ev.cref.height, &ev.cref.block_id, &ev.encode()).unwrap();
    bs
}
fn replace_file(bs: BlockStore<MemStorage>, name: &str, bytes: &[u8]) -> BlockStore<MemStorage> {
    let mut s = bs.into_inner();
    s.write_tmp("x.tmp", bytes).unwrap(); s.sync_file("x.tmp").unwrap(); s.rename("x.tmp", name).unwrap(); s.sync_dir().unwrap();
    BlockStore::new(s)
}
/// Take node `i` down and bring it back with the given block store and application state (its SafetyStore is kept), under a fresh execution log.
fn reinstall(net: &mut DNet, i: usize, bs: BlockStore<MemStorage>, app: MemStorage, tag: &str) -> Result<(), DriverError> {
    let d = net.nodes[i].take().unwrap();
    let (e, _old_bs, _x) = d.into_parts();
    let e = restart_f(e, i, net.n, &net.cc);
    net.logs[i] = Default::default();
    let (nd, first) = start_node(e, bs, app, &net.logs[i], tag, net.now)?;
    net.nodes[i] = Some(nd);
    net.dead[i] = false;
    net.push(i, first);
    Ok(())
}
fn once_from(net: &DNet, i: usize, base: u64, label: &str) {
    for (k, h) in net.logs[i].borrow().iter().enumerate() { assert_eq!(*h, base + k as u64 + 1, "{label}: node {i} executed height {h} as its {}th block after the checkpoint at {base}", k + 1); }
}

#[test]
fn seed_evidence_round_trips_and_its_decoder_is_strict() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "E", Some(cc));
    run_to(&mut net, 36);
    let (ev, _) = evidence_from(net.nodes[0].as_ref().unwrap(), 0);
    let bytes = ev.encode();
    assert_eq!(SeedEvidence::decode(&bytes, MAX_EVIDENCE_HEADERS).unwrap(), ev);
    // every strict prefix, a flipped byte anywhere, a trailing byte and a bound that is too small are all refused
    for cut in [0usize, 1, 10, 40, bytes.len() / 2, bytes.len() - 33, bytes.len() - 1] { assert!(SeedEvidence::decode(&bytes[..cut], MAX_EVIDENCE_HEADERS).is_err(), "prefix {cut}"); }
    for at in [0usize, 20, 25, 60, bytes.len() / 3, bytes.len() / 2, bytes.len() - 40, bytes.len() - 1] { let mut m = bytes.clone(); m[at] ^= 1; assert!(SeedEvidence::decode(&m, MAX_EVIDENCE_HEADERS).is_err(), "flip {at}"); }
    let mut t = bytes.clone(); t.push(0); assert!(SeedEvidence::decode(&t, MAX_EVIDENCE_HEADERS).is_err());
    // trailing bytes INSIDE a correctly checksummed body (so only the structure check can refuse them)
    let mut body = bytes[..bytes.len() - 32].to_vec(); body.push(0);
    let sum = rcodec::sha3(&[&body]); body.extend_from_slice(&sum);
    assert!(SeedEvidence::decode(&body, MAX_EVIDENCE_HEADERS).is_err(), "trailing bytes inside the checksummed body");
    assert!(SeedEvidence::decode(&bytes, ev.headers.len() - 1).is_err(), "more headers than the caller allows");
}

#[test]
fn the_block_store_keeps_seed_evidence_forward_only_never_falls_back_and_tolerates_the_gap_below_a_checkpoint() {
    let mut bs = BlockStore::new(mem());
    assert_eq!(bs.load_seed_evidence().unwrap(), None);
    bs.put_seed_evidence(8, &[1; 32], b"eight").unwrap();
    bs.put_seed_evidence(8, &[1; 32], b"eight").unwrap(); // idempotent
    assert_eq!(bs.put_seed_evidence(8, &[2; 32], b"eight"), Err(StoreError::SeedEvidenceConflict(8)), "a DIFFERENT block at the same height is a conflict");
    bs.put_seed_evidence(8, &[1; 32], b"eight, fresher").unwrap(); // the same checkpoint with fresher evidence replaces it (a staging that crashed half way can be redone)
    assert_eq!(bs.load_seed_evidence().unwrap(), Some((8, [1; 32], b"eight, fresher".to_vec())));
    bs.put_seed_evidence(8, &[1; 32], b"eight").unwrap();
    bs.put_seed_evidence(16, &[2; 32], b"sixteen").unwrap();
    assert_eq!(bs.put_seed_evidence(8, &[1; 32], b"eight"), Err(StoreError::StaleSeedEvidence { have: 16, got: 8 }), "installs only move forward");
    assert_eq!(bs.load_seed_evidence().unwrap(), Some((16, [2; 32], b"sixteen".to_vec())));
    // commit markers: those at or below the checkpoint are not required (nor reported); the rest must continue from it without a gap
    for h in 1..=20u64 { bs.put_commit(h, &[h as u8; 32]).unwrap(); }
    let l = bs.load().unwrap();
    assert_eq!((l.seeded_height, l.committed.first().map(|c| c.0), l.committed.len()), (16, Some(17), 4));
    let mut gap = BlockStore::new(mem());
    gap.put_seed_evidence(16, &[2; 32], b"x").unwrap();
    gap.put_commit(18, &[1; 32]).unwrap();
    assert_eq!(gap.load().unwrap_err(), StoreError::CommittedHistoryGap(17), "a hole right above the checkpoint is still a hole");
    // a damaged newest record is an error: the older one is NOT substituted
    let dmg = replace_file(bs, &format!("seed-{:020}", 16), b"garbage");
    assert_eq!(dmg.load_seed_evidence().unwrap_err(), StoreError::SeedEvidenceDamaged(16));
}

#[test]
fn evidence_is_authenticated_against_this_nodes_own_genesis_profile_validator_set_and_parameters() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "A", Some(cc));
    run_to(&mut net, 36);
    let (ev, _) = evidence_from(net.nodes[0].as_ref().unwrap(), 0);
    let ok = engine3(3, 4, &cc);
    assert!(ok.authenticate_evidence(&ev).is_ok(), "control: this node's own configuration accepts it");
    // another profile (v2), another genesis hash, other checkpoint parameters: each is refused
    assert!(engine(3, 4).authenticate_evidence(&ev).is_err(), "profile v2");
    let other_genesis = E::new(EngineConfig { genesis_hash: [9; 32], ..cfg3(3, 4, &cc) }, store3(3, faults()), TestSigner::new(4), TestVerifier).unwrap();
    assert!(other_genesis.authenticate_evidence(&ev).is_err(), "another genesis hash");
    assert!(engine3(3, 4, &cc3(4, 16)).authenticate_evidence(&ev).is_err(), "other checkpoint parameters (they are bound into the genesis)");
    assert!(engine3(3, 4, &cc3(8, 16)).authenticate_evidence(&ev).is_err(), "another interval");
    // altered evidence: a header, the named root, the named block, a removed header
    let mut h = ev.clone(); let mid = h.headers.len() / 2; h.headers[mid].payload_hash[0] ^= 1;
    assert!(ok.authenticate_evidence(&h).is_err(), "a forged header");
    let mut r = ev.clone(); r.cref.state_root[0] ^= 1;
    assert!(ok.authenticate_evidence(&r).is_err(), "a root no final header carries");
    let mut b = ev.clone(); b.cref.block_id[0] ^= 1;
    assert!(ok.authenticate_evidence(&b).is_err(), "a block that is not on the chain");
    let mut t = ev.clone(); t.headers.truncate(t.cref.height as usize); t.final_qc = None;
    assert!(ok.authenticate_evidence(&t).is_err(), "too short for the checkpoint to be final");
    assert!(ok.authenticate_evidence(&SeedEvidence { headers: vec![], ..ev.clone() }).is_err(), "no headers");
}

#[test]
fn live_v3_snapshot_recovery_restart_successive_installs_and_agreement_without_duplicate_effects() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "L", Some(cc));
    run_to(&mut net, 40);
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);

    // ---- install A: node 3 loses its blocks and application state (its SafetyStore survives); the state at A is installed and the evidence stored
    let (ev_a, a) = evidence_from(net.nodes[0].as_ref().unwrap(), 1);
    let floor0 = net.nodes[3].as_ref().unwrap().engine().store().record().clone();
    assert!(floor0.hvr.unwrap_or(0) > 0, "node 3 has signed before");
    let app_a = snapshot_app(net.nodes[0].as_ref().unwrap(), a.height);
    reinstall(&mut net, 3, store_with(&ev_a), app_a, "L").expect("start from stored evidence");
    {
        let d = net.nodes[3].as_ref().unwrap();
        assert_eq!(d.engine().base().map(|b| (b.height, b.id)), Some((a.height, a.block_id)), "the base was rebuilt from the evidence");
        assert!(d.engine().is_recovering(), "no blocks above the base yet: recovering");
        assert_eq!(d.engine().store().record(), &floor0, "starting from the checkpoint does not move a single signing floor");
        assert_eq!(d.status().exec.height, a.height);
    }
    // crash while still recovering: the same base comes back
    net.recover(3, None, "L").expect("restart while recovering");
    assert_eq!(net.nodes[3].as_ref().unwrap().engine().base().map(|b| b.id), Some(a.block_id));
    assert_eq!(net.nodes[3].as_ref().unwrap().engine().store().record(), &floor0);
    assert!(net.run_until(6000, |n| n.nodes[3].as_ref().map_or(false, |d| !d.engine().is_recovering() && d.status().exec.height >= a.height + 12)), "node 3 recovers and executes on");
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);
    net.assert_agreement("after install A");
    once_from(&net, 3, a.height, "after install A");
    assert!(net.nodes[3].as_ref().unwrap().engine().store().record().hvr >= floor0.hvr, "floors only moved forward");

    // ---- crash and restart after recovery: same base, committed history and cursor; nothing re-executed
    let before = net.nodes[3].as_ref().unwrap().status().exec;
    let log_len = net.logs[3].borrow().len();
    // the root log's record of the checkpoint is damaged while the node is down: the restart writes the authenticated root again
    let d3 = net.nodes[3].take().unwrap();
    let (e3, bs3, x3) = d3.into_parts();
    let bs3 = replace_file(bs3, &format!("root-{:020}", a.height), b"garbage");
    assert!(bs3.load_roots(4).unwrap().damaged.contains(&a.height));
    let (nd, first) = start_node(restart_f(e3, 3, net.n, &net.cc), bs3, x3.inner.into_inner(), &net.logs[3], "L", net.now).expect("restart after recovery");
    net.nodes[3] = Some(nd); net.push(3, first);
    {
        let d = net.nodes[3].as_ref().unwrap();
        let log = d.block_store().load_roots(4).unwrap();
        assert!(log.damaged.is_empty() && log.roots.get(&a.height) == Some(&a.state_root), "the checkpoint's root was written again");
        assert!(!d.engine().is_recovering(), "with every block already in the store, start itself completes recovery (no tick needed)");
        assert_eq!(d.engine().base().map(|b| b.id), Some(a.block_id));
        assert!(d.status().exec.height >= before.height, "no rewind");
        assert!(d.engine().committed_tip().1 >= before.height);
    }
    assert!(net.run_until(4000, |n| n.height(3) >= before.height + 6 && !n.nodes[3].as_ref().unwrap().engine().is_recovering()));
    assert!(net.logs[3].borrow().len() >= log_len, "the log only grows");
    once_from(&net, 3, a.height, "after restart");
    net.assert_agreement("after restart");

    // ---- node 3 goes away; the network moves on; a NEWER checkpoint B is installed into the SAME block store (evidence A and its old blocks are still in it)
    let floor1 = net.nodes[3].as_ref().unwrap().engine().store().record().clone();
    let (e3, mut bs, _x) = net.nodes[3].take().unwrap().into_parts();
    net.dead[3] = true;
    run_to(&mut net, 84);
    let (ev_b, b) = evidence_from(net.nodes[0].as_ref().unwrap(), 1);
    assert!(b.height > a.height + 20, "the second checkpoint is well beyond the first ({} vs {})", b.height, a.height);
    bs.put_seed_evidence(b.height, &b.block_id, &ev_b.encode()).unwrap();
    assert_eq!(bs.put_seed_evidence(a.height, &a.block_id, &ev_a.encode()), Err(StoreError::StaleSeedEvidence { have: b.height, got: a.height }), "the first checkpoint can never be installed again");
    let app_b = snapshot_app(net.nodes[0].as_ref().unwrap(), b.height);
    net.logs[3] = Default::default();
    let (nd, first) = start_node(restart_f(e3, 3, net.n, &net.cc), bs, app_b, &net.logs[3], "L", net.now).expect("start from the second checkpoint");
    net.nodes[3] = Some(nd); net.dead[3] = false; net.push(3, first);
    {
        let d = net.nodes[3].as_ref().unwrap();
        assert_eq!(d.engine().base().map(|x| (x.height, x.id)), Some((b.height, b.block_id)), "the NEWEST evidence is the base; the older one is history");
        assert!(d.engine().is_recovering());
        assert_eq!(d.engine().store().record(), &floor1, "the second install moves no signing floor either");
        assert_eq!(d.status().exec.height, b.height);
    }
    assert!(net.run_until(8000, |n| n.nodes[3].as_ref().map_or(false, |d| !d.engine().is_recovering() && d.status().exec.height >= b.height + 10)), "node 3 recovers from the second checkpoint");
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);
    net.assert_agreement("after install B");
    once_from(&net, 3, b.height, "after install B");
    // and one more crash and restart on top of the second install
    net.recover(3, None, "L").expect("restart after the second install");
    assert_eq!(net.nodes[3].as_ref().unwrap().engine().base().map(|x| x.id), Some(b.block_id));
    assert!(net.run_until(4000, |n| n.height(3) >= b.height + 16 && !n.nodes[3].as_ref().unwrap().engine().is_recovering()));
    net.assert_agreement("end");
    once_from(&net, 3, b.height, "end");
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);
    let end = net.nodes[3].as_ref().unwrap().engine().store().record();
    assert!(end.hvr >= floor1.hvr && end.hqr >= floor1.hqr && end.counter >= floor1.counter, "floors never went back");
}

#[test]
fn a_start_with_missing_damaged_mismatched_or_unauthentic_evidence_or_a_wrong_executor_state_is_refused() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "R", Some(cc));
    run_to(&mut net, 40);
    let donor = net.nodes[0].as_ref().unwrap();
    let (ev, a) = evidence_from(donor, 1);
    let fresh = || restart_f(engine_f(3, 4, &Some(cc)), 3, 4, &Some(cc));
    let go = |bs: BlockStore<MemStorage>, app: MemStorage| start_node(fresh(), bs, app, &Default::default(), "R", 1).err();
    // control: correct evidence and a matching executor start
    assert!(go(store_with(&ev), snapshot_app(donor, a.height)).is_none(), "control");
    // the executor holds the state at the checkpoint, but there is NO evidence: an unseeded engine behind an executor that is ahead of it must not run
    assert!(matches!(go(BlockStore::new(mem()), snapshot_app(donor, a.height)), Some(DriverError::ExecutorAhead { .. })), "missing evidence");
    // damaged evidence (checksum), and damaged evidence that is re-sealed so the store accepts it but the content is not evidence
    let name = format!("seed-{:020}", a.height);
    assert!(matches!(go(replace_file(store_with(&ev), &name, b"garbage"), snapshot_app(donor, a.height)), Some(DriverError::Store(StoreError::SeedEvidenceDamaged(h))) if h == a.height));
    let mut bs = BlockStore::new(mem());
    bs.put_seed_evidence(a.height, &a.block_id, b"not evidence at all, but sealed by the store").unwrap();
    assert!(matches!(go(bs, snapshot_app(donor, a.height)), Some(DriverError::SeedEvidence(_))), "sealed garbage");
    // evidence whose content is altered and re-encoded properly: it parses, and authentication refuses it
    let mut forged = ev.clone(); let mid = forged.headers.len() / 2; forged.headers[mid].payload_hash[0] ^= 1;
    assert!(matches!(go(store_with(&forged), snapshot_app(donor, a.height)), Some(DriverError::SeedEvidence(m)) if m.contains("header chain")), "forged header");
    let mut wrong_root = ev.clone(); wrong_root.cref.state_root[0] ^= 1;
    assert!(matches!(go(store_with(&wrong_root), snapshot_app(donor, a.height)), Some(DriverError::SeedEvidence(_))), "unattested root");
    // authentic evidence stored under another checkpoint's name: the record and its content disagree
    let (_, other) = evidence_from(donor, 2);
    let mut mism = BlockStore::new(mem());
    mism.put_seed_evidence(other.height, &other.block_id, &ev.encode()).unwrap();
    assert!(matches!(go(mism, snapshot_app(donor, a.height)), Some(DriverError::SeedEvidence(m)) if m.contains("does not describe")), "name and content disagree");
    // the executor at the checkpoint height with the RIGHT state digest but a different block id (the app-state record is re-sealed by hand)
    {
        let mut st = snapshot_app(donor, a.height);
        let mut rec = st.read("app-state").unwrap().unwrap();
        rec[59] ^= 1; // block id, bytes 59..91
        let n = rec.len() - 32;
        let sum = rcodec::sha3(&[&rec[..n]]);
        rec[n..].copy_from_slice(&sum);
        st.write_tmp("app-state.tmp", &rec).unwrap(); st.sync_file("app-state.tmp").unwrap(); st.rename("app-state.tmp", "app-state").unwrap(); st.sync_dir().unwrap();
        assert!(matches!(go(store_with(&ev), st), Some(DriverError::BaseMismatch(_))), "same state digest, different block id at the checkpoint");
    }
    // the executor: behind the checkpoint, at the checkpoint with a different state, and with a different block
    assert!(matches!(go(store_with(&ev), snapshot_app(donor, a.height - 4)), Some(DriverError::ExecutorBehindBase { .. })), "executor behind");
    let mut wrong_state = InterimApp::open(mem(), GENESIS_HASH).unwrap();
    for c in donor.engine().committed_after(0).into_iter().filter(|c| c.height <= a.height) { let mut c = c; if c.height == 3 { c.payload.push(0); } wrong_state.apply(&c).unwrap(); }
    assert!(matches!(go(store_with(&ev), wrong_state.into_inner()), Some(DriverError::BaseMismatch(_))), "executor state differs at the checkpoint");
    // an executor AHEAD of everything this node holds (the blocks above the checkpoint are not in its store) fails closed; an executor ahead on blocks the store does hold is
    // the restart case, covered by the live test
    assert!(matches!(go(store_with(&ev), snapshot_app(donor, a.height + 2)), Some(DriverError::ExecutorAhead { .. })), "executor ahead of the node's own committed history");
}

#[test]
fn a_seeded_node_answers_a_request_below_its_base_explicitly_and_a_receiver_treats_that_as_advice_only() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "B", Some(cc));
    run_to(&mut net, 40);
    let (ev, a) = evidence_from(net.nodes[0].as_ref().unwrap(), 1);
    let app = snapshot_app(net.nodes[0].as_ref().unwrap(), a.height);
    reinstall(&mut net, 3, store_with(&ev), app, "B").unwrap();
    assert!(net.run_until(6000, |n| n.nodes[3].as_ref().map_or(false, |d| !d.engine().is_recovering() && d.status().exec.height >= a.height + 6)));
    let lim = *net.nodes[3].as_ref().unwrap().limits();
    let req = |want: BlockId| net::encode(&NetMsg::SyncRequest(SyncRequest { want, max_blocks: 1 }));
    // asking for the base itself, or for a block just below it: an explicit answer naming the base, with no recovery path on offer
    for want in [a.block_id, ev.headers[(a.height - 2) as usize].id(&idctx3(&set_n(4))).unwrap()] {
        let out = net.nodes[3].as_mut().unwrap().on_bytes(0, &req(want), net.now).unwrap();
        assert_eq!(out.len(), 1);
        match net::decode(&out[0].bytes, &lim).unwrap() {
            NetMsg::SyncBelowBase(r) => assert_eq!(r, BelowBase { want, base_height: a.height, base_id: a.block_id, state_root: a.state_root, recovery_available: false }),
            other => panic!("expected a below-base answer, got {other:?}"),
        }
    }
    assert!(net.nodes[3].as_ref().unwrap().stats().below_base_served >= 2);
    // a block above the base is served as blocks; an unknown block gets no answer
    let above = net.nodes[3].as_ref().unwrap().engine().committed_after(a.height)[0].id;
    let out = net.nodes[3].as_mut().unwrap().on_bytes(0, &req(above), net.now).unwrap();
    assert!(matches!(net::decode(&out[0].bytes, &lim).unwrap(), NetMsg::SyncResponse(_)));
    assert!(net.nodes[3].as_mut().unwrap().on_bytes(0, &req([0xAB; 32]), net.now).unwrap().is_empty());
    // the receiving side: a below-base answer changes nothing but a counter - even a lying one
    let lie = net::encode(&NetMsg::SyncBelowBase(BelowBase { want: [1; 32], base_height: 5, base_id: [2; 32], state_root: [3; 32], recovery_available: true }));
    let d0 = net.nodes[0].as_mut().unwrap();
    let (tip, round) = (d0.engine().committed_tip(), d0.engine().round());
    assert!(d0.on_bytes(3, &lie, net.now).unwrap().is_empty());
    assert_eq!((d0.engine().committed_tip(), d0.engine().round(), d0.stats().below_base_advice), (tip, round, 1));
    // the codec is exact: wrong length, wrong flag
    let mut bad = lie.clone(); bad.push(0);
    assert!(net::decode(&bad, &lim).is_err());
    let mut flag = lie.clone(); *flag.last_mut().unwrap() = 2;
    assert!(net::decode(&flag, &lim).is_err());
    assert!(net::decode(&lie[..lie.len() - 1], &lim).is_err());
}


/// Decode every message a driver emitted and say which kinds of SIGNED consensus message are among them.
fn signed_kinds(lim: &MessageLimits, outs: &[Outbound]) -> Vec<&'static str> {
    outs.iter().filter_map(|o| match net::decode(&o.bytes, lim) {
        Ok(NetMsg::Consensus(Msg::Vote(_))) => Some("vote"),
        Ok(NetMsg::Consensus(Msg::Timeout(_))) => Some("timeout"),
        Ok(NetMsg::Consensus(Msg::Proposal(_))) => Some("proposal"),
        _ => None,
    }).collect()
}

#[test]
fn a_correctly_signed_proposal_with_a_conflicting_root_at_exactly_the_installed_base_height_is_mismatch_evidence_and_is_never_signed_for() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "M", Some(cc));
    run_to(&mut net, 56);
    let donor = net.nodes[0].as_ref().unwrap();
    let chain = drv_chain(donor);
    let id_at = |h: u64| id3(&chain[(h - 1) as usize]);
    // a checkpoint whose FIRST carrier is at least four blocks above it, so a fork from two blocks above it has not yet seen the reference (a new one at that height is legal there)
    let (ev, a) = (0..8).map(|k| evidence_from(donor, k)).find(|(_, a)| chain.iter().find(|b| b.checkpoint == Some(*a)).map_or(false, |c| c.height >= a.height + 4)).expect("a checkpoint with room above it");
    let h = a.height;
    assert!(chain[..(h + 2) as usize].iter().all(|b| b.checkpoint.map_or(true, |r| r.height < h)), "up to the fork point no reference at or above the base height has been carried");

    // a node restarted from stored evidence with every block above the base already in its store: fresh signing floors, executor replayed to the tip, not recovering
    let mut bs = store_with(&ev);
    for b in chain.iter().filter(|b| b.height > h) { bs.put_block(&id3(b), b).unwrap(); }
    let fresh = restart_f(engine_f(3, 4, &Some(cc)), 3, 4, &Some(cc));
    // the executor is THREE BLOCKS BEYOND the base (the restart case): its cursor is not the checkpoint, so the checkpoint's root can only come from the authenticated evidence
    let (mut d, _first) = start_node(fresh, bs, snapshot_app(donor, h + 3), &Default::default(), "M", net.now).expect("start");
    assert!(d.status().exec.height >= h + 3 && h % cc.params.interval == 0);
    assert!(!d.engine().is_recovering(), "every dependency is present: the control below can vote");
    assert_eq!(d.engine().root(h), Some(a.state_root), "the authenticated root of the installed base height is the engine's own record of that height");
    assert!(d.engine().executed_height() >= h, "the executor is at or beyond the base height, so a root at that height is not merely pending");
    let lim = *d.limits();

    // the fork: a SIBLING of the real block at height h+3, extending the real block at height h+2, correctly signed by its round's leader, with a certificate for the parent,
    // a consecutive round, a final-enough F, a fresh-enough and correctly identified NEW reference at exactly the base height - and a WRONG root. Only the root is wrong.
    let parent = &chain[(h + 1) as usize];
    assert_eq!(parent.height, h + 2);
    let round = parent.round + 1;
    let proposer = d.engine().leader_of(round);
    let fork = |root: [u8; 32], payload: &[u8]| sign_block3(Block {
        checkpoint: Some(CheckpointRef { height: h, block_id: id_at(h), state_root: root }),
        epoch: 0, round, height: h + 3, parent_id: id3(parent), qc: chain[(h + 2) as usize].qc.clone(), tc: None, payload: payload.to_vec(), proposer, signature: vec![],
    });
    let mut wrong = a.state_root; wrong[0] ^= 0xFF;
    let bad = fork(wrong, b"fork: wrong root");
    let record_before = d.engine().store().record().clone();
    let deferred_before = d.engine().deferred_len();
    let outs = d.on_bytes(proposer, &net::encode(&NetMsg::Consensus(Msg::Proposal(bad.clone()))), net.now).expect("a bad root is not a driver failure");

    // every validity condition passed: the block is in the tree. Only the voting rule (R5) refused it, and said why.
    assert!(d.engine().known_blocks().iter().any(|b| id3(b) == id3(&bad)), "the proposal was ACCEPTED as valid");
    assert_eq!(d.engine().evidence().last(), Some(&Evidence { block_id: id3(&bad), reference: bad.checkpoint.unwrap(), outcome: RootCheck::Mismatch, own_root: Some(a.state_root) }), "classified Mismatch against the authenticated root, not Unknown");
    assert!(d.engine().alarm().is_none(), "an uncertified mismatch is evidence, not an alarm");
    assert!(signed_kinds(&lim, &outs).is_empty(), "nothing signed was sent: {:?}", signed_kinds(&lim, &outs));
    assert_eq!(d.engine().store().record(), &record_before, "no vote, timeout or proposal signature: the whole SafetyStore record (floors, last vote/timeout/proposal, counter) is unchanged");
    assert_eq!(d.engine().deferred_len(), deferred_before, "and it is not deferred: the root is known, not pending");

    // the matching-root control: the same fork with the authenticated root passes the same checks and IS voted for
    let good = fork(a.state_root, b"fork: right root");
    let evidence_len = d.engine().evidence().len();
    d.on_bytes(proposer, &net::encode(&NetMsg::Consensus(Msg::Proposal(good.clone()))), net.now).unwrap();
    assert!(d.engine().known_blocks().iter().any(|b| id3(b) == id3(&good)));
    assert_eq!(d.engine().evidence().len(), evidence_len, "a matching root is not evidence of anything");
    let rec = d.engine().store().record();
    assert!(rec.hvr == Some(round) && rec.last_vote.is_some(), "the control IS voted for: hvr {:?}", rec.hvr);
    let vote = VoteMessage::decode(&rec.last_vote.as_ref().unwrap().message, ALG).unwrap();
    assert_eq!((vote.round, vote.block_id), (round, id3(&good)), "the vote is for the matching-root proposal, not the conflicting one");
}

#[test]
fn rewriting_an_existing_commit_marker_with_the_same_content_changes_nothing_but_the_number_of_writes() {
    // this demonstrates the ONLY sense in which the "commit marker offset" mutant is equivalent: the extra markers it writes are byte-identical to the ones on disk
    let mut bs = BlockStore::new(mem());
    for h in 1..=6u64 { bs.put_commit(h, &[h as u8; 32]).unwrap(); }
    let snap = |bs: &BlockStore<MemStorage>| -> Vec<(String, Vec<u8>)> {
        let s = bs.storage(); let mut v = vec![];
        for h in 1..=6u64 { let n = format!("cmt-{h:016x}"); v.push((n.clone(), s.read(&n).unwrap().unwrap())); }
        v
    };
    let before = snap(&bs);
    for h in 1..=6u64 { bs.put_commit(h, &[h as u8; 32]).unwrap(); } // the mutant's extra writes
    assert_eq!(snap(&bs), before, "byte-identical files");
    let l = bs.load().unwrap();
    assert_eq!(l.committed, (1..=6u64).map(|h| (h, [h as u8; 32])).collect::<Vec<_>>());
    // NOT shown, and not claimed: that the extra writes cost nothing (each is a write, a sync and a rename), nor what a crash in the middle of one would leave
}

#[test]
fn a_seeded_node_that_restarts_with_every_dependency_present_re_sends_its_stored_vote_byte_for_byte_like_any_restarted_node() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "T", Some(cc));
    run_to(&mut net, 56);
    // a validator whose stored vote goes to ANOTHER node, so that the re-send is a visible message
    let i = (0..4).find(|i| { let d = net.nodes[*i].as_ref().unwrap(); d.engine().store().record().last_vote.as_ref().map_or(false, |v| d.engine().leader_of(v.round + 1) != *i) }).expect("a validator with a stored vote for another leader");
    let (ev, a, chain, app) = {
        let donor = net.nodes[(i + 1) % 4].as_ref().unwrap();
        let (ev, a) = evidence_from(donor, 1);
        (ev, a, drv_chain(donor), snapshot_app(donor, a.height + 3))
    };
    let mut bs = store_with(&ev);
    for b in chain.iter().filter(|b| b.height > a.height) { bs.put_block(&id3(b), b).unwrap(); }
    let (e, _old_bs, _x) = net.nodes[i].take().unwrap().into_parts();
    let record = e.store().record().clone();
    let stored = record.last_vote.clone().unwrap();
    let (d, first) = start_node(restart_f(e, i, 4, &net.cc), bs, app, &Default::default(), "T", net.now).expect("start");
    assert!(!d.engine().is_recovering(), "every dependency is present, so the restart completes recovery");
    let lim = *d.limits();
    let votes: Vec<VoteMsg> = first.iter().filter_map(|o| match net::decode(&o.bytes, &lim) { Ok(NetMsg::Consensus(Msg::Vote(v))) => Some(v), _ => None }).collect();
    assert_eq!(votes.len(), 1, "the stored vote is re-sent at start, exactly as an unseeded restart does");
    assert_eq!(votes[0].msg.encode().unwrap(), stored.message, "byte for byte");
    assert_eq!(votes[0].signature, stored.envelope.signature);
    assert_eq!(d.engine().store().record(), &record, "a re-send signs nothing: the whole safety record is unchanged");
}

#[test]
fn a_seeded_node_installed_far_behind_catches_up_while_the_network_keeps_moving() {
    // REPRODUCTION of a live stall: the victim's evidence is old (the network moved on while it was down) and every round the victim would lead times out while it recovers.
    // Catch-up must still complete: the gap above the base is bigger than one sync window.
    let gap_blocks: u64 = std::env::var("PQ_GAP").ok().and_then(|v| v.parse().ok()).unwrap_or(40);
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "G", Some(cc));
    run_to(&mut net, 44);
    let (ev, a) = evidence_from(net.nodes[0].as_ref().unwrap(), 1);
    let (e3, _old_bs, _x) = net.nodes[3].take().unwrap().into_parts();
    net.dead[3] = true;
    run_to(&mut net, a.height + gap_blocks);
    let app = snapshot_app(net.nodes[0].as_ref().unwrap(), a.height);
    let (nd, first) = start_node(restart_f(e3, 3, 4, &net.cc), store_with(&ev), app, &Default::default(), "G", net.now).expect("start");
    net.nodes[3] = Some(nd); net.dead[3] = false; net.push(3, first);
    let gap = net.height(0) - a.height;
    let mut trace = vec![];
    let mut caught_up = false;
    for chunk in 0..6 { // 3,000 ticks: ample (the fixed code needs a few hundred); the unfixed code made no progress at all in 6,000
        caught_up = net.run_until(500, |n| n.nodes[3].as_ref().map_or(false, |d| !d.engine().is_recovering()) && n.height(3) + 3 >= n.height(0));
        let d = net.nodes[3].as_ref().unwrap(); let e = d.engine();
        trace.push(format!("t{}: committed={} held={} hq={} round={} recovering={} sync_req={} queue={} net_h={}", (chunk + 1) * 500, e.committed_tip().1, e.known_blocks().len(), e.high_qc().round(), e.round(), e.is_recovering(), d.stats().sync_requests, net.q.len(), net.height(0)));
        if caught_up { break; }
    }
    let d = net.nodes[3].as_ref().unwrap(); let e = d.engine();
    assert!(caught_up, "STALL: gap {gap} above the base {}; missing={:?}; stats={:?}\n{}", a.height, e.recovery_missing(), d.stats(), trace.join("\n"));
}
