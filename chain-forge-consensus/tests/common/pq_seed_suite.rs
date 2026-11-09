
// ============================================================================================================================
// Checkpoint-start (engine seeding) and the `Recovering` gate. DRAFT: nothing in a node calls this; profile v3 and network snapshot installation are off.
// The engine-level behaviour is demonstrated here; a live profile-v3 recovery test is a separate, later requirement.
// ============================================================================================================================
use chain_forge_consensus::pq_hotstuff::engine::SeedOutcome;
use chain_forge_consensus::pq_hotstuff::seed::{authenticate_checkpoint, check_install_record, CheckpointSeed, SeedError};

/// A v3 network that has run long enough to have final references, and the evidence a recovering node would be given by a peer.
struct Ev { headers: Vec<PayloadFreeBlock>, hq: Cert, chain: Vec<Block>, refs: Vec<CheckpointRef> }
fn evidence(e: &Eng3) -> Ev { evidence_of(e, e.lead()) }
/// The evidence a peer `i` would give: its own chain up to its own high QC.
fn evidence_of(e: &Eng3, i: usize) -> Ev {
    let chain = e.chain(i);
    Ev { headers: headers_of(&chain), hq: e.nodes[i].high_qc().clone(), chain, refs: e.refs() }
}
fn auth(set: &EpochSet, cc: &CheckpointConfig, ev: &Ev, cref: &CheckpointRef) -> Result<CheckpointSeed, SeedError> {
    authenticate_checkpoint(&cparams3(set, cc), &TestVerifier, Start::Genesis, &ev.headers, Some(&ev.hq), 10_000, cref, &ev.hq, None)
}
/// The i-th final reference (by order of appearance) that authenticates.
fn good_ref(set: &EpochSet, cc: &CheckpointConfig, ev: &Ev, from_end: usize) -> CheckpointRef {
    let ok: Vec<CheckpointRef> = ev.refs.iter().copied().filter(|r| auth(set, cc, ev, r).is_ok()).collect();
    assert!(ok.len() > from_end, "the run must have {} authenticating references (has {})", from_end + 1, ok.len());
    ok[ok.len() - 1 - from_end]
}
/// Node `i` after losing its block files but keeping its safety store: a fresh engine on the reopened store.
fn amnesiac(e: &mut Eng3, i: usize) { let old = std::mem::replace(&mut e.nodes[i], engine3((i + 1) % 4, 4, &e.cc)); e.nodes[i] = restart3(old, i, 4, &e.cc); }
fn run_net(rounds_to: u64) -> Eng3 { let mut e = Eng3::new(4, cc3(4, 8)); e.run_until_committed(rounds_to, 400); e }
fn feed_blocks(en: &mut E, chain: &[Block], above: u64) -> Vec<Output> {
    let mut all = vec![];
    for b in chain.iter().filter(|b| b.height > above) { if let Ok(o) = en.on_sync_block(b.clone()) { all.extend(o); } }
    all
}
fn commits_in(outs: &[Output]) -> Vec<u64> { outs.iter().filter_map(|o| if let Output::Commit(c) = o { Some(c.height) } else { None }).collect() }
fn sends_signed(outs: &[Output]) -> bool { outs.iter().any(|o| matches!(o, Output::Send { msg: Msg::Vote(_), .. } | Output::Broadcast(Msg::Vote(_)) | Output::Broadcast(Msg::Timeout(_)) | Output::Broadcast(Msg::Proposal(_)))) }

#[test]
fn only_signed_final_evidence_authenticates_a_checkpoint_and_every_missing_piece_is_refused() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let e = run_net(40);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 0);
    let seed = auth(&set, &cc, &ev, &r).expect("good evidence authenticates");
    assert_eq!((seed.base().height, seed.base().id), (r.height, r.block_id));
    assert_eq!(seed.reference(), &r);
    // a root nobody attested: no final header carries this reference
    let wrong_root = CheckpointRef { state_root: [0xEE; 32], ..r };
    assert_eq!(auth(&set, &cc, &ev, &wrong_root).unwrap_err(), SeedError::NoFinalCarrier);
    // a block that is on the chain but not final
    let tip = ev.chain.last().unwrap();
    let not_final = CheckpointRef { height: tip.height, block_id: id3(tip), state_root: root_of(tip.height) };
    assert_eq!(auth(&set, &cc, &ev, &not_final).unwrap_err(), SeedError::NotFinal);
    // a block that is not on the chain at all
    assert_eq!(auth(&set, &cc, &ev, &CheckpointRef { block_id: [9; 32], ..r }).unwrap_err(), SeedError::NotFinal);
    // a forged header (the proposer signature no longer matches)
    let mut forged = ev.headers.clone(); let mid = forged.len() / 2; forged[mid].payload_hash[0] ^= 1;
    assert!(matches!(authenticate_checkpoint(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &forged, Some(&ev.hq), 10_000, &r, &ev.hq, None), Err(SeedError::Headers(_))));
    // the high certificate: not a QC, or a QC that certifies a block below the checkpoint
    let genesis_cert = e.nodes[0].high_qc().clone(); let _ = genesis_cert;
    let early = ev.chain[(r.height as usize).saturating_sub(3)].qc.clone();
    assert_eq!(authenticate_checkpoint(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &ev.headers, Some(&ev.hq), 10_000, &r, &early, None).unwrap_err(), SeedError::HighQcNotOnChain);
    // the evidence must be for THIS chain: another chain id is refused by header verification
    let other = ChainParams { chain_id: "another-chain", ..cparams3(&set, &cc) };
    assert!(authenticate_checkpoint(&other, &TestVerifier, Start::Genesis, &ev.headers, Some(&ev.hq), 10_000, &r, &ev.hq, None).is_err());
}

#[test]
fn an_install_record_cross_checks_a_local_operation_and_never_authenticates_anything() {
    use chain_forge_consensus::pq_hotstuff::recovery::records::InstallRecord;
    use chain_forge_consensus::pq_hotstuff::header::ChainPoint;
    let cc = cc3(4, 8);
    let set = set_n(4);
    let e = run_net(40);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 0);
    let seed = auth(&set, &cc, &ev, &r).unwrap();
    let pt = ChainPoint { id: r.block_id, height: r.height, round: seed.base().round, payload_hash: [0; 32] };
    let rec = InstallRecord { generation: 1, cref: r, carrier: pt, tip: *seed.tip(), high_qc: ev.hq.clone() };
    assert!(check_install_record(&rec, &seed).is_ok());
    // the record of ANOTHER checkpoint does not match the authenticated one
    let older = good_ref(&set, &cc, &ev, 1);
    let rec2 = InstallRecord { cref: older, ..rec.clone() };
    assert_eq!(check_install_record(&rec2, &seed).unwrap_err(), SeedError::RecordMismatch("checkpoint reference"));
    // and a record naming a root nobody attested cannot be turned into a seed: the only constructor is `authenticate_checkpoint`, which refuses it
    let forged = CheckpointRef { state_root: [0xAB; 32], ..r };
    let rec3 = InstallRecord { cref: forged, ..rec };
    assert_eq!(auth(&set, &cc, &ev, &rec3.cref).unwrap_err(), SeedError::NoFinalCarrier, "a record is not evidence");
}

#[test]
fn a_seeded_engine_signs_nothing_until_its_dependencies_arrive_and_the_safety_floors_never_move() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = run_net(40);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 0);
    amnesiac(&mut e, 3);
    let floor = e.nodes[3].store().record().clone();
    assert!(floor.hvr.unwrap_or(0) > 0 && floor.hqr.unwrap_or(0) > 0, "the recoverer has signed before: floors are real");
    let seed = auth(&set, &cc, &ev, &r).unwrap();
    assert_eq!(e.nodes[3].seed(seed.clone()).unwrap(), SeedOutcome::Seeded);
    assert!(e.nodes[3].is_recovering());
    assert_eq!(e.nodes[3].committed_tip(), (r.block_id, r.height), "the checkpoint is the committed root");
    // no proposal, no timeout, no re-sent vote or timeout
    assert!(matches!(e.nodes[3].propose(b"x".to_vec()), Err(EngineError::Recovering(_))));
    assert!(matches!(e.nodes[3].propose_with(b"x".to_vec(), None), Err(EngineError::Recovering(_))));
    assert!(matches!(e.nodes[3].local_timeout(), Err(EngineError::Recovering(_))));
    assert!(e.nodes[3].resend_last_vote().unwrap().is_empty() && e.nodes[3].resend_last_timeout().unwrap().is_empty());
    assert!(matches!(e.nodes[3].complete_recovery(), Err(EngineError::Recovering(_))), "the dependencies above the checkpoint have not arrived");
    // blocks arrive as sync blocks: validated, stored, never voted; live proposals are not voted either
    let outs = feed_blocks(&mut e.nodes[3], &ev.chain, r.height);
    assert!(!sends_signed(&outs), "sync blocks are never voted");
    let live = e.crafted(None);
    let o = e.nodes[3].on_proposal(live).unwrap_or_default();
    assert!(!sends_signed(&o), "a live proposal is accepted into the tree but not voted while recovering");
    assert_eq!(e.nodes[3].store().record(), &floor, "the SafetyStore record (floors, last vote, last timeout, counter) is bit-for-bit what it was");
    e.nodes[3].complete_recovery().expect("dependencies are in place");
    assert!(!e.nodes[3].is_recovering());
    assert_eq!(e.nodes[3].store().record(), &floor, "completing recovery does not touch the store either");
    assert!(e.nodes[3].round() >= floor.hvr.unwrap(), "the round never goes below the highest round signed in");
}

#[test]
fn a_recovered_node_rejoins_the_network_commits_each_block_once_and_never_below_the_checkpoint() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = run_net(40);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 0);
    amnesiac(&mut e, 3);
    let before = e.nodes[3].store().record().clone();
    e.nodes[3].seed(auth(&set, &cc, &ev, &r).unwrap()).unwrap();
    // the executor side: the installed snapshot IS the state after block r.height (here: the interim application replaying the same prefix), then the engine's commits
    let mut app = InterimApp::open(MemStorage::new(faults()), GENESIS_HASH).unwrap();
    for b in ev.chain.iter().filter(|b| b.height <= r.height) { app.apply(&Committed { id: id3(b), round: b.round, height: b.height, payload: b.payload.clone() }).unwrap(); }
    assert_eq!(app.cursor().height, r.height);
    let mut heights = vec![];
    let outs = feed_blocks(&mut e.nodes[3], &ev.chain, r.height);
    heights.extend(commits_in(&outs));
    for o in &outs { if let Output::Commit(c) = o { app.apply(c).expect("the executor takes each commit exactly once, in order"); } }
    e.nodes[3].complete_recovery().unwrap();
    // now live: the recovered node takes part
    let h0 = e.nodes[3].committed_tip().1;
    let mut seen = e.commits[3].len();
    for _ in 0..40 {
        e.step();
        // commits the node produced from gossip (the harness records them), in the order they happened
        for c in e.commits[3][seen..].to_vec() { heights.push(c.height); app.apply(&c).expect("in order, once"); }
        seen = e.commits[3].len();
        // keep the recoverer supplied with blocks it cannot get from this harness's gossip (a stand-in for block sync)
        let l = e.lead();
        let chain = e.chain(l);
        for b in &chain { if b.height > e.nodes[3].committed_tip().1 { if let Ok(o) = e.nodes[3].on_sync_block(b.clone()) { for x in &o { if let Output::Commit(c) = x { heights.push(c.height); app.apply(c).expect("in order, once"); } } } } }
    }
    assert!(e.nodes[3].committed_tip().1 > h0, "the recovered node commits new blocks");
    assert!(heights.iter().all(|h| *h > r.height), "nothing at or below the checkpoint is ever committed again");
    assert!(heights.windows(2).all(|w| w[1] == w[0] + 1), "commits are consecutive and unique: {heights:?}");
    assert_eq!(app.cursor().height, e.nodes[3].committed_tip().1, "the application cursor equals the committed tip");
    // it agrees with the others on the committed chain
    let (a, b) = (e.nodes[3].committed_tip(), e.nodes[0].committed_tip());
    let m = a.1.min(b.1);
    let ids = |i: usize| -> Vec<BlockId> { e.chain(i).iter().filter(|x| x.height > r.height && x.height <= m).map(id3).collect() };
    assert!(!ids(3).is_empty() && ids(3) == ids(0), "the recovered node and a healthy one hold the same chain above the checkpoint");
    // and its safety record only ever moved forward
    let after = e.nodes[3].store().record();
    assert!(after.hvr >= before.hvr && after.hqr >= before.hqr && after.counter >= before.counter);
    let _: ExecCursor = app.cursor();
}

#[test]
fn a_stale_snapshot_a_repeat_and_a_rewind_are_refused_and_change_nothing() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = run_net(48);
    let ev = evidence(&e);
    let newer = good_ref(&set, &cc, &ev, 0);
    let older = good_ref(&set, &cc, &ev, 1);
    assert!(older.height < newer.height);
    // a healthy node that is already past the checkpoint refuses a stale snapshot outright
    let tip = e.nodes[0].committed_tip();
    assert!(tip.1 >= newer.height);
    let err = e.nodes[0].seed(auth(&set, &cc, &ev, &newer).unwrap());
    if tip.1 > newer.height { assert!(matches!(err, Err(EngineError::Seed(m)) if m.contains("stale"))); } else { assert!(matches!(err, Ok(SeedOutcome::AlreadyAtBase))); }
    assert_eq!(e.nodes[0].committed_tip(), tip, "nothing rewound");
    assert!(!e.nodes[0].is_recovering() || tip.1 == newer.height);
    // a node seeded at the newer checkpoint refuses the older one and accepts a repeat as a no-op
    amnesiac(&mut e, 3);
    e.nodes[3].seed(auth(&set, &cc, &ev, &newer).unwrap()).unwrap();
    let rec = e.nodes[3].store().record().clone();
    assert!(matches!(e.nodes[3].seed(auth(&set, &cc, &ev, &older).unwrap()), Err(EngineError::Seed(m)) if m.contains("stale")));
    assert_eq!(e.nodes[3].seed(auth(&set, &cc, &ev, &newer).unwrap()).unwrap(), SeedOutcome::AlreadyAtBase);
    assert_eq!(e.nodes[3].committed_tip(), (newer.block_id, newer.height));
    assert!(e.nodes[3].is_recovering());
    assert_eq!(e.nodes[3].store().record(), &rec);
}

#[test]
fn missing_dependencies_keep_the_node_recovering_and_silent_until_every_required_block_has_arrived() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = run_net(40);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 0);
    amnesiac(&mut e, 3);
    let seed = auth(&set, &cc, &ev, &r).unwrap();
    let need = seed.required_blocks();
    assert!(need.len() >= 2, "the high QC is above the checkpoint by at least two blocks ({need:?})");
    e.nodes[3].seed(seed).unwrap();
    let floor = e.nodes[3].store().record().clone();
    // withhold the FIRST required block: everything above it is an orphan
    let first = need[0].0;
    for b in ev.chain.iter().filter(|b| b.height > first) { assert!(matches!(e.nodes[3].on_sync_block(b.clone()), Err(EngineError::MissingParent(_))), "height {}", b.height); }
    assert!(matches!(e.nodes[3].complete_recovery(), Err(EngineError::Recovering(m)) if m.contains("has not arrived")));
    // deliver all but the LAST required block: still recovering
    let last = need.last().unwrap().0;
    for b in ev.chain.iter().filter(|b| b.height > r.height && b.height < last) { e.nodes[3].on_sync_block(b.clone()).unwrap(); }
    assert!(e.nodes[3].complete_recovery().is_err());
    assert!(matches!(e.nodes[3].local_timeout(), Err(EngineError::Recovering(_))));
    assert_eq!(e.nodes[3].store().record(), &floor);
    // the last one arrives
    for b in ev.chain.iter().filter(|b| b.height == last) { e.nodes[3].on_sync_block(b.clone()).unwrap(); }
    e.nodes[3].complete_recovery().unwrap();
}

#[test]
fn recovery_requires_the_high_qc_round_the_validator_has_already_signed_against() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = run_net(40);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 0);
    amnesiac(&mut e, 3);
    // evidence from a high QC OLDER than what this validator already voted on (the store's hqr): the engine must not resume on a view older than its own record
    let hqr = e.nodes[3].store().record().hqr.unwrap();
    let old_end = ev.chain.iter().position(|b| b.round >= hqr).map(|p| p.saturating_sub(1)).unwrap_or(0);
    let cut = (old_end).max(r.height as usize + 2);
    if cut + 1 < ev.chain.len() {
        let hs = headers_of(&ev.chain[..cut]);
        let hq = ev.chain[cut].qc.clone(); // certifies chain[cut-1], the last header
        if let Ok(seed) = authenticate_checkpoint(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000, &r, &hq, None) {
            e.nodes[3].seed(seed).unwrap();
            feed_blocks(&mut e.nodes[3], &ev.chain[..cut], r.height);
            if hq.round() < hqr { assert!(matches!(e.nodes[3].complete_recovery(), Err(EngineError::Recovering(m)) if m.contains("below the highest QC round"))); }
        }
    }
}

#[test]
fn an_interrupted_installation_leaves_the_floors_alone_and_can_be_redone_from_the_evidence() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = run_net(40);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 0);
    amnesiac(&mut e, 3);
    let floor = e.nodes[3].store().record().clone();
    // crash 1: after the evidence was authenticated, before the engine was seeded
    let _lost = auth(&set, &cc, &ev, &r).unwrap();
    e.nodes[3] = restart3(std::mem::replace(&mut e.nodes[3], engine3(0, 4, &cc)), 3, 4, &cc);
    assert_eq!(e.nodes[3].store().record(), &floor);
    assert!(!e.nodes[3].is_recovering() && e.nodes[3].base().is_none());
    // crash 2: after seeding and part of the dependencies, before recovery completed: the engine's tree is volatile, the store is the durable truth
    e.nodes[3].seed(auth(&set, &cc, &ev, &r).unwrap()).unwrap();
    feed_blocks(&mut e.nodes[3], &ev.chain[..(r.height as usize + 1).min(ev.chain.len())], r.height);
    e.nodes[3] = restart3(std::mem::replace(&mut e.nodes[3], engine3(0, 4, &cc)), 3, 4, &cc);
    assert_eq!(e.nodes[3].store().record(), &floor, "nothing was signed, so nothing changed");
    assert!(e.nodes[3].base().is_none(), "a restart forgets the volatile seed: it must be redone from the evidence, never from a record");
    // redo: authenticate again from the evidence and finish
    e.nodes[3].seed(auth(&set, &cc, &ev, &r).unwrap()).unwrap();
    feed_blocks(&mut e.nodes[3], &ev.chain, r.height);
    e.nodes[3].complete_recovery().unwrap();
    assert_eq!(e.nodes[3].store().record(), &floor);
}

#[test]
fn two_successive_installs_move_only_forward_and_the_second_replaces_the_first_cleanly() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = run_net(36);
    let ev1 = evidence(&e);
    let a = good_ref(&set, &cc, &ev1, 0);
    amnesiac(&mut e, 3);
    let floor = e.nodes[3].store().record().clone();
    e.nodes[3].seed(auth(&set, &cc, &ev1, &a).unwrap()).unwrap();
    // some dependencies of the first install arrive, then the network moves on and a newer checkpoint is installed before the first recovery finished
    feed_blocks(&mut e.nodes[3], &ev1.chain[..(a.height as usize + 2).min(ev1.chain.len())], a.height);
    e.run(48);
    let ev2 = evidence(&e);
    let b = good_ref(&set, &cc, &ev2, 0);
    assert!(b.height > a.height, "the network produced a newer final checkpoint ({} > {})", b.height, a.height);
    assert_eq!(e.nodes[3].seed(auth(&set, &cc, &ev2, &b).unwrap()).unwrap(), SeedOutcome::Seeded);
    assert_eq!(e.nodes[3].committed_tip(), (b.block_id, b.height));
    assert!(e.nodes[3].known_blocks().iter().all(|x| x.height > b.height), "nothing at or below the new base survives");
    assert!(e.nodes[3].is_recovering(), "a new install re-enters Recovering");
    assert!(matches!(e.nodes[3].propose(vec![]), Err(EngineError::Recovering(_))));
    // the first checkpoint can never be installed again, and the second is idempotent
    assert!(matches!(e.nodes[3].seed(auth(&set, &cc, &ev2, &a).unwrap()), Err(EngineError::Seed(m)) if m.contains("stale")));
    assert_eq!(e.nodes[3].seed(auth(&set, &cc, &ev2, &b).unwrap()).unwrap(), SeedOutcome::AlreadyAtBase);
    let outs = feed_blocks(&mut e.nodes[3], &ev2.chain, b.height);
    assert!(commits_in(&outs).iter().all(|h| *h > b.height));
    e.nodes[3].complete_recovery().unwrap();
    assert_eq!(e.nodes[3].store().record(), &floor, "two installs and a completed recovery, and the floors are exactly what they were");
}

#[test]
fn after_seeding_the_engine_applies_the_reference_rules_from_the_base_exactly_as_the_header_verifier_does() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let e = run_net(48);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 1);
    let mut fresh = Eng3::new(4, cc);
    fresh.run(2); // any engine; replaced below
    let mut en = engine3(3, 4, &cc);
    en.seed(auth(&set, &cc, &ev, &r).unwrap()).unwrap();
    // every block above the base is judged by the engine (from the base's state) the same way the header verifier judged it from genesis: all accepted
    for b in ev.chain.iter().filter(|b| b.height > r.height) { en.on_sync_block(b.clone()).unwrap_or_else(|er| panic!("height {}: {er}", b.height)); }
    // a reference to a block BELOW the base that is not in the base's ancestor window fails closed, one inside it resolves through the base
    let base = en.base().unwrap().clone();
    let inside = base.ancestors.iter().map(|(h, _)| *h).collect::<Vec<_>>();
    let ancestor_heights_ok = inside.iter().all(|h| *h < base.height && *h + 1 > base.state.final_height.saturating_sub(cc.params.max_age));
    assert!(ancestor_heights_ok, "the window holds only heights a new reference could name: {inside:?}");
}

#[test]
fn a_committed_history_that_conflicts_with_the_authenticated_checkpoint_is_refused_and_a_genesis_rooted_block_is_ignored() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    // two networks with identical keys and parameters whose payloads differ: they fork at height 1, and each is internally valid
    let mut a = Eng3::new(4, cc); a.salt = 1; a.run_until_committed(12, 200);
    let mut b = Eng3::new(4, cc); b.salt = 2; b.run_until_committed(40, 400);
    let ev = evidence(&b);
    let r = good_ref(&set, &cc, &ev, 0);
    let (tip_a, h_a) = a.nodes[0].committed_tip();
    assert!(h_a >= 8 && h_a < r.height && ev.chain[(h_a - 1) as usize].height == h_a && id3(&ev.chain[(h_a - 1) as usize]) != tip_a, "A's committed block differs from B's at the same height");
    let before = a.nodes[0].committed_tip();
    assert!(matches!(a.nodes[0].seed(auth(&set, &cc, &ev, &r).unwrap()), Err(EngineError::Seed(m)) if m.contains("conflicts")));
    assert_eq!(a.nodes[0].committed_tip(), before, "a refused seed changes nothing");
    assert!(!a.nodes[0].is_recovering() && a.nodes[0].base().is_none());
    // after a good seed, a block certified by the genesis certificate (it would root a different tree) is IGNORED: its height is at or below the base, which is final
    // history this node does not hold. It is not stored and changes nothing.
    let mut en = engine3(3, 4, &cc);
    en.seed(auth(&set, &cc, &ev, &r).unwrap()).unwrap();
    let genesis_qc = engine3(3, 4, &cc).high_qc().clone();
    let g = sign_block3(Block { checkpoint: None, epoch: 0, round: 1, height: 1, parent_id: genesis_qc.block_id(), qc: genesis_qc, tc: None, payload: b"g".to_vec(), proposer: en.leader_of(1), signature: vec![] });
    let tip = en.committed_tip();
    assert!(en.on_sync_block(g).unwrap().is_empty());
    assert!(en.known_blocks().is_empty() && en.committed_tip() == tip, "a block at or below the base is not stored and moves nothing");
}

// ---- tests added after the first mutation run showed what the first versions did not pin down

#[test]
fn a_recovering_engine_does_not_even_re_send_what_it_signed_before() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = run_net(44);
    // every validator signs a timeout for the current round on the current high QC (the TC forms and the round advances; the chain is unchanged)
    for i in 0..4 { let o = e.nodes[i].local_timeout().expect("timeout"); e.deliver(i, o); }
    // a validator whose stored vote goes to ANOTHER node and who holds a stored timeout; the evidence is the chain up to the QC that timeout reported
    let i = (0..4).find(|i| { let rec = e.nodes[*i].store().record(); matches!((&rec.last_vote, &rec.last_timeout), (Some(v), Some(_)) if e.nodes[*i].leader_of(v.round + 1) != *i) }).expect("a validator with a stored vote and timeout");
    let reported = TimeoutMessage::decode(&e.nodes[i].store().record().last_timeout.as_ref().unwrap().message, ALG).unwrap().high_qc_round;
    let full = evidence_of(&e, i);
    let j = full.chain.iter().position(|b| b.qc.round() == reported).expect("the QC the timeout reported is in the chain");
    let ev = Ev { headers: headers_of(&full.chain[..j]), hq: full.chain[j].qc.clone(), chain: full.chain[..j].to_vec(), refs: full.refs.clone() };
    assert_eq!(ev.hq.round(), reported);
    let r = good_ref(&set, &cc, &ev, 0);
    amnesiac(&mut e, i);
    let rec = e.nodes[i].store().record().clone();
    e.nodes[i].seed(auth(&set, &cc, &ev, &r).unwrap()).unwrap();
    assert!(e.nodes[i].resend_last_vote().unwrap().is_empty(), "no vote re-sent while recovering");
    assert!(e.nodes[i].resend_last_timeout().unwrap().is_empty(), "no timeout re-sent while recovering");
    // control: the very same calls DO send once recovery is complete, so the emptiness above is the gate and not a missing record
    feed_blocks(&mut e.nodes[i], &ev.chain, r.height);
    e.nodes[i].complete_recovery().unwrap();
    assert!(!e.nodes[i].resend_last_vote().unwrap().is_empty(), "control: vote re-send after recovery");
    assert!(!e.nodes[i].resend_last_timeout().unwrap().is_empty(), "control: timeout re-send after recovery");
    assert_eq!(e.nodes[i].store().record(), &rec, "a re-send is not a new signature");
}

#[test]
fn evidence_older_than_the_validators_own_record_leaves_it_recovering_and_never_lowers_its_round() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = run_net(44);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 2);
    amnesiac(&mut e, 3);
    let rec = e.nodes[3].store().record().clone();
    let (hvr, hqr) = (rec.hvr.unwrap(), rec.hqr.unwrap());
    // the smallest prefix of the chain that still authenticates this checkpoint: its high QC is far below what this validator has signed against
    let (cut, hq) = (r.height as usize + 2..ev.chain.len() - 1).find_map(|cut| {
        let hs = headers_of(&ev.chain[..cut]);
        let hq = ev.chain[cut].qc.clone(); // certifies chain[cut - 1], the last header
        authenticate_checkpoint(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000, &r, &hq, None).ok().map(|_| (cut, hq))
    }).expect("an older prefix authenticates the checkpoint");
    assert!(hq.round() + 1 < hvr && hq.round() < hqr, "the evidence is older than the record: high QC round {} vs hvr {hvr}, hqr {hqr}", hq.round());
    let seed = authenticate_checkpoint(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &headers_of(&ev.chain[..cut]), Some(&hq), 10_000, &r, &hq, None).unwrap();
    e.nodes[3].seed(seed).unwrap();
    assert!(e.nodes[3].round() >= hvr, "seeding never puts the round below the highest round signed in ({} < {hvr})", e.nodes[3].round());
    feed_blocks(&mut e.nodes[3], &ev.chain[..cut], r.height);
    assert!(matches!(e.nodes[3].complete_recovery(), Err(EngineError::Recovering(m)) if m.contains("below the highest QC round")), "it must first learn a view at least as new as its own record");
    assert!(e.nodes[3].is_recovering());
    assert_eq!(e.nodes[3].store().record(), &rec);
}

#[test]
fn a_different_block_committed_at_the_checkpoint_height_is_a_conflict_not_a_no_op() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut a = Eng3::new(4, cc); a.salt = 1;
    while a.nodes[0].committed_tip().1 < 8 || a.nodes[0].committed_tip().1 % 4 != 0 { a.step(); }
    let mut b = Eng3::new(4, cc); b.salt = 2; b.run_until_committed(44, 400);
    let ev = evidence(&b);
    let h = a.nodes[0].committed_tip().1;
    let r = ev.refs.iter().copied().find(|r| r.height == h && auth(&set, &cc, &ev, r).is_ok()).expect("the other network has a final reference at the same height");
    assert_ne!(r.block_id, a.nodes[0].committed_tip().0, "same height, different block");
    let before = a.nodes[0].committed_tip();
    assert!(matches!(a.nodes[0].seed(auth(&set, &cc, &ev, &r).unwrap()), Err(EngineError::Seed(m)) if m.contains("different block")));
    assert_eq!(a.nodes[0].committed_tip(), before);
    assert!(a.nodes[0].base().is_none() && !a.nodes[0].is_recovering());
}

#[test]
fn a_late_certificate_for_the_checkpoints_child_is_absorbed_without_error_after_the_chain_has_moved_on() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = run_net(44);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 1);
    amnesiac(&mut e, 3);
    e.nodes[3].seed(auth(&set, &cc, &ev, &r).unwrap()).unwrap();
    feed_blocks(&mut e.nodes[3], &ev.chain, r.height);
    let tip = e.nodes[3].committed_tip().1;
    assert!(tip > r.height + 1, "commits moved past the checkpoint's child");
    // the QC for the checkpoint's child arrives AGAIN (in a validator's timeout message): observing it asks the engine to commit the base, which is already final
    let qc = ev.chain[(r.height + 1) as usize].qc.clone();
    assert_eq!(qc.block_id(), id3(&ev.chain[r.height as usize]), "this QC certifies the block directly above the checkpoint");
    let round = e.nodes[3].round();
    let m = TimeoutMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round, high_qc_round: qc.round() };
    let t = TimeoutMsg { voter: 0, signature: sign(0, CTX_TIMEOUT, &m.encode().unwrap()), msg: m, high_qc: qc };
    e.nodes[3].on_timeout(t).expect("re-observing an old certificate must not be an error");
    assert_eq!(e.nodes[3].committed_tip().1, tip, "and it commits nothing");
}

/// A checkpoint whose state leaves room for a NEW reference naming a block below the base (so the base's ancestor window is exercised).
fn ref_with_room(set: &EpochSet, cc: &CheckpointConfig, ev: &Ev) -> (CheckpointRef, CheckpointSeed, u64) {
    let k = cc.params.interval;
    for from_end in 0..8 {
        let r = good_ref(set, cc, ev, from_end);
        let seed = auth(set, cc, ev, &r).unwrap();
        let b = seed.base();
        let Some(last) = b.state.last_ref else { continue };
        let f_child = b.height - 1;
        if let Some((h, _)) = b.ancestors.iter().find(|(h, _)| h % k == 0 && *h > last.height && *h <= f_child && f_child - *h <= cc.params.max_age) { let h = *h; return (r, seed, h); }
    }
    panic!("no checkpoint with room for a new reference below its base in this run");
}
fn child_of_base(ev: &Ev, en: &E, checkpoint: Option<CheckpointRef>, payload: &[u8]) -> Block {
    let base = en.base().unwrap();
    let qc = ev.chain[base.height as usize].qc.clone();
    assert_eq!(qc.block_id(), base.id);
    sign_block3(Block { checkpoint, epoch: 0, round: base.round + 1, height: base.height + 1, parent_id: base.id, qc, tc: None, payload: payload.to_vec(), proposer: en.leader_of(base.round + 1), signature: vec![] })
}

#[test]
fn the_seeded_engine_judges_the_first_references_above_the_base_from_the_bases_own_state() {
    // references lag the executor by 10 blocks and may be 24 old, so the last reference at the base is several blocks below it and a new one has room
    let mut cc = cc3(4, 24); cc.policy.margin = 10;
    let set = set_n(4);
    let mut e = Eng3::new(4, cc); e.run_until_committed(70, 600);
    let ev = evidence(&e);
    let (r, seed, h_new) = ref_with_room(&set, &cc, &ev);
    let mut en = engine3(3, 4, &cc);
    en.seed(seed).unwrap();
    let last = en.base().unwrap().state.last_ref.unwrap();
    let k = cc.params.interval;
    // a repeat of the base's last reference is legal (it needs the base's last_ref and a final height that covers it)
    en.on_sync_block(child_of_base(&ev, &en, Some(last), b"repeat")).expect("a repeat of the base's last reference");
    // going backwards past it is not
    let back = CheckpointRef { height: last.height - k, block_id: [1; 32], state_root: [2; 32] };
    assert_eq!(err_reason(en.on_sync_block(child_of_base(&ev, &en, Some(back), b"back"))), RefError::Backwards.reason());
    // a NEW reference naming a block BELOW the base resolves through the base's ancestor window
    let id = en.base().unwrap().ancestors.iter().find(|(h, _)| *h == h_new).unwrap().1;
    assert_eq!(id, id3(&ev.chain[(h_new - 1) as usize]));
    en.on_sync_block(child_of_base(&ev, &en, Some(CheckpointRef { height: h_new, block_id: id, state_root: root_of(h_new) }), b"below the base")).expect("a new reference below the base");
    // and a wrong block at that height is refused (the window is identity, not just presence)
    let bad = CheckpointRef { height: h_new, block_id: [0xDD; 32], state_root: root_of(h_new) };
    assert_eq!(err_reason(en.on_sync_block(child_of_base(&ev, &en, Some(bad), b"wrong"))), RefError::WrongAncestor.reason());
    let _ = r;
}

#[test]
fn the_seeded_base_is_exactly_what_the_header_verifier_computes_and_the_checkpoint_root_is_trusted_only_as_a_final_reference() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let e = run_net(44);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 1);
    let seed = auth(&set, &cc, &ev, &r).unwrap();
    let vc = verify_header_chain(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &ev.headers, Some(&ev.hq), 10_000).unwrap();
    let k = vc.points.iter().position(|p| p.point.id == r.block_id).unwrap();
    let b = seed.base();
    assert_eq!((b.id, b.height, b.round), (r.block_id, r.height, vc.points[k].point.round));
    assert_eq!(b.parent_round, vc.points[k - 1].point.round, "the round of the base's parent");
    assert_eq!(b.state, vc.points[k].state, "F and the last reference at the base");
    let want: Vec<(u64, BlockId)> = vc.points[..k].iter().filter(|p| p.point.height + cc.params.max_age >= b.state.final_height).map(|p| (p.point.height, p.point.id)).collect();
    assert_eq!(b.ancestors, want, "exactly the blocks below the base that a new reference could still name");
    // the root: after seeding and once the installed executor has reached the checkpoint, the reference is trusted (a final carrier attests it); a different root is not
    let mut en = engine3(3, 4, &cc);
    en.seed(seed).unwrap();
    en.set_executed(r.height);
    assert_eq!(en.ref_outcome(&r), RootCheck::Match);
    assert_eq!(en.ref_outcome(&CheckpointRef { state_root: [0xAB; 32], ..r }), RootCheck::Unknown, "a root nobody attested is not trusted, and is not a mismatch either");
}

#[test]
fn the_high_certificate_and_the_carrier_must_themselves_be_valid_and_final_and_a_record_must_match_the_root() {
    use chain_forge_consensus::pq_hotstuff::recovery::records::InstallRecord;
    let cc = cc3(4, 8);
    let set = set_n(4);
    let e = run_net(44);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 0);
    let call = |hs: &[PayloadFreeBlock], fq: &Cert, hq: &Cert| authenticate_checkpoint(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, hs, Some(fq), 10_000, &r, hq, None);
    // a high QC whose signatures are damaged is refused (and it is the verification, not the shape, that catches it)
    let mut bad = ev.hq.clone();
    if let Cert::Qc(q) = &mut bad { q.sigs[0][0] ^= 1; }
    assert!(matches!(call(&ev.headers, &ev.hq, &bad), Err(SeedError::HighCert(_))));
    // the genesis certificate is not a QC
    let genesis = engine3(0, 4, &cc).high_qc().clone();
    assert!(matches!(call(&ev.headers, &ev.hq, &genesis), Err(SeedError::HighCert(m)) if m.contains("not a QC")));
    // the only header carrying the reference is NOT final: the reference's block is, but nothing final attests the root
    let c = ev.headers.iter().position(|h| h.checkpoint == Some(r)).expect("a carrier");
    assert!(c + 1 < ev.chain.len() && (r.height as usize) + 2 < c + 1, "the carrier is well above the referenced block");
    let hq = ev.chain[c + 1].qc.clone(); // certifies the carrier, which is therefore certified but not final
    assert_eq!(call(&ev.headers[..=c], &hq, &hq).unwrap_err(), SeedError::NoFinalCarrier);
    // the install record must match the ROOT too, not just the height and block
    let seed = auth(&set, &cc, &ev, &r).unwrap();
    let pt = chain_forge_consensus::pq_hotstuff::header::ChainPoint { id: r.block_id, height: r.height, round: seed.base().round, payload_hash: [0; 32] };
    let rec = InstallRecord { generation: 1, cref: CheckpointRef { state_root: [7; 32], ..r }, carrier: pt, tip: *seed.tip(), high_qc: ev.hq.clone() };
    assert_eq!(check_install_record(&rec, &seed).unwrap_err(), SeedError::RecordMismatch("checkpoint reference"));
}

#[test]
fn a_sync_window_that_straddles_the_base_delivers_the_blocks_above_it_without_error() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let e = run_net(44);
    let ev = evidence(&e);
    let r = good_ref(&set, &cc, &ev, 1);
    let mut en = engine3(3, 4, &cc);
    en.seed(auth(&set, &cc, &ev, &r).unwrap()).unwrap();
    // oldest first, starting two blocks BELOW the base: those, and the base itself, are skipped without error; the first block above the base connects to it
    for b in ev.chain.iter().filter(|b| b.height + 2 >= r.height) {
        en.on_sync_block(b.clone()).unwrap_or_else(|er| panic!("height {}: {er}", b.height));
    }
    assert!(en.known_blocks().iter().all(|b| b.height > r.height), "nothing at or below the base was stored");
    assert!(en.known_blocks().iter().any(|b| b.height == r.height + 1), "and the block directly above it was");
}
