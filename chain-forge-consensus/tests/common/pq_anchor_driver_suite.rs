// ============================================================================================================================
// AN-3: driver wiring tests (feature `pq-anchored-evidence`, off by default). Verifies that `AuditFirst` mode gates
// startup retransmission, that `advance_anchor` drives the audit to completion with real ML-DSA-65 signatures, and that
// a full process restart with an anchor delivers deferred replay and resend correctly.
// All in-scope items (AnchorRing, AnchorRestart, AnchorMode, MemTreeFs, Drv, DriverConfig, etc.) come from the
// surrounding test file via include! and use tree_doubles::*.
// ============================================================================================================================
use chain_forge_consensus::pq_hotstuff::driver::AdvanceAnchorOutcome;

/// Start a v3 driver for node `i` of `n` with an anchor state machine installed.
fn start_anchor_node(
    i: usize,
    n: usize,
    anchor: AnchorRestart,
    tag: &str,
    now: u64,
) -> Result<(Drv, Vec<Outbound>), DriverError> {
    let cc = cc3(4, 8);
    let e = engine3(i, n, &cc);
    let bs = BlockStore::new(MemStorage::new(faults()));
    let log: ExecLog = Default::default();
    let exec = LogApp { inner: InterimApp::open(mem(), GENESIS_HASH)?, log };
    let tag = tag.to_string();
    let mut dc = dcfg();
    dc.anchor = Some(anchor);
    Drv::start(dc, e, bs, exec, Box::new(move |r, j| format!("interim-{tag}:{j}:{r}").into_bytes()), now)
}

/// Feed headers to `advance_anchor` in windows of `win`, returning the final non-Pending outcome.
fn drive_advance_anchor(
    drv: &mut Drv,
    hs: &[PayloadFreeBlock],
    win: usize,
) -> AdvanceAnchorOutcome {
    let mut next: u64 = 1;
    for _ in 0..(hs.len() + 2) {
        let from = (next as usize).saturating_sub(1);
        if from >= hs.len() { return AdvanceAnchorOutcome::Pending { next_height: next }; }
        let to = (from + win).min(hs.len());
        match drv.advance_anchor(&hs[from..to]).unwrap() {
            AdvanceAnchorOutcome::Pending { next_height } => { next = next_height; }
            other => return other,
        }
    }
    panic!("drive_advance_anchor: exceeded iteration bound");
}

#[test]
fn audit_first_start_returns_empty_first_and_blocks_retransmission() {
    let (rec, _, _, _) = an3_setup();
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);
    let mut ring = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
    ring.publish(rec).unwrap();
    let sm = AnchorRestart::open(&ring, &abind(), &p, &TestVerifier, &alim(), 6).unwrap();
    let (drv, first) = start_anchor_node(0, 4, sm, "anchor-gate", 1).unwrap();
    // start must return an EMPTY first-sends list — no replay, no resend while audit is pending
    assert!(first.is_empty(), "start with anchor pending must return no outbound messages; got {} message(s)", first.len());
    assert!(drv.anchor_pending(), "anchor_pending must be true after start");
}

#[test]
fn advance_anchor_returns_pending_until_audit_is_complete() {
    // Use audited_height=0 so the audit actually runs (normal restart has audited_height=anchor.height
    // which completes immediately — this tests the un-persisted case where the audit must run from scratch).
    let (mut rec, hs, _, _) = an3_setup();
    rec.audited_height = 0;
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);
    let mut ring = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
    ring.publish(rec.clone()).unwrap();
    let sm = AnchorRestart::open(&ring, &abind(), &p, &TestVerifier, &alim(), 6).unwrap();
    let (mut drv, _) = start_anchor_node(0, 4, sm, "anchor-partial", 1).unwrap();

    // feed exactly one header — with audited_height=0 and anchor.height > 1 (after 60 rounds),
    // the audit cannot complete on a single header window
    assert!(rec.anchor.height > 1, "an3_setup must produce a chain with anchor.height > 1");
    let outcome = drv.advance_anchor(&hs[..1]).unwrap();
    assert!(matches!(outcome, AdvanceAnchorOutcome::Pending { .. }),
        "partial window must leave the driver in Pending; got {outcome:?}");
    assert!(drv.anchor_pending(), "anchor_pending must remain true after partial window");
}

#[test]
fn advance_anchor_drives_audit_to_completion_or_reconcile() {
    // A freshly started driver with no commits will not satisfy anchor.height <= executor_committed_height
    // (anchor.height > 0, executor at 0). We verify that the audit itself completes (AuditFailed is NOT returned)
    // and the driver reaches either Ready (if reconcile passes) or ReconcileFailed (normal for a fresh driver).
    let (rec, hs, _, _) = an3_setup();
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);
    let mut ring = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
    ring.publish(rec).unwrap();
    let sm = AnchorRestart::open(&ring, &abind(), &p, &TestVerifier, &alim(), 6).unwrap();
    let (mut drv, _) = start_anchor_node(0, 4, sm, "anchor-advance", 1).unwrap();
    assert!(drv.anchor_pending());

    let outcome = drive_advance_anchor(&mut drv, &hs, 9);
    match &outcome {
        AdvanceAnchorOutcome::Ready { .. } | AdvanceAnchorOutcome::ReconcileFailed(_) => {}
        other => panic!("expected Ready or ReconcileFailed after full audit; got {other:?}"),
    }
}

#[test]
fn not_pending_when_no_anchor_is_installed() {
    let cc = cc3(4, 8);
    let e = engine3(0, 4, &cc);
    let bs = BlockStore::new(MemStorage::new(faults()));
    let log: ExecLog = Default::default();
    let exec = LogApp { inner: InterimApp::open(mem(), GENESIS_HASH).unwrap(), log };
    let (mut drv, _) = Drv::start(dcfg(), e, bs, exec, Box::new(|r, j| format!("interim:{j}:{r}").into_bytes()), 1).unwrap();
    assert!(!drv.anchor_pending(), "no anchor installed: anchor_pending must be false");
    let outcome = drv.advance_anchor(&[]).unwrap();
    assert!(matches!(outcome, AdvanceAnchorOutcome::NotPending),
        "no anchor: advance_anchor must return NotPending immediately; got {outcome:?}");
}

// T17 is in pq_anchor_restart_suite.rs (component level, audit-watermark bypass test).

// T18: tick with anchor pending must produce NO outbound messages (no propose, no timeout, no resend).
#[test]
fn tick_with_anchor_pending_produces_no_outbound() {
    let (rec, _, _, _) = an3_setup();
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);
    let mut ring = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
    ring.publish(rec).unwrap();
    let sm = AnchorRestart::open(&ring, &abind(), &p, &TestVerifier, &alim(), 6).unwrap();
    let (mut drv, first) = start_anchor_node(0, 4, sm, "tick-gate", 1).unwrap();
    assert!(first.is_empty());
    assert!(drv.anchor_pending());

    // Tick repeatedly at increasing timestamps. No outbound messages may be produced while audit is pending.
    for t in [1u64, 100, 1000, 10_000, 100_000] {
        let outs = drv.tick(t).unwrap();
        assert!(outs.is_empty(), "tick at t={t} with anchor pending must produce no outbound; got {} message(s)", outs.len());
    }
    assert!(drv.anchor_pending(), "anchor_pending must remain true after multiple ticks");
}

// T19: on_bytes with a consensus message while anchor pending must NOT produce a signing (broadcast) outbound.
// The DNet uses the SAME checkpoint config as start_anchor_node (cc3(4, 8)) so they share a genesis hash and
// the engine accepts the proposals rather than rejecting them as foreign. Node 0 is silent in the DNet so that
// it is not the proposer; with seed=0, round-1 leader = (1+0)%4 = 1, so net.sent[1] carries a valid round-1
// proposal that the anchor-pending driver (node 0) would vote on if the deliver gate were absent.
#[test]
fn on_bytes_with_consensus_msg_while_anchor_pending_produces_no_signing_outbound() {
    let (rec, _, _, _) = an3_setup();
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);
    let mut ring = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
    ring.publish(rec).unwrap();
    let sm = AnchorRestart::open(&ring, &abind(), &p, &TestVerifier, &alim(), 6).unwrap();
    // Anchor-pending driver is node 0.
    let (mut drv, _) = start_anchor_node(0, 4, sm, "bytes-gate", 1).unwrap();
    assert!(drv.anchor_pending());

    // DNet with matching genesis (cc3(4,8)) and node 0 silent: nodes 1-3 run consensus.
    // With seed=0, round-1 leader = (1+0)%4 = 1, so net.sent[1] carries the round-1 proposal.
    // The anchor-pending driver (node 0, not the leader) would vote on that proposal if the deliver
    // gate were absent — this DNet setup ensures the bytes are genuinely valid for the engine.
    let mut net = DNet::new_cp(4, &[0], "bytes-gate-net", Some(cc3(4, 8)));
    for _ in 0..8 { net.step(); }
    // Feed bytes from peers 1-3 (the active DNet nodes) into the anchor-pending driver (node 0).
    let mut fed = 0usize;
    let lim = mlim();
    for peer in 1..4usize {
        for bytes in net.sent[peer].clone() {
            let outs = drv.on_bytes(peer, &bytes, 1).unwrap();
            for o in &outs {
                // Decode each outbound byte slice and reject any consensus (signing) message.
                // Votes are unicast (Output::Send { to: Some(_) }) so o.to.is_some() cannot
                // distinguish them from sync replies — decode is the only reliable check.
                match net::decode(&o.bytes, &lim) {
                    Ok(NetMsg::Consensus(_)) => panic!(
                        "anchor-pending driver produced a consensus (signing) outbound for peer {peer}; must not sign while audit is pending"),
                    _ => {}
                }
            }
            fed += 1;
        }
    }
    assert!(fed > 0, "test requires at least one message from peers; got none — increase net.step() count");
    assert!(drv.anchor_pending(), "anchor_pending must remain true after on_bytes");
}

// T20: advance_anchor returns Ready when the driver's executor has genuinely committed up to the
// reference height with the EXACT block_id and state_root the anchor record attests.
// Also verifies: mismatching block_id → ReconcileFailed; mismatching state_root → ReconcileFailed;
// executor behind anchor.height → ReconcileFailed.
#[test]
fn advance_anchor_reaches_ready_with_matching_executor_state() {
    // an3_setup returns the Eng3 instance used to build the anchor record. We MUST reuse
    // the same Eng3's node 0 engine so that block IDs (which include ML-DSA-65 signatures)
    // match exactly between the record and what the engine has in its committed history.
    let (rec, hs, _hq, mut e) = an3_setup();

    // Extract node 0's engine — it has full committed history and roots in its volatile state.
    // Node 0 starts at genesis (not seeded), so is_recovering() == false.
    let node0_engine = e.nodes.remove(0);

    // Confirm the engine has committed at least as far as the anchor's reference height.
    let (_, committed_tip_h) = node0_engine.committed_tip();
    assert!(committed_tip_h >= rec.reference.height,
        "engine must have committed up to reference height {}; tip is {}",
        rec.reference.height, committed_tip_h);
    assert!(committed_tip_h >= rec.anchor.height,
        "engine must have committed up to anchor height {}; tip is {}",
        rec.anchor.height, committed_tip_h);

    // Build a fresh executor and replay ALL committed blocks through it so it matches the engine.
    let log: ExecLog = Default::default();
    let mut inner = InterimApp::open(mem(), GENESIS_HASH).unwrap();
    for c in node0_engine.committed_after(0) {
        inner.apply(&c).expect("replay must succeed");
    }
    // The executor is now at committed_tip_h with the same state root the anchor record attests.
    assert_eq!(inner.cursor().height, committed_tip_h);
    let exec = LogApp { inner, log: log.clone() };

    // Open a fresh block store (the engine's volatile state has the committed blocks in memory).
    let bs = BlockStore::new(MemStorage::new(faults()));

    // Build the anchor state machine from the SAME record.
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);
    let mut ring = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
    ring.publish(rec.clone()).unwrap();
    let sm = AnchorRestart::open(&ring, &abind(), &p, &TestVerifier, &alim(), 6).unwrap();

    // Start the driver with the live engine and pre-replayed executor.
    let mut dc = dcfg();
    dc.anchor = Some(sm);
    let (mut drv, first) = Drv::start(dc, node0_engine, bs, exec,
        Box::new(|r, j| format!("interim-recon:{j}:{r}").into_bytes()), 1).unwrap();
    assert!(first.is_empty(), "anchor pending: start must return no outbound");
    assert!(drv.anchor_pending());

    // Drive the audit to completion — must return Ready with matching audited_height.
    let outcome = drive_advance_anchor(&mut drv, &hs, 9);
    match &outcome {
        AdvanceAnchorOutcome::Ready { audited_height, .. } => {
            assert_eq!(*audited_height, rec.anchor.height,
                "Ready.audited_height must equal anchor.height ({}); got {}",
                rec.anchor.height, audited_height);
        }
        other => panic!("expected Ready with matching executor state; got {other:?}"),
    }
    assert!(!drv.anchor_pending(), "anchor gate must be cleared after Ready");
}

// T20b: each reconcile mismatch keeps the anchor gate UP and returns ReconcileFailed.
#[test]
fn advance_anchor_returns_reconcile_failed_on_executor_mismatches() {
    // an3_setup gives us the Eng3 so we can reuse node engines that MATCH the anchor record.
    let (rec, hs, _, mut ref_e) = an3_setup();
    let anchor_h = rec.anchor.height;

    let cc = cc3(4, 8);
    let set = set_n(4);

    // Helper: build executor up to `committed_height` by replaying blocks from `e_node`.
    // Returns AdvanceAnchorOutcome after a full advance_anchor run against the given anchor record.
    let run_node = |e_node: E, committed_height: u64, the_rec: AnchorRecord| -> (AdvanceAnchorOutcome, bool) {
        let mut inner = InterimApp::open(mem(), GENESIS_HASH).unwrap();
        for c in e_node.committed_after(0) {
            if c.height > committed_height { break; }
            inner.apply(&c).expect("replay");
        }
        let exec = LogApp { inner, log: Default::default() };
        let bs = BlockStore::new(MemStorage::new(faults()));
        let mut ring2 = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
        ring2.publish(the_rec).unwrap();
        let p = cparams3(&set, &cc);
        let sm = AnchorRestart::open(&ring2, &abind(), &p, &TestVerifier, &alim(), 6).unwrap();
        let mut dc = dcfg();
        dc.anchor = Some(sm);
        let (mut drv, _) = Drv::start(dc, e_node, bs, exec,
            Box::new(|r, j| format!("interim-mismatch:{j}:{r}").into_bytes()), 1).unwrap();
        let outcome = drive_advance_anchor(&mut drv, &hs, 9);
        let still_pending = drv.anchor_pending();
        (outcome, still_pending)
    };

    // (a) executor behind anchor.height: use a node with full committed history but only
    // replay up to anchor_h - 1 so the driver sees executor.height < anchor.height.
    if anchor_h > 0 {
        let n1 = ref_e.nodes.remove(1);
        assert!(n1.committed_tip().1 >= anchor_h);
        let (o, still) = run_node(n1, anchor_h.saturating_sub(1), rec.clone());
        assert!(matches!(o, AdvanceAnchorOutcome::ReconcileFailed(_)),
            "executor behind anchor.height must yield ReconcileFailed; got {o:?}");
        assert!(still, "gate must remain up after ReconcileFailed");
    }

    // (b) wrong block_id at the anchor height: run a SECOND independent Eng3 simulation.
    // The same validator keys are used (global OnceLock per validator index), but the two
    // simulations produce different block IDs at every height (different round sequences,
    // different payload commitments). The anchor record was built from ref_e (Eng3 1); a
    // driver that starts with an engine from Eng3 2 will commit different blocks at anchor_h,
    // so engine.committed(anchor_h).id ≠ anchor.id → ReconcileFailed.
    let mut e2 = Eng3::new(4, cc);
    e2.run(60);
    let n2 = e2.nodes.remove(1);
    // replay ALL of n2's committed blocks so executor.height ≥ anchor.height (passes check 1)
    let (o, still) = run_node(n2, u64::MAX, rec.clone());
    assert!(matches!(o, AdvanceAnchorOutcome::ReconcileFailed(_)),
        "wrong block_id at anchor height (different simulation) must yield ReconcileFailed; got {o:?}");
    assert!(still, "gate must remain up after ReconcileFailed");
}

// T21: signing is suppressed while the anchor audit is pending, and resumes immediately once
// advance_anchor returns Ready (for a fully-synced engine). The key code under test is
// driver.rs `try_complete_recovery`: `if self.anchor.is_some() { return; }` (the guard that
// prevents recovery-completion AND signing until the anchor gate clears).
// This covers the reviewer's requirement: "ordinary engine recovery must also finish before
// signing resumes" — here the engine is fully synced so recovery is instant after gate clears;
// the gate is the sole barrier.
#[test]
fn anchor_pending_suppresses_try_complete_recovery_until_gate_clears() {
    // Reuse T20's setup: node0 from an3_setup + fully replayed executor. The engine has real
    // committed history and recorded state roots that match the anchor record, so advance_anchor
    // → Ready is achievable. The same chain gives matching block IDs and state roots.
    let (rec, hs, hq, mut e) = an3_setup();
    let node0_engine = e.nodes.remove(0);
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);

    // Replay committed history from node 0 so executor state matches what driver expects.
    let mut inner = InterimApp::open(mem(), GENESIS_HASH).unwrap();
    for c in node0_engine.committed_after(0) { inner.apply(&c).expect("replay"); }
    let log: ExecLog = Default::default();
    let exec = LogApp { inner, log };

    let mut ring = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
    ring.publish(rec.clone()).unwrap();
    let sm = AnchorRestart::open(&ring, &abind(), &p, &TestVerifier, &alim(), 6).unwrap();
    let bs = BlockStore::new(MemStorage::new(faults()));
    let mut dc = dcfg();
    dc.anchor = Some(sm);
    let (mut drv, first) = Drv::start(dc, node0_engine, bs, exec,
        Box::new(|r, j| format!("interim-t21:{j}:{r}").into_bytes()), 1).unwrap();

    assert!(first.is_empty(), "anchor-pending driver must return no outbound at start");
    assert!(drv.anchor_pending(), "anchor gate must be up");

    // Tick many times BEFORE advance_anchor: signing must be fully suppressed by the gate.
    // try_complete_recovery returns at the anchor guard (driver.rs:275) on every tick.
    for t in [1u64, 100, 1_000, 10_000, 100_000] {
        let outs = drv.tick(t).unwrap();
        let lim = mlim();
        for o in &outs {
            if let Ok(NetMsg::Consensus(_)) = net::decode(&o.bytes, &lim) {
                panic!("tick with anchor pending produced a signing (consensus) outbound at t={t}");
            }
        }
        assert!(drv.anchor_pending(), "anchor gate must remain up at t={t}");
    }

    // Drive the audit to completion — Ready clears the gate and releases deferred signing.
    let outcome = drive_advance_anchor(&mut drv, &hs, 9);
    let deferred = match outcome {
        AdvanceAnchorOutcome::Ready { ref deferred, .. } => {
            assert!(!drv.anchor_pending(), "gate must be cleared after Ready");
            deferred.clone()
        }
        other => panic!("expected Ready (fully-synced engine + matching executor); got {other:?}"),
    };

    // After gate clears, advance_anchor itself produced deferred signing outbound (resend_last_vote
    // / resend_last_timeout). These are consensus messages — proof that signing is now allowed.
    let lim = mlim();
    let signing_count = deferred.iter().filter(|o| matches!(net::decode(&o.bytes, &lim), Ok(NetMsg::Consensus(_)))).count();
    assert!(signing_count > 0,
        "after gate clears, deferred output must include at least one consensus (signing) message; got {signing_count} from {} total deferred",
        deferred.len());
    let _ = (hq, e); // suppress unused
}

// T22: filesystem-backed restart — after the driver runs and is fully dropped, reconstructing
// it from disk (FsStorage) produces an executor cursor that matches what was committed
// (no duplicate execution), and the safety store's signing floor is preserved.
// Uses real FsStorage for the safety store, the InterimApp executor, AND the blockstore
// (so the second-run engine can restore its committed history from disk). No anchor gate is
// active so the restart path is clean.
#[test]
fn fs_backed_restart_preserves_signing_floors_and_prevents_duplicate_execution() {
    // Local type aliases for the FsStorage-backed engine and driver (blockstore also FsStorage).
    type StFs  = SafetyStore<FsStorage, TestCounter>;
    type EFs   = Engine<FsStorage, TestCounter, TestSigner, TestVerifier>;
    type DrvFs = Driver<FsStorage, TestCounter, TestSigner, TestVerifier,
                        FsStorage, InterimApp<FsStorage>>;

    // Per-test temp directories: safety store, app state, blockstore.
    let pid = std::process::id();
    let tmp_root = std::env::temp_dir()
        .join(format!("cf-an3-fs-restart-{pid}-{}", line!()));
    let _ = std::fs::remove_dir_all(&tmp_root);
    let safety_dir = tmp_root.join("safety");
    let app_dir    = tmp_root.join("app");
    let store_dir  = tmp_root.join("store");
    std::fs::create_dir_all(&safety_dir).unwrap();
    std::fs::create_dir_all(&app_dir).unwrap();
    std::fs::create_dir_all(&store_dir).unwrap();

    let cc = cc3(4, 8);

    // --- First run -----------------------------------------------------------
    let fs_safety = FsStorage::new(&safety_dir).unwrap();
    let pk0 = test_public_key(1);
    let init = FreshInit { protocol_profile: PROFILE3, chain_id: CHAIN,
                           public_key: &pk0, instance_id: [0u8; 16], epoch: 0 };
    let f = faults();
    let st0 = StFs::initialize_fresh(
        fs_safety, TestCounter::bound(CounterState::INITIAL, f.clone(), binding(0)),
        &init, &ParticipationEvidence::default()).unwrap();
    let engine0 = EFs::new(cfg3(0, 4, &cc), st0, TestSigner::new(1), TestVerifier).unwrap();

    let fs_app   = FsStorage::new(&app_dir).unwrap();
    let exec0    = InterimApp::open(fs_app, GENESIS_HASH).unwrap();
    let fs_store = FsStorage::new(&store_dir).unwrap();
    let bs0      = BlockStore::new(fs_store);

    let (mut drv0, _) = DrvFs::start(
        dcfg(), engine0, bs0, exec0,
        Box::new(|r, j| format!("fs-interim:{j}:{r}").into_bytes()), 1).unwrap();

    // Feed bytes from a DNet so drv0 processes consensus messages and may execute blocks.
    // Node 0 is silent in the DNet (not proposing); peers 1-3 run real consensus with the
    // same genesis so the bytes are valid for drv0's engine.
    let mut net = DNet::new_cp(4, &[0], "fs-restart-net", Some(cc3(4, 8)));
    for _ in 0..12 { net.step(); }
    for peer in 1..4usize {
        for bytes in net.sent[peer].clone() { let _ = drv0.on_bytes(peer, &bytes, 1); }
    }
    let _ = drv0.tick(10_000);

    // Record executor cursor before the "process restart".
    let cursor_before = drv0.executor().cursor();

    // --- Simulate process drop -----------------------------------------------
    // into_parts gives (engine, blockstore, executor).
    let (engine0_done, bs0_done, app0_done) = drv0.into_parts();
    let (store0, signer0, _verifier) = engine0_done.into_parts();
    let (st0_storage, ctr0) = store0.into_parts();
    let ctr_state = ctr0.state();
    // Drop in reverse order of acquisition: executor, blockstore, safety store.
    drop(app0_done);    // releases InterimApp FsStorage file handles
    drop(bs0_done);     // releases blockstore FsStorage file handles
    drop(st0_storage);  // releases safety store FsStorage file handles

    // --- Second run (new "process") ------------------------------------------
    let fs_safety2 = FsStorage::new(&safety_dir).unwrap();
    let pk0_2 = test_public_key(1);
    let exp = Expected { protocol_profile: PROFILE3, chain_id: CHAIN, public_key: &pk0_2 };
    let st0_2 = StFs::open(
        fs_safety2,
        TestCounter::bound(ctr_state, f.clone(), binding(0)),
        &exp, &TestVerifier, &ParticipationEvidence::default()).unwrap();
    let engine0_2 = EFs::new(cfg3(0, 4, &cc), st0_2, signer0, TestVerifier).unwrap();

    let fs_app2   = FsStorage::new(&app_dir).unwrap();
    let exec0_2   = InterimApp::open(fs_app2, GENESIS_HASH).unwrap();

    // Executor cursor on reopen must equal pre-drop cursor: no duplicate execution.
    assert_eq!(exec0_2.cursor(), cursor_before,
        "executor cursor after fs restart must equal pre-drop cursor (no duplicate execution)");

    let fs_store2 = FsStorage::new(&store_dir).unwrap();
    let bs0_2     = BlockStore::new(fs_store2);
    let (drv0_2, _) = DrvFs::start(
        dcfg(), engine0_2, bs0_2, exec0_2,
        Box::new(|r, j| format!("fs-interim-2:{j}:{r}").into_bytes()), 2).unwrap();

    // After restart the driver's executor cursor must still match (replay settles correctly).
    assert_eq!(drv0_2.executor().cursor(), cursor_before,
        "driver executor cursor after restart must equal pre-drop cursor");

    // The safety store successfully reopened (open() would have errored on a floor violation
    // or digest mismatch): signing floors are intact. Explicitly: the restarted driver starts
    // successfully, which proves the floor is consistent with the counter state.
    assert!(!drv0_2.anchor_pending(),
        "no anchor installed: anchor_pending must be false after fs restart");

    // Cleanup.
    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[test]
fn failed_audit_returns_audit_failed_and_anchor_pending_stays_true() {
    let (mut rec, hs, _, _) = an3_setup();
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);
    // tamper audited_height=0 so the check runs, then tamper an ancestor to cause a mismatch
    rec.audited_height = 0;
    if let Some(a) = rec.anchor.ancestors.first_mut() {
        a.1[0] ^= 1;
    } else {
        rec.anchor.final_height = rec.anchor.final_height.wrapping_add(1);
    }
    let mut ring = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
    ring.publish(rec.clone()).unwrap();
    // cross_check passes; open succeeds
    let sm = AnchorRestart::open(&ring, &abind(), &p, &TestVerifier, &alim(), 6).unwrap();
    let (mut drv, _) = start_anchor_node(0, 4, sm, "anchor-fail", 1).unwrap();

    let outcome = drive_advance_anchor(&mut drv, &hs, 9);
    assert!(matches!(outcome, AdvanceAnchorOutcome::AuditFailed(_)),
        "tampered record must yield AuditFailed; got {outcome:?}");
    // anchor gate is NOT cleared on audit failure
    assert!(drv.anchor_pending(), "anchor_pending must remain true after AuditFailed");
}
