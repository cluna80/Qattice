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
// A parallel DNet is ticked to generate real proposal/vote/timeout bytes; those bytes are fed to the
// anchor-pending driver (node 0). The driver may emit sync requests (unicast, to: Some(_)) but must
// never broadcast (to: None), because a broadcast means the driver voted or proposed while signing was gated.
#[test]
fn on_bytes_with_consensus_msg_while_anchor_pending_produces_no_signing_outbound() {
    let (rec, _, _, _) = an3_setup();
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);
    let mut ring = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
    ring.publish(rec).unwrap();
    let sm = AnchorRestart::open(&ring, &abind(), &p, &TestVerifier, &alim(), 6).unwrap();
    let (mut drv, _) = start_anchor_node(0, 4, sm, "bytes-gate", 1).unwrap();
    assert!(drv.anchor_pending());

    // Build a parallel DNet (same genesis), run several steps so every peer sends at least proposals/timeouts.
    let mut net = DNet::new(4, &[], "bytes-gate-net");
    for _ in 0..8 { net.step(); }
    // Feed bytes from every peer (1–3) into the anchor-pending driver (node 0).
    let mut fed = 0usize;
    for peer in 1..4usize {
        for bytes in net.sent[peer].clone() {
            let outs = drv.on_bytes(peer, &bytes, 1).unwrap();
            for o in &outs {
                assert!(o.to.is_some(),
                    "anchor-pending driver must not broadcast (sign/vote/propose) from peer {peer}; got to=None outbound");
            }
            fed += 1;
        }
    }
    assert!(fed > 0, "test requires at least one message from peers; got none — increase net.step() count");
    assert!(drv.anchor_pending(), "anchor_pending must remain true after on_bytes");
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
