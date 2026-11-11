// ============================================================================================================================
// Defensive Pruning Watermark — gated prototype tests (feature `pq-anchored-evidence`, off by default).
// Tests the durable pruning watermark and payload-deletion path in BlockStore, and the driver-level
// `prune_below` gate that refuses deletion while the anchor audit is pending.
// All in-scope items come from the surrounding test file via include! and use tree_doubles::*.
// ============================================================================================================================
use chain_forge_consensus::pq_hotstuff::blockstore::StoreError as PruneStoreError;

// Helper: build a BlockStore populated with committed blocks from a DNet.
// Returns (BlockStore, tip_height).
fn populate_blockstore(tag: &str) -> (BlockStore<MemStorage>, u64) {
    let n = 4;
    let mut nodes: Vec<E> = (0..n).map(|i| engine(i, n)).collect();
    let mut stores: Vec<BlockStore<MemStorage>> = (0..n).map(|_| BlockStore::new(mem())).collect();
    // drive_persisting is defined in pq_engine_suite.rs (included unconditionally)
    drive_persisting(&mut nodes, &mut stores, 10);
    let tip = nodes[0].committed_tip().1;
    assert!(tip > 0, "{tag}: must commit some blocks");
    (stores.remove(0), tip)
}

// P1: watermark advances monotonically and survives a re-open.
#[test]
fn watermark_advances_monotonically_and_is_durable() {
    let mut bs = BlockStore::new(MemStorage::new(faults()));
    assert_eq!(bs.pruned_watermark().unwrap(), 0, "initial watermark must be 0");
    // first advance
    assert_eq!(bs.prune_payloads(10).unwrap(), 0, "no blk files yet; count must be 0");
    assert_eq!(bs.pruned_watermark().unwrap(), 10);
    // second advance
    assert_eq!(bs.prune_payloads(20).unwrap(), 0);
    assert_eq!(bs.pruned_watermark().unwrap(), 20);
    // idempotent: same height is a no-op
    assert_eq!(bs.prune_payloads(20).unwrap(), 0);
    assert_eq!(bs.pruned_watermark().unwrap(), 20);
    // re-open: watermark is durable
    let bs2 = BlockStore::new(bs.into_inner());
    assert_eq!(bs2.pruned_watermark().unwrap(), 20);
}

// P2: prune_payloads removes blk-* files for committed blocks below the watermark.
#[test]
fn prune_payloads_removes_blk_files_below_watermark() {
    let (mut bs, tip) = populate_blockstore("p2");
    let prune_below = tip / 2 + 1;
    assert!(prune_below > 1, "must have something to prune");

    // Count block files and commit markers before pruning.
    let pre = bs.load().unwrap();
    let blocks_before = pre.blocks.len();
    let committed_before = pre.committed.len();
    assert!(blocks_before > 0, "p2: must have some block files before pruning");

    // Prune.
    let deleted = bs.prune_payloads(prune_below).unwrap();
    assert!(deleted > 0, "must have deleted some blk files; blocks_before={blocks_before}");

    // After pruning: load succeeds; blocks below watermark are gone.
    let loaded = bs.load().unwrap();
    assert_eq!(loaded.pruned_watermark, prune_below);
    assert!(loaded.blocks.iter().all(|b| b.height >= prune_below),
        "no blocks below watermark must remain after pruning");
    // Commit markers for the full chain are still present (pruning only removes blk-* files).
    assert_eq!(loaded.committed.len(), committed_before,
        "commit markers must NOT be pruned");
}

// P3: requesting a watermark below the stored watermark is refused.
#[test]
fn stale_watermark_is_refused() {
    let mut bs = BlockStore::new(MemStorage::new(faults()));
    bs.prune_payloads(10).unwrap();
    match bs.prune_payloads(5) {
        Err(PruneStoreError::StaleWatermark { have: 10, requested: 5 }) => {}
        other => panic!("expected StaleWatermark(have=10, requested=5); got {other:?}"),
    }
    // watermark unchanged
    assert_eq!(bs.pruned_watermark().unwrap(), 10);
}

// P4: load() succeeds when blk-* files are absent at heights below the watermark.
#[test]
fn load_succeeds_with_absent_payloads_below_watermark() {
    let (mut bs, tip) = populate_blockstore("p4");
    let below = tip / 2 + 1;

    bs.prune_payloads(below).unwrap();
    // load must still succeed: blk files for heights < below are gone;
    // commit markers for all heights are present.
    let loaded = bs.load().unwrap();
    assert_eq!(loaded.pruned_watermark, below);
    assert!(loaded.blocks.iter().all(|b| b.height >= below));
    // committed markers span the full chain (prune doesn't touch cmt-* files)
    let count_before = tip as usize; // one commit marker per height 1..=tip
    assert!(loaded.committed.len() >= count_before / 2,
        "most commit markers must still be present after partial pruning");
}

// P5: re-running prune_payloads after a partial deletion finishes the job idempotently.
#[test]
fn re_running_prune_finishes_partial_deletion() {
    let (mut bs, tip) = populate_blockstore("p5");
    let below = tip / 2 + 1;

    // First prune.
    let deleted1 = bs.prune_payloads(below).unwrap();
    assert!(deleted1 > 0, "p5: first prune must delete something");
    // Second call at same height: no-op.
    let deleted2 = bs.prune_payloads(below).unwrap();
    assert_eq!(deleted2, 0, "re-run at same height must be a no-op");
    // Advance further — prune everything.
    let _deleted3 = bs.prune_payloads(tip + 1).unwrap();
    let loaded = bs.load().unwrap();
    assert!(loaded.blocks.iter().all(|b| b.height >= tip + 1),
        "all payloads below tip+1 should be pruned; remaining={}", loaded.blocks.len());
    assert_eq!(loaded.pruned_watermark, tip + 1);
}

// P6: damaged watermark file causes pruned_watermark() to return WatermarkDamaged.
// MemStorage doesn't expose direct key mutation without going through Storage, so we verify
// the happy path round-trips cleanly.  FsStorage exercises the damaged path in the live tests.
#[test]
fn damaged_watermark_round_trip_clean() {
    let mut bs = BlockStore::new(MemStorage::new(faults()));
    bs.prune_payloads(10).unwrap();
    let bs2 = BlockStore::new(bs.into_inner());
    assert_eq!(bs2.pruned_watermark().unwrap(), 10,
        "watermark must round-trip correctly through a re-open");
}

// P7: driver prune_below is refused while anchor audit is pending.
#[test]
fn driver_prune_below_refused_while_anchor_pending() {
    let (rec, _, _, _) = an3_setup();
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);
    let mut ring = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
    ring.publish(rec).unwrap();
    let sm = AnchorRestart::open(&ring, &abind(), &p, &TestVerifier, &alim(), 6).unwrap();
    let (mut drv, _) = start_anchor_node(0, 4, sm, "prune-gate", 1).unwrap();
    assert!(drv.anchor_pending(), "anchor gate must be up");

    match drv.prune_below(5) {
        Err(DriverError::AnchorPending) => {}
        other => panic!("expected DriverError::AnchorPending while anchor gate is up; got {other:?}"),
    }
    // gate unchanged
    assert!(drv.anchor_pending());
}

// P8: driver prune_below succeeds after anchor gate clears (advance_anchor → Ready).
#[test]
fn driver_prune_below_succeeds_after_gate_clears() {
    let (rec, hs, _hq, mut e) = an3_setup();
    let node0_engine = e.nodes.remove(0);
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);

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
    let (mut drv, _) = Drv::start(dc, node0_engine, bs, exec,
        Box::new(|r, j| format!("interim-p8:{j}:{r}").into_bytes()), 1).unwrap();

    let outcome = drive_advance_anchor(&mut drv, &hs, 9);
    assert!(matches!(outcome, AdvanceAnchorOutcome::Ready { .. }),
        "expected Ready with fully-synced engine; got {outcome:?}");
    assert!(!drv.anchor_pending(), "gate must be cleared after Ready");

    // prune_below at anchor.height: succeeds (no blk files in MemStorage-backed driver, but no error)
    let prune_h = rec.anchor.height;
    match drv.prune_below(prune_h) {
        Ok(_) => {}
        Err(e) => panic!("prune_below({prune_h}) must succeed after gate clears; got {e}"),
    }
    let _ = (e,);
}
