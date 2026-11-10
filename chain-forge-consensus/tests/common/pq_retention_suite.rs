// ============================================================================================================================
// S-2a: bounded, per-node, crash-safe retention of authenticated snapshots (a devnet CACHE policy, not a pruning-safety guarantee). ISOLATED: nothing is wired,
// nothing is captured automatically, no provider serves from it yet, pruning is unimplemented. The snapshot bytes are synthetic opaque data.
// ============================================================================================================================
use chain_forge_consensus::pq_hotstuff::recovery::retention::{Captured, RetentionConfig, RetentionError, SnapshotStore};

fn rsnap(h: u64, size: usize) -> (CheckpointRef, Manifest, Vec<Vec<u8>>) {
    let data: Vec<u8> = (0..size).map(|i| (i as u64 ^ h) as u8).collect();
    let c = CheckpointRef { height: h, block_id: [h as u8; 32], state_root: [(h as u8).wrapping_add(1); 32] };
    let (m, ch) = manifest_for(&data, 64, &c);
    (c, m, ch)
}
fn rcfg(max: usize, budget: u64, one: u64) -> RetentionConfig { RetentionConfig { max_snapshots: max, disk_budget_bytes: budget, max_snapshot_bytes: one } }
type Store = SnapshotStore<MemTreeFs>;
fn rstore(cfg: RetentionConfig) -> Store { let mut fs = MemTreeFs::new(tfaults()); rextras(&mut fs); SnapshotStore::open(fs, cfg, rl(), GENESIS_HASH).expect("open") }
/// Files that belong to the INSTALLER (active generation, staging): the store must never touch them.
fn rextras(fs: &mut MemTreeFs) { fs.set_raw("generations/gen-00000000000000000007/app-state", vec![7; 120]); fs.set_raw("staging/aa/chunk-00000", vec![1; 64]); fs.set_raw("app-pointer", vec![9; 10]); }
fn rextras_view(fs: &MemTreeFs) -> BTreeMap<String, Vec<u8>> { let mut m = fs.files_under("generations"); m.extend(fs.files_under("staging")); if let Some(p) = fs.raw("app-pointer") { m.insert("app-pointer".into(), p); } m }
fn disk_bytes(fs: &MemTreeFs, dir: &str) -> u64 { fs.files_under(dir).values().map(|v| v.len() as u64).sum() }
fn cap(s: &mut Store, h: u64) -> Result<Captured, RetentionError> { let (c, m, ch) = rsnap(h, 200); s.capture(c, &m, &ch) }
fn heights(s: &Store) -> Vec<u64> { s.retained().into_iter().map(|r| r.0.height).collect() }

#[test]
fn a_retention_budget_that_cannot_hold_one_retained_snapshot_and_one_capture_is_refused_before_any_use() {
    assert!(matches!(RetentionConfig { max_snapshots: 0, ..rcfg(3, 1000, 100) }.validate(), Err(RetentionError::Zero)));
    assert!(matches!(rcfg(3, 0, 100).validate(), Err(RetentionError::Zero)));
    assert!(matches!(rcfg(3, 199, 100).validate(), Err(RetentionError::BudgetBelowOneCapture { .. })));
    assert!(rcfg(3, 200, 100).validate().is_ok());
    assert!(matches!(rcfg(3, u64::MAX, u64::MAX).validate(), Err(RetentionError::BudgetBelowOneCapture { .. })), "checked arithmetic");
    let fs = MemTreeFs::new(tfaults());
    assert!(SnapshotStore::open(fs, rcfg(3, 10, 100), rl(), GENESIS_HASH).is_err());
}

#[test]
fn the_newest_three_authenticated_snapshots_are_kept_and_the_accounting_equals_the_disk() {
    let mut s = rstore(rcfg(3, 1 << 20, 1 << 16));
    let extras0 = rextras_view(&s.fs);
    for h in [8u64, 16, 24, 32, 40] { assert!(matches!(cap(&mut s, h), Ok(Captured::Retained { .. }))); }
    assert_eq!(heights(&s), vec![24, 32, 40], "the three newest remain");
    assert_eq!(s.retained_bytes(), disk_bytes(&s.fs, "snapshots"), "accounting equals the bytes on disk");
    assert!(s.fs.files_under("snapshots-tmp").is_empty(), "no temporary capture is left behind");
    assert_eq!(rextras_view(&s.fs), extras0, "the installer's generations and staging are never touched");
    assert_eq!(s.stats.evicted, 2);
    assert!(s.stats.peak_bytes <= s.config().disk_budget_bytes);
    // what is served verifies against its manifest
    let (c, id, _, _) = s.retained().pop().unwrap();
    let m = s.manifest_for(&c).unwrap(); assert_eq!(m.snapshot_id, id);
    for i in 0..m.chunk_count { assert_eq!(rcodec::chunk_hash(i, &s.chunk(&id, i).unwrap()), m.chunk_hashes[i as usize]); }
    assert!(s.chunk(&[0; 32], 0).is_none());
}

#[test]
fn a_pinned_snapshot_is_never_evicted_and_an_exhausted_budget_defers_the_capture_without_evicting_anything() {
    // a budget that holds two snapshots at once
    let (c0, m0, ch0) = rsnap(8, 200);
    let mut s = rstore(rcfg(3, 1200, 600)); // each snapshot is ~500 bytes: two fit, three do not
    s.capture(c0, &m0, &ch0).unwrap(); cap(&mut s, 16).unwrap();
    let (_, id8, _, _) = s.retained()[0]; let (_, id16, _, _) = s.retained()[1];
    s.pin(&id8).unwrap(); s.pin(&id16).unwrap();
    let before = heights(&s);
    let extras0 = rextras_view(&s.fs);
    match cap(&mut s, 24) { Err(RetentionError::BudgetExhausted { needed, available }) => assert!(needed > available), other => panic!("{other:?}") }
    assert_eq!(heights(&s), before, "nothing was evicted: both retained snapshots are pinned");
    assert_eq!(s.stats.deferred, 1);
    assert!(s.chunk(&id8, 0).is_some() && s.chunk(&id16, 0).is_some(), "pinned snapshots are still served");
    assert_eq!(rextras_view(&s.fs), extras0);
    // unpin the OLDEST: the capture now evicts it (and only it)
    s.unpin(&id8);
    match cap(&mut s, 24).unwrap() { Captured::Retained { evicted } => assert_eq!(evicted, vec![id8]), other => panic!("{other:?}") }
    assert_eq!(heights(&s), vec![16, 24]);
    assert!(s.retained().iter().any(|r| r.1 == id16 && r.3), "the still-pinned one survived");
    // a pin keeps the COUNT above target rather than being evicted
    let mut t = rstore(rcfg(1, 1 << 20, 1 << 16));
    cap(&mut t, 8).unwrap(); let id = t.retained()[0].1; t.pin(&id).unwrap();
    cap(&mut t, 16).unwrap();
    assert_eq!(heights(&t), vec![8, 16], "the pinned snapshot is kept although the target is one");
    assert!(matches!(t.pin(&[5; 32]), Err(RetentionError::Unknown)));
}

#[test]
fn bytes_reserved_by_the_installer_count_against_the_budget_and_are_never_evicted() {
    let (c, m, ch) = rsnap(8, 200);
    let mut s = rstore(rcfg(3, 1200, 600));
    s.set_external_reserved(800); // staging + generations take most of the budget
    match s.capture(c, &m, &ch) { Err(RetentionError::BudgetExhausted { .. }) => {} other => panic!("{other:?}") }
    assert!(heights(&s).is_empty() && s.fs.files_under("snapshots").is_empty() && s.fs.files_under("snapshots-tmp").is_empty(), "deferred: nothing written");
    s.set_external_reserved(0);
    assert!(s.capture(c, &m, &ch).is_ok(), "with the reservation released the capture fits");
    assert_eq!(s.used(), s.retained_bytes());
}

#[test]
fn invalid_oversized_stale_and_duplicate_captures_are_refused_or_recognised() {
    let mut s = rstore(rcfg(3, 1 << 20, 600));
    let (c, m, ch) = rsnap(16, 200);
    let mut bad = ch.clone(); bad[1][0] ^= 1;
    assert!(matches!(s.capture(c, &m, &bad), Err(RetentionError::Invalid("chunk"))));
    assert!(matches!(s.capture(c, &m, &ch[..ch.len() - 1]), Err(RetentionError::Invalid("chunk count"))));
    assert!(matches!(s.capture(CheckpointRef { height: 17, ..c }, &m, &ch), Err(RetentionError::Invalid("snapshot id"))));
    let (cb, mb, chb) = rsnap(24, 1000);
    assert!(matches!(s.capture(cb, &mb, &chb), Err(RetentionError::TooLarge { .. })));
    assert!(s.capture(c, &m, &ch).is_ok());
    assert_eq!(s.capture(c, &m, &ch), Ok(Captured::AlreadyRetained));
    let (c8, m8, ch8) = rsnap(8, 200);
    assert!(matches!(s.capture(c8, &m8, &ch8), Err(RetentionError::NotForward)), "an older checkpoint is not captured behind a newer one");
    assert_eq!(heights(&s), vec![16]);
    assert!(s.fs.files_under("snapshots-tmp").is_empty());
}

#[test]
fn a_damaged_retained_snapshot_is_removed_on_open_and_never_served() {
    let mut s = rstore(rcfg(4, 1 << 20, 1 << 16));
    for h in [8u64, 16, 24, 32] { cap(&mut s, h).unwrap(); }
    let ids: Vec<[u8; 32]> = s.retained().iter().map(|r| r.1).collect();
    let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut fs = s.fs;
    // (1) a flipped chunk byte, (2) a missing chunk, (3) a foreign file in the directory
    let p1 = format!("snapshots/{}/chunk-00001", hex(&ids[1])); let mut b = fs.raw(&p1).unwrap(); b[0] ^= 1; fs.delete_raw(&p1); fs.set_raw(&p1, b);
    fs.delete_raw(&format!("snapshots/{}/chunk-00000", hex(&ids[2])));
    fs.set_raw(&format!("snapshots/{}/extra", hex(&ids[0])), vec![1]);
    fs.mkdir_all("snapshots-tmp/leftover").unwrap(); fs.write_file("snapshots-tmp/leftover/chunk-00000", &[1, 2, 3]).unwrap(); fs.sync_file("snapshots-tmp/leftover/chunk-00000").unwrap(); fs.sync_dir("snapshots-tmp/leftover").unwrap(); fs.sync_dir("snapshots-tmp").unwrap();
    let s2 = SnapshotStore::open(fs, rcfg(4, 1 << 20, 1 << 16), rl(), GENESIS_HASH).unwrap();
    assert_eq!(s2.retained().len(), 1, "only the undamaged snapshot is retained");
    assert_eq!(s2.retained()[0].1, ids[3]);
    assert_eq!(s2.stats.discarded_on_open, 3);
    assert!(s2.chunk(&ids[1], 1).is_none() && s2.chunk(&ids[2], 1).is_none(), "a damaged snapshot is never served");
    assert!(s2.fs.files_under("snapshots-tmp").is_empty(), "a leftover capture temporary is removed");
    assert_eq!(s2.retained_bytes(), disk_bytes(&s2.fs, "snapshots"));
}

#[test]
fn a_crash_at_any_point_of_a_capture_leaves_only_complete_verified_snapshots_and_never_a_pinned_loss() {
    // learn the number of mutating operations of one capture that evicts (4 retained at target 3 -> the capture of a 5th evicts)
    let setup = |f: TShared| -> Store { let mut fs = MemTreeFs::new(f); rextras(&mut fs); SnapshotStore::open(fs, rcfg(4, 1 << 20, 1 << 16), rl(), GENESIS_HASH).unwrap() };
    let total = { let f = tfaults(); let mut s = setup(f.clone()); for h in [8u64, 16, 24] { cap(&mut s, h).unwrap(); } let before = f.borrow().ops; cap(&mut s, 32).unwrap(); let t = f.borrow().ops; (before, t) };
    assert!(total.1 > total.0 + 6);
    let extras0 = { let mut fs = MemTreeFs::new(tfaults()); rextras(&mut fs); rextras_view(&fs) };
    let mut saw_old_only = 0; let mut saw_new = 0;
    for k in total.0..=total.1 {
        let f = tfaults(); let mut s = setup(f.clone());
        for h in [8u64, 16, 24] { cap(&mut s, h).unwrap(); }
        let pinned = s.retained()[0].1; s.pin(&pinned).unwrap(); // the oldest is pinned: the capture must keep it (count stays above target)
        f.borrow_mut().crash_before = Some(k);
        let _ = cap(&mut s, 32);
        for (n, fs2) in s.fs.crash_outcomes(6).into_iter().enumerate() {
            let s2 = SnapshotStore::open(fs2, rcfg(4, 1 << 20, 1 << 16), rl(), GENESIS_HASH).unwrap_or_else(|e| panic!("k={k} outcome {n}: reopen failed: {e}"));
            assert_eq!(s2.stats.discarded_on_open <= 1, true, "k={k} outcome {n}: at most the one snapshot being published/removed is discarded");
            for (c, id, _, _) in s2.retained() { let m = s2.manifest_for(&c).unwrap(); for i in 0..m.chunk_count { assert_eq!(rcodec::chunk_hash(i, &s2.chunk(&id, i).unwrap()), m.chunk_hashes[i as usize], "k={k} outcome {n}: every retained snapshot verifies"); } }
            assert!(s2.fs.files_under("snapshots-tmp").is_empty(), "k={k} outcome {n}");
            assert_eq!(rextras_view(&s2.fs), extras0, "k={k} outcome {n}: the installer's files are untouched");
            assert_eq!(s2.retained_bytes(), disk_bytes(&s2.fs, "snapshots"), "k={k} outcome {n}: accounting equals the disk");
            assert!(heights(&s2).contains(&8), "k={k} outcome {n}: the pinned (oldest) snapshot was never lost");
            if heights(&s2).contains(&32) { saw_new += 1 } else { saw_old_only += 1 }
        }
    }
    assert!(saw_new > 0 && saw_old_only > 0, "the matrix reached both 'published' ({saw_new}) and 'not yet published' ({saw_old_only})");
}
