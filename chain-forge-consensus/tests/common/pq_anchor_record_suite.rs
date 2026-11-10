// ============================================================================================================================
// AN-1: the local anchor record and its crash-safe two-generation ring (feature `pq-anchored-evidence`, off by default). STORAGE ONLY: nothing verifies an anchor's proof,
// creates one from verification, audits, or lets a node start from one. Real FIPS 204 headers and certificates from a real driver network. See
// docs/pq-hotstuff-2/phase11-anchored-evidence-scope.md, section 6A.
// ============================================================================================================================
use chain_forge_consensus::pq_hotstuff::anchor_record::{AnchorBinding, AnchorError, AnchorLimits, AnchorProof, AnchorRecord, AnchorRing, Provenance};

fn abind() -> AnchorBinding { AnchorBinding::of(&cfg3(0, 4, &cc3(4, 8))).expect("a v3 configuration has checkpoint parameters") }
fn alim() -> AnchorLimits { AnchorLimits { max_proof_headers: 64, max_proof_bytes: 2 << 20 } }
/// A record over REAL headers from the donor network: the proof is `n` headers starting at the first header at or above height 16.
fn arec(gen: u64, prov: Provenance, audited: u64, n: usize) -> AnchorRecord {
    let d = donor();
    let k = d.headers.iter().position(|h| h.height >= 16).unwrap();
    let h = &d.headers[k];
    AnchorRecord {
        generation: gen, binding: abind(),
        anchor: Anchor { id: d.ids[k], height: h.height, round: h.round, parent_round: d.headers[k - 1].round, final_height: h.height - 1, last_ref: d.headers[..k].iter().rev().find_map(|x| x.checkpoint), ancestors: vec![(h.height - 1, d.ids[k - 1]), (h.height - 2, d.ids[k - 2])] },
        reference: *d.refs.first().unwrap(), proof: AnchorProof { headers: d.headers[k..k + n].to_vec(), final_qc: Some(d.hq.clone()) }, provenance: prov, audited_height: audited,
    }
}
fn aextras(fs: &mut MemTreeFs) { fs.set_raw("generations/gen-00000000000000000003/app-state", vec![3; 100]); fs.set_raw("safety/state", vec![1, 2, 3]); fs.set_raw("app-pointer", vec![9; 10]); }
fn aextras_view(fs: &MemTreeFs) -> BTreeMap<String, Vec<u8>> { let mut m = fs.files_under("generations"); m.extend(fs.files_under("safety")); if let Some(p) = fs.raw("app-pointer") { m.insert("app-pointer".into(), p); } m }
fn aring() -> AnchorRing<MemTreeFs> { let mut fs = MemTreeFs::new(tfaults()); aextras(&mut fs); AnchorRing::open(fs, alim(), abind()).unwrap() }
fn agens(r: &AnchorRing<MemTreeFs>) -> Vec<u64> { r.generations().into_iter().map(|g| g.generation).collect() }

#[test]
fn the_binding_is_recomputed_from_the_nodes_own_configuration_and_a_different_one_is_not_equal() {
    let cc = cc3(4, 8);
    let base = AnchorBinding::of(&cfg3(0, 4, &cc)).unwrap();
    assert_eq!(base, AnchorBinding::of(&cfg3(1, 4, &cc)).unwrap(), "the binding does not depend on which validator this node is");
    assert_ne!(base, AnchorBinding::of(&cfg3(0, 4, &cc3(4, 16))).unwrap(), "other checkpoint parameters");
    assert_ne!(base, AnchorBinding::of(&cfg3(0, 4, &cc3(8, 16))).unwrap(), "another interval");
    assert_ne!(base, AnchorBinding::of(&EngineConfig { genesis_hash: [9; 32], ..cfg3(0, 4, &cc) }).unwrap(), "another genesis hash");
    assert_eq!(AnchorBinding::of(&cfg(0, 4)).unwrap_err(), AnchorError::NoCheckpointParams, "a profile-v2 configuration has no checkpoint parameters: anchors are not supported");
}

#[test]
fn a_record_round_trips_and_its_decoder_is_strict_about_everything_including_inconsistent_fields() {
    let r = arec(2, Provenance::Anchor(1), 8, 6);
    let b = r.encode();
    assert_eq!(AnchorRecord::decode(&b, &alim()).unwrap(), r);
    assert_eq!(AnchorRecord::decode(&arec(1, Provenance::Genesis, 16, 3).encode(), &alim()).unwrap().provenance, Provenance::Genesis);
    for cut in [0usize, 1, 20, 60, b.len() / 2, b.len() - 33, b.len() - 1] { assert!(AnchorRecord::decode(&b[..cut], &alim()).is_err(), "prefix {cut}"); }
    for at in [0usize, 25, 40, 100, b.len() / 3, b.len() / 2, b.len() - 40, b.len() - 1] { let mut m = b.clone(); m[at] ^= 1; assert!(AnchorRecord::decode(&m, &alim()).is_err(), "flip {at}"); }
    let mut t = b.clone(); t.push(0); assert!(AnchorRecord::decode(&t, &alim()).is_err());
    // limits: more headers than allowed, more bytes than allowed
    assert!(matches!(AnchorRecord::decode(&b, &AnchorLimits { max_proof_headers: 5, ..alim() }), Err(AnchorError::ProofTooLarge { .. })));
    assert!(matches!(AnchorRecord::decode(&b, &AnchorLimits { max_proof_bytes: 1000, ..alim() }), Err(AnchorError::ProofTooLarge { .. })));
    // a record with a VALID checksum but fields that contradict each other is refused by the decoder, not handed to a verifier
    let bad = |f: &dyn Fn(&mut AnchorRecord)| { let mut x = r.clone(); f(&mut x); AnchorRecord::decode(&x.encode(), &alim()).is_err() };
    assert!(bad(&|x| x.audited_height = x.anchor.height + 1), "audited height above the anchor");
    assert!(bad(&|x| x.reference.height = x.anchor.height + 1), "a reference above the anchor");
    assert!(bad(&|x| x.provenance = Provenance::Anchor(x.generation)), "provenance generation not older");
    assert!(bad(&|x| x.proof.headers.clear()), "an empty proof");
}

#[test]
fn anchored_start_is_unsupported_when_the_freshness_bound_needs_a_proof_larger_than_the_limits() {
    let b = abind(); // max_age 8 -> at most 11 headers
    let hb = 14_000u64;
    assert!(AnchorLimits { max_proof_headers: 11, max_proof_bytes: 11 * hb }.supports(&b, hb).is_ok());
    assert!(matches!(AnchorLimits { max_proof_headers: 10, max_proof_bytes: 1 << 30 }.supports(&b, hb), Err(AnchorError::ProofTooLarge { .. })), "headers");
    assert!(matches!(AnchorLimits { max_proof_headers: 64, max_proof_bytes: 11 * hb - 1 }.supports(&b, hb), Err(AnchorError::ProofTooLarge { .. })), "bytes");
    assert!(matches!(AnchorLimits { max_proof_headers: 0, max_proof_bytes: 1 }.supports(&b, hb), Err(AnchorError::ZeroLimit)));
    let huge = AnchorBinding { max_age: u64::MAX, ..b };
    assert!(alim().supports(&huge, hb).is_err(), "checked arithmetic");
}

#[test]
fn the_ring_is_forward_only_keeps_two_generations_and_refuses_a_foreign_binding() {
    let mut r = aring();
    assert!(r.newest().is_none());
    r.publish(arec(1, Provenance::Genesis, 16, 4)).unwrap();
    r.publish(arec(2, Provenance::Anchor(1), 16, 4)).unwrap();
    assert_eq!(agens(&r), vec![2, 1]);
    r.publish(arec(3, Provenance::Anchor(2), 16, 4)).unwrap();
    assert_eq!(agens(&r), vec![3, 2], "the oldest generation is removed only after the newest is durable");
    assert_eq!((r.newest().unwrap().generation, r.previous().unwrap().generation), (3, 2));
    assert!(matches!(r.publish(arec(3, Provenance::Genesis, 16, 4)), Err(AnchorError::NotForward { have: 3, got: 3 })));
    assert!(matches!(r.publish(arec(2, Provenance::Genesis, 16, 4)), Err(AnchorError::NotForward { .. })));
    let mut foreign = arec(4, Provenance::Anchor(3), 16, 4); foreign.binding.chain_id = "another-chain".into();
    assert_eq!(r.publish(foreign), Err(AnchorError::BindingMismatch));
    let mut tight = AnchorRing::open(MemTreeFs::new(tfaults()), AnchorLimits { max_proof_headers: 3, max_proof_bytes: 2 << 20 }, abind()).unwrap();
    assert!(matches!(tight.publish(arec(1, Provenance::Genesis, 16, 4)), Err(AnchorError::ProofTooLarge { .. })), "over the proof limits: refused before anything is written");
    assert!(tight.fs.files_under("anchors").is_empty() && tight.fs.files_under("anchors-tmp").is_empty());
    assert_eq!(agens(&r), vec![3, 2]);
    assert!(r.fs.files_under("anchors-tmp").is_empty());
    // reopening finds exactly the same
    let r2 = AnchorRing::open(r.fs, alim(), abind()).unwrap();
    assert_eq!(agens(&r2), vec![3, 2]);
    assert_eq!(r2.newest().unwrap(), &arec(3, Provenance::Anchor(2), 16, 4));
}

#[test]
fn damaged_foreign_misnamed_and_leftover_files_are_never_trusted_on_open() {
    let mut r = aring();
    r.publish(arec(1, Provenance::Genesis, 16, 4)).unwrap();
    r.publish(arec(2, Provenance::Anchor(1), 16, 4)).unwrap();
    let mut fs = r.fs;
    let p2 = "anchors/gen-00000000000000000002".to_string();
    let mut b = fs.raw(&p2).unwrap(); let mid = b.len() / 2; b[mid] ^= 1; fs.delete_raw(&p2); fs.set_raw(&p2, b);                      // damaged newest
    let mut foreign = arec(5, Provenance::Anchor(2), 16, 4); foreign.binding.valset_hash[0] ^= 1;                        // another validator set
    fs.set_raw("anchors/gen-00000000000000000005", foreign.encode());
    fs.set_raw("anchors/gen-00000000000000000009", arec(7, Provenance::Anchor(2), 16, 4).encode());                      // misnamed: the name says 9, the record says 7
    fs.set_raw("anchors/not-an-anchor", vec![1, 2, 3]);
    fs.mkdir_all("anchors-tmp/gen-00000000000000000006").unwrap(); fs.write_file("anchors-tmp/gen-00000000000000000006/x", &[1]).unwrap();
    let r2 = AnchorRing::open(fs, alim(), abind()).unwrap();
    assert_eq!(agens(&r2), vec![1], "only the undamaged, correctly bound, correctly named record survives");
    assert_eq!(r2.stats.discarded_on_open, 4);
    assert!(r2.fs.files_under("anchors-tmp").is_empty());
}

#[test]
fn audit_progress_is_forward_only_bounded_by_the_anchor_durable_and_never_trusted_when_damaged() {
    let mut r = aring();
    r.publish(arec(1, Provenance::Genesis, 8, 4)).unwrap();
    let top = r.newest().unwrap().anchor.height;
    assert!(r.set_audited(1, top + 1).is_err(), "above the anchor");
    assert!(r.set_audited(2, 10).is_err(), "no such generation");
    r.set_audited(1, 12).unwrap(); r.set_audited(1, 10).unwrap(); // a lower value is not an error and not a regression
    assert_eq!(r.newest().unwrap().audited_height, 12);
    let r2 = AnchorRing::open(r.fs, alim(), abind()).unwrap();
    assert_eq!(r2.newest().unwrap().audited_height, 12, "persisted");
    let mut fs = r2.fs;
    let mut p = fs.raw("anchors/audit-progress").unwrap(); let n = p.len(); p[n - 40] ^= 1; fs.delete_raw("anchors/audit-progress"); fs.set_raw("anchors/audit-progress", p);
    let r3 = AnchorRing::open(fs, alim(), abind()).unwrap();
    assert_eq!(r3.newest().unwrap().audited_height, 8, "a damaged progress file is ignored: the record's own value stands");
    assert_eq!(r3.stats.discarded_on_open, 1);
}

#[test]
fn a_crash_at_any_point_of_publishing_or_of_an_audit_update_leaves_the_old_or_the_new_state_and_never_loses_the_previous_generation_early() {
    let setup = |f: TShared| { let mut fs = MemTreeFs::new(f); aextras(&mut fs); let mut r = AnchorRing::open(fs, alim(), abind()).unwrap(); r.publish(arec(1, Provenance::Genesis, 16, 4)).unwrap(); r.publish(arec(2, Provenance::Anchor(1), 16, 4)).unwrap(); r };
    let extras0 = { let mut fs = MemTreeFs::new(tfaults()); aextras(&mut fs); aextras_view(&fs) };
    // (1) publishing generation 3
    let span = { let f = tfaults(); let mut r = setup(f.clone()); let a = f.borrow().ops; r.publish(arec(3, Provenance::Anchor(2), 16, 4)).unwrap(); let z = f.borrow().ops; (a, z) };
    assert!(span.1 > span.0 + 5);
    let (mut saw_old, mut saw_new) = (0, 0);
    for k in span.0..=span.1 {
        let f = tfaults(); let mut r = setup(f.clone());
        f.borrow_mut().crash_before = Some(k);
        let _ = r.publish(arec(3, Provenance::Anchor(2), 16, 4));
        for (n, fs2) in r.fs.crash_outcomes(6).into_iter().enumerate() {
            let r2 = AnchorRing::open(fs2, alim(), abind()).unwrap_or_else(|e| panic!("k={k} outcome {n}: {e}"));
            let g = agens(&r2);
            assert!(g == vec![2, 1] || g == vec![3, 2], "k={k} outcome {n}: {g:?}");
            if g[0] == 3 { saw_new += 1; assert_eq!(r2.newest().unwrap(), &arec(3, Provenance::Anchor(2), 16, 4), "k={k}: a published generation is complete"); } else { saw_old += 1; }
            assert!(r2.fs.files_under("anchors-tmp").is_empty(), "k={k} outcome {n}");
            assert_eq!(aextras_view(&r2.fs), extras0, "k={k} outcome {n}: application state, safety files and the application pointer are never touched");
        }
    }
    assert!(saw_old > 0 && saw_new > 0, "both outcomes reached: old {saw_old}, new {saw_new}");
    // (2) an audit-progress update that really writes (the records say 8; the update says 12)
    let setup2 = |f: TShared| { let mut fs = MemTreeFs::new(f); aextras(&mut fs); let mut r = AnchorRing::open(fs, alim(), abind()).unwrap(); r.publish(arec(1, Provenance::Genesis, 8, 4)).unwrap(); r.publish(arec(2, Provenance::Anchor(1), 8, 4)).unwrap(); r };
    let span = { let f = tfaults(); let mut r = setup2(f.clone()); let a = f.borrow().ops; r.set_audited(2, 12).unwrap(); let z = f.borrow().ops; (a, z) };
    assert!(span.1 > span.0, "the update performs mutating operations");
    let (mut low, mut high) = (0, 0);
    for k in span.0..=span.1 {
        let f = tfaults(); let mut r = setup2(f.clone());
        f.borrow_mut().crash_before = Some(k);
        let _ = r.set_audited(2, 12);
        for (n, fs2) in r.fs.crash_outcomes(6).into_iter().enumerate() {
            let r2 = AnchorRing::open(fs2, alim(), abind()).unwrap();
            let h = r2.newest().unwrap().audited_height;
            assert!(h == 8 || h == 12, "k={k} outcome {n}: {h} is neither the old nor the new value");
            if h == 12 { high += 1 } else { low += 1 }
            assert_eq!(agens(&r2), vec![2, 1]);
        }
    }
    assert!(low > 0 && high > 0, "both outcomes reached: old {low}, new {high}");
}

#[test]
fn a_stale_audit_progress_file_can_never_lower_the_audited_height() {
    let mut r = aring();
    r.publish(arec(1, Provenance::Genesis, 12, 4)).unwrap();
    let mut fs = r.fs;
    let progress = |gen: u64, h: u64| { let mut o = b"CFH1|anchor-audit|".to_vec(); o.extend_from_slice(&gen.to_be_bytes()); o.extend_from_slice(&h.to_be_bytes()); let sum = rcodec::sha3(&[&o]); o.extend_from_slice(&sum); o };
    fs.set_raw("anchors/audit-progress", progress(1, 10)); // valid, names the generation, but is BELOW what the record already says
    let r2 = AnchorRing::open(fs, alim(), abind()).unwrap();
    assert_eq!(r2.newest().unwrap().audited_height, 12, "progress only ever raises the audited height");
    let mut fs = r2.fs;
    fs.delete_raw("anchors/audit-progress"); fs.set_raw("anchors/audit-progress", progress(1, 14));
    let r3 = AnchorRing::open(fs, alim(), abind()).unwrap();
    assert_eq!(r3.newest().unwrap().audited_height, 14, "control: a higher valid progress value is applied");
    let top = r3.newest().unwrap().anchor.height;
    let mut fs = r3.fs;
    fs.delete_raw("anchors/audit-progress"); fs.set_raw("anchors/audit-progress", progress(1, top + 1));
    let r4 = AnchorRing::open(fs, alim(), abind()).unwrap();
    assert_eq!(r4.newest().unwrap().audited_height, 12, "progress above the anchor is ignored");
}
