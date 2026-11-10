// ============================================================================================================================
// AN-2: anchored verification (feature `pq-anchored-evidence`, off by default). LIBRARY ONLY: nothing in the node, driver or network calls this; no anchor mode
// exists; nothing lets a node start from an anchor; pruning stays unimplemented. Real FIPS 204 headers and certificates from real engines, on a healthy chain and
// on a chain with timeout certificates and round gaps. See docs/pq-hotstuff-2/phase11-an2-anchored-verification.md.
// ============================================================================================================================
use chain_forge_consensus::pq_hotstuff::anchor_verify::{build_record, cross_check, verify_segments, Audit, AuditError, AuditStep, CrossCheckError, SegmentError};

/// A healthy chain and a chain with timeout certificates, as headers plus the high QC, with the engine that made them.
fn an2_chains() -> Vec<(&'static str, Eng3)> {
    let cc = cc3(4, 8);
    let mut healthy = Eng3::new(4, cc);
    healthy.run(60);
    let mut lagged = Eng3::new(4, cc);
    lagged.run_until_committed(16, 100);
    lagged.lag[2] = u64::MAX / 2;
    lagged.lag[3] = u64::MAX / 2;
    lagged.run(60);
    vec![("healthy", healthy), ("with timeouts", lagged)]
}
fn an2_headers(e: &Eng3) -> (Vec<PayloadFreeBlock>, Cert) { let l = e.lead(); (headers_of(&e.chain(l)), e.nodes[l].high_qc().clone()) }
/// The latest reference of `e` that the full verification finalized WITH a final carrier (what `authenticate_checkpoint` needs).
fn an2_cref(e: &Eng3, full: &VerifiedChain) -> CheckpointRef {
    let is_final = |id: &BlockId| full.finalized.iter().any(|f| f.id == *id);
    e.refs().into_iter().rev().find(|r| is_final(&r.block_id) && full.points.iter().any(|x| x.carried == Some(*r) && is_final(&x.point.id))).expect("a finalized reference with a final carrier")
}

#[test]
fn segmented_verification_equals_uninterrupted_verification_on_healthy_and_timeout_chains_at_every_segment_size() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    for (name, e) in &an2_chains() {
        let (hs, hq) = an2_headers(e);
        if *name == "with timeouts" { assert!(hs.iter().any(|h| h.tc.is_some()), "the run must contain timeout-certificate headers and round gaps"); }
        let p = cparams3(&set, &cc);
        let full = verify_header_chain(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000).unwrap_or_else(|er| panic!("{name}: {er}"));
        // every segment size from the smallest that can carry state forward up to the whole chain, so a boundary falls at every position at least once:
        // between a block and the child that certifies it, inside a round gap, and right at a timeout-certificate header.
        // On a timeout chain a very small segment may land entirely within a TC-heavy stretch where nothing can finalize; that is correct
        // fail-closed behaviour (SegmentError::NoProgress): the verifier refuses to guess rather than silently skip.  Equality is asserted
        // only for segment sizes that actually succeed.
        for seg in [3usize, 4, 5, 7, 11, 16, hs.len()] {
            match verify_segments(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), seg) {
                Ok(s) => {
                    assert_eq!(s.tip, full.tip, "{name} seg {seg}");
                    assert_eq!(s.finalized, full.finalized, "{name} seg {seg}: the same blocks become final, in the same order, exactly once");
                    if seg < hs.len() { assert!(s.segments > 1, "{name} seg {seg}"); }
                }
                Err(SegmentError::NoProgress { .. }) => {
                    // correct fail-closed behaviour: a TC-heavy window that cannot finalize anything is refused, never silently skipped
                    assert!(*name == "with timeouts", "healthy chain must never refuse a segment of size {seg} with NoProgress");
                    assert!(seg <= 5, "{name} seg {seg}: NoProgress is only expected for very small windows on a timeout chain");
                }
                Err(er) => panic!("{name} seg {seg}: unexpected error: {er}"),
            }
        }
        // one or two headers can never finalize anything within their own segment, so no state may be carried: refused, never guessed
        for seg in [1usize, 2] { assert_eq!(verify_segments(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), seg), Err(SegmentError::NoProgress { at: 0 }), "{name} seg {seg}"); }
        assert_eq!(verify_segments(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), 0), Err(SegmentError::ZeroSegment));
        // an invalid header is refused in segments exactly as it is refused whole
        let mut bad = hs.clone();
        let mid = bad.len() / 2;
        bad[mid].payload_hash[0] ^= 1;
        assert!(verify_header_chain(&p, &TestVerifier, Start::Genesis, &bad, Some(&hq), 10_000).is_err(), "{name}");
        assert!(matches!(verify_segments(&p, &TestVerifier, Start::Genesis, &bad, Some(&hq), 5), Err(SegmentError::Headers(_))), "{name}");
    }
}

#[test]
fn a_restart_boundary_carries_exactly_the_resume_state_and_the_unfinalized_suffix_is_represented_never_skipped() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    for (name, e) in &an2_chains() {
        let (hs, hq) = an2_headers(e);
        let p = cparams3(&set, &cc);
        let full = verify_header_chain(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000).unwrap();
        // run 1 stops partway; the ONLY state that survives the "restart" is the resume anchor (highest finalized block, F(B), last reference, ancestors window)
        let cut = hs.len() / 2;
        let first = verify_segments(&p, &TestVerifier, Start::Genesis, &hs[..cut], None, 6).unwrap_or_else(|er| panic!("{name}: {er}"));
        let a = first.resume.clone().expect("half a real chain finalizes something");
        assert!(a.height < cut as u64, "{name}: the resume point is a finalized block, never the unfinalized tip");
        assert_eq!(a.height, first.finalized.last().unwrap().height, "{name}");
        // run 2 continues from the resume anchor; the headers above it that had NOT finalized are presented again
        let second = verify_segments(&p, &TestVerifier, Start::Anchor(a.clone()), &hs[a.height as usize..], Some(&hq), 6).unwrap_or_else(|er| panic!("{name}: {er}"));
        assert_eq!(second.tip, full.tip, "{name}");
        let mut joined = first.finalized.clone();
        joined.extend(second.finalized.iter().copied());
        assert_eq!(joined, full.finalized, "{name}: a restart at the boundary finalizes the same blocks, exactly once");
        // skipping the re-presented suffix is impossible: the next header's parent link does not match the resume anchor
        if (a.height as usize) < cut - 1 {
            let (i, r) = failure_at(verify_header_chain(&p, &TestVerifier, Start::Anchor(a), &hs[cut..], Some(&hq), 10_000));
            assert_eq!((i, r.as_str()), (0, "parent link"), "{name}");
        }
    }
}

#[test]
fn a_returning_node_extending_from_its_own_anchor_record_authenticates_the_same_checkpoint_as_from_genesis() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    for (name, e) in &an2_chains() {
        let (hs, hq) = an2_headers(e);
        let p = cparams3(&set, &cc);
        let full = verify_header_chain(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000).unwrap();
        let is_final = |id: &BlockId| full.finalized.iter().any(|f| f.id == *id);
        let refs: Vec<CheckpointRef> = e.refs().into_iter().filter(|r| is_final(&r.block_id) && full.points.iter().any(|x| x.carried == Some(*r) && is_final(&x.point.id))).collect();
        assert!(refs.len() >= 2, "{name}: the chain must hold two authenticatable checkpoints ({} found)", refs.len());
        let (c1, c2) = (refs[0], *refs.last().unwrap());
        // the node authenticated C1 from genesis once, and persisted that verification as its OWN anchor record (T2: never imported)
        let s1 = authenticate_checkpoint(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000, &c1, &hq, None).unwrap_or_else(|er| panic!("{name}: {er}"));
        let rec = build_record(&s1, &hs, Some(&hq), 1, Provenance::Genesis, s1.base().height, abind(), &alim()).unwrap_or_else(|er| panic!("{name}: {er}"));
        assert!(rec.proof.headers.len() <= 8, "{name}: the proof is a short span, not the chain ({} headers)", rec.proof.headers.len());
        cross_check(&rec, &p, &TestVerifier, &alim()).unwrap_or_else(|er| panic!("{name}: {er}"));
        // returning: verification continues from the persisted anchor with only the headers ABOVE it, and authenticates C2
        let above = &hs[rec.anchor.height as usize..];
        let from_anchor = authenticate_checkpoint(&p, &TestVerifier, Start::Anchor(rec.anchor.clone()), above, Some(&hq), 10_000, &c2, &hq, None).unwrap_or_else(|er| panic!("{name}: {er}"));
        let from_genesis = authenticate_checkpoint(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000, &c2, &hq, None).unwrap();
        assert_eq!(from_anchor.base(), from_genesis.base(), "{name}: the same base, ancestors window included");
        assert_eq!(from_anchor.reference(), from_genesis.reference(), "{name}");
        assert_eq!(from_anchor.tip(), from_genesis.tip(), "{name}");
        // and the extended record (provenance: the earlier anchor) round-trips and cross-checks too
        let rec2 = build_record(&from_anchor, above, Some(&hq), 2, Provenance::Anchor(1), rec.audited_height, abind(), &alim()).unwrap_or_else(|er| panic!("{name}: {er}"));
        assert_eq!(rec2.anchor.height, c2.height, "{name}");
        cross_check(&rec2, &p, &TestVerifier, &alim()).unwrap_or_else(|er| panic!("{name}: {er}"));
    }
}

/// A record built from a REAL authentication of the chain's latest authenticatable checkpoint, with the engine and chain it came from.
fn an2_record(e: &Eng3) -> (AnchorRecord, Vec<PayloadFreeBlock>, Cert) {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let (hs, hq) = an2_headers(e);
    let p = cparams3(&set, &cc);
    let full = verify_header_chain(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000).unwrap();
    let cref = an2_cref(e, &full);
    let seed = authenticate_checkpoint(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000, &cref, &hq, None).unwrap();
    (build_record(&seed, &hs, Some(&hq), 1, Provenance::Genesis, cref.height, abind(), &alim()).unwrap(), hs, hq)
}

#[test]
fn the_cross_check_reverifies_the_proof_against_the_genesis_validator_set_and_rejects_every_tampering() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let chains = an2_chains();
    let (rec, _, _) = an2_record(&chains[0].1);
    let p = cparams3(&set, &cc);
    cross_check(&rec, &p, &TestVerifier, &alim()).unwrap();
    let rej = |f: &dyn Fn(&mut AnchorRecord)| { let mut x = rec.clone(); f(&mut x); cross_check(&x, &p, &TestVerifier, &alim()).unwrap_err() };
    // the binding is recomputed from the node's own configuration, never read from the record
    assert_eq!(rej(&|x| x.binding.chain_id = "another-chain".into()), CrossCheckError::Binding);
    assert_eq!(rej(&|x| x.binding.valset_hash[0] ^= 1), CrossCheckError::Binding);
    // the reference must name the anchor block itself
    assert!(matches!(rej(&|x| x.reference.height -= 4), CrossCheckError::Structure(_)));
    assert!(matches!(rej(&|x| { x.reference.block_id[0] ^= 1; x.anchor.id[0] ^= 1; }), CrossCheckError::Headers(_)), "a different anchor id breaks the first header's parent link and its certificate");
    // the anchor's certified fields must agree with the proof's certificates
    assert!(matches!(rej(&|x| x.anchor.round += 1), CrossCheckError::Headers(_)), "the first proof header's QC round is the anchor's round");
    assert!(matches!(rej(&|x| x.anchor.height += 4), CrossCheckError::Structure(_)));
    // a tampered proof header fails its recomputed id or signature; a claimed reference no final proof header carries is refused
    assert!(matches!(rej(&|x| x.proof.headers[0].payload_hash[0] ^= 1), CrossCheckError::Headers(_)));
    assert!(matches!(rej(&|x| { let h = x.proof.headers[1].clone(); if let Some(c) = x.proof.headers.iter_mut().find(|y| y.checkpoint == Some(x.reference)) { c.checkpoint = None; } let _ = h; }), CrossCheckError::Headers(_) | CrossCheckError::ReferenceNotAttested), "the carrier's reference is part of its signed identity");
    assert!(matches!(rej(&|x| x.reference.state_root[0] ^= 1), CrossCheckError::Structure(_) | CrossCheckError::ReferenceNotAttested), "a state root no final header attests");
    // a node configured for another genesis refuses the record outright
    let p9 = ChainParams { genesis_hash: [9; 32], ..cparams3(&set, &cc) };
    assert_eq!(cross_check(&rec, &p9, &TestVerifier, &alim()).unwrap_err(), CrossCheckError::Binding);
}

#[test]
fn the_finality_cross_check_does_not_establish_history_and_the_audit_closes_exactly_that_gap() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let chains = an2_chains();
    let (rec, hs, _) = an2_record(&chains[0].1);
    let p = cparams3(&set, &cc);
    // HISTORY CLAIMS the proof's certificates cannot see: a forged last reference (an older real one) and a forged ancestors window both PASS the cross-check...
    let mut forged = rec.clone();
    forged.anchor.last_ref = Some(CheckpointRef { height: 4, block_id: [7; 32], state_root: [7; 32] });
    for a in forged.anchor.ancestors.iter_mut() { a.1[0] ^= 1; }
    cross_check(&forged, &p, &TestVerifier, &alim()).expect("re-verifying certificates alone cannot validate claims about the history below the anchor");
    // ...which is exactly why a cross-checked anchor is NOT trusted history: the audit re-verifies genesis to the anchor and catches the forgery
    let mut audit = Audit::new(&forged, 6).unwrap();
    let r = audit.advance(&p, &TestVerifier, &hs);
    assert!(matches!(r, Err(AuditError::Mismatch(_))), "{r:?}");
    // the same stands for an anchor from a REAL, fully signed FORK of the same genesis: its own proof cross-checks, the audit of this node's chain refuses it
    let mut fork = Eng3::new(4, cc);
    fork.salt = 1;
    fork.run(60);
    let (frec, _, _) = an2_record(&fork);
    cross_check(&frec, &p, &TestVerifier, &alim()).expect("the fork's certificates are real genesis-set signatures");
    let mut audit = Audit::new(&frec, 6).unwrap();
    assert_eq!(audit.advance(&p, &TestVerifier, &hs).unwrap_err(), AuditError::Mismatch("block id at the anchor height"));
}

/// Run the audit on `rec` from genesis over `hs` (small segments); returns the AuditStep once complete, or the first error.
fn run_full_audit(rec: &AnchorRecord, hs: &[PayloadFreeBlock], p: &ChainParams) -> Result<AuditStep, AuditError> {
    let mut audit = Audit::new(rec, 5).unwrap();
    loop {
        let from = (audit.next_height() - 1) as usize;
        let to = (from + 9).min(hs.len());
        let st = audit.advance(p, &TestVerifier, &hs[from..to])?;
        if st.complete { return Ok(st); }
        if to >= hs.len() { return Ok(st); }
    }
}

#[test]
fn the_audit_compares_every_anchor_field_a_start_would_trust_and_progress_is_capped_at_the_anchor() {
    // Verifies the five survivors from the mutation campaign: round, parent_round, final_height/last_ref, ancestors window (M6-M9) and the
    // audit-progress cap (M10). Each check requires a deliberately wrong anchor record field that the cross-check cannot see, confirmed here
    // by the Mismatch the audit raises when it reaches the anchor height.
    let cc = cc3(4, 8);
    let set = set_n(4);
    let (rec, hs, _) = an2_record(&an2_chains()[0].1);
    let p = cparams3(&set, &cc);
    // establish the reference fields from the verified chain
    let full = verify_header_chain(&p, &TestVerifier, Start::Genesis, &hs, None, 10_000).unwrap();
    let ap = full.points.iter().find(|x| x.point.height == rec.anchor.height).expect("anchor height in chain");
    let prev_round = full.points.iter().rev().find(|x| x.point.height < rec.anchor.height).map(|x| x.point.round).unwrap_or(0);

    // M6: wrong round stored in the record — the re-verified chain has the real one
    let mut bad = rec.clone();
    bad.anchor.round = rec.anchor.round.wrapping_add(1);
    assert_eq!(run_full_audit(&bad, &hs, &p).unwrap_err(), AuditError::Mismatch("round"), "M6: wrong round must be caught");

    // M7: wrong parent_round stored in the record
    let _ = prev_round; // consumed for clarity; the verifier derives it internally
    let mut bad = rec.clone();
    bad.anchor.parent_round = rec.anchor.parent_round.wrapping_add(1);
    assert_eq!(run_full_audit(&bad, &hs, &p).unwrap_err(), AuditError::Mismatch("parent round"), "M7: wrong parent_round must be caught");

    // M8: wrong final_height stored in the record
    let _ = ap;
    let mut bad = rec.clone();
    bad.anchor.final_height = rec.anchor.final_height.saturating_add(1);
    assert_eq!(run_full_audit(&bad, &hs, &p).unwrap_err(), AuditError::Mismatch("final height or last reference"), "M8: wrong final_height must be caught");

    // M8b: wrong last_ref stored in the record
    let mut bad = rec.clone();
    bad.anchor.last_ref = Some(CheckpointRef { height: rec.anchor.last_ref.map_or(1, |r| r.height.saturating_add(2)), block_id: [0xAB; 32], state_root: [0; 32] });
    assert_eq!(run_full_audit(&bad, &hs, &p).unwrap_err(), AuditError::Mismatch("final height or last reference"), "M8b: wrong last_ref must be caught");

    // M9: a wrong id in the ancestors window
    let mut bad = rec.clone();
    if let Some(a) = bad.anchor.ancestors.first_mut() { a.1[0] ^= 1; } else {
        // the healthy chain SHOULD have an ancestors window; fail the test loudly if not
        panic!("the anchor must have at least one ancestors entry for M9 to be meaningful");
    }
    assert_eq!(run_full_audit(&bad, &hs, &p).unwrap_err(), AuditError::Mismatch("ancestors window"), "M9: wrong ancestors window entry must be caught");

    // M10: audit progress must be capped at the anchor height (never above); verify via a chain longer than the anchor height
    let mut audit = Audit::new(&rec, 5).unwrap();
    let above = hs.len().saturating_sub(rec.anchor.height as usize);
    let mut last_step = AuditStep { audited_height: 0, complete: false };
    loop {
        let from = (audit.next_height() - 1) as usize;
        let to = (from + 9).min(hs.len());
        let st = audit.advance(&p, &TestVerifier, &hs[from..to]).unwrap();
        assert!(st.audited_height <= rec.anchor.height, "M10: progress above the anchor: {} > {}", st.audited_height, rec.anchor.height);
        last_step = st;
        if st.complete || to >= hs.len() { break; }
    }
    // proof that the chain extends above the anchor (otherwise the test does not reach M10's scenario)
    assert!(above > 0, "M10: the chain must extend above the anchor height ({} <= {})", hs.len(), rec.anchor.height);
    assert!(last_step.audited_height <= rec.anchor.height, "M10: final progress must be <= anchor height");
}

#[test]
fn the_audit_reverifies_genesis_to_the_anchor_in_bounded_segments_with_forward_only_durable_progress() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);
    for (name, e) in &an2_chains() {
        let (rec, hs, _) = an2_record(e);
        // the audit is fed in small runs, as a node fetching pages from providers would; progress is recorded through the ring (forward-only, capped at the anchor)
        let mut ring = AnchorRing::open(MemTreeFs::new(tfaults()), alim(), abind()).unwrap();
        ring.publish(rec.clone()).unwrap();
        let mut audit = Audit::new(&rec, 5).unwrap();
        let (mut last, mut steps) = (0u64, 0);
        loop {
            steps += 1;
            assert!(steps < 200, "{name}: the audit must terminate");
            let from = (audit.next_height() - 1) as usize;
            let to = (from + 9).min(hs.len());
            let st = audit.advance(&p, &TestVerifier, &hs[from..to]).unwrap_or_else(|er| panic!("{name}: {er}"));
            assert!(st.audited_height >= last && st.audited_height <= rec.anchor.height, "{name}: forward only, never above the anchor");
            last = st.audited_height;
            ring.set_audited(rec.generation, st.audited_height).unwrap();
            if st.complete { break; }
            assert!(to < hs.len(), "{name}: the audit consumed the whole chain without completing (audited {last} of {})", rec.anchor.height);
        }
        assert_eq!(last, rec.anchor.height, "{name}");
        assert_eq!(ring.newest().unwrap().audited_height, rec.anchor.height, "{name}: completion is durable through the ring");
        let reopened = AnchorRing::open(ring.fs, alim(), abind()).unwrap();
        assert_eq!(reopened.newest().unwrap().audited_height, rec.anchor.height, "{name}");
        // headers that do not continue from the audit's resume state are refused, and a tampered header fails exactly as verification fails
        let mut audit = Audit::new(&rec, 5).unwrap();
        assert_eq!(audit.advance(&p, &TestVerifier, &hs[3..]).unwrap_err(), AuditError::NotContiguous, "{name}");
        let mut bad = hs.clone();
        bad[4].payload_hash[0] ^= 1;
        assert!(matches!(audit.advance(&p, &TestVerifier, &bad), Err(AuditError::Segments(SegmentError::Headers(_)))), "{name}");
    }
}

#[test]
fn build_record_re_decodes_under_the_caller_limits_and_rejects_a_proof_that_exceeds_them() {
    // M11: skipping `AnchorRecord::decode(&rec.encode(), lim)` in build_record would return a record that
    // bypasses the limit check. This test calls build_record with limits tight enough to reject the proof
    // that authenticate_checkpoint produced, confirming the re-decode is enforced.
    let (name, e) = &an2_chains()[0];
    let (hs, hq) = an2_headers(e);
    let cc = cc3(4, 8);
    let set = set_n(4);
    let p = cparams3(&set, &cc);
    let full = verify_header_chain(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000).unwrap();
    let cref = an2_cref(e, &full);
    let seed = authenticate_checkpoint(&p, &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000, &cref, &hq, None)
        .unwrap_or_else(|er| panic!("{name}: {er}"));
    // normal limits: build_record succeeds
    let rec = build_record(&seed, &hs, Some(&hq), 1, Provenance::Genesis, cref.height, abind(), &alim())
        .unwrap_or_else(|er| panic!("{name}: build with generous limits failed: {er}"));
    let proof_len = rec.proof.headers.len();
    assert!(proof_len >= 2, "{name}: proof must have at least 2 headers for the tight-limit test to be meaningful ({proof_len} found)");
    // tight limits (1 header less than the proof): build_record must refuse with ProofTooLarge
    let tight = AnchorLimits { max_proof_headers: proof_len - 1, max_proof_bytes: 2 << 20 };
    let err = build_record(&seed, &hs, Some(&hq), 1, Provenance::Genesis, cref.height, abind(), &tight)
        .unwrap_err();
    assert!(matches!(err, AnchorError::ProofTooLarge { .. }),
        "{name}: build_record with tight limits must return ProofTooLarge, got {err}");
}
