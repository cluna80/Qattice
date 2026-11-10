//! AN-2: anchored verification (docs/pq-hotstuff-2/phase11-anchored-evidence-scope.md, sections 5 A+B and 6A; plan in phase11-an2-anchored-verification.md). Compiled only with
//! the `pq-anchored-evidence` feature (off by default). **Library only**: nothing in the node, driver or network calls this; no anchor mode exists; nothing lets a node START
//! from an anchor; pruning stays unimplemented.
//!
//! Four pieces, all on the EXISTING verifier (`verify_header_chain`), whose rules are the engine's:
//! 1. [`resume_point`]: the EXACT verification state carried across a segment boundary, as an [`Anchor`] at the highest block the segment itself finalized.
//! 2. [`verify_segments`]: a long chain verified in bounded segments. An UNFINISHED finality relationship survives a boundary because the boundary is always placed AT a
//!    finalized block and every header above it is RE-PRESENTED to the next segment; nothing is ever finalized from state remembered outside a verified segment.
//! 3. [`build_record`] / [`cross_check`]: an anchor record built ONLY from this node's own [`CheckpointSeed`] (which only `authenticate_checkpoint` constructs), and the
//!    start-time re-verification of its finality proof against the genesis validator set.
//! 4. [`Audit`]: the resumable re-verification of genesis to the anchor that closes the gap the cross-check leaves (detection, not prevention).
//!
//! **What the cross-check proves, and what it does not (T5).** [`cross_check`] re-verifies real signatures: it proves that a quorum of the GENESIS validator set certified the
//! anchor block id, that the proof's headers chain from it under the engine's rules, and that a block carrying the record's reference became FINAL above it, so the anchor and
//! the reference's state root are attested by genesis-rooted keys. It does NOT prove that the history from genesis to the anchor was rule-valid (R1-R4, R6, the attested roots),
//! and it canNOT validate the anchor's own HISTORY CLAIMS (`final_height`, `last_ref`, `ancestors`) beyond what the proof's own reference checks happen to consume: those claims
//! rest on this node's earlier verification and on its local storage until the [`Audit`] has re-verified them from genesis. Re-verifying certificates alone never turns an
//! arbitrary persisted anchor into trusted history; provenance stays uncertain until the audit reaches the anchor.
use super::anchor_record::{AnchorBinding, AnchorError, AnchorLimits, AnchorProof, AnchorRecord, Provenance};
use super::certs::Cert;
use super::checkpoint::{effective_genesis_hash, ChainRefState};
use super::header::{verify_header_chain, Anchor, ChainParams, ChainPoint, HeaderError, PayloadFreeBlock, Start, VerifiedChain};
use super::safety::ConsensusVerifier;
use super::seed::CheckpointSeed;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SegmentError {
    #[error("header chain: {0}")]
    Headers(#[from] HeaderError),
    #[error("no block became final within one whole segment at offset {at}: the segment limit is too small to carry verification state forward")]
    NoProgress { at: usize },
    #[error("a segment limit of zero verifies nothing")]
    ZeroSegment,
}

/// The verification state carried across a segment boundary: an [`Anchor`] at the HIGHEST BLOCK THIS RUN ITSELF FINALIZED (never the unfinalized tip), carrying exactly
/// (1) that block's id, height and round; (2) its parent's round (needed to finalize the anchor's parent-side neighbour in the next segment -- it never is: the anchor is
/// already final); (3) the chain's `F(B)` and most recent checkpoint reference AT that block, verbatim from the verified state, so the reference rules R1-R4/R6 continue
/// with the same inputs; (4) the `(height, id)` window of blocks below it that a NEW reference may still name under the freshness bound (R3/R6) -- heights older than
/// `F(B) - max_age` are dropped because R6 refuses them before R3 ever looks. Returns the anchor and the number of verified headers it consumes (the boundary position);
/// `None` when the run finalized nothing, in which case no state may be carried and the caller must present a larger run.
pub fn resume_point(p: &ChainParams, start: &Start, vc: &VerifiedChain) -> Option<(Anchor, usize)> {
    let top = *vc.finalized.last()?;
    let i = vc.points.iter().position(|x| x.point.id == top.id)?;
    let pt = &vc.points[i];
    let parent_round = if i > 0 { vc.points[i - 1].point.round } else { match start { Start::Anchor(a) => a.round, Start::Genesis => 0 } };
    let lo = p.checkpoint.map_or(u64::MAX, |c| pt.state.final_height.saturating_sub(c.max_age));
    let mut ancestors: Vec<(u64, super::certs::BlockId)> = vc.points[..i].iter().map(|x| (x.point.height, x.point.id)).collect();
    if let Start::Anchor(a) = start { ancestors.push((a.height, a.id)); ancestors.extend(a.ancestors.iter().copied()); }
    ancestors.retain(|(h, _)| *h >= lo && *h < pt.point.height);
    ancestors.sort_by_key(|(h, _)| *h);
    ancestors.dedup_by_key(|(h, _)| *h);
    Some((Anchor { id: pt.point.id, height: pt.point.height, round: pt.point.round, parent_round, final_height: pt.state.final_height, last_ref: pt.state.last_ref, ancestors }, i + 1))
}

/// The result of a segmented run: the same tip and (concatenated) finalized blocks an uninterrupted [`verify_header_chain`] over the whole input yields, plus the final
/// carried state. Headers above the last boundary that did not finalize are re-verified by the following segment, so `segments` counts verification passes, not disjoint
/// header spans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segmented { pub tip: ChainPoint, pub finalized: Vec<ChainPoint>, pub resume: Option<Anchor>, pub segments: usize }

/// Verify `headers` from `start` in segments of at most `seg` headers, carrying state with [`resume_point`]. Memory is bounded by the segment, work stays proportional to
/// the distance (re-presented suffixes add at most one segment of overlap per boundary). The result equals the uninterrupted run's `tip` and `finalized`; an invalid header
/// is refused exactly as the uninterrupted run refuses it (the error's index is segment-relative).
pub fn verify_segments<V: ConsensusVerifier>(p: &ChainParams, v: &V, start: Start, headers: &[PayloadFreeBlock], final_qc: Option<&Cert>, seg: usize) -> Result<Segmented, SegmentError> {
    if seg == 0 { return Err(SegmentError::ZeroSegment); }
    let (mut cur, mut consumed, mut finalized, mut segments) = (start, 0usize, Vec::new(), 0usize);
    let mut resume: Option<Anchor> = None;
    loop {
        let end = (consumed + seg).min(headers.len());
        let slice = &headers[consumed..end];
        let last = end == headers.len();
        let vc = verify_header_chain(p, v, cur.clone(), slice, if last { final_qc } else { None }, seg)?;
        segments += 1;
        finalized.extend(vc.finalized.iter().copied());
        let rp = resume_point(p, &cur, &vc);
        if last {
            if let Some((a, _)) = rp { resume = Some(a); }
            return Ok(Segmented { tip: vc.tip, finalized, resume, segments });
        }
        match rp {
            Some((a, k)) => { consumed += k; cur = Start::Anchor(a.clone()); resume = Some(a); }
            None => return Err(SegmentError::NoProgress { at: consumed }),
        }
    }
}

/// Build an anchor record from this node's OWN authentication: `seed` can only be constructed by `authenticate_checkpoint`, so a record never summarises anything this node
/// did not verify itself (T2). The anchor is the authenticated checkpoint block; the proof is the SHORTEST run of `headers` strictly above it that re-verification needs: up
/// to a final carrier of the reference and the two further headers (or the final certificate) whose certificates make it final. `audited_height` is the caller's claim of how
/// far its verification reached FROM GENESIS (the anchor height itself when `start` was genesis; the previous record's value when extending an anchor); it is stored, never
/// derived. The built record is re-decoded under `lim`, so what is returned is exactly what a later open would accept.
pub fn build_record(
    seed: &CheckpointSeed, headers: &[PayloadFreeBlock], final_qc: Option<&Cert>,
    generation: u64, provenance: Provenance, audited_height: u64, binding: AnchorBinding, lim: &AnchorLimits,
) -> Result<AnchorRecord, AnchorError> {
    let base = seed.base();
    let cref = *seed.reference();
    if audited_height > base.height { return Err(AnchorError::Record("audited height above the anchor")); }
    let above: Vec<PayloadFreeBlock> = headers.iter().filter(|h| h.height > base.height).cloned().collect();
    if above.first().map(|h| h.height) != Some(base.height + 1) { return Err(AnchorError::Record("no headers above the anchor")); }
    // the first final carrier of the reference, then the first consecutive-round pair at or above it; the pair's certifier closes the proof
    let ci = above.iter().position(|h| h.checkpoint == Some(cref)).ok_or(AnchorError::Record("no carrier of the reference above the anchor"))?;
    let mut end = None;
    for m in ci..above.len().saturating_sub(1) {
        if above[m].round.checked_add(1) == Some(above[m + 1].round) {
            if m + 2 < above.len() { end = Some((m + 2, false)); } else { end = Some((m + 1, true)); }
            break;
        }
    }
    let (end, needs_qc) = end.ok_or(AnchorError::Record("no finality above the carrier"))?;
    let fq = if needs_qc { Some(final_qc.ok_or(AnchorError::Record("no finality above the carrier"))?.clone()) } else { None };
    let rec = AnchorRecord {
        generation, binding,
        anchor: Anchor { id: base.id, height: base.height, round: base.round, parent_round: base.parent_round, final_height: base.state.final_height, last_ref: base.state.last_ref, ancestors: base.ancestors.clone() },
        reference: cref,
        proof: AnchorProof { headers: above[..=end].to_vec(), final_qc: fq },
        provenance, audited_height,
    };
    AnchorRecord::decode(&rec.encode(), lim)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CrossCheckError {
    #[error("the record is bound to another genesis, profile, chain, validator set or checkpoint parameters")]
    Binding,
    #[error("anchor record structure: {0}")]
    Structure(&'static str),
    #[error("proof: {0}")]
    Headers(#[from] HeaderError),
    #[error("no FINAL header of the proof carries the record's reference")]
    ReferenceNotAttested,
}

/// Evidence that [`cross_check`] re-verified a record's finality proof against the GENESIS validator set. It states exactly this and no more: a genesis-keyed quorum
/// certified the anchor block id, the proof's headers chain from it under the engine's rules, and a FINAL header above the anchor carries the record's reference. It does
/// NOT state that the history from genesis to the anchor was rule-valid, nor that the anchor's history claims (`final_height`, `last_ref`, `ancestors`) are true: those are
/// this node's own earlier verification until [`Audit`] has re-verified them (see the module documentation). It is a cross-check on a LOCAL record, never an authentication
/// of imported history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofChecked { pub anchor_height: u64, pub proof_headers: usize }

/// Re-verify a record's finality proof against the node's OWN parameters and the genesis validator set (section 6A, start check (c)/(d)): the binding is recomputed and
/// compared; the reference must name the anchor block itself; every proof header's id is recomputed, its proposer, quorum and timeout certificates verified with real
/// signatures from the genesis set, chaining from the anchor; and a FINAL header of the proof must carry the reference. The anchor's finality follows: the committed pair's
/// ancestors include it. See [`ProofChecked`] for what this does NOT establish.
pub fn cross_check<V: ConsensusVerifier>(rec: &AnchorRecord, p: &ChainParams, v: &V, lim: &AnchorLimits) -> Result<ProofChecked, CrossCheckError> {
    let eff = effective_genesis_hash(p.protocol_profile, &p.genesis_hash, p.checkpoint.as_ref()).map_err(|_| CrossCheckError::Binding)?;
    let cp = p.checkpoint.as_ref().ok_or(CrossCheckError::Binding)?;
    let own = AnchorBinding { genesis_hash: eff, profile: p.protocol_profile.to_string(), chain_id: p.chain_id.to_string(), valset_hash: p.set.validator_set_hash(), interval: cp.interval, max_age: cp.max_age };
    if rec.binding != own { return Err(CrossCheckError::Binding); }
    if rec.reference.height != rec.anchor.height || rec.reference.block_id != rec.anchor.id { return Err(CrossCheckError::Structure("the reference does not name the anchor block")); }
    let vc = verify_header_chain(p, v, Start::Anchor(rec.anchor.clone()), &rec.proof.headers, rec.proof.final_qc.as_ref(), lim.max_proof_headers)?;
    let is_final = |id: &super::certs::BlockId| vc.finalized.iter().any(|f| f.id == *id);
    if !vc.points.iter().any(|x| x.carried == Some(rec.reference) && is_final(&x.point.id)) { return Err(CrossCheckError::ReferenceNotAttested); }
    Ok(ProofChecked { anchor_height: rec.anchor.height, proof_headers: rec.proof.headers.len() })
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    #[error("segments: {0}")]
    Segments(#[from] SegmentError),
    #[error("the fed headers do not continue from the audit's resume state")]
    NotContiguous,
    #[error("the audit reached the anchor height and the record does not match the re-verified chain: {0}")]
    Mismatch(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditStep {
    /// The highest height re-verified AND finalized from genesis so far, capped at the anchor: what `AnchorRing::set_audited` may durably record.
    pub audited_height: u64,
    /// True once the anchor height is finalized by the audit's own run and every compared field matched.
    pub complete: bool,
}

/// The resumable re-verification of genesis to the anchor (section 6A: DETECTION under the trusted-local-storage assumption, not prevention -- it can only find a bad anchor
/// LATER and undoes nothing). Feed it headers from genesis in bounded runs; it verifies them in segments, reports forward-only progress for `AnchorRing::set_audited`, and,
/// when its own verification crosses the anchor height, compares the re-verified chain against EVERY anchor field a start trusts: the block id, round, parent round, `F(B)`,
/// the last reference and the ancestors window. Any difference is [`AuditError::Mismatch`]: the caller must treat the anchor as bad (fail closed; the node never repairs
/// itself). The audit holds no files: persisting its resume state is the caller's (a later slice's) concern; after a restart it resumes from genesis or from a height whose
/// state the caller re-derives by re-feeding headers.
pub struct Audit {
    anchor: Anchor,
    cur: Start,
    next_height: u64,
    audited: u64,
    seg: usize,
    checked_anchor: bool,
}

impl Audit {
    /// Audit `rec` from genesis, verifying at most `seg` headers per segment.
    pub fn new(rec: &AnchorRecord, seg: usize) -> Result<Audit, SegmentError> {
        if seg == 0 { return Err(SegmentError::ZeroSegment); }
        Ok(Audit { anchor: rec.anchor.clone(), cur: Start::Genesis, next_height: 1, audited: 0, seg, checked_anchor: false })
    }
    /// The height the next fed header must have.
    pub fn next_height(&self) -> u64 { self.next_height }
    /// The carried verification state (an anchor at the last block the audit finalized, or genesis), for a caller that wants to persist it later.
    pub fn resume(&self) -> &Start { &self.cur }

    /// Verify the next run of headers (which must start exactly at [`Audit::next_height`]). Headers above the anchor height are verified too (they must still chain), but the
    /// audit completes as soon as the anchor height is FINAL in its own run and the record matched.
    pub fn advance<V: ConsensusVerifier>(&mut self, p: &ChainParams, v: &V, headers: &[PayloadFreeBlock]) -> Result<AuditStep, AuditError> {
        if headers.first().map(|h| h.height) != Some(self.next_height) { return Err(AuditError::NotContiguous); }
        let mut consumed = 0usize;
        while consumed < headers.len() {
            let end = (consumed + self.seg).min(headers.len());
            let vc = verify_header_chain(p, v, self.cur.clone(), &headers[consumed..end], None, self.seg).map_err(SegmentError::from)?;
            // the moment the re-verified chain covers the anchor height, every field a start would trust is compared (id first: a different block there is already a mismatch)
            if !self.checked_anchor {
                if let Some(i) = vc.points.iter().position(|x| x.point.height == self.anchor.height) {
                    let (pt, prev_round) = (&vc.points[i], if i > 0 { vc.points[i - 1].point.round } else { match &self.cur { Start::Anchor(a) => a.round, Start::Genesis => 0 } });
                    if pt.point.id != self.anchor.id { return Err(AuditError::Mismatch("block id at the anchor height")); }
                    if pt.point.round != self.anchor.round { return Err(AuditError::Mismatch("round")); }
                    if prev_round != self.anchor.parent_round { return Err(AuditError::Mismatch("parent round")); }
                    if pt.state != (ChainRefState { final_height: self.anchor.final_height, last_ref: self.anchor.last_ref }) { return Err(AuditError::Mismatch("final height or last reference")); }
                    for (h, id) in &self.anchor.ancestors {
                        let found = vc.points[..i].iter().find(|x| x.point.height == *h).map(|x| x.point.id).or_else(|| match &self.cur { Start::Anchor(a) => (a.height == *h).then_some(a.id).or_else(|| a.ancestors.iter().find(|(ah, _)| ah == h).map(|(_, aid)| *aid)), Start::Genesis => None });
                        if found != Some(*id) { return Err(AuditError::Mismatch("ancestors window")); }
                    }
                    self.checked_anchor = true;
                }
            }
            match resume_point(p, &self.cur, &vc) {
                Some((a, k)) => { consumed += k; self.audited = self.audited.max(a.height.min(self.anchor.height)); self.next_height = a.height + 1; self.cur = Start::Anchor(a); }
                None => { if end == headers.len() { break; } return Err(AuditError::Segments(SegmentError::NoProgress { at: consumed })); }
            }
        }
        Ok(AuditStep { audited_height: self.audited, complete: self.checked_anchor && self.audited >= self.anchor.height })
    }
}
