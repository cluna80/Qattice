//! Checkpoint-start: authenticating a checkpoint and turning it into an engine root (DISABLED: no network path calls this; profile v3 and snapshot installation are off).
//!
//! **What authenticates a checkpoint.** Only the signatures of the validator set do: a [`CheckpointSeed`] can be built ONLY by [`authenticate_checkpoint`], which
//! (1) verifies a header chain from a trusted start (genesis or a previously authenticated anchor) with the same rules the engine applies, so every header is
//! signed by its round's leader and every parent is certified by a quorum QC; (2) requires the checkpoint block to be FINAL on that chain under the two-chain
//! predicate; (3) requires a FINAL header to carry the identical reference `(height, block id, state root)`, which is what attests the state root: every honest
//! voter of that block compared the root with its own execution (rule R5) or relied on an earlier final carrier; (4) verifies the high QC (and TC) and requires
//! the high QC to certify a header of the verified chain at or above the checkpoint. Nothing else is accepted: in particular an install record
//! ([`crate::pq_hotstuff::recovery::records::InstallRecord`]) records a LOCAL operation (which snapshot this machine staged and published) and proves neither
//! authenticity nor finality; it is only cross-checked by [`check_install_record`], never trusted instead of the above.
//!
//! The finality claim is the protocol's usual one: finalized under the stated fault (f < n/3 by voting power) and cryptographic (ML-DSA-65 unforgeability) assumptions.
use super::certs::{verify_cert, verify_tc, BlockId, Cert, GenesisCert, Tc, VerifyCtx};
use super::checkpoint::{effective_genesis_hash, ChainRefState, CheckpointRef};
use super::header::{verify_header_chain, ChainParams, ChainPoint, HeaderError, PayloadFreeBlock, Start};
use super::safety::ConsensusVerifier;

/// The checkpoint block as the engine's root: everything the engine needs to treat it as the finalized parent of new blocks, exactly as the header verifier's
/// `Start::Anchor` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base {
    pub id: BlockId,
    pub height: u64,
    pub round: u64,
    /// Round of the base's parent (0 when the parent is the genesis block).
    pub parent_round: u64,
    /// `F` and the last reference up to and including the base block.
    pub state: ChainRefState,
    /// `(height, id)` of blocks below the base that a new reference may still name (R3/R6); other heights below the base are unverifiable and fail closed.
    pub ancestors: Vec<(u64, BlockId)>,
}

/// An authenticated checkpoint. The fields are crate-private: there is no other constructor than [`authenticate_checkpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSeed {
    pub(crate) base: Base,
    pub(crate) cref: CheckpointRef,
    pub(crate) high_qc: Cert,
    pub(crate) high_tc: Option<Tc>,
    pub(crate) tip: ChainPoint,
    pub(crate) chain: Vec<ChainPoint>,
}

impl CheckpointSeed {
    pub fn base(&self) -> &Base { &self.base }
    pub fn reference(&self) -> &CheckpointRef { &self.cref }
    /// The last verified header; the blocks from the base up to here are the dependencies the engine needs before it may sign again.
    pub fn tip(&self) -> &ChainPoint { &self.tip }
    pub fn high_qc_round(&self) -> u64 { self.high_qc.round() }
    /// `(height, id)` of the blocks strictly above the base up to the high QC's block: the dependencies that must arrive as full blocks.
    pub fn required_blocks(&self) -> Vec<(u64, BlockId)> {
        let top = self.high_qc.block_id();
        let mut v = vec![];
        for p in self.chain.iter().filter(|p| p.height > self.base.height) { v.push((p.height, p.id)); if p.id == top { break; } }
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SeedError {
    #[error("header chain: {0}")]
    Headers(#[from] HeaderError),
    #[error("the checkpoint block is not final on the verified chain")]
    NotFinal,
    #[error("no FINAL header carries the identical reference, so its state root is not attested")]
    NoFinalCarrier,
    #[error("the high certificate is invalid: {0}")]
    HighCert(String),
    #[error("the high QC does not certify a verified header at or above the checkpoint")]
    HighQcNotOnChain,
    #[error("parameters: {0}")]
    Params(String),
    #[error("the install record does not match the authenticated checkpoint: {0}")]
    RecordMismatch(&'static str),
}

/// Authenticate `cref` against signed evidence. `headers` continue from `start`; `final_qc` may certify the last header. `high_qc`/`high_tc` are the highest
/// certificates the sender holds.
pub fn authenticate_checkpoint<V: ConsensusVerifier>(
    p: &ChainParams, v: &V, start: Start, headers: &[PayloadFreeBlock], final_qc: Option<&Cert>, max_headers: usize,
    cref: &CheckpointRef, high_qc: &Cert, high_tc: Option<&Tc>,
) -> Result<CheckpointSeed, SeedError> {
    let vc = verify_header_chain(p, v, start.clone(), headers, final_qc, max_headers)?;
    let is_final = |id: &BlockId| vc.finalized.iter().any(|f| f.id == *id);
    let k = vc.points.iter().position(|x| x.point.height == cref.height && x.point.id == cref.block_id).ok_or(SeedError::NotFinal)?;
    if !is_final(&cref.block_id) { return Err(SeedError::NotFinal); }
    if !vc.points.iter().any(|x| x.carried == Some(*cref) && is_final(&x.point.id)) { return Err(SeedError::NoFinalCarrier); }

    let genesis_hash = effective_genesis_hash(p.protocol_profile, &p.genesis_hash, p.checkpoint.as_ref()).map_err(|e| SeedError::Params(e.to_string()))?;
    let valset_hash = p.set.validator_set_hash();
    let genesis = GenesisCert { protocol_profile: p.protocol_profile.to_string(), chain_id: p.chain_id.to_string(), genesis_hash, valset_hash };
    let vctx = VerifyCtx { chain_id: p.chain_id, set: p.set, valset_hash, genesis: &genesis, verifier: v };
    if !matches!(high_qc, Cert::Qc(_)) { return Err(SeedError::HighCert("not a QC".into())); }
    verify_cert(&vctx, high_qc).map_err(|e| SeedError::HighCert(e.to_string()))?;
    if let Some(t) = high_tc { verify_tc(&vctx, t).map_err(|e| SeedError::HighCert(e.to_string()))?; }
    let top = high_qc.block_id();
    if !vc.points.iter().any(|x| x.point.id == top && x.point.height >= cref.height) { return Err(SeedError::HighQcNotOnChain); }

    let pt = vc.points[k];
    let parent_round = if k > 0 { vc.points[k - 1].point.round } else { match &start { Start::Anchor(a) => a.round, Start::Genesis => 0 } };
    // blocks below the base that a new reference could still name
    let lo = p.checkpoint.map_or(u64::MAX, |c| pt.state.final_height.saturating_sub(c.max_age));
    let mut ancestors: Vec<(u64, BlockId)> = vc.points[..k].iter().map(|x| (x.point.height, x.point.id)).collect();
    if let Start::Anchor(a) = &start { ancestors.push((a.height, a.id)); ancestors.extend(a.ancestors.iter().copied()); }
    ancestors.retain(|(h, _)| *h >= lo && *h < cref.height);
    ancestors.sort_by_key(|(h, _)| *h);
    ancestors.dedup_by_key(|(h, _)| *h);
    let chain: Vec<ChainPoint> = vc.points.iter().map(|x| x.point).collect();
    Ok(CheckpointSeed {
        base: Base { id: pt.point.id, height: pt.point.height, round: pt.point.round, parent_round, state: pt.state, ancestors },
        cref: *cref, high_qc: high_qc.clone(), high_tc: high_tc.cloned(), tip: vc.tip, chain,
    })
}

/// Cross-check a local install record against an AUTHENTICATED seed: the record must describe the same checkpoint. A match proves only that this machine's
/// staged state belongs to that checkpoint; it never authenticates the checkpoint, which `authenticate_checkpoint` alone does.
pub fn check_install_record(rec: &super::recovery::records::InstallRecord, seed: &CheckpointSeed) -> Result<(), SeedError> {
    let c = &rec.cref;
    if c.height != seed.cref.height || c.block_id != seed.cref.block_id || c.state_root != seed.cref.state_root {
        return Err(SeedError::RecordMismatch("checkpoint reference"));
    }
    Ok(())
}
