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
    /// The verified chain point with this block id, if the authenticated chain contains it.
    pub fn chain_point(&self, id: &BlockId) -> Option<ChainPoint> { self.chain.iter().find(|p| p.id == *id).copied() }
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
    #[error("seed evidence is malformed: {0}")]
    Evidence(&'static str),
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

// ---------------------------------------------------------------------------------------------------------------------------------------
// Persisted seed evidence. Stored by the block store, RE-AUTHENTICATED at every start by `Engine::authenticate_evidence` against the node's own genesis, profile,
// validator set and checkpoint parameters. The checksum below detects damage only; it authenticates nothing.
// ---------------------------------------------------------------------------------------------------------------------------------------
use super::netmsg::{decode_header, encode_header};
use sha3::{Digest, Sha3_256};

const EV_TAG: &[u8] = b"CFH1|seed-evidence|";
const EV_VERSION: u16 = 1;
/// Upper bound on the headers one piece of evidence may carry (decode refuses more; evidence from genesis grows with the chain until anchored evidence exists).
pub const MAX_EVIDENCE_HEADERS: usize = 1 << 20;

/// Everything `authenticate_checkpoint` consumed, so that a restart can authenticate the same checkpoint again from durable data. Evidence starts at genesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedEvidence {
    pub headers: Vec<PayloadFreeBlock>,
    pub final_qc: Option<Cert>,
    pub cref: CheckpointRef,
    pub high_qc: Cert,
    pub high_tc: Option<Tc>,
}

fn put_blob(o: &mut Vec<u8>, b: &[u8]) { o.extend_from_slice(&(b.len() as u32).to_be_bytes()); o.extend_from_slice(b); }

impl SeedEvidence {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = EV_TAG.to_vec();
        o.extend_from_slice(&EV_VERSION.to_be_bytes());
        o.extend_from_slice(&self.cref.height.to_be_bytes());
        o.extend_from_slice(&self.cref.block_id);
        o.extend_from_slice(&self.cref.state_root);
        o.extend_from_slice(&(self.headers.len() as u32).to_be_bytes());
        for h in &self.headers { put_blob(&mut o, &encode_header(h)); }
        match &self.final_qc { Some(c) => { o.push(1); put_blob(&mut o, &c.encode()); } None => o.push(0) }
        put_blob(&mut o, &self.high_qc.encode());
        match &self.high_tc { Some(t) => { o.push(1); put_blob(&mut o, &t.encode()); } None => o.push(0) }
        let sum = Sha3_256::digest(&o);
        o.extend_from_slice(&sum);
        o
    }

    /// Strict: wrong tag, version, checksum, length, trailing bytes or more than `max_headers` headers is an error. Allocation is bounded by the input length.
    pub fn decode(b: &[u8], max_headers: usize) -> Result<Self, SeedError> {
        let bad = SeedError::Evidence;
        if b.len() < EV_TAG.len() + 2 + 72 + 4 + 32 { return Err(bad("too short")); }
        let (body, sum) = b.split_at(b.len() - 32);
        if Sha3_256::digest(body)[..] != *sum { return Err(bad("checksum")); }
        let mut r = Cur { b: body, p: 0 };
        if r.take(EV_TAG.len())? != EV_TAG { return Err(bad("tag")); }
        if u16::from_be_bytes(r.take(2)?.try_into().unwrap()) != EV_VERSION { return Err(bad("version")); }
        let height = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
        let cref = CheckpointRef { height, block_id: r.take(32)?.try_into().unwrap(), state_root: r.take(32)?.try_into().unwrap() };
        let n = u32::from_be_bytes(r.take(4)?.try_into().unwrap()) as usize;
        if n > max_headers.min(MAX_EVIDENCE_HEADERS) { return Err(bad("too many headers")); }
        let mut headers = Vec::with_capacity(n.min(body.len() / 64));
        for _ in 0..n { let blob = r.blob()?; headers.push(decode_header(blob).map_err(|_| bad("header"))?); }
        let final_qc = match r.take(1)?[0] { 0 => None, 1 => Some(Cert::decode(r.blob()?).map_err(|_| bad("final certificate"))?), _ => return Err(bad("flag")) };
        let high_qc = Cert::decode(r.blob()?).map_err(|_| bad("high certificate"))?;
        let high_tc = match r.take(1)?[0] { 0 => None, 1 => Some(Tc::decode(r.blob()?).map_err(|_| bad("timeout certificate"))?), _ => return Err(bad("flag")) };
        if r.p != body.len() { return Err(bad("trailing bytes")); }
        Ok(SeedEvidence { headers, final_qc, cref, high_qc, high_tc })
    }
}

struct Cur<'a> { b: &'a [u8], p: usize }
impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SeedError> {
        let end = self.p.checked_add(n).ok_or(SeedError::Evidence("length"))?;
        let s = self.b.get(self.p..end).ok_or(SeedError::Evidence("truncated"))?;
        self.p = end; Ok(s)
    }
    fn blob(&mut self) -> Result<&'a [u8], SeedError> { let n = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize; self.take(n) }
}
