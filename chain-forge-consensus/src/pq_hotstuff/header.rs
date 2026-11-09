//! Payload-free block headers and header-chain verification (snapshot-recovery Step 1). **DRAFT; payloads are `devnet-interim`.**
//!
//! A [`PayloadFreeBlock`] is a [`Block`] with the payload bytes replaced by `SHA3-256(payload)`. **Block identity is unchanged**: `block_id` already
//! commits to `SHA3-256(payload)` (not to the bytes or their length), to `H(qc)` and to `H(tc)`, so a header reconstructs exactly the same id
//! ([`PayloadFreeBlock::id`] feeds the same `BlockIdInput`), and the proposer's signature, which covers that id, verifies from the header alone.
//!
//! [`verify_header_chain`] checks a linear run of headers against nothing but the genesis hash and the fixed validator set (or a trusted
//! anchor): proposer authentication, leader schedule, parent links, heights and rounds, the parent QC and any TC, and the chain/genesis binding,
//! and it reports which headers are FINAL under the engine's own two-chain predicate (`commits_parent`).
//!
//! **What it proves, and what it does not.** It authenticates the committed block history: ids, the payload hash each block commits to, and finality.
//! It does NOT authenticate any application state: no block commits to a state digest, so a snapshot cannot be verified from headers. It cannot check
//! the payload size limit (the length is not part of the id), so a payload fetched later must be checked with [`PayloadFreeBlock::check_payload`].
use sha3::{Digest, Sha3_256};

use super::certs::{block_id_of, id_from_parts, verify_cert, verify_tc, Block, BlockId, Cert, CertError, GenesisCert, IdCtx, Tc, VerifyCtx, ALG};
use super::checkpoint::{check_reference, effective_genesis_hash, final_height_after, is_v3, ChainRefState, CheckpointParams, CheckpointRef, RefContext};
use super::leader::leader_index;
use super::rules::commits_parent;
use super::safety::{ConsensusVerifier, Kind};
use super::types::EpochSet;
use super::wire::BlockSigningMessage;

fn sha3(b: &[u8]) -> [u8; 32] { Sha3_256::digest(b).into() }

/// A block with its payload replaced by the payload's SHA3-256 hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadFreeBlock {
    pub epoch: u64,
    pub round: u64,
    pub height: u64,
    pub parent_id: BlockId,
    pub qc: Cert,
    pub tc: Option<Tc>,
    pub payload_hash: [u8; 32],
    pub proposer: usize,
    pub signature: Vec<u8>,
    pub checkpoint: Option<CheckpointRef>,
}

impl Block {
    /// The payload-free form of this block (same identity).
    pub fn to_header(&self) -> PayloadFreeBlock {
        PayloadFreeBlock { epoch: self.epoch, round: self.round, height: self.height, parent_id: self.parent_id, qc: self.qc.clone(), tc: self.tc.clone(), payload_hash: sha3(&self.payload), proposer: self.proposer, signature: self.signature.clone(), checkpoint: self.checkpoint }
    }
}

impl PayloadFreeBlock {
    /// The block id: byte for byte what [`block_id_of`] returns for the full block.
    pub fn id(&self, ctx: &IdCtx) -> Result<BlockId, CertError> {
        let proposer = ctx.set.entries().get(self.proposer).ok_or(CertError::Invalid("proposer index"))?.address.clone();
        id_from_parts(ctx, self.epoch, self.round, self.height, self.parent_id, self.payload_hash, self.qc.hash(), self.tc.as_ref().map(Tc::hash), proposer, self.checkpoint.as_ref())
    }
    /// Whether `payload` is the payload this header commits to.
    pub fn matches_payload(&self, payload: &[u8]) -> bool { sha3(payload) == self.payload_hash }
    /// A fetched payload must hash to the committed value AND respect the size limit (which a header cannot check by itself).
    pub fn check_payload(&self, payload: &[u8], max_bytes: u64) -> Result<(), HeaderError> {
        if payload.len() as u64 > max_bytes { return Err(HeaderError::PayloadTooLarge); }
        if !self.matches_payload(payload) { return Err(HeaderError::PayloadMismatch); }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("no headers")]
    Empty,
    #[error("more than {0} headers")]
    TooMany(usize),
    #[error("header {index}: {reason}")]
    Invalid { index: usize, reason: &'static str },
    #[error("header {index}: certificate: {source}")]
    Cert { index: usize, source: CertError },
    #[error("the final certificate does not certify the last header")]
    FinalCert,
    #[error("payload is above the size limit")]
    PayloadTooLarge,
    #[error("payload does not hash to the committed value")]
    PayloadMismatch,
}

/// Everything the verifier needs from the chain's identity. The genesis certificate and `valset_hash` are derived exactly as the engine derives them.
pub struct ChainParams<'a> {
    pub protocol_profile: &'a str,
    pub chain_id: &'a str,
    pub set: &'a EpochSet,
    pub genesis_hash: [u8; 32],
    /// Leader-rotation seed (0 in Phase 0), as in the engine configuration.
    pub seed: u64,
    /// Profile v3 only: the genesis-bound checkpoint parameters (required there, refused on any other profile).
    pub checkpoint: Option<CheckpointParams>,
}

/// A block already verified and final, from which a chain of headers continues (never verified here; the caller vouches for it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub id: BlockId,
    pub height: u64,
    pub round: u64,
    /// The round of the anchor's parent (0 if the anchor's parent is the genesis block). Needed to decide, for the first header after the anchor, whether the
    /// anchor's parent becomes final.
    pub parent_round: u64,
    /// `F` of the anchor block itself (the final height its own certificate implied); at least `height - 1`.
    pub final_height: u64,
    /// The most recent checkpoint reference on the chain up to and including the anchor.
    pub last_ref: Option<CheckpointRef>,
    /// The ids of the blocks just below the anchor (height, id), as many as a new reference could name: rule R3 identifies the referenced block by height, and
    /// R6 lets a new reference name a block up to the freshness bound below the final height. Heights not listed (and below the anchor) are unverifiable and
    /// fail closed.
    pub ancestors: Vec<(u64, BlockId)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start { Genesis, Anchor(Anchor) }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPoint { pub id: BlockId, pub height: u64, pub round: u64, pub payload_hash: [u8; 32] }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    /// The last header verified (valid and linked, not necessarily final).
    pub tip: ChainPoint,
    /// Newly FINAL blocks above the start, in height order, under the two-chain predicate.
    pub finalized: Vec<ChainPoint>,
    /// Every verified header after the start, in height order (final or not), with the checkpoint state at it and the reference it carries.
    pub points: Vec<VerifiedPoint>,
}

/// One verified header: its identity, the chain's checkpoint state up to and including it (F(B) and the last reference), and the reference IT carries (if any).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPoint { pub point: ChainPoint, pub state: ChainRefState, pub carried: Option<CheckpointRef> }

/// Verify a linear run of headers (oldest first) from `start`. `final_qc` may be a QC for the LAST header (for example the high QC), which can finalize
/// one more block. `max_headers` bounds the work; verification stops at the first invalid header and nothing is returned for a partly valid run.
pub fn verify_header_chain<V: ConsensusVerifier>(p: &ChainParams, v: &V, start: Start, headers: &[PayloadFreeBlock], final_qc: Option<&Cert>, max_headers: usize) -> Result<VerifiedChain, HeaderError> {
    if headers.is_empty() { return Err(HeaderError::Empty); }
    if headers.len() > max_headers { return Err(HeaderError::TooMany(max_headers)); }
    let valset_hash = p.set.validator_set_hash();
    let genesis_hash = effective_genesis_hash(p.protocol_profile, &p.genesis_hash, p.checkpoint.as_ref()).map_err(|_| HeaderError::Invalid { index: 0, reason: "checkpoint parameters do not fit the profile" })?;
    let genesis = GenesisCert { protocol_profile: p.protocol_profile.to_string(), chain_id: p.chain_id.to_string(), genesis_hash, valset_hash };
    let genesis_id = genesis.block_id();
    let vctx = VerifyCtx { chain_id: p.chain_id, set: p.set, valset_hash, genesis: &genesis, verifier: v };
    let idctx = IdCtx { protocol_profile: p.protocol_profile, chain_id: p.chain_id, set: p.set };

    let (mut prev_id, mut prev_height, mut prev_round, mut final_height) = match &start { Start::Genesis => (genesis_id, 0u64, 0u64, 0u64), Start::Anchor(a) => (a.id, a.height, a.round, a.height) };
    let mut chain: Vec<ChainPoint> = Vec::with_capacity(headers.len());
    // per-header checkpoint state, parallel to `chain`: F(B) and the most recent reference up to and including that header
    let mut states: Vec<ChainRefState> = Vec::with_capacity(headers.len());
    let (start_height, start_round, start_state, start_parent): (u64, u64, ChainRefState, Option<(u64, u64)>) = match &start {
        Start::Genesis => (0, 0, ChainRefState::default(), None),
        Start::Anchor(a) => (a.height, a.round, ChainRefState { final_height: a.final_height, last_ref: a.last_ref }, if a.height >= 2 { Some((a.parent_round, a.height - 1)) } else { None }),
    };
    let start_id = prev_id;
    let mut finalized: Vec<ChainPoint> = vec![];
    let bad = |index: usize, reason: &'static str| HeaderError::Invalid { index, reason };

    // the two-chain predicate, applied when a QC for `chain.last()` is known: if its parent is exactly one round earlier, that parent and its ancestors are final
    let finalize = |chain: &[ChainPoint], final_height: &mut u64, finalized: &mut Vec<ChainPoint>| {
        if chain.len() < 2 { return; } // the parent of the first header is the genesis block or the (already final) anchor
        let (c, par) = (chain[chain.len() - 1], chain[chain.len() - 2]);
        if commits_parent(par.round, c.round) {
            for pt in chain.iter().filter(|pt| pt.height <= par.height && pt.height > *final_height) { finalized.push(*pt); }
            if par.height > *final_height { *final_height = par.height; }
        }
    };

    for (i, h) in headers.iter().enumerate() {
        if h.epoch != p.set.epoch() { return Err(bad(i, "epoch")); }
        if h.round == 0 { return Err(bad(i, "round 0")); }
        let leader = leader_index(p.set, h.round, p.seed).map_err(|_| bad(i, "no eligible leader"))?;
        if h.proposer != leader { return Err(bad(i, "proposer is not the leader of the round")); }
        let id = h.id(&idctx).map_err(|e| HeaderError::Cert { index: i, source: e })?;
        let msg = BlockSigningMessage { alg_id: ALG, block_id: id }.encode().map_err(|_| bad(i, "block signing message"))?;
        if !v.verify(&p.set.entries()[h.proposer].public_key, Kind::Proposal.context(), &msg, &h.signature) { return Err(bad(i, "proposer signature")); }
        if h.parent_id != prev_id { return Err(bad(i, "parent link")); }
        verify_cert(&vctx, &h.qc).map_err(|e| HeaderError::Cert { index: i, source: e })?;
        if h.qc.block_id() != h.parent_id { return Err(bad(i, "parent_id differs from the certificate's block")); }
        if h.height != prev_height.checked_add(1).ok_or(bad(i, "height"))? { return Err(bad(i, "height")); }
        // an honest quorum signs a vote for the block's own round, so the QC's round is the parent's round; anything else is refused (fail closed)
        if h.qc.round() != prev_round { return Err(bad(i, "certificate round differs from the parent's round")); }
        if h.qc.round() >= h.round { return Err(bad(i, "round is not above the certificate's round")); }
        let consecutive = h.qc.round().checked_add(1) == Some(h.round);
        match (&h.tc, consecutive) {
            (None, true) => {}
            (Some(t), false) => {
                verify_tc(&vctx, t).map_err(|e| HeaderError::Cert { index: i, source: e })?;
                if t.round.checked_add(1) != Some(h.round) { return Err(bad(i, "timeout certificate is not for the previous round")); }
            }
            _ => return Err(bad(i, "timeout certificate presence")),
        }
        // checkpoint reference (profile v3): F(B) and the chain's last reference come from the parent and grandparent, exactly as in the engine
        let (c_round, c_state) = match states.last() { Some(st) => (chain[chain.len() - 1].round, *st), None => (start_round, start_state) };
        // the parent's parent: two verified headers back; with one verified header it is the anchor itself (never the genesis block); before any it is the anchor's parent
        let gp = if chain.len() >= 2 { let g = &chain[chain.len() - 2]; Some((g.round, g.height)) } else if chain.len() == 1 { if start_height > 0 { Some((start_round, start_height)) } else { None } } else { start_parent };
        let f_b = final_height_after(c_state.final_height, c_round, gp);
        if let (true, Some(params), Some(r)) = (is_v3(p.protocol_profile), p.checkpoint.as_ref(), h.checkpoint.as_ref()) {
            let at = |height: u64| -> Option<BlockId> {
                if height == start_height && start_height > 0 { return Some(start_id); }
                if height <= start_height { return if let Start::Anchor(a) = &start { a.ancestors.iter().find(|(h, _)| *h == height).map(|(_, id)| *id) } else { None }; }
                chain.get((height - start_height - 1) as usize).map(|pt| pt.id)
            };
            check_reference(r, &RefContext { params, final_height: f_b, last_ref: c_state.last_ref, block_id_at: &at }).map_err(|e| bad(i, e.reason()))?;
        }
        let this_state = ChainRefState { final_height: f_b, last_ref: h.checkpoint.or(c_state.last_ref) };
        // h.qc certifies the previous header: finality may advance
        finalize(&chain, &mut final_height, &mut finalized);
        chain.push(ChainPoint { id, height: h.height, round: h.round, payload_hash: h.payload_hash });
        states.push(this_state);
        prev_id = id; prev_height = h.height; prev_round = h.round;
    }
    if let Some(q) = final_qc {
        verify_cert(&vctx, q).map_err(|e| HeaderError::Cert { index: headers.len(), source: e })?;
        if !matches!(q, Cert::Qc(_)) || q.block_id() != prev_id || q.round() != prev_round { return Err(HeaderError::FinalCert); }
        finalize(&chain, &mut final_height, &mut finalized);
    }
    let points = chain.iter().zip(states.iter()).zip(headers.iter()).map(|((pt, st), h)| VerifiedPoint { point: *pt, state: *st, carried: h.checkpoint }).collect();
    Ok(VerifiedChain { tip: *chain.last().unwrap(), finalized, points })
}

/// The id of a full block, for callers that hold both forms (a convenience used by the equivalence tests).
pub fn full_block_id(b: &Block, ctx: &IdCtx) -> Result<BlockId, CertError> { block_id_of(b, ctx) }
