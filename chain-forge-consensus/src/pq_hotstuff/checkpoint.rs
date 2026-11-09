//! Checkpoint references (protocol profile v3). **DRAFT; OFF unless a chain is configured with profile v3; never activated on any network.**
//!
//! A v3 block may carry one optional [`CheckpointRef`] `(height, block_id, state_root)`: a claim that the application's canonical state after executing the
//! block at `height` (which has id `block_id`) is `state_root`. The reference is part of the signed block identity (the v3 preimage commits to its hash), so
//! it cannot be altered without invalidating the proposer's signature, and the validity rules below (R1 to R4 and R6) are checked identically by the engine and
//! by header-chain verification, through the single implementation in this module. R5 (comparing the root with the validator's own execution) is a VOTING rule,
//! not a validity rule, and lives in the engine.
//!
//! Profile identity: v2 (`qattice-pq-hotstuff-2-v2`) block ids, wire bytes and behavior are unchanged. v3 (`qattice-pq-hotstuff-2-v3`) uses a different profile
//! string (so ids differ by construction) and a separate, domain-separated id preimage. The validity-affecting parameters ([`CheckpointParams`]) are bound into the
//! genesis certificate through [`effective_genesis_hash`], so a validator configured differently has a different genesis and rejects every certificate and block.
use sha3::{Digest, Sha3_256};

use super::certs::BlockId;
use super::rules::commits_parent;

pub const PROFILE_V2: &str = "qattice-pq-hotstuff-2-v2";
pub const PROFILE_V3: &str = "qattice-pq-hotstuff-2-v3";
/// Bytes a reference adds to an encoded block or header: a flag byte and the 72-byte reference.
pub const REF_EXTENSION_LEN: usize = 73;
const TAG_PARAMS: &[u8] = b"CFH1|ckpt-params|";
const PARAMS_VERSION: u16 = 1;
/// Ceilings that keep every product and sum in this module far from overflow.
pub const MAX_INTERVAL: u64 = 1 << 40;
pub const MAX_AGE: u64 = 1 << 50;

pub fn is_v3(profile: &str) -> bool { profile == PROFILE_V3 }

fn sha3(parts: &[&[u8]]) -> [u8; 32] { let mut h = Sha3_256::new(); for p in parts { h.update(p); } h.finalize().into() }

/// `height u64 || block_id [32] || state_root [32]`, big-endian, 72 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CheckpointRef { pub height: u64, pub block_id: BlockId, pub state_root: [u8; 32] }

impl CheckpointRef {
    pub fn encode(&self) -> [u8; 72] {
        let mut o = [0u8; 72];
        o[..8].copy_from_slice(&self.height.to_be_bytes());
        o[8..40].copy_from_slice(&self.block_id);
        o[40..].copy_from_slice(&self.state_root);
        o
    }
    /// Exactly 72 bytes, otherwise `None`.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 72 { return None; }
        Some(CheckpointRef { height: u64::from_be_bytes(b[..8].try_into().ok()?), block_id: b[8..40].try_into().ok()?, state_root: b[40..].try_into().ok()? })
    }
    /// `SHA3-256("CFH1|ckpt|" || reference)`: what the v3 block-id preimage commits to.
    pub fn hash(&self) -> [u8; 32] { sha3(&[b"CFH1|ckpt|", &self.encode()]) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParamError {
    #[error("checkpoint interval must be between 1 and 2^40")]
    Interval,
    #[error("freshness bound must be at least the interval and at most 2^50")]
    MaxAge,
    #[error("profile v3 requires checkpoint parameters")]
    MissingParams,
    #[error("checkpoint parameters are only valid with profile v3")]
    ParamsOnLegacyProfile,
}

/// Validity-affecting parameters. Genesis-bound: see [`effective_genesis_hash`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointParams {
    /// `K`: references are only for heights that are multiples of this.
    pub interval: u64,
    /// R6: a new reference must satisfy `F(B) - height <= max_age`.
    pub max_age: u64,
}

impl CheckpointParams {
    pub fn validate(&self) -> Result<(), ParamError> {
        if self.interval == 0 || self.interval > MAX_INTERVAL { return Err(ParamError::Interval); }
        if self.max_age < self.interval || self.max_age > MAX_AGE { return Err(ParamError::MaxAge); }
        Ok(())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = TAG_PARAMS.to_vec();
        o.extend_from_slice(&PARAMS_VERSION.to_be_bytes());
        o.extend_from_slice(&self.interval.to_be_bytes());
        o.extend_from_slice(&self.max_age.to_be_bytes());
        o
    }
}

/// The genesis hash a chain actually uses. v2: the configured hash, unchanged. v3: `SHA3-256("CFH1|v3-genesis|" || genesis_hash || params)`, so any difference in
/// the validity-affecting parameters yields a different genesis block id and genesis certificate, which every other check already binds to.
pub fn effective_genesis_hash(profile: &str, genesis_hash: &[u8; 32], params: Option<&CheckpointParams>) -> Result<[u8; 32], ParamError> {
    match (is_v3(profile), params) {
        (true, Some(p)) => { p.validate()?; Ok(sha3(&[b"CFH1|v3-genesis|", genesis_hash, &p.encode()])) }
        (true, None) => Err(ParamError::MissingParams),
        (false, None) => Ok(*genesis_hash),
        (false, Some(_)) => Err(ParamError::ParamsOnLegacyProfile),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RefError {
    #[error("reference height is zero or not a multiple of the interval")]
    Shape,
    #[error("reference is above the finalized height")]
    NotFinal,
    #[error("reference names a block that is not on this chain at that height")]
    WrongAncestor,
    #[error("the block at the reference height cannot be identified (below the trusted anchor)")]
    Unverifiable,
    #[error("reference is below the chain's most recent reference")]
    Backwards,
    #[error("reference conflicts with the chain's reference at the same height")]
    Conflicting,
    #[error("a new reference is older than the freshness bound")]
    TooOld,
}

impl RefError {
    /// A stable description for `EngineError::Invalid` and header-verification reasons.
    pub fn reason(&self) -> &'static str {
        match self {
            RefError::Shape => "checkpoint reference: shape (R1)",
            RefError::NotFinal => "checkpoint reference: not final (R2)",
            RefError::WrongAncestor => "checkpoint reference: not an ancestor at that height (R3)",
            RefError::Unverifiable => "checkpoint reference: ancestor unverifiable (R3)",
            RefError::Backwards => "checkpoint reference: goes backwards (R4)",
            RefError::Conflicting => "checkpoint reference: conflicts at the same height (R4)",
            RefError::TooOld => "checkpoint reference: too old (R6)",
        }
    }
}

/// What the rules need about the chain a block extends. `final_height` is `F(B)`; `last_ref` is the most recent reference on `B`'s ancestor chain.
pub struct RefContext<'a> {
    pub params: &'a CheckpointParams,
    pub final_height: u64,
    pub last_ref: Option<CheckpointRef>,
    /// The id of the block at a given height on `B`'s own chain (`None` if it cannot be identified).
    pub block_id_at: &'a dyn Fn(u64) -> Option<BlockId>,
}

/// Rules R1 (shape), R4 (monotonic; a repeated reference is legal), R2 (final), R3 (identity) and R6 (freshness of a NEW reference). One implementation, used by
/// the engine and by header-chain verification.
pub fn check_reference(r: &CheckpointRef, c: &RefContext) -> Result<(), RefError> {
    if r.height == 0 || r.height % c.params.interval != 0 { return Err(RefError::Shape); }
    let repeated = c.last_ref == Some(*r);
    if let Some(l) = c.last_ref {
        if r.height < l.height { return Err(RefError::Backwards); }
        if r.height == l.height && !repeated { return Err(RefError::Conflicting); }
    }
    if r.height > c.final_height { return Err(RefError::NotFinal); }
    if !repeated {
        // R6 before R3: the age check is O(1), and it bounds the ancestor walk below to `max_age` plus the finality lag, so a stale
        // reference cannot make a verifier walk the whole chain before being refused. (r.height <= final_height was checked above.)
        if c.final_height - r.height > c.params.max_age { return Err(RefError::TooOld); }
        match (c.block_id_at)(r.height) {
            Some(id) if id == r.block_id => {}
            Some(_) => return Err(RefError::WrongAncestor),
            None => return Err(RefError::Unverifiable),
        }
    }
    Ok(())
}

/// `F(B)` for a block whose parent `C` has final height `f_of_c` and round `c_round`, and whose grandparent `P` is `p` = `(round, height)` (or `None` when `P` is
/// the genesis block or unknown): the two-chain rule finalizes `P` exactly when `P` and `C` have consecutive rounds.
pub fn final_height_after(f_of_c: u64, c_round: u64, p: Option<(u64, u64)>) -> u64 {
    match p { Some((pr, ph)) if commits_parent(pr, c_round) => f_of_c.max(ph), _ => f_of_c }
}

/// The per-block state the rules and the proposer policy track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChainRefState { pub final_height: u64, pub last_ref: Option<CheckpointRef> }

/// Local, non-validity proposer policy and monitoring knobs. NOT genesis-bound: they change what a node proposes or reports, never what is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefPolicy {
    /// Whether this node puts references in its proposals at all (a node that never does is an "omitting leader").
    pub propose_refs: bool,
    /// Reference only checkpoints at least this many blocks behind the node's own executor height.
    pub margin: u64,
    /// After one of this node's reference-bearing proposals failed to gather a QC, omit references for this many leader rotations (`n` rounds each).
    pub omit_rotations: u64,
    /// `checkpoint_age` above this many intervals is reported as stale by [`Engine::checkpoint_stale`].
    pub alarm_age_intervals: u64,
}

impl RefPolicy {
    pub fn validate(&self) -> Result<(), ParamError> {
        if self.margin > MAX_AGE || self.omit_rotations > (1 << 20) || self.alarm_age_intervals > (1 << 20) { return Err(ParamError::MaxAge); }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointConfig { pub params: CheckpointParams, pub policy: RefPolicy }

/// What the engine concluded about a reference-bearing proposal's root (rule R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootCheck {
    /// The validator's own root (or an authenticated final ancestor's identical reference) equals the claim: vote.
    Match,
    /// The validator's executor has not reached the height yet: do not vote now; this is deferral, not evidence.
    NotYet,
    /// No root is obtainable locally and no final ancestor carries the same reference: do not vote, record no mismatch.
    Unknown,
    /// The validator's own root differs: do not vote, keep the evidence.
    Mismatch,
}

/// Safety/execution-consistency alarms. They attribute nothing: conflicting roots can come from nondeterministic execution, a version difference or a bug, and are
/// NOT by themselves cryptographic equivocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alarm {
    /// This validator's own root at a height differs from the reference in a block that carries a QC (so a quorum accepted it).
    LocalDivergence { reference: CheckpointRef, own_root: [u8; 32] },
    /// Two QC'd blocks carry different references for one height.
    ConflictingCertifiedRoots { first: CheckpointRef, second: CheckpointRef },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence { pub block_id: BlockId, pub reference: CheckpointRef, pub outcome: RootCheck, pub own_root: Option<[u8; 32]> }
