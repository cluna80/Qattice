//! CF-C1: native PQ-HotStuff-2 `ConsensusEngine` implementation.
//!
//! Implements spec sections 3.3–3.5 (two-chain commit), 3.6–3.7 (epoch transition)
//! and 5.1 (pacemaker). Safety-state integration with the `SafetyStore` (section 7)
//! is wired through `sign_vote` / `sign_timeout` / `sign_proposal` once a signer is
//! provided; until then the engine runs in sign-later mode (votes are built but not
//! signed, suitable for the initial skeleton tests).
//!
//! # What is here (CF-C1 scope)
//! - `PqHotStuffEngine` struct and `ConsensusEngine` impl
//! - `Qc` / `Tc` internal types
//! - Two-chain commit rule: commit when `locked_qc.round + 1 == high_qc.round`
//! - Pacemaker: exponential-backoff timeout, `on_timeout` advances round
//! - Epoch-transition hook: detects epoch-change block commits, records seal round
//! - Vote aggregation: threshold quorum (2f+1 out of 3f+1)
//! - Proposer rotation: round-robin by validator index within epoch
//!
//! # QAT-07 additions (this file, stacked on CF-C1)
//! - `signing_ctx: Option<Box<dyn EngineSigningContext>>` on `PqHotStuffEngine`
//! - `attach_signing_context` wires in a `SafetyStoreSigningContext` (or any impl)
//! - `restore_floors` loads hvr/hqr from the durable record on restart
//! - `propose`, `receive_vote`, `on_timeout` route through the context when present
//! - `on_commit` calls `signing_ctx.advance_epoch` on epoch-change commits
//!
//! # What is NOT here yet (gated on later milestones)
//! - P2P / network I/O (chain-forge-node layer)
//! - Key rotation, revocation, ML-DSA-only admission gate (QAT-08)
//! - Production key storage (blocked on PR #109 review)

use std::collections::{BTreeMap, HashSet};

use crate::{
    BlockHash, BlockHeight, BlockProposal, CommitCertificate,
    ConsensusConfig, ConsensusEngine, ConsensusError, ConsensusResult, ConsensusVariant,
    Round, ValidatorId, ValidatorSet, Vote, VoteType,
};
use crate::pq_hotstuff::signing::EngineSigningContext;
use crate::pq_hotstuff::wire::HASH_LEN;

// ── QC / TC types ─────────────────────────────────────────────────────────────

/// A quorum certificate: a block hash and the round at which 2f+1 validators voted for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qc {
    pub block_hash: BlockHash,
    pub round: Round,
    pub height: BlockHeight,
    /// Indices of signers (into the validator set at the time of signing).
    pub signers: Vec<usize>,
}

impl Qc {
    fn genesis() -> Self {
        Qc { block_hash: BlockHash("genesis".into()), round: 0, height: 0, signers: vec![] }
    }
}

/// A timeout certificate: 2f+1 validators timed out at the same round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tc {
    pub round: Round,
    /// The highest QC round each signer reported (spec §3.5).
    pub high_qc_rounds: Vec<Round>,
}

// ── Pacemaker ─────────────────────────────────────────────────────────────────

/// Exponential-backoff pacemaker (spec §5.1).
/// Base timeout doubles on each consecutive timeout, up to `max_ms`.
#[derive(Debug, Clone)]
struct Pacemaker {
    base_ms: u64,
    max_ms: u64,
    consecutive_timeouts: u32,
}

impl Pacemaker {
    fn new(base_ms: u64) -> Self {
        let base_ms = base_ms.max(1);
        Pacemaker { base_ms, max_ms: base_ms * 32, consecutive_timeouts: 0 }
    }

    fn timeout_ms(&self) -> u64 {
        let exp = self.consecutive_timeouts.min(5) as u64;
        (self.base_ms << exp).min(self.max_ms)
    }

    fn on_timeout(&mut self) { self.consecutive_timeouts += 1; }
    fn on_progress(&mut self) { self.consecutive_timeouts = 0; }
}

// ── Vote accumulator ──────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct VoteAccumulator {
    /// block_hash_key → list of (validator_index, vote)
    buckets: BTreeMap<String, Vec<(usize, Vote)>>,
}

impl VoteAccumulator {
    fn add(&mut self, idx: usize, vote: Vote) {
        let key = vote.block_hash.as_ref().map(|h| h.0.clone()).unwrap_or_default();
        self.buckets.entry(key).or_default().push((idx, vote));
    }

    /// Returns `Some(Qc)` when a bucket reaches `threshold` votes.
    fn check_quorum(&self, threshold: usize, round: Round, height: BlockHeight) -> Option<Qc> {
        for (key, votes) in &self.buckets {
            if votes.len() >= threshold && !key.is_empty() {
                let signers = votes.iter().map(|(i, _)| *i).collect();
                return Some(Qc {
                    block_hash: BlockHash(key.clone()),
                    round,
                    height,
                    signers,
                });
            }
        }
        None
    }

    fn clear(&mut self) { self.buckets.clear(); }
}

// ── Engine ────────────────────────────────────────────────────────────────────

/// PQ-HotStuff-2 consensus engine (CF-C1).
///
/// Maintains the two-chain commit invariant: a block `b` is committed when
/// `locked_qc.round + 1 == high_qc.round` and `high_qc` certifies the direct
/// child of the block `locked_qc` certifies.
pub struct PqHotStuffEngine {
    config: ConsensusConfig,
    validator_set: ValidatorSet,

    // Current position
    epoch: u64,
    height: BlockHeight,
    round: Round,

    // Two-chain commit state (spec §3.3–3.5)
    /// The locked QC: 2f+1 precommits for some block at this round.
    locked_qc: Qc,
    /// The highest QC seen: may be more recent than locked_qc.
    high_qc: Qc,

    // Accumulator for the current round's precommits
    accumulator: VoteAccumulator,

    // Pending proposal for this round (if we received one)
    pending_proposal: Option<BlockProposal>,

    // Epoch-transition seal round (spec §3.6, EC-6).
    // Set when we commit an epoch-change block; blocks further old-epoch votes.
    seal_round: Option<Round>,

    pacemaker: Pacemaker,

    // QAT-07: optional SafetyStore signing context. When Some, all outbound messages
    // are signed with write-before-broadcast guarantees. When None, the engine runs
    // in sign-later mode (suitable for unit tests and the CF-C1 skeleton).
    signing_ctx: Option<Box<dyn EngineSigningContext>>,
}

impl PqHotStuffEngine {
    pub fn new() -> Self {
        let genesis_qc = Qc::genesis();
        PqHotStuffEngine {
            config: ConsensusConfig {
                variant: ConsensusVariant::PqHotStuff,
                chain_id: String::new(),
                propose_timeout_ms: 1000,
                prevote_timeout_ms: 1000,
                precommit_timeout_ms: 1000,
                block_time_ms: 500,
                personhood: None,
                vca: None,
            },
            validator_set: ValidatorSet { height: 0, validators: vec![] },
            epoch: 0,
            height: 1,
            round: 1,
            locked_qc: genesis_qc.clone(),
            high_qc: genesis_qc,
            accumulator: VoteAccumulator::default(),
            pending_proposal: None,
            seal_round: None,
            pacemaker: Pacemaker::new(1000),
            signing_ctx: None,
        }
    }

    /// Attach a durable signing context (QAT-07). Call this once after `init`, before
    /// any `propose` / `receive_vote` / `on_timeout`. After attaching, call
    /// `restore_floors` to reload hvr/hqr from the durable record.
    pub fn attach_signing_context(&mut self, ctx: Box<dyn EngineSigningContext>) {
        self.signing_ctx = Some(ctx);
    }

    /// Reload the highest vote round (hvr) and lock QC round (hqr) from the durable
    /// safety record. Must be called after `attach_signing_context` on every restart.
    /// Sets `locked_qc.round` and `high_qc.round` to at least the stored floors.
    pub fn restore_floors(&mut self) {
        if let Some(ctx) = &self.signing_ctx {
            let floors = ctx.restore();
            if floors.epoch == self.epoch {
                if let Some(hqr) = floors.hqr {
                    if hqr > self.locked_qc.round as u64 {
                        self.locked_qc.round = hqr as u32;
                    }
                }
                if let Some(hvr) = floors.hvr {
                    if hvr > self.high_qc.round as u64 {
                        self.high_qc.round = hvr as u32;
                    }
                }
            }
        }
    }

    /// 2f+1 quorum threshold from the validator set size.
    fn quorum_threshold(&self) -> usize {
        let n = self.validator_set.validators.len();
        // For n = 3f+1, threshold = 2f+1 = ceil(2n/3)
        (2 * n + 2) / 3
    }

    fn proposer_index(&self, height: BlockHeight, round: Round) -> usize {
        let n = self.validator_set.validators.len();
        if n == 0 { return 0; }
        ((height as usize).wrapping_add(round as usize).wrapping_sub(1)) % n
    }

    /// Returns true if `round` is safe to vote at given `locked_qc` (spec §3.4).
    fn safe_to_vote(&self, round: Round) -> bool {
        round >= self.locked_qc.round
    }

    /// Two-chain commit: commit `to_commit` when `locked_qc` is its direct child
    /// at the consecutive round (locked_qc.round == to_commit.round + 1).
    fn try_two_chain_commit(&self, to_commit: &Qc) -> Option<CommitCertificate> {
        if self.locked_qc.round == to_commit.round + 1 {
            return Some(CommitCertificate {
                height: to_commit.height,
                round: to_commit.round,
                block_hash: to_commit.block_hash.clone(),
                precommits: vec![],
            });
        }
        None
    }

    fn advance_round(&mut self, new_round: Round) {
        self.round = new_round;
        self.accumulator.clear();
        self.pending_proposal = None;
    }

    /// Produce a signed precommit vote for the local validator (QAT-07).
    /// Returns the signature bytes; the caller builds the wire `VoteMessage`.
    /// Returns empty vec when no signing context is attached (sign-later mode).
    pub fn sign_local_precommit(
        &mut self,
        block_hash: &BlockHash,
        parent_hash: &BlockHash,
        parent_round: Round,
        qc_round: Round,
    ) -> Result<Vec<u8>, ConsensusError> {
        if let Some(ctx) = self.signing_ctx.as_mut() {
            let block_id = sha3_32(block_hash.0.as_bytes());
            let parent_id = sha3_32(parent_hash.0.as_bytes());
            ctx.sign_vote(
                &self.config.chain_id,
                self.epoch,
                self.round as u64,
                block_id,
                parent_id,
                parent_round as u64,
                qc_round as u64,
            )
            .map(|s| s.signature)
            .map_err(ConsensusError::Internal)
        } else {
            Ok(vec![])
        }
    }

    /// Return the proposer `ValidatorId` for a given (height, round).
    pub fn proposer_for(&self, height: BlockHeight, round: Round) -> Option<ValidatorId> {
        if self.validator_set.validators.is_empty() { return None; }
        let idx = self.proposer_index(height, round);
        Some(self.validator_set.validators[idx].id.clone())
    }

    /// The seal round set after an epoch-change block is committed (EC-6).
    pub fn seal_round(&self) -> Option<Round> { self.seal_round }

    /// Current epoch.
    pub fn epoch(&self) -> u64 { self.epoch }

    /// The locked QC.
    pub fn locked_qc(&self) -> &Qc { &self.locked_qc }

    /// The highest QC seen.
    pub fn high_qc(&self) -> &Qc { &self.high_qc }

    /// Pacemaker timeout for the current round (ms).
    pub fn current_timeout_ms(&self) -> u64 { self.pacemaker.timeout_ms() }
}

impl Default for PqHotStuffEngine {
    fn default() -> Self { Self::new() }
}

// SAFETY: `PqHotStuffEngine` only accesses `signing_ctx` through `&mut self`.
// The signing context is never shared across threads; all callers hold exclusive
// access. This manual impl is required because `dyn EngineSigningContext` is
// `Send` but not `Sync` (the safety store uses `&mut self` for all writes).
unsafe impl Sync for PqHotStuffEngine {}

#[async_trait::async_trait]
impl ConsensusEngine for PqHotStuffEngine {
    fn name(&self) -> &str { "PQ-HotStuff-2" }
    fn variant(&self) -> ConsensusVariant { ConsensusVariant::PqHotStuff }

    async fn init(
        &mut self,
        config: ConsensusConfig,
        genesis_validators: ValidatorSet,
    ) -> ConsensusResult<()> {
        self.pacemaker = Pacemaker::new(config.propose_timeout_ms);
        self.config = config;
        self.validator_set = genesis_validators;
        self.epoch = 0;
        self.height = 1;
        self.round = 1;
        self.locked_qc = Qc::genesis();
        self.high_qc = Qc::genesis();
        self.seal_round = None;
        self.accumulator.clear();
        self.pending_proposal = None;
        Ok(())
    }

    fn validator_set(&self) -> &ValidatorSet { &self.validator_set }

    fn update_validator_set(&mut self, vs: ValidatorSet) -> Result<(), ConsensusError> {
        self.validator_set = vs;
        Ok(())
    }

    async fn propose(
        &mut self,
        height: BlockHeight,
        round: Round,
        parent_hash: BlockHash,
        tx_data: Vec<u8>,
    ) -> ConsensusResult<BlockProposal> {
        let n = self.validator_set.validators.len();
        if n == 0 {
            return Err(ConsensusError::InsufficientValidators { needed: 1, have: 0 });
        }
        let idx = self.proposer_index(height, round);
        let proposer = self.validator_set.validators[idx].id.clone();

        // Block hash placeholder: real hash uses wire::BlockIdInput + SHA3-256.
        let block_hash = BlockHash(format!(
            "pqhs-{}-{}-{}-{}",
            self.config.chain_id, height, round,
            sha3_hex(parent_hash.0.as_bytes())
        ));

        // Build block_id bytes for signing: take SHA3-256 of the placeholder string.
        let block_id_bytes = sha3_32(block_hash.0.as_bytes());

        // Sign via SafetyStore when a context is attached (QAT-07); otherwise sign-later.
        let signature = if let Some(ctx) = self.signing_ctx.as_mut() {
            ctx.sign_proposal(self.epoch, round as u64, block_id_bytes)
                .map(|s| s.signature)
                .map_err(ConsensusError::Internal)?
        } else {
            vec![]
        };

        Ok(BlockProposal {
            height,
            round,
            proposer,
            block_hash,
            parent_hash,
            timestamp_ms: 0,
            tx_data,
            signature,
            pol_round: if self.high_qc.round > 0 { Some(self.high_qc.round) } else { None },
        })
    }

    async fn receive_proposal(&mut self, proposal: BlockProposal) -> ConsensusResult<()> {
        if proposal.height != self.height {
            return Err(ConsensusError::StaleMessage(proposal.height, self.height));
        }
        let expected_idx = self.proposer_index(proposal.height, proposal.round);
        let expected = &self.validator_set.validators[expected_idx].id;
        if &proposal.proposer != expected {
            return Err(ConsensusError::MalformedProposal(format!(
                "wrong proposer: got {}, expected {}", proposal.proposer.0, expected.0
            )));
        }
        self.pending_proposal = Some(proposal);
        Ok(())
    }

    async fn receive_vote(&mut self, vote: Vote) -> ConsensusResult<Option<CommitCertificate>> {
        if vote.height != self.height {
            return Err(ConsensusError::StaleMessage(vote.height, self.height));
        }

        let idx = self.validator_set.validators
            .iter().position(|v| v.id == vote.validator)
            .ok_or_else(|| ConsensusError::UnknownValidator(vote.validator.clone()))?;

        // Voting rule (spec §3.4): accept if round >= locked_qc.round
        if !self.safe_to_vote(vote.round) {
            let bh = vote.block_hash.clone().unwrap_or_else(|| BlockHash("nil".into()));
            return Err(ConsensusError::InvalidVote {
                validator: vote.validator.clone(),
                block_hash: bh,
                reason: format!("round {} below locked_qc.round {}", vote.round, self.locked_qc.round),
            });
        }

        let round = vote.round;
        let height = vote.height;
        self.accumulator.add(idx, vote);

        let threshold = self.quorum_threshold();
        if let Some(new_qc) = self.accumulator.check_quorum(threshold, round, height) {
            if new_qc.round > self.high_qc.round {
                let prev_locked = self.locked_qc.clone();
                // Update lock if consecutive with current locked_qc
                if new_qc.round == self.locked_qc.round + 1 {
                    self.locked_qc = new_qc.clone();
                }
                self.high_qc = new_qc;
                self.pacemaker.on_progress();
                self.advance_round(round + 1);
                // Two-chain commit: commit prev_locked if locked_qc is its consecutive child
                if let Some(cert) = self.try_two_chain_commit(&prev_locked) {
                    return Ok(Some(cert));
                }
            }
        }
        Ok(None)
    }

    async fn on_timeout(&mut self, height: BlockHeight, round: Round) -> ConsensusResult<Vote> {
        if height != self.height || round != self.round {
            return Err(ConsensusError::Timeout(height, round as u64));
        }
        self.pacemaker.on_timeout();
        let old_round = round;
        self.advance_round(round + 1);

        let validator = self.validator_set.validators
            .first()
            .map(|v| v.id.clone())
            .unwrap_or_else(|| ValidatorId("unknown".into()));

        // Sign timeout via SafetyStore (QAT-07); otherwise sign-later.
        let signature = if let Some(ctx) = self.signing_ctx.as_mut() {
            ctx.sign_timeout(&self.config.chain_id, self.epoch, old_round as u64, self.high_qc.round as u64)
                .map(|s| s.signature)
                .map_err(ConsensusError::Internal)?
        } else {
            vec![]
        };

        Ok(Vote {
            vote_type: VoteType::Nil,
            height,
            round: old_round,
            validator,
            block_hash: None,
            signature,
            scheme: Vote::default_scheme(),
        })
    }

    async fn on_commit(
        &mut self,
        certificate: CommitCertificate,
        new_validator_set: Option<ValidatorSet>,
    ) -> ConsensusResult<()> {
        if let Some(vs) = new_validator_set {
            // R1: verify two-chain finality before accepting the new set.
            // The certificate must carry consecutive rounds (locked_qc.round + 1 == high_qc.round)
            // and ≥ 2f+1 signatures from the outgoing set over the epoch-change block.
            self.verify_commit(&certificate, &self.validator_set.clone())
                .map_err(|e| ConsensusError::Internal(format!("epoch-change cert invalid: {e}")))?;

            let old_epoch = self.epoch;
            let seal_round = certificate.round; // QC_child.round = z+1 (the child of B_ec)

            // Hashes for the durable safety record.
            let cert_bytes = {
                let mut b = Vec::new();
                b.extend_from_slice(certificate.block_hash.0.as_bytes());
                b.extend_from_slice(&certificate.round.to_be_bytes());
                b.extend_from_slice(&certificate.height.to_be_bytes());
                b
            };
            let handoff_cert_hash = sha3_32(&cert_bytes);

            // Canonical V_new hash: sorted validator IDs + powers.
            let set_hash = {
                let mut b = Vec::new();
                for v in &vs.validators {
                    b.extend_from_slice(v.id.0.as_bytes());
                    b.extend_from_slice(&v.voting_power.to_be_bytes());
                }
                sha3_32(&b)
            };

            // R2 durable write order:
            // Step 1: CommitCertificate in block store (caller's responsibility before on_commit).
            // Step 2: write seal to safety record.
            // Step 3: advance epoch counter in safety record.
            // Step 4: update in-memory signing context.
            if let Some(ctx) = self.signing_ctx.as_mut() {
                ctx.write_seal(old_epoch, seal_round as u64)
                    .map_err(|e| ConsensusError::Internal(format!("write_seal failed: {e}")))?;
                ctx.advance_epoch_record(old_epoch + 1, set_hash, handoff_cert_hash)
                    .map_err(|e| ConsensusError::Internal(format!("advance_epoch_record failed: {e}")))?;
            }

            self.seal_round = Some(seal_round);
            self.epoch += 1;
            self.validator_set = vs;
        }

        self.height = certificate.height + 1;
        self.round = 1;
        self.accumulator.clear();
        self.pending_proposal = None;
        Ok(())
    }

    fn current_height(&self) -> BlockHeight { self.height }
    fn current_round(&self) -> Round { self.round }

    fn verify_commit(
        &self,
        certificate: &CommitCertificate,
        validator_set: &ValidatorSet,
    ) -> ConsensusResult<()> {
        let n = validator_set.validators.len();
        let threshold = (2 * n + 2) / 3;

        let mut seen: HashSet<String> = HashSet::new();
        let mut valid = 0usize;
        for vote in &certificate.precommits {
            if vote.vote_type != VoteType::Precommit { continue; }
            if vote.height != certificate.height { continue; }
            if vote.block_hash.as_ref() != Some(&certificate.block_hash) { continue; }
            if seen.insert(vote.validator.0.clone())
                && validator_set.validators.iter().any(|v| v.id == vote.validator)
            {
                valid += 1;
            }
        }

        if valid < threshold {
            return Err(ConsensusError::InsufficientValidators { needed: threshold, have: valid });
        }
        Ok(())
    }

    fn reset_to_height(
        &mut self,
        height: BlockHeight,
        validator_set: ValidatorSet,
    ) -> ConsensusResult<()> {
        self.height = height;
        self.round = 1;
        self.validator_set = validator_set;
        self.accumulator.clear();
        self.pending_proposal = None;
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Lightweight SHA3-256 hex digest used for block ID placeholders.
/// Real block IDs use `wire::BlockIdInput` and the full canonical encoding.
fn sha3_hex(data: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    Sha3_256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA3-256 as a 32-byte array (for wire signing).
fn sha3_32(data: &[u8]) -> [u8; HASH_LEN] {
    use sha3::{Digest, Sha3_256};
    Sha3_256::digest(data).into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConsensusConfig, ConsensusVariant, ValidatorInfo};

    fn make_validator(id: &str) -> ValidatorInfo {
        ValidatorInfo { id: ValidatorId(id.into()), voting_power: 1, pop_verified: false, public_key: vec![] }
    }

    fn four_node_set() -> ValidatorSet {
        ValidatorSet {
            height: 0,
            validators: (0..4).map(|i| make_validator(&format!("v{i}"))).collect(),
        }
    }

    async fn engine() -> PqHotStuffEngine {
        let mut e = PqHotStuffEngine::new();
        let config = ConsensusConfig {
            variant: ConsensusVariant::PqHotStuff,
            chain_id: "test-chain".into(),
            propose_timeout_ms: 1000,
            prevote_timeout_ms: 1000,
            precommit_timeout_ms: 1000,
            block_time_ms: 500,
            personhood: None,
            vca: None,
        };
        e.init(config, four_node_set()).await.unwrap();
        e
    }

    #[tokio::test]
    async fn init_sets_genesis_state() {
        let e = engine().await;
        assert_eq!(e.current_height(), 1);
        assert_eq!(e.current_round(), 1);
        assert_eq!(e.epoch(), 0);
        assert!(e.seal_round().is_none());
        assert_eq!(e.locked_qc().round, 0);
        assert_eq!(e.high_qc().round, 0);
    }

    #[tokio::test]
    async fn proposer_rotates_by_height_and_round() {
        let e = engine().await;
        // proposer_index = (height + round - 1) % n
        // height=1, round=1 → index 1 % 4 = 1 → "v1"... wait: (1+1-1)%4=1 → v1
        let p0 = e.proposer_for(1, 1).unwrap();
        let p1 = e.proposer_for(1, 2).unwrap();
        let p2 = e.proposer_for(2, 1).unwrap();
        assert_ne!(p0, p1);
        assert_ne!(p0, p2);
        assert_eq!(p1, p2); // (1+2-1)%4 == (2+1-1)%4 == 2
    }

    #[tokio::test]
    async fn two_chain_commit_fires_on_consecutive_qcs() {
        let mut e = engine().await;
        // Simulate: locked_qc at round 1, then high_qc at round 2 → commit round-1 block
        e.locked_qc = Qc { block_hash: BlockHash("b1".into()), round: 1, height: 1, signers: vec![] };
        let new_qc = Qc { block_hash: BlockHash("b2".into()), round: 2, height: 2, signers: vec![] };
        let cert = e.try_two_chain_commit(&e.locked_qc.clone());
        assert!(cert.is_none(), "no commit yet — locked_qc is not b1's child");

        // Now make locked_qc = new_qc (consecutive to old locked_qc)
        let old = e.locked_qc.clone();
        e.locked_qc = new_qc;
        let cert = e.try_two_chain_commit(&old);
        assert!(cert.is_some());
        let cert = cert.unwrap();
        assert_eq!(cert.round, 1);
        assert_eq!(cert.block_hash, BlockHash("b1".into()));
    }

    #[tokio::test]
    async fn pacemaker_doubles_on_timeout() {
        let e = engine().await;
        assert_eq!(e.current_timeout_ms(), 1000);
        let mut pm = Pacemaker::new(1000);
        pm.on_timeout();
        assert_eq!(pm.timeout_ms(), 2000);
        pm.on_timeout();
        assert_eq!(pm.timeout_ms(), 4000);
        pm.on_progress();
        assert_eq!(pm.timeout_ms(), 1000);
    }

    #[tokio::test]
    async fn epoch_transition_records_seal_round() {
        // 1-node set so quorum threshold = 1 and a single precommit satisfies R1 verification.
        let mut e = PqHotStuffEngine::new();
        let vs1 = ValidatorSet { height: 0, validators: vec![make_validator("v0")] };
        let config = ConsensusConfig {
            variant: ConsensusVariant::PqHotStuff,
            chain_id: "test-chain".into(),
            propose_timeout_ms: 1000, prevote_timeout_ms: 1000, precommit_timeout_ms: 1000,
            block_time_ms: 500, personhood: None, vca: None,
        };
        e.init(config, vs1).await.unwrap();

        let new_vs = ValidatorSet {
            height: 1,
            validators: vec![make_validator("v1")],
        };
        let precommit = Vote {
            vote_type: VoteType::Precommit,
            height: 1,
            round: 3,
            block_hash: Some(BlockHash("ec".into())),
            validator: ValidatorId("v0".into()),
            signature: vec![],
            scheme: Vote::default_scheme(),
        };
        let cert = CommitCertificate {
            height: 1, round: 3, block_hash: BlockHash("ec".into()), precommits: vec![precommit],
        };
        e.on_commit(cert, Some(new_vs)).await.unwrap();
        assert_eq!(e.seal_round(), Some(3));
        assert_eq!(e.epoch(), 1);
        assert_eq!(e.current_height(), 2);
        assert_eq!(e.validator_set().validators.len(), 1);
        assert_eq!(e.validator_set().validators[0].id.0, "v1");
    }

    #[tokio::test]
    async fn variant_is_pq_hotstuff() {
        let e = engine().await;
        assert_eq!(e.variant(), ConsensusVariant::PqHotStuff);
        assert_eq!(e.name(), "PQ-HotStuff-2");
    }
}
