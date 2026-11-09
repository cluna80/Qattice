//! The PQ-HotStuff-2 engine state machine for a FIXED validator set (epoch 0 only; dynamic membership is disabled, PO-4).
//!
//! Sans-IO: callers feed it messages and timer expiries and carry out the [`Output`]s it returns. Every signature goes through
//! the crash-safe [`SafetyStore`]: the engine decides *whether* to sign with the section 5 rules ([`super::rules`]) and the store
//! is the durable record that makes a restart unable to sign a conflicting message. After a restart the engine has lost its
//! volatile block tree (the p2p sync that refills it is later work); it can never sign anything the store forbids.
//!
//! The payload is opaque bytes, `devnet-interim` (the canonical payload codec is blocked on U5). Not activated on any network.
use std::collections::{BTreeMap, BTreeSet};

use super::certs::*;
use super::seed::{authenticate_checkpoint, Base, CheckpointSeed, SeedError, SeedEvidence};
use super::header::{ChainParams, Start};
use super::sync::BelowBase;
use super::checkpoint::{check_reference, effective_genesis_hash, final_height_after, is_v3, Alarm, ChainRefState, CheckpointConfig, CheckpointRef, Evidence, RefContext, RootCheck};
use super::leader::leader_index;
use super::limits::PqLimits;
use super::rules::{commits_parent, next_round, safe_to_timeout, safe_to_vote, BlockHeader, TcInfo, TimeoutRequest, VoterState};
use super::sync::{SyncRequest, SyncResponse};
use super::safety::{ConsensusSigner, ConsensusVerifier, Kind, MonotonicCounter, SafetyStore, SignError, Storage, CTX_TIMEOUT, CTX_VOTE};
use super::types::{EpochSet, Round};
use super::wire::{BlockSigningMessage, SignatureEnvelope, TimeoutMessage, VoteMessage, MLDSA65_SIGNATURE_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteMsg { pub voter: usize, pub msg: VoteMessage, pub signature: Vec<u8> }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutMsg { pub voter: usize, pub msg: TimeoutMessage, pub signature: Vec<u8>, pub high_qc: Cert }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg { Proposal(Block), Vote(VoteMsg), Timeout(TimeoutMsg), Tc(Tc) }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committed { pub id: BlockId, pub round: Round, pub height: u64, pub payload: Vec<u8> }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Deliver to one validator (a vote goes to the next leader).
    Send { to: usize, msg: Msg },
    Broadcast(Msg),
    /// A block is final. Emitted in height order, each block exactly once.
    Commit(Committed),
    /// The engine entered `round`; `leader` leads it (the caller schedules the round timer).
    EnteredRound { round: Round, leader: usize },
    /// Durable-state requests. The driver applies them IN ORDER, before it sends anything that follows them in the same
    /// output list: a block is persisted before it is voted for, a commit marker is persisted before the block is executed.
    PersistBlock(Block),
    PersistCommit { height: u64, id: BlockId },
    PersistHighQc(Cert),
    PersistHighTc(Tc),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeSync { Blocks(SyncResponse), BelowBase(BelowBase), Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedOutcome { Seeded, AlreadyAtBase }

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("configuration: {0}")]
    Config(String),
    #[error("invalid message: {0}")]
    Invalid(&'static str),
    #[error("certificate: {0}")]
    Cert(#[from] CertError),
    #[error("the parent block {0:02x?} is not known yet")]
    MissingParent(BlockId),
    #[error("not the leader of this round")]
    NotLeader,
    #[error("no timeout certificate for the previous round, and the high QC is not the previous round's")]
    NoTc,
    #[error("signing was refused by the safety store: {0}")]
    Sign(#[from] SignError),
    #[error("SAFETY VIOLATION: a conflicting block would be committed")]
    ConflictingCommit,
    #[error("recovery refused: {0}")]
    Restore(String),
    #[error("signing is halted by a safety/execution-consistency alarm: {0}")]
    Halted(String),
    #[error("RECOVERING: no signing until the seeded checkpoint's dependencies are in place ({0})")]
    Recovering(String),
    #[error("seed refused: {0}")]
    Seed(String),
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub chain_id: String,
    pub protocol_profile: String,
    pub set: EpochSet,
    pub my_index: usize,
    pub genesis_hash: [u8; 32],
    pub limits: PqLimits,
    /// Leader-rotation seed (the reduction of the epoch seed is unspecified, finding K3); 0 in Phase 0.
    pub seed: u64,
    /// Profile v3 only (and required there): the genesis-bound checkpoint parameters and the local proposer policy.
    pub checkpoint: Option<CheckpointConfig>,
}

struct Stored { block: Block, round: Round, height: u64, parent: BlockId, state: ChainRefState }

type VoteKey = (Round, BlockId, BlockId, Round);

pub struct Engine<S: Storage, C: MonotonicCounter, G: ConsensusSigner, V: ConsensusVerifier> {
    cfg: EngineConfig,
    store: SafetyStore<S, C>,
    signer: G,
    verifier: V,
    valset_hash: [u8; 32],
    genesis: GenesisCert,
    genesis_id: BlockId,
    /// Set by [`Engine::seed`]: the authenticated checkpoint block that stands in for the tree below it.
    base: Option<Base>,
    /// The authenticated reference of the base (set by `seed`); its state root is what a below-base answer names.
    base_ref: Option<CheckpointRef>,
    /// While true the engine signs NOTHING (no proposal, vote or timeout, and no re-send of a stored one).
    recovering: bool,
    blocks: BTreeMap<BlockId, Stored>,
    high_qc: Cert,
    high_tc: Option<Tc>,
    round: Round,
    committed_tip: BlockId,
    committed_height: u64,
    votes: BTreeMap<VoteKey, BTreeMap<usize, Vec<u8>>>,
    voted: BTreeSet<(usize, Round)>,
    timeouts: BTreeMap<Round, BTreeMap<usize, (u64, Vec<u8>, Cert)>>,
    proposed: Round,
    // checkpoint references (profile v3); all empty and unused on profile v2
    roots: BTreeMap<u64, [u8; 32]>,
    executed_height: u64,
    deferred: BTreeSet<BlockId>,
    final_refs: BTreeMap<u64, CheckpointRef>,
    certified_refs: BTreeMap<u64, CheckpointRef>,
    alarm: Option<Alarm>,
    evidence: Vec<Evidence>,
    omit_until: Round,
    proposed_ref_round: Option<Round>,
    proposed_ref_block: Option<BlockId>,
    omit_streak: u32,
}

/// Bounds on the volatile checkpoint bookkeeping.
const MAX_DEFERRED: usize = 64;
const MAX_EVIDENCE: usize = 32;

impl<S: Storage, C: MonotonicCounter, G: ConsensusSigner, V: ConsensusVerifier> Engine<S, C, G, V> {
    pub fn new(cfg: EngineConfig, store: SafetyStore<S, C>, signer: G, verifier: V) -> Result<Self, EngineError> {
        cfg.limits.validate().map_err(|e| EngineError::Config(e.to_string()))?;
        cfg.limits.check_set_size(cfg.set.len()).map_err(|e| EngineError::Config(e.to_string()))?;
        let me = cfg.set.entries().get(cfg.my_index).ok_or_else(|| EngineError::Config("my_index is outside the validator set".into()))?;
        if signer.public_key() != me.public_key.as_slice() {
            return Err(EngineError::Config("the signer's key is not this validator's registered key".into()));
        }
        if store.record().public_key != me.public_key {
            return Err(EngineError::Config("the safety store belongs to another key".into()));
        }
        let valset_hash = cfg.set.validator_set_hash();
        // v3: the validity-affecting checkpoint parameters are bound into the genesis, so a validator configured differently has a different genesis
        let genesis_hash = effective_genesis_hash(&cfg.protocol_profile, &cfg.genesis_hash, cfg.checkpoint.as_ref().map(|c| &c.params)).map_err(|e| EngineError::Config(e.to_string()))?;
        if let Some(c) = &cfg.checkpoint { c.policy.validate().map_err(|e| EngineError::Config(e.to_string()))?; }
        let genesis = GenesisCert { protocol_profile: cfg.protocol_profile.clone(), chain_id: cfg.chain_id.clone(), genesis_hash, valset_hash };
        let genesis_id = genesis.block_id();
        Ok(Self {
            valset_hash, genesis_id, base: None, base_ref: None, recovering: false, high_qc: Cert::Genesis(genesis.clone()), genesis, cfg, store, signer, verifier,
            blocks: BTreeMap::new(), high_tc: None, round: 1, committed_tip: genesis_id, committed_height: 0,
            votes: BTreeMap::new(), voted: BTreeSet::new(), timeouts: BTreeMap::new(), proposed: 0,
            roots: BTreeMap::new(), executed_height: 0, deferred: BTreeSet::new(), final_refs: BTreeMap::new(), certified_refs: BTreeMap::new(), alarm: None, evidence: vec![], omit_until: 0, proposed_ref_round: None, proposed_ref_block: None, omit_streak: 0,
        })
    }

    // ------------------------------------------------------------------------------------------------------ accessors
    pub fn round(&self) -> Round { self.round }
    pub fn high_qc(&self) -> &Cert { &self.high_qc }
    pub fn committed_tip(&self) -> (BlockId, u64) { (self.committed_tip, self.committed_height) }
    pub fn genesis_id(&self) -> BlockId { self.genesis_id }
    pub fn config(&self) -> &EngineConfig { &self.cfg }
    pub fn store(&self) -> &SafetyStore<S, C> { &self.store }
    pub fn into_parts(self) -> (SafetyStore<S, C>, G, V) { (self.store, self.signer, self.verifier) }
    pub fn known_blocks(&self) -> Vec<&Block> { self.blocks.values().map(|s| &s.block).collect() }
    pub fn leader_of(&self, round: Round) -> usize { leader_index(&self.cfg.set, round, self.cfg.seed).expect("a validated set has an eligible leader") }
    pub fn is_leader(&self) -> bool { self.leader_of(self.round) == self.cfg.my_index }

    fn ctx(&self) -> VerifyCtx<'_> {
        VerifyCtx { chain_id: &self.cfg.chain_id, set: &self.cfg.set, valset_hash: self.valset_hash, genesis: &self.genesis, verifier: &self.verifier }
    }
    fn idctx(&self) -> IdCtx<'_> { IdCtx { protocol_profile: &self.cfg.protocol_profile, chain_id: &self.cfg.chain_id, set: &self.cfg.set } }
    fn height_of(&self, id: &BlockId) -> Option<u64> { if *id == self.genesis_id { Some(0) } else if self.base.as_ref().map_or(false, |b| b.id == *id) { self.base.as_ref().map(|b| b.height) } else { self.blocks.get(id).map(|s| s.height) } }
    fn round_of(&self, id: &BlockId) -> Option<Round> { if *id == self.genesis_id { Some(0) } else if self.base.as_ref().map_or(false, |b| b.id == *id) { self.base.as_ref().map(|b| b.round) } else { self.blocks.get(id).map(|s| s.round) } }
    fn is_base(&self, id: &BlockId) -> bool { self.base.as_ref().map_or(false, |b| b.id == *id) }
    fn voter_state(&self) -> VoterState {
        let r = self.store.record();
        VoterState { hvr: r.hvr.unwrap_or(0), hqr: r.hqr.unwrap_or(0) }
    }

    // ------------------------------------------------------------------------------------------------------ dispatch
    pub fn on_message(&mut self, m: Msg) -> Result<Vec<Output>, EngineError> {
        match m {
            Msg::Proposal(b) => self.on_proposal(b),
            Msg::Vote(v) => self.on_vote(v),
            Msg::Timeout(t) => self.on_timeout(t),
            Msg::Tc(t) => self.on_tc(t),
        }
    }

    // ------------------------------------------------------------------------------------------------------ proposals
    pub fn on_proposal(&mut self, b: Block) -> Result<Vec<Output>, EngineError> {
        let Some((id, mut out)) = self.accept(b.clone())? else { return Ok(vec![]) };
        self.vote_or_defer(&b, id, &mut out)?;
        Ok(out)
    }

    /// Rule R5 (a voting rule, not a validity rule): a block that carries a reference is voted for only if the validator's own root matches; `NotYet` defers the
    /// vote until the executor catches up; `Unknown` and `Mismatch` withhold it (a mismatch against an uncertified proposal is evidence, not an alarm). A halted
    /// engine votes for nothing.
    fn vote_or_defer(&mut self, b: &Block, id: BlockId, out: &mut Vec<Output>) -> Result<(), EngineError> {
        if self.alarm.is_some() { return Ok(()); }
        let Some(r) = b.checkpoint else { return self.vote_for(b, id, out) };
        match self.ref_outcome(&r) {
            RootCheck::Match => self.vote_for(b, id, out),
            RootCheck::NotYet => { if self.deferred.len() >= MAX_DEFERRED { self.evict_oldest_deferred(); } self.deferred.insert(id); Ok(()) }
            outcome => { self.note_evidence(id, r, outcome); Ok(()) }
        }
    }

    /// Drop the deferred proposal of the LOWEST round (the one least likely to be votable still), not an arbitrary one: ids are hashes, so set order says nothing about age.
    fn evict_oldest_deferred(&mut self) {
        let oldest = self.deferred.iter().min_by_key(|id| self.blocks.get(*id).map(|s| s.round).unwrap_or(0)).copied();
        if let Some(o) = oldest { self.deferred.remove(&o); }
    }

    /// The lowest round among the deferred proposals (monitoring and tests).
    pub fn deferred_min_round(&self) -> Option<u64> { self.deferred.iter().filter_map(|id| self.blocks.get(id).map(|s| s.round)).min() }

    /// The highest round among the deferred proposals (monitoring and tests).
    pub fn deferred_max_round(&self) -> Option<u64> { self.deferred.iter().filter_map(|id| self.blocks.get(id).map(|s| s.round)).max() }

    fn note_evidence(&mut self, block_id: BlockId, reference: CheckpointRef, outcome: RootCheck) {
        if self.evidence.len() >= MAX_EVIDENCE { self.evidence.remove(0); }
        self.evidence.push(Evidence { block_id, reference, outcome, own_root: self.roots.get(&reference.height).copied() });
    }

    /// R5: compare a reference with this validator's own execution.
    pub fn ref_outcome(&self, r: &CheckpointRef) -> RootCheck {
        match self.roots.get(&r.height) {
            Some(root) => if *root == r.state_root { RootCheck::Match } else { RootCheck::Mismatch },
            None if r.height > self.executed_height => RootCheck::NotYet,
            None if self.final_refs.get(&r.height) == Some(r) => RootCheck::Match, // authenticated by a final ancestor carrying the identical reference
            None => RootCheck::Unknown,
        }
    }

    /// A block received through block sync (not as a live proposal): validated exactly like a proposal and added to the tree,
    /// its certificates adopted and any commits they prove emitted, but NEVER voted for.
    pub fn on_sync_block(&mut self, b: Block) -> Result<Vec<Output>, EngineError> {
        Ok(self.accept(b)?.map(|(_, out)| out).unwrap_or_default())
    }

    /// Validation and storage shared by proposals and synced blocks. `None` for a block already known.
    fn accept(&mut self, b: Block) -> Result<Option<(BlockId, Vec<Output>)>, EngineError> {
        // rule 1: well formed
        if b.epoch != self.cfg.set.epoch() { return Err(EngineError::Invalid("epoch")); }
        if b.round == 0 { return Err(EngineError::Invalid("round 0")); }
        // at or below the seeded checkpoint is final history this node deliberately does not hold: skipped, not an error, so that a sync window that straddles the base still delivers the blocks above it
        if let Some(base) = &self.base { if b.height <= base.height { return Ok(None); } }
        if b.payload.len() as u64 > self.cfg.limits.max_block_payload_bytes { return Err(EngineError::Invalid("payload above the limit")); }
        if b.proposer != self.leader_of(b.round) { return Err(EngineError::Invalid("proposer is not the leader of the round")); }
        let id = block_id_of(&b, &self.idctx())?;
        if self.blocks.contains_key(&id) { return Ok(None); }
        let msg = BlockSigningMessage { alg_id: ALG, block_id: id }.encode().map_err(|_| EngineError::Invalid("block signing message"))?;
        if !self.verifier.verify(&self.cfg.set.entries()[b.proposer].public_key, Kind::Proposal.context(), &msg, &b.signature) {
            return Err(EngineError::Invalid("proposer signature"));
        }
        // parent certificate
        if self.base.is_some() && matches!(b.qc, Cert::Genesis(_)) { return Err(EngineError::Invalid("does not extend the seeded checkpoint")); }
        verify_cert(&self.ctx(), &b.qc)?;
        if b.qc.block_id() != b.parent_id { return Err(EngineError::Invalid("parent_id differs from the certificate's block")); }
        let parent_height = match &b.qc {
            Cert::Genesis(_) => 0,
            Cert::Qc(_) => self.height_of(&b.parent_id).ok_or(EngineError::MissingParent(b.parent_id))?,
        };
        if b.height != parent_height.checked_add(1).ok_or(EngineError::Invalid("height"))? { return Err(EngineError::Invalid("height")); }
        if b.qc.round() >= b.round { return Err(EngineError::Invalid("round is not above the certificate's round")); }
        // timeout certificate: present exactly when the round is not the certificate's successor
        let consecutive = b.qc.round().checked_add(1) == Some(b.round);
        match (&b.tc, consecutive) {
            (None, true) => {}
            (Some(t), false) => {
                verify_tc(&self.ctx(), t)?;
                if t.round.checked_add(1) != Some(b.round) { return Err(EngineError::Invalid("timeout certificate is not for the previous round")); }
            }
            _ => return Err(EngineError::Invalid("timeout certificate presence")),
        }

        let (final_height, last_ref) = self.child_state(&b.parent_id);
        if let (true, Some(cc)) = (is_v3(&self.cfg.protocol_profile), self.cfg.checkpoint) {
            if let Some(r) = &b.checkpoint {
                let at = |h: u64| self.ancestor_at(&b.parent_id, h);
                check_reference(r, &RefContext { params: &cc.params, final_height, last_ref, block_id_at: &at }).map_err(|e| EngineError::Invalid(e.reason()))?;
            }
        }
        let state = ChainRefState { final_height, last_ref: b.checkpoint.or(last_ref) };
        self.blocks.insert(id, Stored { block: b.clone(), round: b.round, height: b.height, parent: b.parent_id, state });
        let mut out = vec![Output::PersistBlock(b.clone())];
        self.observe_cert(&b.qc.clone(), &mut out)?;
        if let Some(t) = &b.tc { self.observe_tc(t.clone(), &mut out); }
        self.try_form_qc_for(&id, &mut out)?;
        Ok(Some((id, out)))
    }

    fn vote_for(&mut self, b: &Block, id: BlockId, out: &mut Vec<Output>) -> Result<(), EngineError> {
        if self.recovering { return Ok(()); } // no vote (and no re-send of a stored one) while recovering
        let msg = VoteMessage { alg_id: ALG, chain_id: self.cfg.chain_id.clone(), epoch: b.epoch, round: b.round, block_id: id, parent_id: b.parent_id, parent_round: b.qc.round() };
        let bytes = msg.encode().map_err(|_| EngineError::Invalid("vote message"))?;
        let to = self.leader_of(b.round.saturating_add(1));
        // a restart re-sends the stored vote byte for byte instead of re-deriving it
        if let Some(last) = &self.store.record().last_vote {
            if last.round == b.round && last.message == bytes {
                let signature = last.envelope.signature.clone();
                return self.deliver_vote(to, VoteMsg { voter: self.cfg.my_index, msg, signature }, out);
            }
        }
        let header = BlockHeader { round: b.round, qc_round: b.qc.round(), tc: b.tc.as_ref().map(|t| TcInfo { round: t.round, max_high_qc_round: t.max_high_qc_round() }) };
        if safe_to_vote(&self.voter_state(), &header).is_err() { return Ok(()); } // not votable: no error, no vote
        let signed = self.store.sign_vote(&msg, b.qc.round(), &mut self.signer)?;
        self.deliver_vote(to, VoteMsg { voter: self.cfg.my_index, msg, signature: signed.envelope.signature }, out)
    }

    /// A vote goes to the next leader; if that is this node, count it here (a node never sends to itself).
    fn deliver_vote(&mut self, to: usize, v: VoteMsg, out: &mut Vec<Output>) -> Result<(), EngineError> {
        if to == self.cfg.my_index { let more = self.on_vote(v)?; out.extend(more); } else { out.push(Output::Send { to, msg: Msg::Vote(v) }); }
        Ok(())
    }

    // ------------------------------------------------------------------------------------------------------ votes -> QC
    pub fn on_vote(&mut self, v: VoteMsg) -> Result<Vec<Output>, EngineError> {
        let m = &v.msg;
        if m.chain_id != self.cfg.chain_id || m.epoch != self.cfg.set.epoch() || m.alg_id != ALG { return Err(EngineError::Invalid("vote identity")); }
        let pk = &self.cfg.set.entries().get(v.voter).ok_or(EngineError::Invalid("voter index"))?.public_key;
        if self.cfg.set.entries()[v.voter].power == 0 { return Err(EngineError::Invalid("zero-power voter")); }
        let bytes = m.encode().map_err(|_| EngineError::Invalid("vote message"))?;
        if v.signature.len() != MLDSA65_SIGNATURE_LEN || !self.verifier.verify(pk, CTX_VOTE, &bytes, &v.signature) {
            return Err(EngineError::Invalid("vote signature"));
        }
        // one counted vote per voter per round; a second, different vote is equivocation evidence for the caller, not counted
        if !self.voted.insert((v.voter, m.round)) { return Ok(vec![]); }
        self.votes.entry((m.round, m.block_id, m.parent_id, m.parent_round)).or_default().insert(v.voter, v.signature.clone());
        let mut out = vec![];
        self.try_form_qc_for(&m.block_id.clone(), &mut out)?;
        Ok(out)
    }

    fn try_form_qc_for(&mut self, id: &BlockId, out: &mut Vec<Output>) -> Result<(), EngineError> {
        if !self.blocks.contains_key(id) { return Ok(()); }
        let keys: Vec<VoteKey> = self.votes.keys().filter(|k| &k.1 == id).cloned().collect();
        for k in keys {
            let voters = &self.votes[&k];
            let idx: Vec<usize> = voters.keys().copied().collect();
            let power = self.cfg.set.signer_power(&idx).map_err(|_| EngineError::Invalid("voter power"))?;
            if !self.cfg.set.is_quorum(power) || k.0 <= self.high_qc.round() { continue; }
            let mut signers = vec![false; self.cfg.set.len()];
            let mut sigs = vec![];
            for (i, s) in voters { signers[*i] = true; sigs.push(s.clone()); } // BTreeMap iterates in ascending index order
            let qc = Qc { epoch: self.cfg.set.epoch(), round: k.0, block_id: k.1, parent_id: k.2, parent_round: k.3, valset_hash: self.valset_hash, signers, sigs };
            self.observe_cert(&Cert::Qc(qc), out)?;
        }
        Ok(())
    }

    /// Adopt a verified certificate: raise the high QC, commit by the two-chain rule, advance the round.
    fn observe_cert(&mut self, c: &Cert, out: &mut Vec<Output>) -> Result<(), EngineError> {
        let Cert::Qc(q) = c else { return Ok(()) };
        let Some(cr) = self.round_of(&q.block_id) else { return Ok(()) }; // block not known: cannot extend or commit through it
        if let Some(r) = self.blocks.get(&q.block_id).and_then(|s| s.block.checkpoint) { self.note_certified(r); }
        if self.proposed_ref_block == Some(q.block_id) { self.proposed_ref_block = None; self.omit_streak = 0; } // our reference-bearing proposal was certified
        if q.round > self.high_qc.round() { self.high_qc = c.clone(); out.push(Output::PersistHighQc(c.clone())); }
        if let Some(parent) = self.blocks.get(&q.block_id).map(|s| s.parent) {
            if let Some(pr) = self.round_of(&parent) {
                if parent != self.genesis_id && commits_parent(pr, cr) { self.commit_through(parent, out)?; }
            }
        }
        let before = self.round;
        self.round = next_round(self.round, q.round);
        if self.round != before { self.entered(out); }
        Ok(())
    }

    fn observe_tc(&mut self, t: Tc, out: &mut Vec<Output>) {
        let r = t.round;
        if self.high_tc.as_ref().map_or(true, |h| r > h.round) { out.push(Output::PersistHighTc(t.clone())); self.high_tc = Some(t); }
        let before = self.round;
        self.round = next_round(self.round, r);
        if self.round != before { self.entered(out); }
    }

    fn entered(&self, out: &mut Vec<Output>) { out.push(Output::EnteredRound { round: self.round, leader: self.leader_of(self.round) }); }

    /// Commit `target` and its uncommitted ancestors in height order. Refuses (and reports) a block that does not extend the tip.
    fn commit_through(&mut self, target: BlockId, out: &mut Vec<Output>) -> Result<(), EngineError> {
        // a target at or below the tip is already committed if it is an ancestor of the tip, and a fork if it is not
        if target == self.genesis_id || self.is_base(&target) { return Ok(()); } // the base is final by construction (authenticated), never re-emitted
        if self.blocks.get(&target).map_or(false, |s| s.height <= self.committed_height) {
            let mut cur = self.committed_tip;
            while cur != self.genesis_id {
                if cur == target { return Ok(()); }
                match self.blocks.get(&cur) { Some(s) if s.height > self.blocks[&target].height => cur = s.parent, _ => break }
            }
            return Err(EngineError::ConflictingCommit);
        }
        let mut chain = vec![];
        let mut cur = target;
        while cur != self.committed_tip {
            let Some(s) = self.blocks.get(&cur) else { return Err(EngineError::ConflictingCommit) };
            if s.height <= self.committed_height { return Err(EngineError::ConflictingCommit); } // at or below the tip but not the tip: a fork
            chain.push(cur);
            cur = s.parent;
            if cur == self.genesis_id && self.committed_tip != self.genesis_id { return Err(EngineError::ConflictingCommit); }
        }
        for id in chain.into_iter().rev() {
            let s = &self.blocks[&id];
            out.push(Output::PersistCommit { height: s.height, id });
            out.push(Output::Commit(Committed { id, round: s.round, height: s.height, payload: s.block.payload.clone() }));
            if let Some(r) = s.block.checkpoint { self.final_refs.insert(r.height, r); }
            self.committed_tip = id;
            self.committed_height = s.height;
        }
        Ok(())
    }

    // ------------------------------------------------------------------------------------------------------ timeouts -> TC
    /// The round timer expired: sign and broadcast a timeout for the current round (if the safety rules allow it).
    pub fn local_timeout(&mut self) -> Result<Vec<Output>, EngineError> {
        self.refuse_if_halted()?;
        self.refuse_if_recovering()?;
        let r = self.round;
        // a reference-bearing proposal of this node failed to gather a QC: omit references for a growing number of leader rotations (doubling per consecutive failure,
        // capped at 2^9 rotations) so that a quorum that cannot check references is not asked again every rotation
        if self.proposed_ref_round == Some(r) {
            self.proposed_ref_round = None;
            if let Some(cc) = self.cfg.checkpoint {
                self.omit_streak = self.omit_streak.saturating_add(1).min(10);
                let rotations = cc.policy.omit_rotations.saturating_mul(1u64 << (self.omit_streak - 1));
                self.omit_until = r.saturating_add((self.cfg.set.len() as u64).saturating_mul(rotations));
            }
        }
        let req = TimeoutRequest { round: r, high_qc_round: self.high_qc.round(), tc_round: self.high_tc.as_ref().map(|t| t.round) };
        let msg = TimeoutMessage { alg_id: ALG, chain_id: self.cfg.chain_id.clone(), epoch: self.cfg.set.epoch(), round: r, high_qc_round: self.high_qc.round() };
        let bytes = msg.encode().map_err(|_| EngineError::Invalid("timeout message"))?;
        let resend = matches!(&self.store.record().last_timeout, Some(l) if l.round == r && l.message == bytes);
        if !resend && safe_to_timeout(&self.voter_state(), &req).is_err() { return Err(EngineError::Invalid("timeout refused by the safety rules")); }
        let signed = self.store.sign_timeout(&msg, &mut self.signer)?;
        let tm = TimeoutMsg { voter: self.cfg.my_index, msg, signature: signed.envelope.signature, high_qc: self.high_qc.clone() };
        let mut out = vec![Output::Broadcast(Msg::Timeout(tm.clone()))];
        if let Some(t) = &self.high_tc { out.push(Output::Broadcast(Msg::Tc(t.clone()))); } // re-gossip the highest TC to laggards
        out.extend(self.on_timeout(tm)?);
        Ok(out)
    }

    pub fn on_timeout(&mut self, t: TimeoutMsg) -> Result<Vec<Output>, EngineError> {
        let m = &t.msg;
        if m.chain_id != self.cfg.chain_id || m.epoch != self.cfg.set.epoch() || m.alg_id != ALG { return Err(EngineError::Invalid("timeout identity")); }
        let entry = self.cfg.set.entries().get(t.voter).ok_or(EngineError::Invalid("voter index"))?;
        if entry.power == 0 { return Err(EngineError::Invalid("zero-power voter")); }
        let bytes = m.encode().map_err(|_| EngineError::Invalid("timeout message"))?;
        if t.signature.len() != MLDSA65_SIGNATURE_LEN || !self.verifier.verify(&entry.public_key, CTX_TIMEOUT, &bytes, &t.signature) {
            return Err(EngineError::Invalid("timeout signature"));
        }
        verify_cert(&self.ctx(), &t.high_qc)?;
        if t.high_qc.round() != m.high_qc_round { return Err(EngineError::Invalid("reported high QC round differs from the signed round")); }
        let mut out = vec![];
        self.observe_cert(&t.high_qc.clone(), &mut out)?;
        self.timeouts.entry(m.round).or_default().entry(t.voter).or_insert((m.high_qc_round, t.signature.clone(), t.high_qc.clone()));
        let r = m.round;
        let have = &self.timeouts[&r];
        let idx: Vec<usize> = have.keys().copied().collect();
        let power = self.cfg.set.signer_power(&idx).map_err(|_| EngineError::Invalid("voter power"))?;
        if self.cfg.set.is_quorum(power) && self.high_tc.as_ref().map_or(true, |h| r > h.round) {
            let mut signers = vec![false; self.cfg.set.len()];
            let (mut rounds, mut sigs) = (vec![], vec![]);
            let mut best: Option<&Cert> = None;
            for (i, (hr, s, hq)) in have { // ascending index order
                signers[*i] = true; rounds.push(*hr); sigs.push(s.clone());
                if best.map_or(true, |b| hq.round() > b.round()) { best = Some(hq); }
            }
            let tc = Tc { epoch: self.cfg.set.epoch(), round: r, valset_hash: self.valset_hash, signers, high_qc_rounds: rounds, sigs, high_qc: best.cloned().expect("a quorum is non-empty") };
            out.push(Output::Broadcast(Msg::Tc(tc.clone()))); // so a node that missed a timeout still advances
            self.observe_cert(&tc.high_qc.clone(), &mut out)?;
            self.observe_tc(tc, &mut out);
        }
        Ok(out)
    }

    /// A timeout certificate received from a peer (formed elsewhere): verify it, adopt its nested QC and advance the round.
    pub fn on_tc(&mut self, t: Tc) -> Result<Vec<Output>, EngineError> {
        verify_tc(&self.ctx(), &t)?;
        let mut out = vec![];
        self.observe_cert(&t.high_qc.clone(), &mut out)?;
        self.observe_tc(t, &mut out);
        Ok(out)
    }

    // ------------------------------------------------------------------------------------------------------ sync and recovery
    /// Serve a block-sync request: the requested block and up to `max_blocks - 1` of its ancestors that this node knows, oldest first.
    /// `None` if the requested block is unknown.
    /// Like [`Engine::serve_sync`], but a request that reaches the seeded base or below it gets an explicit [`ServeSync::BelowBase`] instead of silence.
    pub fn serve_sync_ex(&self, req: &SyncRequest, max_blocks: usize) -> ServeSync {
        if let (Some(b), Some(r)) = (self.base.as_ref(), self.base_ref.as_ref()) {
            if req.want == b.id || b.ancestors.iter().any(|(_, id)| *id == req.want) {
                return ServeSync::BelowBase(BelowBase { want: req.want, base_height: b.height, base_id: b.id, state_root: r.state_root, recovery_available: false });
            }
        }
        match self.serve_sync(req, max_blocks) { Some(r) => ServeSync::Blocks(r), None => ServeSync::Unknown }
    }

    pub fn serve_sync(&self, req: &SyncRequest, max_blocks: usize) -> Option<SyncResponse> {
        let cap = (req.max_blocks as usize).min(max_blocks).max(1);
        let mut chain = vec![];
        let mut cur = req.want;
        while chain.len() < cap {
            let Some(s) = self.blocks.get(&cur) else { break };
            chain.push(s.block.clone());
            cur = s.parent;
            if cur == self.genesis_id { break; }
        }
        if chain.is_empty() { return None; }
        chain.reverse();
        Some(SyncResponse { want: req.want, blocks: chain })
    }

    /// Committed blocks above `height`, in height order (the driver executes these after a restart so that an executor that
    /// is behind catches up exactly once: it compares its own durable height with this list).
    pub fn committed_after(&self, height: u64) -> Vec<Committed> {
        let mut chain = vec![];
        let mut cur = self.committed_tip;
        while cur != self.genesis_id {
            let Some(s) = self.blocks.get(&cur) else { break };
            if s.height <= height { break; }
            chain.push(Committed { id: cur, round: s.round, height: s.height, payload: s.block.payload.clone() });
            cur = s.parent;
        }
        chain.reverse();
        chain
    }

    /// Rebuild the volatile state from durable data after a restart. Every block is re-validated (leader, proposer signature,
    /// certificates) as when it first arrived, so a forged or damaged file cannot inject state. Commits are NOT re-emitted:
    /// the committed tip is rebuilt silently and `committed_after` tells the driver what its executor is missing. A block
    /// that fails validation is dropped (it can be fetched again by sync) unless it is part of the persisted committed
    /// history, in which case recovery is refused. Returns (blocks restored, blocks dropped).
    pub fn restore(&mut self, mut blocks: Vec<Block>, committed: &[(u64, BlockId)], high_qc: Option<Cert>, high_tc: Option<Tc>) -> Result<(usize, usize), EngineError> {
        blocks.sort_by_key(|b| b.height);
        let (mut ok, mut dropped) = (0, 0);
        // blocks may arrive in any order within a height; retry the ones whose parent was not yet known
        let mut pending = blocks;
        loop {
            let before = pending.len();
            let mut next = vec![];
            for b in pending {
                match self.accept(b.clone()) {
                    Ok(_) => ok += 1,
                    Err(EngineError::MissingParent(_)) => next.push(b),
                    Err(_) => dropped += 1,
                }
            }
            pending = next;
            if pending.is_empty() || pending.len() == before { break; }
        }
        dropped += pending.len();
        if let Some(c) = high_qc {
            if verify_cert(&self.ctx(), &c).is_ok() { let mut sink = vec![]; self.observe_cert(&c, &mut sink)?; }
        }
        if let Some(t) = high_tc {
            if verify_tc(&self.ctx(), &t).is_ok() { let mut sink = vec![]; self.observe_cert(&t.high_qc.clone(), &mut sink)?; self.observe_tc(t, &mut sink); }
        }
        for (height, id) in committed {
            let known = self.blocks.get(id).map(|s| s.height);
            if known != Some(*height) { return Err(EngineError::Restore(format!("committed block at height {height} is missing or damaged"))); }
            let mut sink = vec![];
            self.commit_through(*id, &mut sink).map_err(|_| EngineError::Restore(format!("committed history conflicts at height {height}")))?;
        }
        if let Some((h, id)) = committed.last() {
            if self.committed_height < *h || (self.committed_height == *h && self.committed_tip != *id) {
                return Err(EngineError::Restore("committed tip not reproduced".into()));
            }
        }
        // resume from max(high QC, high TC) + 1, and never below a round this validator already signed in
        let hvr = self.store.record().hvr.unwrap_or(0);
        self.round = self.round.max(hvr);
        Ok((ok, dropped))
    }

    /// After a restart: the stored vote, byte for byte, addressed to the next leader again (a restored node's block tree already holds
    /// the block, so a re-delivered proposal would not be voted for a second time). Counted locally if this node is that leader.
    pub fn resend_last_vote(&mut self) -> Result<Vec<Output>, EngineError> {
        if self.recovering { return Ok(vec![]); }
        let Some(l) = self.store.record().last_vote.clone() else { return Ok(vec![]) };
        let Ok(msg) = VoteMessage::decode(&l.message, ALG) else { return Ok(vec![]) };
        let to = self.leader_of(msg.round.saturating_add(1));
        let mut out = vec![];
        self.deliver_vote(to, VoteMsg { voter: self.cfg.my_index, msg, signature: l.envelope.signature }, &mut out)?;
        Ok(out)
    }

    /// After a restart: the stored timeout, byte for byte, broadcast again - only if the high QC this node holds is still the one it
    /// reported when it signed (otherwise peers would reject the carried certificate; a later round's timeout is built fresh).
    pub fn resend_last_timeout(&mut self) -> Result<Vec<Output>, EngineError> {
        if self.recovering { return Ok(vec![]); }
        let Some(l) = self.store.record().last_timeout.clone() else { return Ok(vec![]) };
        let Ok(msg) = TimeoutMessage::decode(&l.message, ALG) else { return Ok(vec![]) };
        if self.high_qc.round() != msg.high_qc_round { return Ok(vec![]); }
        let tm = TimeoutMsg { voter: self.cfg.my_index, msg, signature: l.envelope.signature, high_qc: self.high_qc.clone() };
        let mut out = vec![Output::Broadcast(Msg::Timeout(tm.clone()))];
        out.extend(self.on_timeout(tm)?);
        Ok(out)
    }

    // ------------------------------------------------------------------------------------------------------ proposing
    /// Propose for the current round with an opaque (`devnet-interim`) payload. The leader processes its own proposal, so it votes.
    pub fn propose(&mut self, payload: Vec<u8>) -> Result<Vec<Output>, EngineError> {
        let checkpoint = self.suggest_ref();
        self.propose_with(payload, checkpoint)
    }

    /// Like [`Engine::propose`] with an explicit reference (tests and tools). The block is still subject to every rule when the leader processes its own proposal.
    pub fn propose_with(&mut self, payload: Vec<u8>, checkpoint: Option<CheckpointRef>) -> Result<Vec<Output>, EngineError> {
        self.refuse_if_halted()?;
        self.refuse_if_recovering()?;
        let r = self.round;
        if !self.is_leader() { return Err(EngineError::NotLeader); }
        if r <= self.proposed { return Err(EngineError::Invalid("already proposed this round")); }
        if payload.len() as u64 > self.cfg.limits.max_block_payload_bytes { return Err(EngineError::Invalid("payload above the limit")); }
        let qc = self.high_qc.clone();
        let parent_id = qc.block_id();
        let height = self.height_of(&parent_id).ok_or(EngineError::MissingParent(parent_id))?.checked_add(1).ok_or(EngineError::Invalid("height"))?;
        let tc = if qc.round().checked_add(1) == Some(r) { None } else {
            match &self.high_tc { Some(t) if t.round.checked_add(1) == Some(r) => Some(t.clone()), _ => return Err(EngineError::NoTc) }
        };
        let mut b = Block { epoch: self.cfg.set.epoch(), round: r, height, parent_id, qc, tc, payload, proposer: self.cfg.my_index, signature: vec![], checkpoint };
        let id = block_id_of(&b, &self.idctx())?;
        let msg = BlockSigningMessage { alg_id: ALG, block_id: id };
        b.signature = self.store.sign_proposal(b.epoch, r, &msg, &mut self.signer)?.envelope.signature;
        self.proposed = r;
        self.proposed_ref_round = if b.checkpoint.is_some() { Some(r) } else { None };
        self.proposed_ref_block = if b.checkpoint.is_some() { Some(id) } else { None };
        let mut out = vec![Output::Broadcast(Msg::Proposal(b.clone()))];
        out.extend(self.on_proposal(b)?);
        Ok(out)
    }

    // ------------------------------------------------------------------------------------------------------ checkpoint references
    fn refuse_if_recovering(&self) -> Result<(), EngineError> {
        if self.recovering { Err(EngineError::Recovering(self.recovery_missing().unwrap_or_else(|| "complete_recovery has not been called".into()))) } else { Ok(()) }
    }

    /// Authenticate persisted or received evidence against THIS engine's own genesis, profile, chain id, validator set, leader seed and checkpoint parameters (never
    /// against values carried in the evidence). The result is a seed only if the whole of [`authenticate_checkpoint`] holds.
    pub fn authenticate_evidence(&self, ev: &SeedEvidence) -> Result<CheckpointSeed, SeedError> {
        let p = ChainParams { protocol_profile: &self.cfg.protocol_profile, chain_id: &self.cfg.chain_id, set: &self.cfg.set, genesis_hash: self.cfg.genesis_hash, seed: self.cfg.seed, checkpoint: self.cfg.checkpoint.map(|c| c.params) };
        authenticate_checkpoint(&p, &self.verifier, Start::Genesis, &ev.headers, ev.final_qc.as_ref(), ev.headers.len().max(1), &ev.cref, &ev.high_qc, ev.high_tc.as_ref())
    }

    /// The seeded checkpoint reference (height, block id, attested state root), if seeded.
    pub fn base_ref(&self) -> Option<&CheckpointRef> { self.base_ref.as_ref() }

    pub fn is_recovering(&self) -> bool { self.recovering }
    pub fn base(&self) -> Option<&Base> { self.base.as_ref() }

    /// Why the engine may not sign yet, or `None` when every condition holds: the high QC's block is known (so its ancestry down to the base is), and the
    /// engine has seen at least the highest QC round it ever voted on (the SafetyStore's `hqr`), so it never proposes or votes on a view older than its own record.
    pub fn recovery_missing(&self) -> Option<String> {
        if !self.recovering { return None; }
        let q = &self.high_qc;
        if self.height_of(&q.block_id()).is_none() && !matches!(q, Cert::Genesis(_)) { return Some(format!("the block certified by the high QC (round {}) has not arrived", q.round())); }
        let hqr = self.store.record().hqr.unwrap_or(0);
        if q.round() < hqr { return Some(format!("the high QC round {} is below the highest QC round this validator has signed against ({hqr})", q.round())); }
        None
    }

    /// Leave `Recovering` when [`Engine::recovery_missing`] is `None`.
    pub fn complete_recovery(&mut self) -> Result<(), EngineError> {
        if let Some(why) = self.recovery_missing() { return Err(EngineError::Recovering(why)); }
        self.recovering = false; // the round was raised to at least the store's hvr by `seed` and never goes down
        Ok(())
    }

    /// Checkpoint-start: adopt an AUTHENTICATED checkpoint as the root of the block tree. The engine enters `Recovering` (no signing at all) until the blocks above
    /// the base up to the high QC have arrived through [`Engine::on_sync_block`] (validated exactly like proposals, never voted) and [`Engine::complete_recovery`]
    /// succeeds. The SafetyStore is not touched: its floors (hvr, hqr, last vote, last timeout) are exactly what they were, and the engine's round never goes below hvr.
    ///
    /// Forward only and never a rewind: a checkpoint at a height below the committed tip is refused (a stale snapshot); the same checkpoint again is a no-op; a
    /// different block at the committed height is a conflict. Blocks that do not descend from the new base are dropped (they are below it or on another fork).
    /// What [`Engine::seed`] would do, without doing it: `AlreadyAtBase`, `Seeded` (it would proceed), or the error it would return. Nothing changes.
    pub fn seed_precheck(&self, seed: &CheckpointSeed) -> Result<SeedOutcome, EngineError> {
        let b = &seed.base;
        if self.committed_height > b.height { return Err(EngineError::Seed(format!("stale checkpoint: height {} is below the committed height {}", b.height, self.committed_height))); }
        if self.committed_height == b.height {
            return if self.committed_tip == b.id { Ok(SeedOutcome::AlreadyAtBase) } else { Err(EngineError::Seed("a different block is already committed at the checkpoint height".into())) };
        }
        // a committed prefix below the checkpoint must be on the authenticated (final) chain: wherever the evidence names the block at our committed height, it must be our tip.
        // Where the evidence does not reach that height there is nothing to compare with; under the stated assumptions two final chains cannot differ.
        if self.committed_height > 0 {
            let at = seed.chain.iter().find(|p| p.height == self.committed_height).map(|p| p.id).or_else(|| b.ancestors.iter().find(|(h, _)| *h == self.committed_height).map(|(_, id)| *id));
            if let Some(id) = at { if id != self.committed_tip { return Err(EngineError::Seed("the committed history conflicts with the authenticated checkpoint".into())); } }
        }
        Ok(SeedOutcome::Seeded)
    }

    pub fn seed(&mut self, seed: CheckpointSeed) -> Result<SeedOutcome, EngineError> {
        if self.seed_precheck(&seed)? == SeedOutcome::AlreadyAtBase { return Ok(SeedOutcome::AlreadyAtBase); }
        let b = &seed.base;
        self.base = Some(b.clone());
        self.base_ref = Some(seed.cref);
        self.committed_tip = b.id;
        self.committed_height = b.height;
        // keep only blocks that descend from the base
        let base_id = b.id; let base_h = b.height;
        let keep: Vec<BlockId> = self.blocks.iter().filter(|(_, s)| s.height > base_h).map(|(id, _)| *id).filter(|id| {
            let mut cur = *id;
            loop { match self.blocks.get(&cur) { Some(s) => { if s.parent == base_id { return true; } if s.height <= base_h + 1 { return false; } cur = s.parent; } None => return false } }
        }).collect();
        let keep: std::collections::BTreeSet<BlockId> = keep.into_iter().collect();
        self.blocks.retain(|id, _| keep.contains(id));
        self.deferred.retain(|id| keep.contains(id));
        if let Some(r) = b.state.last_ref { self.final_refs.insert(r.height, r); }
        self.final_refs.insert(seed.cref.height, seed.cref);
        // the authenticated checkpoint root is attested by a final carrier: the engine may rely on it like a final ancestor's reference
        let mut sink = vec![];
        if seed.high_qc.round() > self.high_qc.round() { self.high_qc = seed.high_qc.clone(); }
        if let Some(t) = &seed.high_tc { self.observe_tc(t.clone(), &mut sink); }
        let before = self.round;
        self.round = next_round(self.round, self.high_qc.round()).max(self.store.record().hvr.unwrap_or(0));
        if self.round != before { self.entered(&mut sink); }
        self.recovering = true;
        Ok(SeedOutcome::Seeded)
    }

    fn refuse_if_halted(&self) -> Result<(), EngineError> {
        match &self.alarm { Some(a) => Err(EngineError::Halted(format!("{a:?}"))), None => Ok(()) }
    }

    /// `(F(B), last reference)` for a child of `parent`: the two-chain rule applied to the parent and its own parent, and the most recent reference on the chain.
    fn child_state(&self, parent: &BlockId) -> (u64, Option<CheckpointRef>) {
        if let Some(b) = self.base.as_ref().filter(|b| b.id == *parent) {
            let p = if b.height >= 2 { Some((b.parent_round, b.height - 1)) } else { None };
            return (final_height_after(b.state.final_height, b.round, p), b.state.last_ref);
        }
        let Some(c) = self.blocks.get(parent) else { return (0, None) }; // the genesis block
        let p = if c.parent == self.genesis_id { None } else if let Some(b) = self.base.as_ref().filter(|b| b.id == c.parent) { Some((b.round, b.height)) } else { self.blocks.get(&c.parent).map(|s| (s.round, s.height)) };
        (final_height_after(c.state.final_height, c.round, p), c.state.last_ref)
    }

    /// The id of the block at `height` on the chain ending at `from` (walking parents), if it is known.
    fn ancestor_at(&self, from: &BlockId, height: u64) -> Option<BlockId> {
        let mut cur = *from;
        loop {
            if let Some(b) = self.base.as_ref().filter(|b| b.id == cur) {
                if b.height == height { return Some(cur); }
                if b.height < height { return None; }
                return b.ancestors.iter().find(|(h, _)| *h == height).map(|(_, id)| *id);
            }
            let s = self.blocks.get(&cur)?;
            if s.height == height { return Some(cur); }
            if s.height < height { return None; }
            cur = s.parent;
        }
    }

    /// Record a root this validator computed by executing the block at a checkpoint height. A different root for the same height is refused.
    pub fn record_root(&mut self, height: u64, root: [u8; 32]) -> Result<(), EngineError> {
        if let Some(prev) = self.roots.get(&height) { if *prev != root { return Err(EngineError::Invalid("a different root is already recorded for this height")); } return Ok(()); }
        self.roots.insert(height, root);
        if let Some(r) = self.certified_refs.get(&height).copied() { self.note_certified(r); }
        Ok(())
    }

    /// The executor has durably executed up to `height` (no votes are produced; see [`Engine::on_executed`]).
    pub fn set_executed(&mut self, height: u64) { if height > self.executed_height { self.executed_height = height; } }

    /// The executor advanced: re-evaluate the proposals whose vote was deferred for lack of a root, and vote for those that now match.
    pub fn on_executed(&mut self, height: u64) -> Result<Vec<Output>, EngineError> {
        self.set_executed(height);
        let mut out = vec![];
        for id in std::mem::take(&mut self.deferred) {
            let Some(b) = self.blocks.get(&id).map(|s| s.block.clone()) else { continue };
            let Some(r) = b.checkpoint else { continue };
            match self.ref_outcome(&r) {
                RootCheck::Match => { if self.alarm.is_none() { self.vote_for(&b, id, &mut out)?; } }
                RootCheck::NotYet => { self.deferred.insert(id); }
                outcome => self.note_evidence(id, r, outcome),
            }
        }
        Ok(out)
    }

    /// A reference carried by a block that has a QC (so a quorum accepted it): contradictions raise a generic alarm and halt signing. Nothing is attributed.
    fn note_certified(&mut self, r: CheckpointRef) {
        if self.alarm.is_some() { return; }
        if let Some(prev) = self.certified_refs.get(&r.height).copied() {
            if prev != r { self.alarm = Some(Alarm::ConflictingCertifiedRoots { first: prev, second: r }); return; }
        } else { self.certified_refs.insert(r.height, r); }
        if let Some(own) = self.roots.get(&r.height).copied() { if own != r.state_root { self.alarm = Some(Alarm::LocalDivergence { reference: r, own_root: own }); } }
    }

    /// The reference this node would put in a proposal built on its high QC, by policy (not a validity rule): the newest checkpoint height that is final, at least
    /// `margin` blocks behind its own executor, has a recorded root, is not already covered by the chain's last reference, and passes every validity rule.
    pub fn suggest_ref(&self) -> Option<CheckpointRef> {
        let cc = self.cfg.checkpoint?;
        if !is_v3(&self.cfg.protocol_profile) || !cc.policy.propose_refs || self.round < self.omit_until { return None; }
        let parent = self.high_qc.block_id();
        let (final_height, last_ref) = self.child_state(&parent);
        let limit = final_height.min(self.executed_height.checked_sub(cc.policy.margin)?);
        let h = limit - limit % cc.params.interval;
        if h == 0 || last_ref.map_or(false, |l| h <= l.height) { return None; }
        let r = CheckpointRef { height: h, block_id: self.ancestor_at(&parent, h)?, state_root: *self.roots.get(&h)? };
        let at = |x: u64| self.ancestor_at(&parent, x);
        check_reference(&r, &RefContext { params: &cc.params, final_height, last_ref, block_id_at: &at }).ok()?;
        Some(r)
    }

    /// Heights between the committed tip and the most recent reference on the committed chain (or the whole committed height if there is none): the monitoring
    /// figure for "optional references do not guarantee checkpoint progress".
    pub fn checkpoint_age(&self) -> u64 {
        let last = (if self.is_base(&self.committed_tip) { self.base.as_ref().and_then(|b| b.state.last_ref) } else { self.blocks.get(&self.committed_tip).and_then(|s| s.state.last_ref) }).map_or(0, |r| r.height);
        self.committed_height.saturating_sub(last)
    }
    /// Whether `checkpoint_age` exceeds the configured alarm age (a number of intervals); always false without checkpoint configuration.
    pub fn checkpoint_stale(&self) -> bool {
        self.cfg.checkpoint.map_or(false, |c| self.checkpoint_age() > c.params.interval.saturating_mul(c.policy.alarm_age_intervals))
    }
    /// `(omit_until round, consecutive failed reference-bearing proposals)`: the proposer policy's backoff state (monitoring and tests).
    pub fn ref_backoff(&self) -> (Round, u32) { (self.omit_until, self.omit_streak) }
    pub fn alarm(&self) -> Option<&Alarm> { self.alarm.as_ref() }
    pub fn evidence(&self) -> &[Evidence] { &self.evidence }
    pub fn root(&self, height: u64) -> Option<[u8; 32]> { self.roots.get(&height).copied() }
    pub fn deferred_len(&self) -> usize { self.deferred.len() }
    pub fn executed_height(&self) -> u64 { self.executed_height }
    /// The chain-derived reference state of a known block (tests, monitoring).
    pub fn chain_ref_state(&self, id: &BlockId) -> Option<ChainRefState> { self.blocks.get(id).map(|s| s.state) }

    /// Envelope of a signature, for callers that need to forward a stored signature (the wire envelope of spec 3.2).
    pub fn envelope(sig: Vec<u8>) -> SignatureEnvelope { SignatureEnvelope { alg_id: ALG, signature: sig } }
}
