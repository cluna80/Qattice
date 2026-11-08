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
}

struct Stored { block: Block, round: Round, height: u64, parent: BlockId }

type VoteKey = (Round, BlockId, BlockId, Round);

pub struct Engine<S: Storage, C: MonotonicCounter, G: ConsensusSigner, V: ConsensusVerifier> {
    cfg: EngineConfig,
    store: SafetyStore<S, C>,
    signer: G,
    verifier: V,
    valset_hash: [u8; 32],
    genesis: GenesisCert,
    genesis_id: BlockId,
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
}

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
        let genesis = GenesisCert { protocol_profile: cfg.protocol_profile.clone(), chain_id: cfg.chain_id.clone(), genesis_hash: cfg.genesis_hash, valset_hash };
        let genesis_id = genesis.block_id();
        Ok(Self {
            valset_hash, genesis_id, high_qc: Cert::Genesis(genesis.clone()), genesis, cfg, store, signer, verifier,
            blocks: BTreeMap::new(), high_tc: None, round: 1, committed_tip: genesis_id, committed_height: 0,
            votes: BTreeMap::new(), voted: BTreeSet::new(), timeouts: BTreeMap::new(), proposed: 0,
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
    fn height_of(&self, id: &BlockId) -> Option<u64> { if *id == self.genesis_id { Some(0) } else { self.blocks.get(id).map(|s| s.height) } }
    fn round_of(&self, id: &BlockId) -> Option<Round> { if *id == self.genesis_id { Some(0) } else { self.blocks.get(id).map(|s| s.round) } }
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
        self.vote_for(&b, id, &mut out)?;
        Ok(out)
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
        if b.payload.len() as u64 > self.cfg.limits.max_block_payload_bytes { return Err(EngineError::Invalid("payload above the limit")); }
        if b.proposer != self.leader_of(b.round) { return Err(EngineError::Invalid("proposer is not the leader of the round")); }
        let id = block_id_of(&b, &self.idctx())?;
        if self.blocks.contains_key(&id) { return Ok(None); }
        let msg = BlockSigningMessage { alg_id: ALG, block_id: id }.encode().map_err(|_| EngineError::Invalid("block signing message"))?;
        if !self.verifier.verify(&self.cfg.set.entries()[b.proposer].public_key, Kind::Proposal.context(), &msg, &b.signature) {
            return Err(EngineError::Invalid("proposer signature"));
        }
        // parent certificate
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

        self.blocks.insert(id, Stored { block: b.clone(), round: b.round, height: b.height, parent: b.parent_id });
        let mut out = vec![Output::PersistBlock(b.clone())];
        self.observe_cert(&b.qc.clone(), &mut out)?;
        if let Some(t) = &b.tc { self.observe_tc(t.clone(), &mut out); }
        self.try_form_qc_for(&id, &mut out)?;
        Ok(Some((id, out)))
    }

    fn vote_for(&mut self, b: &Block, id: BlockId, out: &mut Vec<Output>) -> Result<(), EngineError> {
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
        if target == self.genesis_id { return Ok(()); }
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
            self.committed_tip = id;
            self.committed_height = s.height;
        }
        Ok(())
    }

    // ------------------------------------------------------------------------------------------------------ timeouts -> TC
    /// The round timer expired: sign and broadcast a timeout for the current round (if the safety rules allow it).
    pub fn local_timeout(&mut self) -> Result<Vec<Output>, EngineError> {
        let r = self.round;
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
        let mut b = Block { epoch: self.cfg.set.epoch(), round: r, height, parent_id, qc, tc, payload, proposer: self.cfg.my_index, signature: vec![] };
        let id = block_id_of(&b, &self.idctx())?;
        let msg = BlockSigningMessage { alg_id: ALG, block_id: id };
        b.signature = self.store.sign_proposal(b.epoch, r, &msg, &mut self.signer)?.envelope.signature;
        self.proposed = r;
        let mut out = vec![Output::Broadcast(Msg::Proposal(b.clone()))];
        out.extend(self.on_proposal(b)?);
        Ok(out)
    }

    /// Envelope of a signature, for callers that need to forward a stored signature (the wire envelope of spec 3.2).
    pub fn envelope(sig: Vec<u8>) -> SignatureEnvelope { SignatureEnvelope { alg_id: ALG, signature: sig } }
}
