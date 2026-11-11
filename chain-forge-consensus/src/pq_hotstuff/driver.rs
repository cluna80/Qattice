//! PQ-HotStuff-2 node driver: a sans-IO shell around the [`Engine`] that owns durable state, block sync, the pacemaker and the execution
//! handoff. The caller supplies bytes and a clock (any monotonic unit, the same one the configuration uses) and sends what comes back.
//!
//! Ordering rules the driver enforces (each has a test):
//! * Durable-state requests (`PersistBlock`, `PersistCommit`, `PersistHighQc`, `PersistHighTc`) are applied in order BEFORE anything that
//!   follows them in the same output list is sent or executed: a block is stored before its vote leaves, a commit marker before execution.
//! * A finalized block goes to the [`Executor`] once; the executor's own durable cursor decides what is replayed after a restart.
//! * On start the driver recovers everything from disk (re-validating every block), checks the executor's cursor against the recovered committed
//!   history and refuses to run on a mismatch, replays what the executor missed, then re-sends the stored vote/timeout byte for byte.
//! * Storage, executor and safety-store failures are FATAL (`Err`): the process must stop and recover from disk. Bad messages are not.
//!
//! The configuration is validated at start ([`validate_config`]): the validator count and the worst-case proposal, timeout, TC and sync
//! response are derived with checked arithmetic and must fit the configured transport limit, otherwise the driver refuses to start.
//!
//! Payloads are `devnet-interim` opaque bytes; dynamic membership is disabled (the validator set is fixed for the run).
use std::collections::VecDeque;

use super::blockstore::{BlockFiles, BlockStore, StoreError};
use super::certs::{block_id_of, BlockId, IdCtx};
use super::engine::{Committed, Engine, EngineConfig, EngineError, Msg, Output};
use super::exec::{ExecCursor, ExecError, Executor};
use super::netmsg::{self as net, MessageLimits, NetLimitError, NetMsg};
use super::pacemaker::{Pacemaker, PacemakerConfig, PacemakerError};
use super::safety::{ConsensusSigner, ConsensusVerifier, MonotonicCounter, Storage};
use super::sync::{check_response, SyncClient, SyncRequest, SyncResponse};
use super::engine::ServeSync;
use super::seed::{SeedEvidence, MAX_EVIDENCE_HEADERS};
use super::types::EpochSet;
#[cfg(feature = "pq-anchored-evidence")]
use super::anchor_restart::{AnchorRestart, RestartError, RestartOutcome};
#[cfg(feature = "pq-anchored-evidence")]
use super::header::{ChainParams, PayloadFreeBlock};

#[derive(Debug)]
pub struct DriverConfig {
    /// Blocks per sync response this node asks for and serves.
    pub max_sync_blocks: usize,
    pub pace: PacemakerConfig,
    /// How long a sync request stays outstanding, and how many may be outstanding at once.
    pub sync_ttl: u64,
    pub sync_outstanding: usize,
    /// A leader waits this long after entering a round before it proposes (throttles block production).
    pub min_propose_gap: u64,
    /// Messages waiting for a missing ancestor: how many are kept and for how long.
    pub park_capacity: usize,
    pub park_ttl: u64,
    /// How many recently executed blocks to remember for status reporting.
    pub recent: usize,
    /// `None`: a finalized block is executed immediately, inline. `Some(n)`: finalized blocks are queued and at most `n` are executed per `tick` (`Some(0)` pauses
    /// execution entirely). This models execution lag; the executor's own durable cursor still decides what is replayed after a restart.
    pub exec_per_tick: Option<usize>,
    /// AN-3: when `AuditFirst` mode is in use, the caller pre-opens the ring, runs `AnchorRestart::open`, and places the result here before calling `start`.
    /// Signing stays disabled until `advance_anchor` delivers `AdvanceAnchorOutcome::Ready`. `Off` behavior is fully preserved when this is `None`.
    #[cfg(feature = "pq-anchored-evidence")]
    pub anchor: Option<AnchorRestart>,
}

#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error("unsupported configuration: {0}")]
    Config(String),
    #[error("engine: {0}")]
    Engine(#[from] EngineError),
    #[error("block store: {0}")]
    Store(#[from] StoreError),
    #[error("executor: {0}")]
    Exec(#[from] ExecError),
    #[error("the executor is at height {exec} but the recovered committed history ends at {committed}; refusing to run")]
    ExecutorAhead { exec: u64, committed: u64 },
    #[error("the executor's block at height {height} is not the recovered committed block at that height; refusing to run")]
    Diverged { height: u64 },
    #[error("SAFETY: {0}")]
    Safety(String),
    /// Persisted seed evidence is missing its parts, damaged, for another chain/profile/validator set/parameters, or does not authenticate. The node does not run.
    #[error("seed evidence refused: {0}")]
    SeedEvidence(String),
    #[error("the executor is at height {exec}, below the seeded checkpoint at {base}: the application state must be installed at the checkpoint first; refusing to run")]
    ExecutorBehindBase { exec: u64, base: u64 },
    #[error("the executor and the seeded checkpoint disagree: {0}; refusing to run")]
    BaseMismatch(String),
    /// AN-3: the anchor ring record or its cross-check failed; the driver will not start in AuditFirst mode.
    #[cfg(feature = "pq-anchored-evidence")]
    #[error("anchor refused at startup: {0}")]
    AnchorRefused(RestartError),
    /// AN-3: audit completed but executor-state reconciliation failed; the driver will not start in AuditFirst mode.
    #[cfg(feature = "pq-anchored-evidence")]
    #[error("anchor reconciliation failed: {0}")]
    AnchorInconsistent(RestartError),
}

/// Something to send: to one validator, or (`to == None`) to all the others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound { pub to: Option<usize>, pub bytes: Vec<u8> }

/// AN-3 (`pq-anchored-evidence` feature): the outcome of a [`Driver::advance_anchor`] call.
#[cfg(feature = "pq-anchored-evidence")]
#[derive(Debug)]
pub enum AdvanceAnchorOutcome {
    /// No anchor is installed; the driver is running in `AnchorMode::Off` mode.
    NotPending,
    /// More headers needed; call `advance_anchor` again with the window starting at `next_height`.
    Pending { next_height: u64 },
    /// Audit and reconciliation succeeded; `deferred` are the replay and resend messages that were held back at startup.
    /// The caller should send `deferred` to peers before processing new messages.
    Ready { audited_height: u64, deferred: Vec<Outbound> },
    /// The audit failed; signing stays disabled.
    AuditFailed(RestartError),
    /// The audit succeeded but executor-state reconciliation failed; signing stays disabled.
    ReconcileFailed(RestartError),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats { pub malformed: u64, pub bad_sync: u64, pub sync_requests: u64, pub unsolicited_sync: u64, pub parked_dropped: u64, pub below_base_served: u64, pub below_base_advice: u64,
    /// How many times the engine REFUSED to propose / time out because it was `Recovering` (the gate was reached and held; nothing was signed).
    pub propose_refused_while_recovering: u64, pub timeout_refused_while_recovering: u64 }

#[derive(Debug, Clone)]
pub struct Status {
    pub round: u64,
    pub high_qc_round: u64,
    pub committed_height: u64,
    pub committed_tip: BlockId,
    pub exec: ExecCursor,
    pub stats: Stats,
    pub recent: Vec<ExecCursor>,
}

/// Supplies the opaque (`devnet-interim`) payload for a round this node leads: `(round, my index)`.
pub type PayloadSource = Box<dyn FnMut(u64, usize) -> Vec<u8> + Send>;

/// Check the configuration BEFORE building anything: pacemaker, sync size, and the derived worst-case message of every kind against the
/// configured transport limit (`PqLimits::max_message_bytes`, which must be set). Unsupported configurations are rejected explicitly.
pub fn validate_config(e: &EngineConfig, d: &DriverConfig) -> Result<MessageLimits, DriverError> {
    d.pace.validate().map_err(|e: PacemakerError| DriverError::Config(e.to_string()))?;
    if d.sync_outstanding == 0 || d.sync_ttl == 0 || d.park_capacity == 0 || d.recent == 0 {
        return Err(DriverError::Config("sync_outstanding, sync_ttl, park_capacity and recent must be positive".into()));
    }
    let n = e.set.len();
    let lim = MessageLimits::derive(&e.limits, n, e.chain_id.len(), d.max_sync_blocks).map_err(|err: NetLimitError| DriverError::Config(err.to_string()))?;
    let prop = e.limits.proposal_envelope_max(n).ok_or_else(|| DriverError::Config("proposal size overflows".into()))?;
    if prop > lim.transport { return Err(DriverError::Config(format!("the worst-case proposal ({prop} bytes) exceeds the transport limit {}", lim.transport))); }
    Ok(lim)
}

/// Which engine errors stop the node: a conflicting commit, or a refusal by a latched signing-safety store. Everything else is a bad message.
pub fn classify_engine_error(e: EngineError, store_latched: bool) -> Result<(), DriverError> {
    match e {
        EngineError::ConflictingCommit => Err(DriverError::Safety("a conflicting block would be committed".into())),
        EngineError::Halted(m) => Err(DriverError::Safety(format!("signing is halted by a safety/execution-consistency alarm: {m}"))),
        EngineError::Sign(_) if store_latched => Err(DriverError::Safety("the signing-safety store is latched; this validator will not sign".into())),
        _ => Ok(()),
    }
}

struct Parked { from: usize, msg: Msg, until: u64 }

pub struct Driver<S: Storage, C: MonotonicCounter, G: ConsensusSigner, V: ConsensusVerifier, B: BlockFiles, X: Executor> {
    dc: DriverConfig,
    lim: MessageLimits,
    engine: Engine<S, C, G, V>,
    store: BlockStore<B>,
    exec: X,
    pace: Pacemaker,
    sync: SyncClient,
    payload: PayloadSource,
    profile: String,
    chain: String,
    set: EpochSet,
    me: usize,
    n: usize,
    now: u64,
    round_started: u64,
    last_round: u64,
    last_hqc: u64,
    rr: usize,
    parked: VecDeque<Parked>,
    recent: VecDeque<ExecCursor>,
    stats: Stats,
    pending_exec: VecDeque<Committed>,
    interval: Option<u64>,
    /// AN-3: when `AuditFirst` mode is in use, this holds the restart state machine until `advance_anchor` finishes.
    #[cfg(feature = "pq-anchored-evidence")]
    anchor: Option<AnchorRestart>,
    /// Snapshot capture and serving (S-2b): absent unless the `pq-snapshot-transfer` feature is built AND the node opted in at runtime.
    #[cfg(feature = "pq-snapshot-transfer")]
    recovery: Option<Box<dyn super::serving::RecoveryService>>,
}

impl<S: Storage, C: MonotonicCounter, G: ConsensusSigner, V: ConsensusVerifier, B: BlockFiles, X: Executor> Driver<S, C, G, V, B, X> {
    /// Recover from disk and start. Returns the messages to send first (the stored vote/timeout, byte for byte).
    pub fn start(mut dc: DriverConfig, mut engine: Engine<S, C, G, V>, mut store: BlockStore<B>, exec: X, payload: PayloadSource, now: u64) -> Result<(Self, Vec<Outbound>), DriverError> {
        let lim = validate_config(engine.config(), &dc)?;
        let loaded = store.load()?;
        // A stored seed (checkpoint-start) is RE-AUTHENTICATED from its evidence against this node's own genesis, profile, validator set and parameters before anything
        // else is restored; damaged, mismatched or unauthentic evidence stops the node (it never runs unseeded on top of history it does not hold).
        if let Some((h, id, bytes)) = store.load_seed_evidence()? {
            let ev = SeedEvidence::decode(&bytes, MAX_EVIDENCE_HEADERS).map_err(|e| DriverError::SeedEvidence(e.to_string()))?;
            let seed = engine.authenticate_evidence(&ev).map_err(|e| DriverError::SeedEvidence(e.to_string()))?;
            if seed.base().height != h || seed.base().id != id || loaded.seeded_height != h { return Err(DriverError::SeedEvidence("the stored evidence does not describe the checkpoint its name and record claim".into())); }
            engine.seed(seed.clone()).map_err(|e| DriverError::SeedEvidence(e.to_string()))?;
        }
        // checkpoint roots (profile v3) are loaded BEFORE recovery so that references in recovered blocks are judged against them; damaged or missing records are
        // left out (a missing root only costs a vote or a deferral, never a guess)
        let interval = engine.config().checkpoint.filter(|_| super::checkpoint::is_v3(&engine.config().protocol_profile)).map(|c| c.params.interval);
        if let Some(k) = interval { for (h, r) in store.load_roots(k)?.roots { engine.record_root(h, r)?; } }
        engine.restore(loaded.blocks, &loaded.committed, loaded.high_qc, loaded.high_tc)?;
        // commit markers a crash lost are written again (the engine re-derived them from the certificates it recovered)
        for c in engine.committed_after(loaded.seeded_height + loaded.committed.len() as u64) { store.put_commit(c.height, &c.id)?; }

        let cur = exec.cursor();
        let (_, tip) = engine.committed_tip();
        if cur.height > tip { return Err(DriverError::ExecutorAhead { exec: cur.height, committed: tip }); }
        let seeded = engine.base().map(|b| (b.height, b.id)).zip(engine.base_ref().copied());
        if let Some(((bh, bid), bref)) = seeded {
            // the executor must hold the state at the checkpoint (or beyond it, on the committed chain); it cannot be caught up from history this node does not have
            if cur.height < bh { return Err(DriverError::ExecutorBehindBase { exec: cur.height, base: bh }); }
            if cur.height == bh && (cur.block_id != bid || cur.state_digest != bref.state_root) { return Err(DriverError::BaseMismatch("the executor's cursor at the checkpoint height is not the authenticated checkpoint (block or state root)".into())); }
        }
        if cur.height > 0 && seeded.map_or(true, |((bh, _), _)| cur.height > bh) {
            match engine.committed_after(cur.height - 1).first() {
                Some(c) if c.height == cur.height && c.id == cur.block_id => {}
                _ => return Err(DriverError::Diverged { height: cur.height }),
            }
        }
        let mut recent = VecDeque::new();
        if cur.height > 0 { recent.push_back(cur); }
        // the root of the executor's own checkpoint is always derivable from its cursor, so a crash between executing a checkpoint block and logging its root loses nothing
        if let (Some(k), Some((_, bref))) = (interval, seeded.map(|(b, r)| (b, r))) {
            // the authenticated root of the checkpoint goes in the root log like an executed one; a different root already there refuses the start
            store.put_root(k, bref.height, &bref.state_root).map_err(|e| DriverError::BaseMismatch(e.to_string()))?;
            engine.record_root(bref.height, bref.state_root).map_err(|e| DriverError::BaseMismatch(e.to_string()))?;
        }
        if let Some(k) = interval {
            engine.set_executed(cur.height);
            if cur.height > 0 && cur.height % k == 0 { store.put_root(k, cur.height, &cur.state_digest)?; engine.record_root(cur.height, cur.state_digest)?; }
        }
        // AN-3: extract the anchor before consuming dc
        #[cfg(feature = "pq-anchored-evidence")]
        let anchor_sm = dc.anchor.take();
        let cfg = engine.config();
        let (profile, chain, set, me) = (cfg.protocol_profile.clone(), cfg.chain_id.clone(), cfg.set.clone(), cfg.my_index);
        let n = set.len();
        let mut d = Driver {
            pace: Pacemaker::new(dc.pace).map_err(|e| DriverError::Config(e.to_string()))?, sync: SyncClient::new(dc.sync_ttl, dc.sync_outstanding),
            round_started: now, last_round: engine.round(), last_hqc: engine.high_qc().round(), rr: me,
            dc, lim, engine, store, exec, payload, profile, chain, set, me, n, now, parked: VecDeque::new(), recent, stats: Stats::default(), pending_exec: VecDeque::new(), interval,
            #[cfg(feature = "pq-anchored-evidence")] anchor: anchor_sm,
            #[cfg(feature = "pq-snapshot-transfer")] recovery: None,
        };
        // Leave `Recovering` first if every dependency is already present (it signs nothing: it only checks that the high QC's block is known and that the round is not
        // below the store's `hqr`): the re-sends below are gated while recovering, and a restarted node that is not recovering must re-send its stored vote and timeout
        // exactly as an unseeded restart does.
        d.try_complete_recovery();
        // AN-3: when AuditFirst mode is active the anchor audit must complete before any replay or resend.
        // The driver is returned in a pending state; signing stays disabled until `advance_anchor` delivers Ready.
        #[cfg(feature = "pq-anchored-evidence")]
        if d.anchor.is_some() {
            return Ok((d, vec![]));
        }
        // the executor catches up from ITS durable cursor, exactly once
        let mut replay_outs = vec![];
        for c in d.engine.committed_after(cur.height) { replay_outs.extend(d.execute(c)?); }
        let replay_sends = d.route(replay_outs)?;
        let mut outs = d.engine.resend_last_vote().unwrap_or_default();
        outs.extend(d.engine.resend_last_timeout().unwrap_or_default());
        let mut first = replay_sends;
        first.extend(d.route(outs)?);
        Ok((d, first))
    }

    /// Leave `Recovering` as soon as the engine says every condition holds (it never signs before that).
    /// Skipped when the anchor audit is pending — signing must remain gated until `advance_anchor` returns `Ready`.
    fn try_complete_recovery(&mut self) {
        #[cfg(feature = "pq-anchored-evidence")]
        if self.anchor.is_some() { return; }
        if self.engine.is_recovering() { let _ = self.engine.complete_recovery(); }
    }

    /// AN-3 (`pq-anchored-evidence` feature): feed the next window of headers to the anchor audit.
    ///
    /// Returns `NotPending` immediately if no anchor state machine is installed (`AnchorMode::Off` behavior). Otherwise
    /// drives the audit forward; on `Ready`, reconciles executor state, then completes the deferred replay and resend
    /// that `start` skipped. On any failure returns the error without clearing the anchor gate — signing stays disabled.
    #[cfg(feature = "pq-anchored-evidence")]
    pub fn advance_anchor(&mut self, headers: &[PayloadFreeBlock]) -> Result<AdvanceAnchorOutcome, DriverError> {
        if self.anchor.is_none() { return Ok(AdvanceAnchorOutcome::NotPending); }
        // Build ChainParams from the engine config (all borrows from the EngineConfig stored in self.engine).
        let cfg = self.engine.config();
        let cp = cfg.checkpoint.map(|c| c.params);
        // ChainParams borrows from cfg; create it with a local reference to avoid lifetime tangles.
        let (profile, chain_id, set, genesis_hash, seed) =
            (cfg.protocol_profile.clone(), cfg.chain_id.clone(), cfg.set.clone(), cfg.genesis_hash, cfg.seed);
        let p = ChainParams { protocol_profile: &profile, chain_id: &chain_id, set: &set, genesis_hash, seed, checkpoint: cp };
        // Advance the audit — sm borrow ends before we touch self.engine below.
        let outcome = {
            let sm = self.anchor.as_mut().unwrap();
            sm.advance(&p, self.engine.verifier(), headers)
        };
        match outcome {
            RestartOutcome::NeedHeaders { next_height } => Ok(AdvanceAnchorOutcome::Pending { next_height }),
            RestartOutcome::Failed(e) => Ok(AdvanceAnchorOutcome::AuditFailed(e)),
            RestartOutcome::Ready { audited_height } => {
                // Collect the reconciliation inputs from the engine before borrowing sm again.
                let cur = self.exec.cursor();
                let sm = self.anchor.as_ref().unwrap();
                let ref_height = sm.record.reference.height;
                let ref_block_id = sm.record.reference.block_id;
                let ref_state_root = sm.record.reference.state_root;
                let anchor_height = sm.record.anchor.height;
                // Look up (block_id, state_root) at the reference height from the engine's committed history and root store.
                let engine_block = self.engine.committed_after(ref_height.saturating_sub(1))
                    .into_iter().find(|c| c.height == ref_height);
                let engine_root = self.engine.root(ref_height);
                let cursor_at: Option<([u8; 32], [u8; 32])> = match (engine_block, engine_root) {
                    (Some(c), Some(r)) => Some((c.id, r)),
                    _ => None,
                };
                // Run reconcile checks inline (matches what AnchorRestart::reconcile does).
                let rec_result: Result<(), RestartError> = (|| {
                    if anchor_height > cur.height {
                        return Err(RestartError::Inconsistent("executor has not committed up to the anchor height"));
                    }
                    match cursor_at {
                        None => Err(RestartError::Inconsistent("executor has no committed state at the reference height")),
                        Some((bid, _)) if bid != ref_block_id =>
                            Err(RestartError::Inconsistent("attested block id disagrees with executor's committed block")),
                        Some((_, root)) if root != ref_state_root =>
                            Err(RestartError::Inconsistent("attested state root disagrees with executor's committed state")),
                        Some(_) => Ok(()),
                    }
                })();
                if let Err(e) = rec_result {
                    return Ok(AdvanceAnchorOutcome::ReconcileFailed(e));
                }
                // Clear the anchor gate and perform the deferred replay + resend.
                self.anchor = None;
                let mut replay_outs = vec![];
                for c in self.engine.committed_after(cur.height) { replay_outs.extend(self.execute(c)?); }
                let mut sends = self.route(replay_outs)?;
                let mut outs = self.engine.resend_last_vote().unwrap_or_default();
                outs.extend(self.engine.resend_last_timeout().unwrap_or_default());
                sends.extend(self.route(outs)?);
                Ok(AdvanceAnchorOutcome::Ready { audited_height, deferred: sends })
            }
        }
    }

    /// Whether the driver is currently pending an anchor audit (signing stays disabled until `advance_anchor` returns `Ready`).
    #[cfg(feature = "pq-anchored-evidence")]
    pub fn anchor_pending(&self) -> bool { self.anchor.is_some() }

    pub fn engine(&self) -> &Engine<S, C, G, V> { &self.engine }

    /// Opt in to snapshot capture and serving (needs the `pq-snapshot-transfer` feature). Nothing here touches signing state, and nothing is installed or pruned.
    #[cfg(feature = "pq-snapshot-transfer")]
    pub fn enable_snapshot_serving(&mut self, svc: Box<dyn super::serving::RecoveryService>) { self.recovery = Some(svc); }
    #[cfg(feature = "pq-snapshot-transfer")]
    pub fn snapshot_serving(&self) -> Option<super::serving::ServingCounters> { self.recovery.as_ref().map(|s| s.counters()) }
    /// Retained snapshots, oldest first: (height, snapshot id, bytes, pinned). Empty when serving is not enabled.
    #[cfg(feature = "pq-snapshot-transfer")]
    pub fn snapshot_retained(&self) -> Vec<(u64, [u8; 32], u64, bool)> { self.recovery.as_ref().map_or(vec![], |s| s.retained()) }
    /// Stop and give back the durable pieces (a process restart in tests; a clean shutdown in a node).
    pub fn into_parts(self) -> (Engine<S, C, G, V>, BlockStore<B>, X) { (self.engine, self.store, self.exec) }
    pub fn executor(&self) -> &X { &self.exec }
    pub fn block_store(&self) -> &BlockStore<B> { &self.store }
    pub fn limits(&self) -> &MessageLimits { &self.lim }
    pub fn stats(&self) -> Stats { self.stats }

    pub fn status(&self) -> Status {
        let (tip, h) = self.engine.committed_tip();
        Status { round: self.engine.round(), high_qc_round: self.engine.high_qc().round(), committed_height: h, committed_tip: tip, exec: self.exec.cursor(), stats: self.stats, recent: self.recent.iter().copied().collect() }
    }

    /// Execute one finalized block. At a checkpoint height the new root is logged durably (after the executor made the state durable: a crash in between is
    /// reconciled from the cursor at start) and handed to the engine, which may now vote for proposals whose vote it had deferred.
    fn execute(&mut self, c: Committed) -> Result<Vec<Output>, DriverError> {
        let cur = self.exec.apply(&c)?;
        #[cfg(feature = "pq-snapshot-transfer")]
        if self.recovery.is_some() {
            // a block that carries a reference is final here (it was just finalized); the state it attests was executed at a LOWER height, earlier in this same order
            let snap = self.exec.snapshot_bytes();
            let r = self.engine.checkpoint_of(&c.id);
            if let Some(svc) = self.recovery.as_mut() { svc.note_executed(&cur, snap); if let Some(r) = r { svc.note_final_ref(&r); } }
        }
        self.recent.push_back(cur);
        while self.recent.len() > self.dc.recent { self.recent.pop_front(); }
        let Some(k) = self.interval else { return Ok(vec![]) };
        if cur.height % k == 0 { self.store.put_root(k, cur.height, &cur.state_digest)?; self.engine.record_root(cur.height, cur.state_digest)?; }
        Ok(self.engine.on_executed(cur.height)?)
    }

    /// Change how finalized blocks are executed (see [`DriverConfig::exec_per_tick`]); switching to inline drains the queue first.
    pub fn set_exec_budget(&mut self, budget: Option<usize>) -> Result<Vec<Outbound>, DriverError> {
        self.dc.exec_per_tick = budget;
        if budget.is_some() { return Ok(vec![]); }
        let mut outs = vec![];
        while let Some(c) = self.pending_exec.pop_front() { outs.extend(self.execute(c)?); }
        self.route(outs)
    }
    /// Finalized blocks waiting for the executor.
    pub fn exec_backlog(&self) -> usize { self.pending_exec.len() }

    /// Apply outputs in order. Durable requests first, then execution, then sends.
    fn route(&mut self, outs: Vec<Output>) -> Result<Vec<Outbound>, DriverError> {
        let mut out = vec![];
        let mut follow_up: Vec<Output> = vec![];
        for o in outs {
            match o {
                Output::PersistBlock(_) | Output::PersistCommit { .. } | Output::PersistHighQc(_) | Output::PersistHighTc(_) => {
                    let idc = IdCtx { protocol_profile: &self.profile, chain_id: &self.chain, set: &self.set };
                    self.store.apply(&o, &|b| block_id_of(b, &idc).ok())?;
                }
                Output::Commit(c) => { if self.dc.exec_per_tick.is_some() { self.pending_exec.push_back(c); } else { follow_up.extend(self.execute(c)?); } }
                Output::Broadcast(m) => out.push(Outbound { to: None, bytes: net::encode(&NetMsg::Consensus(m)) }),
                Output::Send { to, msg } => { if to != self.me && to < self.n { out.push(Outbound { to: Some(to), bytes: net::encode(&NetMsg::Consensus(msg)) }); } }
                Output::EnteredRound { .. } => {}
            }
        }
        // votes the engine had deferred until the executor caught up (and their persistence) come back as ordinary outputs
        if !follow_up.is_empty() { out.extend(self.route(follow_up)?); }
        Ok(out)
    }

    /// Process engine outputs while the anchor audit is pending: persist block/QC/TC state to maintain DAG integrity,
    /// but suppress all signing outputs (`Broadcast`, `Send`) and defer execution (`Commit`). The deferred replay in
    /// `advance_anchor` handles execution catch-up and resend after the audit completes.
    #[cfg(feature = "pq-anchored-evidence")]
    fn route_anchor_pending(&mut self, outs: Vec<Output>) -> Result<Vec<Outbound>, DriverError> {
        let idc = IdCtx { protocol_profile: &self.profile, chain_id: &self.chain, set: &self.set };
        for o in outs {
            match o {
                Output::PersistBlock(_) | Output::PersistCommit { .. } | Output::PersistHighQc(_) | Output::PersistHighTc(_) => {
                    self.store.apply(&o, &|b| block_id_of(b, &idc).ok())?;
                }
                // Suppress: signing outputs. Commits are deferred to advance_anchor's replay.
                Output::Commit(_) | Output::Broadcast(_) | Output::Send { .. } | Output::EnteredRound { .. } => {}
            }
        }
        Ok(vec![])
    }

    /// An engine error is either fatal (safety) or just a bad message.
    fn soft(&self, e: EngineError) -> Result<(), DriverError> { classify_engine_error(e, self.engine.store().is_latched()) }

    fn pick_peer(&mut self, hint: usize) -> usize {
        self.rr = (self.rr + 1) % self.n;
        if self.rr == self.me { self.rr = (self.rr + 1) % self.n; }
        if hint != self.me && hint < self.n && self.rr % 2 == 0 { hint } else { self.rr }
    }

    fn request_sync(&mut self, want: BlockId, hint: usize) -> Option<Outbound> {
        let req = self.sync.want(want, self.now, self.dc.max_sync_blocks as u32)?;
        self.stats.sync_requests += 1;
        let to = self.pick_peer(hint);
        Some(Outbound { to: Some(to), bytes: net::encode(&NetMsg::SyncRequest(req)) })
    }

    /// Feed one received datagram. Undecodable or oversize input is counted and dropped; only durable-state, executor or safety failures are `Err`.
    pub fn on_bytes(&mut self, from: usize, bytes: &[u8], now: u64) -> Result<Vec<Outbound>, DriverError> {
        self.now = now;
        // S-2b (opt-in only): recovery kinds go to the snapshot service; with no service installed this branch does not exist and the bytes fall through to the decoder
        // below exactly as before (kinds 7 to 14 are unknown input there).
        #[cfg(feature = "pq-snapshot-transfer")]
        if let Some(svc) = self.recovery.as_mut() {
            if super::serving::is_recovery_kind(bytes) {
                if from == self.me || from >= self.n { self.stats.malformed += 1; return Ok(vec![]); }
                let chain = EngineChain(&self.engine);
                return Ok(svc.on_bytes(&chain, from, bytes, now).into_iter().map(|b| Outbound { to: Some(from), bytes: b }).collect());
            }
        }
        let msg = match net::decode(bytes, &self.lim) { Ok(m) => m, Err(_) => { self.stats.malformed += 1; return Ok(vec![]); } };
        match msg {
            NetMsg::SyncRequest(req) => {
                let mut out = vec![];
                if from != self.me && from < self.n {
                    match self.engine.serve_sync_ex(&req, self.dc.max_sync_blocks) {
                        ServeSync::Blocks(r) => out.push(Outbound { to: Some(from), bytes: net::encode(&NetMsg::SyncResponse(r)) }),
                        ServeSync::BelowBase(b) => { self.stats.below_base_served += 1; out.push(Outbound { to: Some(from), bytes: net::encode(&NetMsg::SyncBelowBase(b)) }); }
                        ServeSync::Unknown => {}
                    }
                }
                Ok(out)
            }
            NetMsg::SyncResponse(resp) => self.apply_sync(from, resp),
            // advice only: it proves nothing and changes nothing but a counter; recovery comes from authenticated evidence, never from this message
            NetMsg::SyncBelowBase(_) => { self.stats.below_base_advice += 1; Ok(vec![]) }
            NetMsg::Consensus(m) => self.deliver(from, m),
        }
    }

    fn deliver(&mut self, from: usize, m: Msg) -> Result<Vec<Outbound>, DriverError> {
        // When the anchor audit is pending: process the message so the engine can build its DAG and collect
        // QCs, but suppress all signing outputs and defer execution via route_anchor_pending.
        #[cfg(feature = "pq-anchored-evidence")]
        if self.anchor.is_some() {
            return match self.engine.on_message(m.clone()) {
                Ok(outs) => self.route_anchor_pending(outs),
                Err(EngineError::MissingParent(p)) => {
                    let mut out = vec![];
                    if let Some(o) = self.request_sync(p, from) { out.push(o); }
                    self.park(from, m);
                    Ok(out)
                }
                Err(e) => { self.soft(e)?; Ok(vec![]) }
            };
        }
        match self.engine.on_message(m.clone()) {
            Ok(outs) => self.route(outs),
            Err(EngineError::MissingParent(p)) => {
                let mut out = vec![];
                if let Some(o) = self.request_sync(p, from) { out.push(o); }
                self.park(from, m);
                Ok(out)
            }
            Err(e) => { self.soft(e)?; Ok(vec![]) }
        }
    }

    fn park(&mut self, from: usize, msg: Msg) {
        if self.parked.len() >= self.dc.park_capacity { self.parked.pop_front(); self.stats.parked_dropped += 1; }
        self.parked.push_back(Parked { from, msg, until: self.now.saturating_add(self.dc.park_ttl) });
    }

    fn retry_parked(&mut self) -> Result<Vec<Outbound>, DriverError> {
        let mut out = vec![];
        let now = self.now;
        let items: Vec<Parked> = self.parked.drain(..).collect();
        for p in items {
            if p.until <= now { self.stats.parked_dropped += 1; continue; }
            match self.engine.on_message(p.msg.clone()) {
                Ok(outs) => out.extend(self.route(outs)?),
                Err(EngineError::MissingParent(m)) => {
                    // still missing: ask again if the earlier request has expired or was lost (a request already outstanding is not repeated)
                    if let Some(o) = self.request_sync(m, p.from) { out.push(o); }
                    self.parked.push_back(p);
                }
                Err(e) => self.soft(e)?,
            }
        }
        Ok(out)
    }

    fn apply_sync(&mut self, from: usize, resp: SyncResponse) -> Result<Vec<Outbound>, DriverError> {
        if !self.sync.is_pending(&resp.want) { self.stats.unsolicited_sync += 1; return Ok(vec![]); }
        let req = SyncRequest { want: resp.want, max_blocks: self.dc.max_sync_blocks as u32 };
        let idc = IdCtx { protocol_profile: &self.profile, chain_id: &self.chain, set: &self.set };
        if check_response(&req, &resp, &idc, self.dc.max_sync_blocks).is_err() { self.stats.bad_sync += 1; return Ok(vec![]); }
        let want = resp.want;
        // The request was ANSWERED with a structurally valid chain: free its slot NOW, whether or not the blocks can be applied yet. A window whose oldest block's parent is still
        // unknown (every non-bottom window of a climb towards a base or a gap) used to keep its slot until the TTL, while each live proposal took a new slot for its own parent;
        // with the table near full the next hop of the climb found no slot and the climb starved (observed: a node 40 blocks behind its base never stored a single block in
        // 6,000 ticks and 2,368 requests).
        self.sync.complete(&want);
        let mut out = vec![];
        for b in resp.blocks {
            match self.engine.on_sync_block(b) {
                Ok(outs) => out.extend(self.route(outs)?),
                Err(EngineError::MissingParent(p)) => { if let Some(o) = self.request_sync(p, from) { out.push(o); } break; }
                Err(e) => { self.stats.bad_sync += 1; self.soft(e)?; break; }
            }
        }
        out.extend(self.retry_parked()?);
        Ok(out)
    }

    /// Advance timers: retry parked messages, propose if this node leads the round, and time the round out with exponential backoff.
    pub fn tick(&mut self, now: u64) -> Result<Vec<Outbound>, DriverError> {
        self.now = now;
        #[cfg(feature = "pq-snapshot-transfer")]
        if let Some(svc) = self.recovery.as_mut() { svc.tick(now); }
        self.try_complete_recovery();
        let mut out = vec![];
        let (r, hq) = (self.engine.round(), self.engine.high_qc().round());
        if hq > self.last_hqc { self.last_hqc = hq; self.pace.on_progress(); }
        if r != self.last_round { self.last_round = r; self.round_started = now; }
        if let Some(budget) = self.dc.exec_per_tick {
            let mut outs = vec![];
            for _ in 0..budget { let Some(c) = self.pending_exec.pop_front() else { break }; outs.extend(self.execute(c)?); }
            out.extend(self.route(outs)?);
        }
        out.extend(self.retry_parked()?);
        // When the anchor audit is pending: suppress all signing operations (propose, timeout, resend).
        // try_complete_recovery is also skipped (see above), so the engine stays in Recovering on seeded
        // starts. On genesis starts the engine is not recovering but the driver gate below is authoritative.
        #[cfg(feature = "pq-anchored-evidence")]
        if self.anchor.is_some() { return Ok(out); }
        if self.engine.is_leader() && now.saturating_sub(self.round_started) >= self.dc.min_propose_gap {
            let p = (self.payload)(self.engine.round(), self.me);
            match self.engine.propose(p) { Ok(outs) => out.extend(self.route(outs)?), Err(EngineError::Recovering(_)) => self.stats.propose_refused_while_recovering += 1, Err(e) => self.soft(e)? }
        }
        if now.saturating_sub(self.round_started) >= self.pace.timeout() {
            self.round_started = now;
            match self.engine.local_timeout() { Ok(outs) => { self.pace.on_timeout(); out.extend(self.route(outs)?); } Err(EngineError::Recovering(_)) => self.stats.timeout_refused_while_recovering += 1, Err(e) => self.soft(e)? }
        }
        Ok(out)
    }
}

/// The engine as the snapshot service's read-only view of this node's chain.
#[cfg(feature = "pq-snapshot-transfer")]
struct EngineChain<'a, S: Storage, C: MonotonicCounter, G: ConsensusSigner, V: ConsensusVerifier>(&'a Engine<S, C, G, V>);
#[cfg(feature = "pq-snapshot-transfer")]
impl<S: Storage, C: MonotonicCounter, G: ConsensusSigner, V: ConsensusVerifier> super::serving::ChainView for EngineChain<'_, S, C, G, V> {
    fn headers_after(&self, after: &BlockId, max: u32) -> super::recovery::codec::HeaderBody {
        use super::recovery::codec::HeaderBody;
        match self.0.headers_after(after, max as usize) {
            None => HeaderBody::NotFound,
            Some((h, tip, _)) if h.is_empty() => HeaderBody::AtTip { tip_height: tip },
            Some((h, tip, at_end)) => HeaderBody::Ok { headers: h, final_qc: if at_end { Some(self.0.high_qc().clone()) } else { None }, tip_height: tip },
        }
    }
}
