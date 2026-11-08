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
use super::types::EpochSet;

#[derive(Debug, Clone)]
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
}

/// Something to send: to one validator, or (`to == None`) to all the others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound { pub to: Option<usize>, pub bytes: Vec<u8> }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats { pub malformed: u64, pub bad_sync: u64, pub sync_requests: u64, pub unsolicited_sync: u64, pub parked_dropped: u64 }

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
}

impl<S: Storage, C: MonotonicCounter, G: ConsensusSigner, V: ConsensusVerifier, B: BlockFiles, X: Executor> Driver<S, C, G, V, B, X> {
    /// Recover from disk and start. Returns the messages to send first (the stored vote/timeout, byte for byte).
    pub fn start(dc: DriverConfig, mut engine: Engine<S, C, G, V>, mut store: BlockStore<B>, exec: X, payload: PayloadSource, now: u64) -> Result<(Self, Vec<Outbound>), DriverError> {
        let lim = validate_config(engine.config(), &dc)?;
        let loaded = store.load()?;
        engine.restore(loaded.blocks, &loaded.committed, loaded.high_qc, loaded.high_tc)?;
        // commit markers a crash lost are written again (the engine re-derived them from the certificates it recovered)
        for c in engine.committed_after(loaded.committed.len() as u64) { store.put_commit(c.height, &c.id)?; }

        let cur = exec.cursor();
        let (_, tip) = engine.committed_tip();
        if cur.height > tip { return Err(DriverError::ExecutorAhead { exec: cur.height, committed: tip }); }
        if cur.height > 0 {
            match engine.committed_after(cur.height - 1).first() {
                Some(c) if c.height == cur.height && c.id == cur.block_id => {}
                _ => return Err(DriverError::Diverged { height: cur.height }),
            }
        }
        let mut recent = VecDeque::new();
        if cur.height > 0 { recent.push_back(cur); }
        let cfg = engine.config();
        let (profile, chain, set, me) = (cfg.protocol_profile.clone(), cfg.chain_id.clone(), cfg.set.clone(), cfg.my_index);
        let n = set.len();
        let mut d = Driver {
            pace: Pacemaker::new(dc.pace).map_err(|e| DriverError::Config(e.to_string()))?, sync: SyncClient::new(dc.sync_ttl, dc.sync_outstanding),
            round_started: now, last_round: engine.round(), last_hqc: engine.high_qc().round(), rr: me,
            dc, lim, engine, store, exec, payload, profile, chain, set, me, n, now, parked: VecDeque::new(), recent, stats: Stats::default(),
        };
        // the executor catches up from ITS durable cursor, exactly once
        for c in d.engine.committed_after(cur.height) { d.execute(c)?; }
        let mut outs = d.engine.resend_last_vote().unwrap_or_default();
        outs.extend(d.engine.resend_last_timeout().unwrap_or_default());
        let first = d.route(outs)?;
        Ok((d, first))
    }

    pub fn engine(&self) -> &Engine<S, C, G, V> { &self.engine }
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

    fn execute(&mut self, c: Committed) -> Result<(), DriverError> {
        let cur = self.exec.apply(&c)?;
        self.recent.push_back(cur);
        while self.recent.len() > self.dc.recent { self.recent.pop_front(); }
        Ok(())
    }

    /// Apply outputs in order. Durable requests first, then execution, then sends.
    fn route(&mut self, outs: Vec<Output>) -> Result<Vec<Outbound>, DriverError> {
        let mut out = vec![];
        for o in outs {
            match o {
                Output::PersistBlock(_) | Output::PersistCommit { .. } | Output::PersistHighQc(_) | Output::PersistHighTc(_) => {
                    let idc = IdCtx { protocol_profile: &self.profile, chain_id: &self.chain, set: &self.set };
                    self.store.apply(&o, &|b| block_id_of(b, &idc).ok())?;
                }
                Output::Commit(c) => self.execute(c)?,
                Output::Broadcast(m) => out.push(Outbound { to: None, bytes: net::encode(&NetMsg::Consensus(m)) }),
                Output::Send { to, msg } => { if to != self.me && to < self.n { out.push(Outbound { to: Some(to), bytes: net::encode(&NetMsg::Consensus(msg)) }); } }
                Output::EnteredRound { .. } => {}
            }
        }
        Ok(out)
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
        let msg = match net::decode(bytes, &self.lim) { Ok(m) => m, Err(_) => { self.stats.malformed += 1; return Ok(vec![]); } };
        match msg {
            NetMsg::SyncRequest(req) => {
                let mut out = vec![];
                if from != self.me && from < self.n {
                    if let Some(r) = self.engine.serve_sync(&req, self.dc.max_sync_blocks) { out.push(Outbound { to: Some(from), bytes: net::encode(&NetMsg::SyncResponse(r)) }); }
                }
                Ok(out)
            }
            NetMsg::SyncResponse(resp) => self.apply_sync(from, resp),
            NetMsg::Consensus(m) => self.deliver(from, m),
        }
    }

    fn deliver(&mut self, from: usize, m: Msg) -> Result<Vec<Outbound>, DriverError> {
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
        let mut out = vec![];
        let mut complete = true;
        for b in resp.blocks {
            match self.engine.on_sync_block(b) {
                Ok(outs) => out.extend(self.route(outs)?),
                Err(EngineError::MissingParent(p)) => { if let Some(o) = self.request_sync(p, from) { out.push(o); } complete = false; break; }
                Err(e) => { self.stats.bad_sync += 1; self.soft(e)?; complete = false; break; }
            }
        }
        if complete { self.sync.complete(&want); }
        out.extend(self.retry_parked()?);
        Ok(out)
    }

    /// Advance timers: retry parked messages, propose if this node leads the round, and time the round out with exponential backoff.
    pub fn tick(&mut self, now: u64) -> Result<Vec<Outbound>, DriverError> {
        self.now = now;
        let mut out = vec![];
        let (r, hq) = (self.engine.round(), self.engine.high_qc().round());
        if hq > self.last_hqc { self.last_hqc = hq; self.pace.on_progress(); }
        if r != self.last_round { self.last_round = r; self.round_started = now; }
        out.extend(self.retry_parked()?);
        if self.engine.is_leader() && now.saturating_sub(self.round_started) >= self.dc.min_propose_gap {
            let p = (self.payload)(self.engine.round(), self.me);
            match self.engine.propose(p) { Ok(outs) => out.extend(self.route(outs)?), Err(e) => self.soft(e)? }
        }
        if now.saturating_sub(self.round_started) >= self.pace.timeout() {
            self.round_started = now;
            match self.engine.local_timeout() { Ok(outs) => { self.pace.on_timeout(); out.extend(self.route(outs)?); } Err(e) => self.soft(e)? }
        }
        Ok(out)
    }
}
