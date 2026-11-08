//! Bounded request handling for snapshot recovery (spec 3.4 and 3.5). Pure state machines over an injected clock in milliseconds; no I/O.
//! * [`RequestTable`]: requester-side correlation (request id, peer, kind and echoed selector must all match) with per-peer and global caps.
//! * [`Cooldown`], [`Suppression`], [`StallDetector`]: peer advice (`TOO_LARGE`, `BUSY`) is only advice; suppression is temporary and based on locally verified invalidity.
//! * [`ServeGate`]: responder-side admission with a reserve-then-refund token bucket, concurrency and spacing limits.
use std::collections::BTreeMap;

use super::codec::{CheckpointRef, ChunkBody, HeaderBody, ManifestBody, RecoveryMsg, KIND_CHUNK_REQ, KIND_CHUNK_RESP, KIND_HEADER_REQ, KIND_HEADER_RESP, KIND_MANIFEST_REQ, KIND_MANIFEST_RESP, MAX_CHUNK_COUNT};
use crate::pq_hotstuff::certs::BlockId;

// ---------------------------------------------------------------------------------------------------------------- correlation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Selector { After(BlockId), Ref(CheckpointRef), Chunk([u8; 32], u32) }

impl Selector {
    pub fn request_kind(&self) -> u8 { match self { Selector::After(_) => KIND_HEADER_REQ, Selector::Ref(_) => KIND_MANIFEST_REQ, Selector::Chunk(..) => KIND_CHUNK_REQ } }
    fn per_peer_cap(&self) -> usize { match self { Selector::Chunk(..) => 4, _ => 1 } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending { pub peer: usize, pub request_id: u64, pub selector: Selector, pub deadline: u64 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError { GlobalCap, PeerCap, IdExhausted }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped { NotAResponse, Unsolicited, SelectorMismatch, Late }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TableStats { pub issued: u64, pub accepted: u64, pub unsolicited: u64, pub selector_mismatch: u64, pub late: u64 }

pub struct RequestTable { cap: usize, timeout_ms: u64, next_id: u64, entries: Vec<Pending>, pub stats: TableStats }

/// The response's (kind-of-request, request id, echoed selector), or `None` for a request message.
fn response_parts(m: &RecoveryMsg) -> Option<(u8, u64, Selector)> {
    Some(match m {
        RecoveryMsg::HeaderResp { request_id, after, .. } => (KIND_HEADER_REQ, *request_id, Selector::After(*after)),
        RecoveryMsg::ManifestResp { request_id, cref, .. } => (KIND_MANIFEST_REQ, *request_id, Selector::Ref(*cref)),
        RecoveryMsg::ChunkResp { request_id, snapshot_id, index, .. } => (KIND_CHUNK_REQ, *request_id, Selector::Chunk(*snapshot_id, *index)),
        _ => return None,
    })
}

impl RequestTable {
    /// `cap` is the global outstanding cap; `first_id` the starting request id (random per process in production, fixed in tests); ids never repeat.
    pub fn new(cap: usize, first_id: u64, timeout_ms: u64) -> Self { RequestTable { cap, timeout_ms, next_id: first_id, entries: Vec::new(), stats: TableStats::default() } }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn issue(&mut self, peer: usize, selector: Selector, now: u64) -> Result<u64, IssueError> {
        if self.entries.len() >= self.cap { return Err(IssueError::GlobalCap); }
        let same = self.entries.iter().filter(|e| e.peer == peer && e.selector.request_kind() == selector.request_kind()).count();
        if same >= selector.per_peer_cap() { return Err(IssueError::PeerCap); }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(IssueError::IdExhausted)?;
        self.entries.push(Pending { peer, request_id: id, selector, deadline: now.saturating_add(self.timeout_ms) });
        self.stats.issued += 1;
        Ok(id)
    }

    /// Match a response against the table. Accepted only on peer, kind, request id AND echoed selector, within the deadline; the entry is then removed.
    pub fn accept(&mut self, peer: usize, m: &RecoveryMsg, now: u64) -> Result<Pending, Dropped> {
        let Some((kind, id, sel)) = response_parts(m) else { return Err(Dropped::NotAResponse) };
        let Some(pos) = self.entries.iter().position(|e| e.peer == peer && e.request_id == id && e.selector.request_kind() == kind) else {
            self.stats.unsolicited += 1;
            return Err(Dropped::Unsolicited);
        };
        if self.entries[pos].deadline < now { self.entries.remove(pos); self.stats.late += 1; return Err(Dropped::Late); }
        if self.entries[pos].selector != sel { self.stats.selector_mismatch += 1; return Err(Dropped::SelectorMismatch); }
        self.stats.accepted += 1;
        Ok(self.entries.remove(pos))
    }

    pub fn expire(&mut self, now: u64) -> Vec<Pending> {
        let (dead, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.entries).into_iter().partition(|e| e.deadline < now);
        self.entries = keep;
        dead
    }
}

// ---------------------------------------------------------------------------------------------------------------- advice
/// What a response says about the peer, judged only from what the node itself can verify. `TooLarge` and `Busy` are advice and never invalidity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advice { None, TooLarge, Busy { retry_after_ms: u32 } }

pub fn advice_of(m: &RecoveryMsg) -> Advice {
    match m {
        RecoveryMsg::HeaderResp { body: HeaderBody::TooLarge { .. }, .. } | RecoveryMsg::ManifestResp { body: ManifestBody::TooLarge { .. }, .. } => Advice::TooLarge,
        RecoveryMsg::HeaderResp { body: HeaderBody::Busy { retry_after_ms }, .. } | RecoveryMsg::ManifestResp { body: ManifestBody::Busy { retry_after_ms }, .. }
        | RecoveryMsg::ChunkResp { body: ChunkBody::Busy { retry_after_ms }, .. } => Advice::Busy { retry_after_ms: *retry_after_ms },
        _ => Advice::None,
    }
}

/// A peer's `retry_after_ms` is advice: clamp it to 100 ms .. 60 s.
pub fn clamp_retry_after(ms: u32) -> u64 { u64::from(ms).clamp(100, 60_000) }

/// Per-(peer, selector) cool-down after a peer did not serve a request: 1 s, doubling, up to 5 minutes. Never a ban.
#[derive(Default)]
pub struct Cooldown { map: BTreeMap<(usize, Selector), (u64, u32)> }
impl Cooldown {
    pub fn note_unserved(&mut self, peer: usize, sel: Selector, now: u64) -> u64 {
        let e = self.map.entry((peer, sel)).or_insert((0, 0));
        let wait = (1_000u64.checked_shl(e.1).unwrap_or(300_000)).min(300_000);
        *e = (now.saturating_add(wait), e.1.saturating_add(1).min(20));
        e.0
    }
    pub fn note_served(&mut self, peer: usize, sel: Selector) { self.map.remove(&(peer, sel)); }
    pub fn ready(&self, peer: usize, sel: &Selector, now: u64) -> bool { self.map.get(&(peer, *sel)).map_or(true, |(until, _)| now >= *until) }
}

/// Temporary peer suppression for LOCALLY VERIFIED invalid responses: 3 within 5 minutes suppress for 10 minutes, doubling per repeat up to 1 hour,
/// forgotten after 1 hour without incident. Never permanent. `TOO_LARGE` and `BUSY` must never be recorded here.
pub struct Suppression { peers: BTreeMap<usize, Rec> }
#[derive(Default, Clone)]
struct Rec { strikes: Vec<u64>, level: u32, until: u64, last: u64 }
const WINDOW: u64 = 300_000; const THRESHOLD: usize = 3; const BASE: u64 = 600_000; const MAXS: u64 = 3_600_000; const FORGET: u64 = 3_600_000;
impl Default for Suppression { fn default() -> Self { Suppression { peers: BTreeMap::new() } } }
impl Suppression {
    pub fn record_invalid(&mut self, peer: usize, now: u64) {
        let r = self.peers.entry(peer).or_default();
        if r.last != 0 && now.saturating_sub(r.last) >= FORGET && now >= r.until { *r = Rec::default(); }
        r.strikes.retain(|t| now.saturating_sub(*t) < WINDOW);
        r.strikes.push(now);
        r.last = now;
        if r.strikes.len() >= THRESHOLD {
            let dur = BASE.checked_shl(r.level).unwrap_or(MAXS).min(MAXS);
            r.until = now.saturating_add(dur);
            r.level = r.level.saturating_add(1).min(20);
            r.strikes.clear();
        }
    }
    pub fn is_suppressed(&self, peer: usize, now: u64) -> bool { self.peers.get(&peer).map_or(false, |r| now < r.until) }
}

/// Non-terminal stall diagnosis: raised when at least `min_peers` distinct peers failed to serve the same selector for `window_ms`. Changes nothing.
pub struct StallDetector { min_peers: usize, window_ms: u64, first: BTreeMap<Selector, BTreeMap<usize, u64>> }
impl StallDetector {
    pub fn new(min_peers: usize, window_ms: u64) -> Self { StallDetector { min_peers, window_ms, first: BTreeMap::new() } }
    pub fn note_unserved(&mut self, peer: usize, sel: Selector, now: u64) { self.first.entry(sel).or_default().entry(peer).or_insert(now); }
    pub fn note_served(&mut self, sel: &Selector) { self.first.remove(sel); }
    /// Selectors on which `min_peers` peers have been failing for at least `window_ms`.
    pub fn stalled(&self, now: u64) -> Vec<Selector> {
        self.first.iter().filter(|(_, peers)| peers.values().filter(|t| now.saturating_sub(**t) >= self.window_ms).count() >= self.min_peers).map(|(s, _)| *s).collect()
    }
}

// ---------------------------------------------------------------------------------------------------------------- serving
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("burst {burst} is below twice the transport limit {limit}")]
    BurstBelowTwiceLimit { burst: u64, limit: u64 },
    #[error("refill {refill} bytes/s is below a quarter of the transport limit per second ({limit})")]
    RefillTooSlow { refill: u64, limit: u64 },
    #[error("aggregate rate is below the per-peer refill")]
    AggregateBelowRefill,
    #[error("a limit or count is zero")]
    Zero,
    #[error("outstanding cap is zero: recovery memory is below the transport limit")]
    NoOutstandingBudget,
    #[error("arithmetic overflow")]
    Overflow,
}

/// `min(16, floor(max_recovery_memory / transport_limit))`; the feature refuses to enable when this is 0.
pub fn outstanding_cap(max_recovery_memory: u64, transport_limit: u64) -> Result<usize, ConfigError> {
    if transport_limit == 0 { return Err(ConfigError::Zero); }
    let c = (max_recovery_memory / transport_limit).min(16) as usize;
    if c == 0 { Err(ConfigError::NoOutstandingBudget) } else { Ok(c) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeConfig {
    /// The transport limit `L`.
    pub limit: u64,
    pub burst: u64,
    pub refill_per_s: u64,
    pub aggregate_per_s: u64,
    pub max_concurrent: usize,
    pub per_peer_outstanding: usize,
    pub min_spacing_ms: u64,
    pub chunk_size: u32,
}

impl ServeConfig {
    /// Spec 3.5 invariants: `burst >= 2 L`, `refill >= L / 4 s`, `aggregate >= refill`, nothing zero.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.limit == 0 || self.refill_per_s == 0 || self.max_concurrent == 0 || self.per_peer_outstanding == 0 || self.chunk_size == 0 { return Err(ConfigError::Zero); }
        if self.burst < self.limit.checked_mul(2).ok_or(ConfigError::Overflow)? { return Err(ConfigError::BurstBelowTwiceLimit { burst: self.burst, limit: self.limit }); }
        if self.refill_per_s.checked_mul(4).ok_or(ConfigError::Overflow)? < self.limit { return Err(ConfigError::RefillTooSlow { refill: self.refill_per_s, limit: self.limit }); }
        if self.aggregate_per_s < self.refill_per_s { return Err(ConfigError::AggregateBelowRefill); }
        Ok(())
    }
    /// The worst-case response size reserved at admission.
    pub fn reservation(&self, request_kind: u8) -> u64 {
        match request_kind {
            KIND_MANIFEST_REQ => self.limit.min(143 + 32 * u64::from(MAX_CHUNK_COUNT)),
            KIND_CHUNK_REQ => (61 + u64::from(self.chunk_size)).min(self.limit),
            _ => self.limit,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Busy { pub retry_after_ms: u32 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket { peer: usize, reserved: u64 }
impl Ticket { pub fn reserved(&self) -> u64 { self.reserved } }

/// Token bucket in milli-bytes (bytes x 1000) so that refill `rate_per_s x dt_ms` is exact integer arithmetic.
#[derive(Clone)]
struct Bucket { tokens_milli: u128, cap_milli: u128, rate_per_s: u64, last_ms: u64 }
impl Bucket {
    fn new(cap: u64, rate_per_s: u64, now: u64) -> Self { Bucket { tokens_milli: u128::from(cap) * 1000, cap_milli: u128::from(cap) * 1000, rate_per_s, last_ms: now } }
    fn refill(&mut self, now: u64) {
        let dt = now.saturating_sub(self.last_ms);
        self.tokens_milli = (self.tokens_milli + u128::from(self.rate_per_s) * u128::from(dt)).min(self.cap_milli);
        self.last_ms = self.last_ms.max(now);
    }
    /// Milliseconds until `cost` bytes are available (0 if available now).
    fn wait_ms(&self, cost: u64) -> u64 {
        let need = u128::from(cost) * 1000;
        if self.tokens_milli >= need { 0 } else { u64::try_from((need - self.tokens_milli).div_ceil(u128::from(self.rate_per_s))).unwrap_or(u64::MAX) }
    }
}

pub struct ServeGate {
    cfg: ServeConfig,
    peers: BTreeMap<usize, PeerState>,
    agg: Bucket,
    concurrent: usize,
}
#[derive(Clone)]
struct PeerState { bucket: Bucket, outstanding: usize, last_served: Option<u64> }

impl ServeGate {
    pub fn new(cfg: ServeConfig, now: u64) -> Result<Self, ConfigError> {
        cfg.validate()?;
        let agg_cap = cfg.burst.max(cfg.limit.checked_mul(2).ok_or(ConfigError::Overflow)?);
        Ok(ServeGate { cfg, peers: BTreeMap::new(), agg: Bucket::new(agg_cap, cfg.aggregate_per_s, now), concurrent: 0 })
    }
    pub fn concurrent(&self) -> usize { self.concurrent }

    fn busy(ms: u64) -> Busy { Busy { retry_after_ms: u32::try_from(ms.max(1)).unwrap_or(u32::MAX) } }

    /// Admit one request: reserve its worst-case response from the peer's and the aggregate bucket, or answer `BUSY` with an exact retry hint.
    pub fn admit(&mut self, peer: usize, request_kind: u8, now: u64) -> Result<Ticket, Busy> {
        let cost = self.cfg.reservation(request_kind);
        let cfg = self.cfg;
        let st = self.peers.entry(peer).or_insert_with(|| PeerState { bucket: Bucket::new(cfg.burst, cfg.refill_per_s, now), outstanding: 0, last_served: None });
        st.bucket.refill(now);
        self.agg.refill(now);
        if st.outstanding >= self.cfg.per_peer_outstanding { return Err(Self::busy(100)); }
        if self.concurrent >= self.cfg.max_concurrent { return Err(Self::busy(100)); }
        if let Some(last) = st.last_served {
            let ready = last.saturating_add(self.cfg.min_spacing_ms);
            if now < ready { return Err(Self::busy(ready - now)); }
        }
        let wait = st.bucket.wait_ms(cost).max(self.agg.wait_ms(cost));
        if wait > 0 { return Err(Self::busy(wait)); }
        let milli = u128::from(cost) * 1000;
        st.bucket.tokens_milli -= milli;
        self.agg.tokens_milli -= milli;
        st.outstanding += 1;
        st.last_served = Some(now);
        self.concurrent += 1;
        Ok(Ticket { peer, reserved: cost })
    }

    /// Finish a served request and refund the difference between the reservation and the bytes actually sent.
    pub fn finish(&mut self, t: Ticket, actual_bytes: u64) {
        let refund = u128::from(t.reserved.saturating_sub(actual_bytes)) * 1000;
        if let Some(st) = self.peers.get_mut(&t.peer) {
            st.bucket.tokens_milli = (st.bucket.tokens_milli + refund).min(st.bucket.cap_milli);
            st.outstanding = st.outstanding.saturating_sub(1);
        }
        self.agg.tokens_milli = (self.agg.tokens_milli + refund).min(self.agg.cap_milli);
        self.concurrent = self.concurrent.saturating_sub(1);
    }
}

#[allow(dead_code)]
const _: (u8, u8, u8) = (KIND_HEADER_RESP, KIND_MANIFEST_RESP, KIND_CHUNK_RESP);
