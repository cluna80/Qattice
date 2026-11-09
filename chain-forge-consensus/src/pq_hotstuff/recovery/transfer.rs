//! S-1: ISOLATED, sans-IO snapshot-transfer state machines (requester and provider). **Not wired into any node**: nothing here is reachable from the driver, the
//! network decoder still rejects kinds 7 to 14, installation over the network and pruning stay disabled. Policy (owner, 2026-11-09):
//! * the trust anchor is the node's own genesis: checkpoint evidence is accepted only if the injected [`Authenticator`] (the engine's own
//!   `authenticate_evidence`) accepts it;
//! * ANY peer may serve; acceptance depends on verification, never on who served or how many agree. There is no provider-agreement threshold: several providers
//!   improve availability only;
//! * install ordering: the seed evidence is made durable (`EvidenceSink`) after the staged state is measured and BEFORE the application generation is published.
use std::collections::{BTreeMap, BTreeSet};

use super::codec::{chunk_hash, encode, ChunkBody, CodecLimits, HeaderBody, Manifest, ManifestBody, RecoveryMsg, KIND_CHUNK_REQ, KIND_HEADER_REQ, KIND_MANIFEST_REQ};
use super::install::{InstallError, InstallProof, Installer, ShadowApp};
use super::records::InstallRecord;
use super::requests::{advice_of, clamp_retry_after, Advice, Cooldown, Dropped, IssueError, RequestTable, Selector, ServeGate, Suppression};
use super::tree::TreeFs;
use crate::pq_hotstuff::certs::Cert;
use crate::pq_hotstuff::checkpoint::CheckpointRef;
use crate::pq_hotstuff::header::{ChainPoint, PayloadFreeBlock};
use crate::pq_hotstuff::seed::{CheckpointSeed, SeedEvidence};
use crate::pq_hotstuff::certs::BlockId;

// ------------------------------------------------------------------------------------------------------------------------------ provider
/// What a serving node can read. The provider never authenticates the requester and never trusts a store answer to be small: it re-checks sizes.
pub trait ProviderStore {
    /// Up to `max` payload-free headers whose first header's parent is `after`, plus the certificate of the last header if it has one.
    fn headers_after(&self, after: &BlockId, max: u32) -> HeaderBody;
    /// The manifest of a snapshot retained for FINAL checkpoint `cref`.
    fn manifest(&self, cref: &CheckpointRef) -> Option<Manifest>;
    /// Pins the snapshot while a transfer is active; the store must not remove a pinned snapshot.
    fn chunk(&self, snapshot_id: &[u8; 32], index: u32) -> Option<Vec<u8>>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProviderStats { pub served: u64, pub busy: u64, pub too_large: u64, pub not_found: u64, pub ignored: u64 }

/// Serves recovery requests under the existing [`ServeGate`] (rate limits, reservations, per-peer and global caps).
pub struct Provider<S: ProviderStore> { store: S, gate: ServeGate, limits: CodecLimits, pub stats: ProviderStats }

impl<S: ProviderStore> Provider<S> {
    pub fn new(store: S, gate: ServeGate, limits: CodecLimits) -> Self { Provider { store, gate, limits, stats: ProviderStats::default() } }
    pub fn store(&self) -> &S { &self.store }
    pub fn concurrent(&self) -> usize { self.gate.concurrent() }

    /// Handle one decoded request from `peer`. `None` for anything that is not a request (responses are never answered). The reply is built, size-checked
    /// against the kind's maximum, and the gate's reservation released before returning (the machine is synchronous).
    pub fn handle(&mut self, peer: usize, m: &RecoveryMsg, now: u64) -> Option<RecoveryMsg> {
        let kind = match m { RecoveryMsg::HeaderReq { .. } => KIND_HEADER_REQ, RecoveryMsg::ManifestReq { .. } => KIND_MANIFEST_REQ, RecoveryMsg::ChunkReq { .. } => KIND_CHUNK_REQ, _ => { self.stats.ignored += 1; return None; } };
        let ticket = match self.gate.admit(peer, kind, now) {
            Ok(t) => t,
            Err(b) => { self.stats.busy += 1; return Some(Self::busy(m, b.retry_after_ms)); }
        };
        let mut reply = match m {
            RecoveryMsg::HeaderReq { request_id, after, max_headers } => {
                let max = (*max_headers).min(self.limits.max_headers);
                RecoveryMsg::HeaderResp { request_id: *request_id, after: *after, body: if max == 0 { HeaderBody::NotFound } else { self.store.headers_after(after, max) } }
            }
            RecoveryMsg::ManifestReq { request_id, cref } => RecoveryMsg::ManifestResp { request_id: *request_id, cref: *cref, body: match self.store.manifest(cref) { Some(mf) => ManifestBody::Ok(mf), None => ManifestBody::NotFound } },
            RecoveryMsg::ChunkReq { request_id, snapshot_id, index } => RecoveryMsg::ChunkResp { request_id: *request_id, snapshot_id: *snapshot_id, index: *index, body: match self.store.chunk(snapshot_id, *index) { Some(d) => ChunkBody::Ok(d), None => ChunkBody::NotFound } },
            _ => unreachable!(),
        };
        // never send what the peer's decoder would refuse: an oversized reply (or one the codec will not encode) degrades to advice
        let max = self.limits.max_len(reply_kind(&reply));
        let needed = encode(&reply).ok();
        let degraded = !matches!(&needed, Some(b) if max.map_or(false, |mx| b.len() as u64 <= mx));
        if degraded { reply = Self::too_large(&reply, needed.as_ref().map_or(0, |b| b.len() as u64)); self.stats.too_large += 1; }
        let actual = encode(&reply).map(|b| b.len() as u64).unwrap_or(0);
        if !degraded { if is_not_found(&reply) { self.stats.not_found += 1 } else { self.stats.served += 1 } }
        self.gate.finish(ticket, actual);
        Some(reply)
    }

    fn busy(m: &RecoveryMsg, retry_after_ms: u32) -> RecoveryMsg {
        match m {
            RecoveryMsg::HeaderReq { request_id, after, .. } => RecoveryMsg::HeaderResp { request_id: *request_id, after: *after, body: HeaderBody::Busy { retry_after_ms } },
            RecoveryMsg::ManifestReq { request_id, cref } => RecoveryMsg::ManifestResp { request_id: *request_id, cref: *cref, body: ManifestBody::Busy { retry_after_ms } },
            RecoveryMsg::ChunkReq { request_id, snapshot_id, index } => RecoveryMsg::ChunkResp { request_id: *request_id, snapshot_id: *snapshot_id, index: *index, body: ChunkBody::Busy { retry_after_ms } },
            _ => unreachable!(),
        }
    }
    /// The advice that replaces an answer too large for the peer's decoder: the size the answer would have needed, where the codec can say so.
    fn too_large(r: &RecoveryMsg, needed: u64) -> RecoveryMsg {
        match r {
            RecoveryMsg::HeaderResp { request_id, after, body } => {
                let next_height = if let HeaderBody::Ok { headers, .. } = body { headers.first().map_or(0, |h| h.height) } else { 0 };
                RecoveryMsg::HeaderResp { request_id: *request_id, after: *after, body: HeaderBody::TooLarge { needed_bytes: needed, next_height } }
            }
            RecoveryMsg::ManifestResp { request_id, cref, .. } => RecoveryMsg::ManifestResp { request_id: *request_id, cref: *cref, body: ManifestBody::TooLarge { needed_bytes: needed } },
            RecoveryMsg::ChunkResp { request_id, snapshot_id, index, .. } => RecoveryMsg::ChunkResp { request_id: *request_id, snapshot_id: *snapshot_id, index: *index, body: ChunkBody::Unavailable },
            _ => unreachable!(),
        }
    }
}
fn reply_kind(m: &RecoveryMsg) -> u8 { m.kind() }
fn is_not_found(m: &RecoveryMsg) -> bool { matches!(m, RecoveryMsg::HeaderResp { body: HeaderBody::NotFound, .. } | RecoveryMsg::ManifestResp { body: ManifestBody::NotFound, .. } | RecoveryMsg::ChunkResp { body: ChunkBody::NotFound, .. }) }

// ------------------------------------------------------------------------------------------------------------------------------ requester
/// The node's own authentication of evidence (genesis-anchored). Injected so this module holds no cryptography and the same code runs with either signature backend.
pub trait Authenticator {
    fn authenticate(&self, ev: &SeedEvidence) -> Result<CheckpointSeed, String>;
    /// The block id of a header under the node's own profile and validator set (`None`: the header cannot even be identified).
    fn header_id(&self, h: &PayloadFreeBlock) -> Option<BlockId>;
}
/// Durable storage of the evidence (the block store's forward-only `put_seed_evidence` in a node). Called before the application generation is published.
pub trait EvidenceSink { fn persist(&mut self, ev: &SeedEvidence) -> Result<(), String>; }

/// The installer as the requester sees it.
pub trait InstallSink {
    fn begin(&mut self, cref: CheckpointRef, manifest: Manifest, current_height: u64) -> Result<(), InstallError>;
    fn put_chunk(&mut self, index: u32, data: &[u8]) -> Result<(), InstallError>;
    fn finish_with(&mut self, proof: InstallProof, before_publish: &mut dyn FnMut() -> Result<(), String>) -> Result<InstallRecord, InstallError>;
    fn abort(&mut self) -> Result<(), InstallError>;
}
impl<F: TreeFs, A: ShadowApp> InstallSink for Installer<F, A> {
    fn begin(&mut self, cref: CheckpointRef, manifest: Manifest, current_height: u64) -> Result<(), InstallError> { Installer::begin(self, cref, manifest, current_height) }
    fn put_chunk(&mut self, index: u32, data: &[u8]) -> Result<(), InstallError> { Installer::put_chunk(self, index, data) }
    fn finish_with(&mut self, proof: InstallProof, f: &mut dyn FnMut() -> Result<(), String>) -> Result<InstallRecord, InstallError> { Installer::finish_with(self, proof, f) }
    fn abort(&mut self) -> Result<(), InstallError> { Installer::abort(self) }
}

/// Separate bounds (owner decision): none is derived from another and each is checked before the work it bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequesterLimits {
    /// Headers requested per page (also bounded by the codec's `max_headers`).
    pub headers_per_request: u32,
    /// Headers held while a chain is assembled; reaching it without an authenticating checkpoint abandons that source.
    pub max_accumulated_headers: usize,
    /// Snapshot size the node is willing to stage (the staging-disk budget); a larger manifest is refused locally.
    pub max_staging_bytes: u64,
    /// Outstanding requests, total and per peer.
    pub max_outstanding: usize,
    pub per_peer_outstanding: usize,
    pub request_timeout_ms: u64,
    /// Whole-transfer deadline from `start`.
    pub overall_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransferConfigError {
    #[error("a limit is zero")] Zero,
    #[error("per-peer outstanding {per} exceeds the total {total}")] PerPeerAboveTotal { per: usize, total: usize },
    #[error("headers per request {req} is above the codec's maximum {codec}")] HeadersAboveCodec { req: u32, codec: u32 },
    #[error("a header response at the configured page size cannot fit the transport limit")] HeadersDoNotFit,
    #[error("staging budget {budget} is below the codec's snapshot ceiling {ceiling}")] StagingBelowCodec { budget: u64, ceiling: u64 },
}
impl RequesterLimits {
    /// Refuse locally, before any network use, a configuration the codec or the 8 MiB envelope cannot carry.
    pub fn validate(&self, codec: &CodecLimits) -> Result<(), TransferConfigError> {
        if self.headers_per_request == 0 || self.max_accumulated_headers == 0 || self.max_staging_bytes == 0 || self.max_outstanding == 0 || self.per_peer_outstanding == 0 || self.request_timeout_ms == 0 || self.overall_timeout_ms == 0 { return Err(TransferConfigError::Zero); }
        if self.per_peer_outstanding > self.max_outstanding { return Err(TransferConfigError::PerPeerAboveTotal { per: self.per_peer_outstanding, total: self.max_outstanding }); }
        if self.headers_per_request > codec.max_headers { return Err(TransferConfigError::HeadersAboveCodec { req: self.headers_per_request, codec: codec.max_headers }); }
        let one = CodecLimits { max_headers: self.headers_per_request, ..*codec };
        match one.max_len(super::codec::KIND_HEADER_RESP) { Some(m) if m < codec.transport => {} _ => return Err(TransferConfigError::HeadersDoNotFit) }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase { Idle, Headers, Manifest, Chunks, Done(InstallRecord), Failed(String) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RequesterStats {
    pub requests: u64, pub dropped_unsolicited: u64, pub dropped_mismatch: u64, pub dropped_late: u64, pub peers_suppressed: u64,
    pub headers_rejected: u64, pub manifests_rejected: u64, pub chunks_rejected: u64, pub snapshots_rejected: u64, pub no_checkpoint_yet: u64,
}

/// What the requester wants sent. The caller encodes and delivers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Out { pub peer: usize, pub msg: RecoveryMsg }

struct Chosen { seed: CheckpointSeed, ev: SeedEvidence }

pub struct Requester<A: Authenticator, I: InstallSink, E: EvidenceSink> {
    auth: A, sink: I, evidence: E,
    genesis_id: BlockId, genesis_hash: [u8; 32], codec: CodecLimits, lim: RequesterLimits,
    local_height: u64,
    peers: BTreeSet<usize>,
    table: RequestTable, cool: Cooldown, supp: Suppression,
    phase: Phase, started_at: u64,
    // headers: ONE source at a time, so a bad page can only ever poison (and is discarded with) that source
    hsrc: Option<usize>, headers: Vec<PayloadFreeBlock>, final_qc: Option<Cert>, tip_height: u64,
    chosen: Option<Chosen>,
    manifest: Option<Manifest>, manifest_src: Option<usize>, bad_snapshots: BTreeSet<[u8; 32]>,
    have: BTreeSet<u32>, chunk_src: BTreeMap<u32, usize>,
    pub stats: RequesterStats,
}

impl<A: Authenticator, I: InstallSink, E: EvidenceSink> Requester<A, I, E> {
    pub fn new(auth: A, sink: I, evidence: E, genesis_id: BlockId, genesis_hash: [u8; 32], codec: CodecLimits, lim: RequesterLimits, local_height: u64) -> Result<Self, TransferConfigError> {
        lim.validate(&codec)?;
        Ok(Requester {
            auth, sink, evidence, genesis_id, genesis_hash, codec, lim, local_height, peers: BTreeSet::new(),
            table: RequestTable::new(lim.max_outstanding, 1, lim.request_timeout_ms), cool: Cooldown::default(), supp: Suppression::default(), phase: Phase::Idle, started_at: 0,
            hsrc: None, headers: vec![], final_qc: None, tip_height: 0, chosen: None, manifest: None, manifest_src: None, bad_snapshots: BTreeSet::new(), have: BTreeSet::new(), chunk_src: BTreeMap::new(),
            stats: RequesterStats::default(),
        })
    }
    pub fn phase(&self) -> &Phase { &self.phase }
    pub fn outstanding(&self) -> usize { self.table.len() }
    pub fn add_peer(&mut self, peer: usize) { self.peers.insert(peer); }
    pub fn remove_peer(&mut self, peer: usize) { self.peers.remove(&peer); }
    pub fn is_finished(&self) -> bool { matches!(self.phase, Phase::Done(_) | Phase::Failed(_)) }
    pub fn sink(&self) -> &I { &self.sink }
    pub fn evidence(&self) -> &E { &self.evidence }

    /// Operator-initiated start (the only trigger in this release).
    pub fn start(&mut self, now: u64) -> Vec<Out> {
        if self.phase != Phase::Idle { return vec![]; }
        self.phase = Phase::Headers; self.started_at = now;
        self.pump(now)
    }

    fn fail(&mut self, why: impl Into<String>) { if !self.is_finished() { let _ = self.sink.abort(); self.phase = Phase::Failed(why.into()); } }
    fn blame(&mut self, peer: usize, now: u64) { self.supp.record_invalid(peer, now); self.stats.peers_suppressed += 1; }
    fn usable(&self, peer: usize, sel: &Selector, now: u64) -> bool { self.peers.contains(&peer) && !self.supp.is_suppressed(peer, now) && self.cool.ready(peer, sel, now) }
    fn peer_load(&self, peer: usize) -> usize { self.table.entries_for(peer) }

    fn issue(&mut self, peer: usize, sel: Selector, now: u64, out: &mut Vec<Out>) -> bool {
        if self.peer_load(peer) >= self.lim.per_peer_outstanding { return false; }
        let id = match self.table.issue(peer, sel, now) { Ok(id) => id, Err(IssueError::GlobalCap) | Err(IssueError::PeerCap) | Err(IssueError::IdExhausted) => return false };
        self.stats.requests += 1;
        out.push(Out { peer, msg: match sel {
            Selector::After(after) => RecoveryMsg::HeaderReq { request_id: id, after, max_headers: self.lim.headers_per_request.min(self.codec.max_headers) },
            Selector::Ref(cref) => RecoveryMsg::ManifestReq { request_id: id, cref },
            Selector::Chunk(sid, index) => RecoveryMsg::ChunkReq { request_id: id, snapshot_id: sid, index },
        } });
        true
    }

    /// Fill every free slot the current phase can use. Called after every event, so a released slot is reused at once (a leaked slot would stall the transfer).
    fn pump(&mut self, now: u64) -> Vec<Out> {
        let mut out = vec![];
        if self.is_finished() || self.phase == Phase::Idle { return out; }
        if now.saturating_sub(self.started_at) > self.lim.overall_timeout_ms { self.fail("the transfer deadline passed"); return out; }
        let peers: Vec<usize> = self.peers.iter().copied().collect();
        match self.phase {
            Phase::Headers => {
                if self.table.entries_of_kind(KIND_HEADER_REQ) > 0 { return out; }
                let after = self.last_id();
                let sel = Selector::After(after);
                let src = self.hsrc.filter(|p| self.usable(*p, &sel, now)).or_else(|| peers.iter().copied().find(|p| self.usable(*p, &sel, now)));
                if let Some(p) = src { if p != self.hsrc.unwrap_or(p) { self.reset_headers(); } self.hsrc = Some(p); let sel = Selector::After(self.last_id()); self.issue(p, sel, now, &mut out); }
            }
            Phase::Manifest => {
                let Some(c) = self.chosen.as_ref().map(|c| c.seed.reference().to_owned()) else { return out };
                if self.table.entries_of_kind(KIND_MANIFEST_REQ) > 0 { return out; }
                let sel = Selector::Ref(c);
                if let Some(p) = peers.iter().copied().find(|p| self.usable(*p, &sel, now)) { self.issue(p, sel, now, &mut out); }
            }
            Phase::Chunks => {
                let Some(mf) = self.manifest.clone() else { return out };
                let inflight: BTreeSet<u32> = self.table.chunk_indices();
                for i in 0..mf.chunk_count {
                    if self.have.contains(&i) || inflight.contains(&i) { continue; }
                    let sel = Selector::Chunk(mf.snapshot_id, i);
                    // spread across providers: the least loaded usable peer
                    let best = peers.iter().copied().filter(|p| self.usable(*p, &sel, now) && self.peer_load(*p) < self.lim.per_peer_outstanding).min_by_key(|p| self.peer_load(*p));
                    match best { Some(p) => { if !self.issue(p, sel, now, &mut out) { break; } } None => break }
                }
            }
            _ => {}
        }
        out
    }

    fn last_id(&self) -> BlockId { self.headers.last().and_then(|h| self.auth.header_id(h)).unwrap_or(self.genesis_id) }
    fn reset_headers(&mut self) { self.headers.clear(); self.final_qc = None; self.tip_height = 0; }

    /// Periodic call: expire requests (their slots are released and the silent peer is put on cooldown for that selector) and issue more.
    pub fn on_tick(&mut self, now: u64) -> Vec<Out> {
        for p in self.table.expire(now) { self.cool.note_unserved(p.peer, p.selector, now); if matches!(p.selector, Selector::After(_)) && Some(p.peer) == self.hsrc { self.hsrc = None; } }
        if self.phase == Phase::Headers && self.table.entries_of_kind(KIND_HEADER_REQ) == 0 && self.hsrc.is_none() { /* a new source continues from the start */ self.reset_headers(); }
        self.pump(now)
    }

    /// One decoded message from `peer`.
    pub fn on_message(&mut self, peer: usize, m: &RecoveryMsg, now: u64) -> Vec<Out> {
        if self.is_finished() { return vec![]; }
        let pending = match self.table.accept(peer, m, now) {
            Ok(p) => p,
            Err(Dropped::Unsolicited) | Err(Dropped::NotAResponse) => { self.stats.dropped_unsolicited += 1; return vec![]; }
            Err(Dropped::SelectorMismatch) => { self.stats.dropped_mismatch += 1; self.blame(peer, now); return self.pump(now); }
            Err(Dropped::Late) => { self.stats.dropped_late += 1; return vec![]; }
        };
        // the request's slot is released by `accept`; everything below may immediately reuse it
        match (m, pending.selector) {
            (RecoveryMsg::HeaderResp { body, .. }, Selector::After(after)) => self.on_headers(peer, after, body, now),
            (RecoveryMsg::ManifestResp { body, .. }, Selector::Ref(cref)) => self.on_manifest(peer, cref, body, now),
            (RecoveryMsg::ChunkResp { body, .. }, Selector::Chunk(sid, idx)) => self.on_chunk(peer, sid, idx, body, now),
            _ => {}
        }
        self.pump(now)
    }

    fn advise(&mut self, peer: usize, sel: Selector, body_advice: Advice, now: u64) {
        match body_advice { Advice::Busy { retry_after_ms } => { self.cool.note_unserved_for(peer, sel, now, clamp_retry_after(retry_after_ms)); } _ => { self.cool.note_unserved(peer, sel, now); } }
    }

    fn on_headers(&mut self, peer: usize, after: BlockId, body: &HeaderBody, now: u64) {
        if Some(peer) != self.hsrc { return; } // an answer from a source that was replaced
        match body {
            HeaderBody::Ok { headers, final_qc, tip_height } => {
                // cheap structure checks BEFORE the page is kept (the cryptographic check is the authenticator's)
                let mut prev = (after, self.headers.last().map_or(0, |h| h.height));
                for h in headers { if h.parent_id != prev.0 || h.height != prev.1 + 1 { self.stats.headers_rejected += 1; self.blame(peer, now); self.reset_headers(); self.hsrc = None; return; } match self.auth.header_id(h) { Some(i) => prev = (i, h.height), None => { self.stats.headers_rejected += 1; self.blame(peer, now); self.reset_headers(); self.hsrc = None; return; } } }
                if self.headers.len().saturating_add(headers.len()) > self.lim.max_accumulated_headers { self.stats.headers_rejected += 1; self.blame(peer, now); self.reset_headers(); self.hsrc = None; return; }
                self.headers.extend(headers.iter().cloned());
                if final_qc.is_some() { self.final_qc = final_qc.clone(); }
                self.tip_height = *tip_height;
                if self.headers.last().map_or(false, |h| h.height >= self.tip_height) { self.try_authenticate(peer, now); }
            }
            HeaderBody::AtTip { .. } => self.try_authenticate(peer, now),
            other => { let a = advice_of(&RecoveryMsg::HeaderResp { request_id: 0, after, body: other.clone() }); self.advise(peer, Selector::After(after), a, now); self.hsrc = None; }
        }
    }

    /// Choose the highest checkpoint reference carried by a header of the assembled chain that the node's own authenticator accepts.
    fn try_authenticate(&mut self, peer: usize, now: u64) {
        let Some(final_qc) = self.final_qc.clone() else { self.stats.headers_rejected += 1; self.blame(peer, now); self.reset_headers(); self.hsrc = None; return };
        let mut refs: Vec<CheckpointRef> = self.headers.iter().filter_map(|h| h.checkpoint).filter(|c| c.height > self.local_height).collect();
        refs.sort_by_key(|c| std::cmp::Reverse(c.height)); refs.dedup();
        if refs.is_empty() { self.stats.no_checkpoint_yet += 1; self.reset_headers(); self.hsrc = None; return; } // honest peer, young chain: not blamed
        let mut last_err = String::new();
        for cref in refs {
            let ev = SeedEvidence { headers: self.headers.clone(), final_qc: Some(final_qc.clone()), cref, high_qc: final_qc.clone(), high_tc: None };
            match self.auth.authenticate(&ev) {
                Ok(seed) => { self.chosen = Some(Chosen { seed, ev }); self.phase = Phase::Manifest; self.hsrc = None; return; }
                Err(e) => last_err = e,
            }
        }
        let _ = last_err;
        self.stats.headers_rejected += 1; self.blame(peer, now); self.reset_headers(); self.hsrc = None;
    }

    fn on_manifest(&mut self, peer: usize, cref: CheckpointRef, body: &ManifestBody, now: u64) {
        match body {
            ManifestBody::Ok(mf) => {
                let malformed = mf.validate(&self.codec).is_err() || mf.compute_id(&self.genesis_hash, &cref) != mf.snapshot_id;
                if malformed { self.stats.manifests_rejected += 1; self.blame(peer, now); return; }
                // over the local staging budget, or a snapshot already shown not to measure: refused WITHOUT blame (a local limit is not misbehaviour)
                if mf.total_bytes > self.lim.max_staging_bytes || self.bad_snapshots.contains(&mf.snapshot_id) { self.stats.manifests_rejected += 1; self.cool.note_unserved(peer, Selector::Ref(cref), now); return; }
                if self.sink.begin(cref, mf.clone(), self.local_height).is_err() { self.stats.manifests_rejected += 1; self.cool.note_unserved(peer, Selector::Ref(cref), now); return; }
                self.manifest = Some(mf.clone()); self.manifest_src = Some(peer); self.phase = Phase::Chunks;
            }
            other => { let a = advice_of(&RecoveryMsg::ManifestResp { request_id: 0, cref, body: other.clone() }); self.advise(peer, Selector::Ref(cref), a, now); }
        }
    }

    fn on_chunk(&mut self, peer: usize, sid: [u8; 32], idx: u32, body: &ChunkBody, now: u64) {
        let Some(mf) = self.manifest.as_ref() else { return };
        if mf.snapshot_id != sid { return; }
        match body {
            ChunkBody::Ok(data) => {
                // the manifest's hash decides, never the provider; a bad chunk costs the provider its standing, not the transfer its progress
                let want = mf.chunk_hashes.get(idx as usize).copied();
                if want != Some(chunk_hash(idx, data)) || mf.chunk_len(idx) != Some(data.len() as u64) { self.stats.chunks_rejected += 1; self.blame(peer, now); return; }
                if self.sink.put_chunk(idx, data).is_err() { self.stats.chunks_rejected += 1; return; }
                self.have.insert(idx); self.chunk_src.insert(idx, peer);
                self.cool.note_served(peer, Selector::Chunk(sid, idx));
                if self.have.len() == mf.chunk_count as usize { self.finish(now); }
            }
            other => { let a = advice_of(&RecoveryMsg::ChunkResp { request_id: 0, snapshot_id: sid, index: idx, body: other.clone() }); self.advise(peer, Selector::Chunk(sid, idx), a, now); }
        }
    }

    fn finish(&mut self, now: u64) {
        let Some(ch) = self.chosen.as_ref() else { return };
        let (seed, ev) = (&ch.seed, ch.ev.clone());
        let cref = *seed.reference();
        let carrier = self.headers_point_for(&ev, &cref);
        let proof = match carrier { Some(c) => InstallProof { carrier: c, tip: *seed.tip(), high_qc: ev.high_qc.clone() }, None => { self.fail("no carrier point for the checkpoint"); return } };
        let ev2 = ev.clone();
        let evidence = &mut self.evidence;
        let mut local: Option<String> = None;
        let r = self.sink.finish_with(proof, &mut || evidence.persist(&ev2).map_err(|e| { local = Some(e.clone()); e }));
        match r {
            Ok(rec) => self.phase = Phase::Done(rec),
            // the evidence could not be made durable: a LOCAL failure. Nothing was published; no provider is blamed and the transfer stops.
            Err(_) if local.is_some() => self.fail(format!("the seed evidence could not be made durable: {}", local.unwrap_or_default())),
            Err(_) => {
                // the staged state did not measure to the authenticated root. The manifest's source is to blame; retry with another snapshot id and provider
                // rather than trusting the same manifest again.
                let sid = self.manifest.as_ref().map(|m| m.snapshot_id);
                if let Some(s) = sid { self.bad_snapshots.insert(s); }
                if let Some(p) = self.manifest_src { self.blame(p, now); }
                for p in self.chunk_src.values().copied().collect::<BTreeSet<_>>() { self.blame(p, now); }
                self.stats.snapshots_rejected += 1;
                self.manifest = None; self.manifest_src = None; self.have.clear(); self.chunk_src.clear();
                self.phase = Phase::Manifest;
            }
        }
    }

    fn headers_point_for(&self, ev: &SeedEvidence, cref: &CheckpointRef) -> Option<ChainPoint> {
        let h = ev.headers.iter().find(|h| h.checkpoint == Some(*cref))?;
        let id = self.auth.header_id(h)?;
        self.chosen.as_ref()?.seed.chain_point(&id)
    }
}
