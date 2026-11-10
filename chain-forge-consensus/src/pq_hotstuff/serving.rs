//! S-2b: snapshot CAPTURE and SERVING for a running PQ-HotStuff-2 driver. Compiled only with the `pq-snapshot-transfer` feature (off by default) and active only after an
//! explicit runtime opt-in (`Driver::enable_snapshot_serving`); with either missing the driver behaves exactly as before (recovery kinds 7 to 14 are unknown input).
//! Scope: the PROVIDER side. Installation is operator-initiated and install-then-restart (a later slice); nothing here installs anything, imports provider signing state,
//! or prunes. The snapshots are of the DEVNET-INTERIM application (a hash chain of opaque payloads), not Qattice transaction state. Retention is a devnet cache policy.
use std::collections::BTreeMap;

use super::certs::BlockId;
use super::checkpoint::CheckpointRef;
use super::exec::ExecCursor;
use super::netmsg::TAG_NET;
use super::recovery::codec::{chunk_hash, decode, encode, CodecLimits, HeaderBody, Manifest, RecoveryMsg};
use super::recovery::requests::{ConfigError, ServeConfig, ServeGate};
use super::recovery::retention::{RetentionError, SnapshotStore};
use super::recovery::transfer::{ProviderStore, ServeCore};
use super::recovery::tree::TreeFs;

/// What the driver lets the service read about its chain.
pub trait ChainView {
    fn headers_after(&self, after: &BlockId, max: u32) -> HeaderBody;
}

/// The driver's view of the service (object safe, so the driver needs no new type parameter).
pub trait RecoveryService {
    /// A datagram of kind 7 to 12 from peer `from`. The replies to send back to `from`.
    fn on_bytes(&mut self, chain: &dyn ChainView, from: usize, bytes: &[u8], now: u64) -> Vec<Vec<u8>>;
    /// The executor just applied `cur`; `snapshot` is its state at exactly that cursor (kept only as a bounded candidate).
    fn note_executed(&mut self, cur: &ExecCursor, snapshot: Option<Vec<u8>>);
    /// A checkpoint reference carried by a block that has just been FINALIZED and executed (so the referenced block is final and its root attested).
    fn note_final_ref(&mut self, r: &CheckpointRef);
    fn tick(&mut self, now: u64);
    fn counters(&self) -> ServingCounters;
    /// Retained snapshots, oldest first: (height, snapshot id, bytes, pinned).
    fn retained(&self) -> Vec<(u64, [u8; 32], u64, bool)>;
}

/// Is `bytes` a datagram of a recovery kind (7 to 12)? Only the envelope is looked at.
pub fn is_recovery_kind(bytes: &[u8]) -> bool {
    let k = TAG_NET.len() + 2;
    bytes.len() > k && bytes.starts_with(TAG_NET) && (7..=12).contains(&bytes[k])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingConfig {
    pub serve: ServeConfig,
    pub codec: CodecLimits,
    /// The genesis hash snapshot ids are bound to (the same value the installer uses).
    pub genesis_hash: [u8; 32],
    pub chunk_size: u32,
    /// Executed checkpoint-height states kept in memory while waiting for their reference to be attested final.
    pub max_candidates: usize,
    /// A transfer that has gone quiet for this long releases its pin.
    pub pin_idle_ms: u64,
    /// Snapshots one peer may keep pinned, and the total pinned for all peers. A peer that asks for more is told BUSY.
    pub max_pins_per_peer: usize,
    pub max_pins_total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServingConfigError {
    #[error("serve configuration: {0}")] Serve(#[from] ConfigError),
    #[error("a limit is zero")] Zero,
    #[error("chunk size {chunk} is above the codec's maximum {max} or does not fit the transport limit")] ChunkSize { chunk: u32, max: u32 },
    #[error("per-peer pins {per} exceed the total {total}")] PinsPerPeer { per: usize, total: usize },
}
impl ServingConfig {
    pub fn validate(&self) -> Result<(), ServingConfigError> {
        self.serve.validate()?;
        if self.chunk_size == 0 || self.max_candidates == 0 || self.pin_idle_ms == 0 || self.max_pins_per_peer == 0 || self.max_pins_total == 0 { return Err(ServingConfigError::Zero); }
        if self.chunk_size > self.codec.max_chunk_size || u64::from(self.chunk_size) + 61 > self.codec.transport { return Err(ServingConfigError::ChunkSize { chunk: self.chunk_size, max: self.codec.max_chunk_size }); }
        if self.max_pins_per_peer > self.max_pins_total { return Err(ServingConfigError::PinsPerPeer { per: self.max_pins_per_peer, total: self.max_pins_total }); }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ServingCounters {
    pub malformed: u64, pub unsolicited_responses: u64, pub requests: u64, pub replies_busy_for_pins: u64,
    pub captured: u64, pub capture_deferred: u64, pub capture_other_error: u64, pub candidates_dropped: u64,
    pub pins_released_complete: u64, pub pins_released_idle: u64, pub pinned_now: u64, pub retained: u64, pub retained_bytes: u64, pub gate_concurrent: u64,
}

struct Pin { last: u64, served: Vec<bool>, remaining: usize }

/// Read-only view for one request: the chain through the driver, the snapshots through the store.
struct View<'a, F: TreeFs> { chain: &'a dyn ChainView, snaps: &'a SnapshotStore<F> }
impl<F: TreeFs> ProviderStore for View<'_, F> {
    fn headers_after(&self, after: &BlockId, max: u32) -> HeaderBody { self.chain.headers_after(after, max) }
    fn manifest(&self, cref: &CheckpointRef) -> Option<Manifest> { self.snaps.manifest_for(cref) }
    fn chunk(&self, id: &[u8; 32], index: u32) -> Option<Vec<u8>> { self.snaps.chunk(id, index) }
}

pub struct SnapshotServing<F: TreeFs> {
    pub store: SnapshotStore<F>,
    core: ServeCore,
    cfg: ServingConfig,
    candidates: BTreeMap<u64, (BlockId, [u8; 32], Vec<u8>)>,
    pins: BTreeMap<(usize, [u8; 32]), Pin>,
    counters: ServingCounters,
}

impl<F: TreeFs> SnapshotServing<F> {
    pub fn new(store: SnapshotStore<F>, cfg: ServingConfig, now: u64) -> Result<Self, ServingConfigError> {
        cfg.validate()?;
        let core = ServeCore::new(ServeGate::new(cfg.serve, now)?, cfg.codec);
        Ok(SnapshotServing { store, core, cfg, candidates: BTreeMap::new(), pins: BTreeMap::new(), counters: ServingCounters::default() })
    }
    pub fn gate_concurrent(&self) -> usize { self.core.concurrent() }
    pub fn pins(&self) -> usize { self.pins.len() }

    /// Pin `(peer, id)` for the length of a transfer, or refuse when this peer or the node as a whole already holds its share.
    fn pin(&mut self, peer: usize, id: [u8; 32], chunk_count: u32, now: u64) -> bool {
        if let Some(p) = self.pins.get_mut(&(peer, id)) { p.last = now; return true; }
        if self.pins.keys().filter(|(q, _)| *q == peer).count() >= self.cfg.max_pins_per_peer || self.pins.len() >= self.cfg.max_pins_total { return false; }
        if self.store.pin(&id).is_err() { return true; } // not retained: nothing to protect (the request is answered NOT_FOUND)
        self.pins.insert((peer, id), Pin { last: now, served: vec![false; chunk_count as usize], remaining: chunk_count as usize });
        true
    }
    fn release(&mut self, key: (usize, [u8; 32])) { if self.pins.remove(&key).is_some() { self.store.unpin(&key.1); } }
}

impl<F: TreeFs> RecoveryService for SnapshotServing<F> {
    fn on_bytes(&mut self, chain: &dyn ChainView, from: usize, bytes: &[u8], now: u64) -> Vec<Vec<u8>> {
        let msg = match decode(bytes, &self.cfg.codec) { Ok(m) => m, Err(_) => { self.counters.malformed += 1; return vec![]; } };
        let is_request = matches!(msg, RecoveryMsg::HeaderReq { .. } | RecoveryMsg::ManifestReq { .. } | RecoveryMsg::ChunkReq { .. });
        if !is_request { self.counters.unsolicited_responses += 1; return vec![]; } // this node asked for nothing
        self.counters.requests += 1;
        // transfers pin the snapshot they read, per peer and bounded; a peer over its share is told BUSY instead of being allowed to hold the cache hostage
        let (sid_count, sid) = match &msg {
            RecoveryMsg::ManifestReq { cref, .. } => match self.store.manifest_for(cref) { Some(m) => (m.chunk_count, m.snapshot_id), None => (0, [0; 32]) },
            RecoveryMsg::ChunkReq { snapshot_id, .. } => match self.store.retained().into_iter().find(|r| r.1 == *snapshot_id) { Some(_) => (self.chunk_count_of(snapshot_id), *snapshot_id), None => (0, [0; 32]) },
            _ => (0, [0; 32]),
        };
        if sid_count > 0 && !self.pin(from, sid, sid_count, now) {
            self.counters.replies_busy_for_pins += 1;
            return encode(&ServeCore::busy(&msg, 1_000)).map(|b| vec![b]).unwrap_or_default();
        }
        let reply = { let view = View { chain, snaps: &self.store }; self.core.handle_with(&view, from, &msg, now) };
        // a transfer that has been served every chunk is complete from this provider's side
        if let (Some(RecoveryMsg::ChunkResp { snapshot_id, index, body: super::recovery::codec::ChunkBody::Ok(_), .. }), true) = (&reply, sid_count > 0) {
            let key = (from, *snapshot_id);
            let done = self.pins.get_mut(&key).map_or(false, |p| { if let Some(s) = p.served.get_mut(*index as usize) { if !*s { *s = true; p.remaining -= 1; } } p.remaining == 0 });
            if done { self.release(key); self.counters.pins_released_complete += 1; }
        }
        reply.and_then(|r| encode(&r).ok()).map(|b| vec![b]).unwrap_or_default()
    }

    fn note_executed(&mut self, cur: &ExecCursor, snapshot: Option<Vec<u8>>) {
        let Some(bytes) = snapshot else { return };
        self.candidates.insert(cur.height, (cur.block_id, cur.state_digest, bytes));
        while self.candidates.len() > self.cfg.max_candidates { let k = *self.candidates.keys().next().unwrap(); self.candidates.remove(&k); self.counters.candidates_dropped += 1; }
    }

    fn note_final_ref(&mut self, r: &CheckpointRef) {
        let Some((bid, root, bytes)) = self.candidates.get(&r.height).cloned() else { return };
        // only the state this node itself executed AT that height, and only if it is exactly what the final reference attests
        if bid != r.block_id || root != r.state_root { return; }
        let chunks: Vec<Vec<u8>> = bytes.chunks(self.cfg.chunk_size as usize).map(|c| c.to_vec()).collect();
        if chunks.is_empty() { return; }
        let mut m = Manifest { format_version: 1, snapshot_id: [0; 32], total_bytes: bytes.len() as u64, chunk_size: self.cfg.chunk_size, chunk_count: chunks.len() as u32, chunk_hashes: chunks.iter().enumerate().map(|(i, c)| chunk_hash(i as u32, c)).collect() };
        m.snapshot_id = m.compute_id(&self.cfg.genesis_hash, r);
        match self.store.capture(*r, &m, &chunks) {
            Ok(_) => self.counters.captured += 1,
            Err(RetentionError::BudgetExhausted { .. }) => self.counters.capture_deferred += 1,
            Err(_) => self.counters.capture_other_error += 1,
        }
        // the candidates at or below this height can never be attested by a later reference (references only move forward)
        self.candidates.retain(|h, _| *h > r.height);
    }

    fn tick(&mut self, now: u64) {
        let idle: Vec<(usize, [u8; 32])> = self.pins.iter().filter(|(_, p)| now.saturating_sub(p.last) >= self.cfg.pin_idle_ms).map(|(k, _)| *k).collect();
        for k in idle { self.release(k); self.counters.pins_released_idle += 1; }
    }

    fn retained(&self) -> Vec<(u64, [u8; 32], u64, bool)> { self.store.retained().into_iter().map(|r| (r.0.height, r.1, r.2, r.3)).collect() }

    fn counters(&self) -> ServingCounters {
        let mut c = self.counters;
        c.gate_concurrent = self.core.concurrent() as u64; c.pinned_now = self.pins.len() as u64; c.retained = self.store.retained().len() as u64; c.retained_bytes = self.store.retained_bytes();
        c
    }
}

impl<F: TreeFs> SnapshotServing<F> {
    pub fn set_external_reserved(&mut self, bytes: u64) { self.store.set_external_reserved(bytes); }
    fn chunk_count_of(&self, id: &[u8; 32]) -> u32 { self.store.retained().into_iter().find(|r| r.1 == *id).and_then(|r| self.store.manifest_for(&r.0)).map_or(0, |m| m.chunk_count) }
}
