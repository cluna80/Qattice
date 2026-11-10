//! S-2a: bounded, per-node, crash-safe RETENTION of authenticated snapshots (a devnet CACHE policy; it is NOT a guarantee that pruning is safe). Isolated: nothing here
//! is wired into the node, no provider serves from it yet, nothing is captured automatically, and pruning stays unimplemented. Owner decisions (2026-11-10):
//! the budget is configured per node with validated limits and explicit accounting; three snapshots is the initial target; **pinned snapshots and the active
//! recovery generation are never evicted**; when the budget cannot hold a new capture the capture is DEFERRED with a clear resource error.
//! Accounting covers retained snapshots, temporary capture, and `external` bytes (the installer's staging and generations, reported by the caller and never evicted).
use std::collections::BTreeMap;

use super::codec::{chunk_hash, decode, encode, CodecLimits, Manifest, ManifestBody, RecoveryMsg};
use super::tree::{FsError, TreeFs};
use crate::pq_hotstuff::checkpoint::CheckpointRef;

const DIR: &str = "snapshots";
const TMP: &str = "snapshots-tmp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Snapshots kept (the initial devnet target is 3).
    pub max_snapshots: usize,
    /// Everything this node may spend on snapshots, retained + capturing + `external` (installer staging and generations).
    pub disk_budget_bytes: u64,
    /// The largest single snapshot this node will capture or keep.
    pub max_snapshot_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RetentionError {
    #[error("a limit is zero")] Zero,
    #[error("the disk budget {budget} cannot hold one retained snapshot and one capture of the largest size ({max_snapshot} each)")]
    BudgetBelowOneCapture { budget: u64, max_snapshot: u64 },
    #[error("resource budget exhausted: the capture needs {needed} bytes, {available} are available even after evicting every unpinned snapshot")]
    BudgetExhausted { needed: u64, available: u64 },
    #[error("snapshot of {bytes} bytes exceeds the per-snapshot limit {max}")] TooLarge { bytes: u64, max: u64 },
    #[error("not newer than the newest retained snapshot")] NotForward,
    #[error("invalid snapshot: {0}")] Invalid(&'static str),
    #[error("no such retained snapshot")] Unknown,
    #[error("{0}")] Fs(String),
}
impl From<FsError> for RetentionError { fn from(e: FsError) -> Self { RetentionError::Fs(e.0) } }

impl RetentionConfig {
    /// Refuse locally, before any capture, a budget that cannot work: at least one retained snapshot plus one capture of the largest size must fit.
    pub fn validate(&self) -> Result<(), RetentionError> {
        if self.max_snapshots == 0 || self.disk_budget_bytes == 0 || self.max_snapshot_bytes == 0 { return Err(RetentionError::Zero); }
        match self.max_snapshot_bytes.checked_mul(2) { Some(m) if self.disk_budget_bytes >= m => Ok(()), _ => Err(RetentionError::BudgetBelowOneCapture { budget: self.disk_budget_bytes, max_snapshot: self.max_snapshot_bytes }) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Captured { Retained { evicted: Vec<[u8; 32]> }, AlreadyRetained }

#[derive(Debug, Clone)]
struct Meta { cref: CheckpointRef, manifest: Manifest, bytes: u64 }

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetentionStats { pub captured: u64, pub deferred: u64, pub evicted: u64, pub discarded_on_open: u64, pub peak_bytes: u64 }

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn is_hex64(s: &str) -> bool { s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) }

pub struct SnapshotStore<F: TreeFs> {
    pub fs: F,
    cfg: RetentionConfig, codec: CodecLimits, genesis_hash: [u8; 32],
    retained: BTreeMap<[u8; 32], Meta>,
    pins: BTreeMap<[u8; 32], u32>,
    external: u64,
    pub stats: RetentionStats,
}

impl<F: TreeFs> SnapshotStore<F> {
    /// Open the store: leftover capture temporaries are removed, and every retained snapshot is RE-VERIFIED from its files (id, manifest, every chunk's length and hash);
    /// anything that does not verify is removed and never served.
    pub fn open(mut fs: F, cfg: RetentionConfig, codec: CodecLimits, genesis_hash: [u8; 32]) -> Result<Self, RetentionError> {
        cfg.validate()?;
        fs.mkdir_all(DIR)?; fs.mkdir_all(TMP)?;
        for n in fs.list(TMP)? { fs.remove_all(&format!("{TMP}/{n}"))?; }
        let mut s = SnapshotStore { fs, cfg, codec, genesis_hash, retained: BTreeMap::new(), pins: BTreeMap::new(), external: 0, stats: RetentionStats::default() };
        for n in s.fs.list(DIR)? {
            let path = format!("{DIR}/{n}");
            match if is_hex64(&n) { s.verify(&n)? } else { None } { Some((id, meta)) => { s.retained.insert(id, meta); } None => { s.fs.remove_all(&path)?; s.stats.discarded_on_open += 1; } }
        }
        s.fs.sync_dir(TMP)?; s.fs.sync_dir(DIR)?; s.fs.sync_dir("")?;
        s.stats.peak_bytes = s.used();
        Ok(s)
    }

    fn verify(&self, name: &str) -> Result<Option<([u8; 32], Meta)>, RetentionError> {
        let dir = format!("{DIR}/{name}");
        let Some(mb) = self.fs.read(&format!("{dir}/manifest"))? else { return Ok(None) };
        let Ok(RecoveryMsg::ManifestResp { cref, body: ManifestBody::Ok(m), .. }) = decode(&mb, &self.codec) else { return Ok(None) };
        if hex(&m.snapshot_id) != name || m.compute_id(&self.genesis_hash, &cref) != m.snapshot_id || m.validate(&self.codec).is_err() { return Ok(None); }
        let mut bytes = mb.len() as u64;
        for i in 0..m.chunk_count {
            let Some(c) = self.fs.read(&format!("{dir}/chunk-{i:05}"))? else { return Ok(None) };
            if Some(c.len() as u64) != m.chunk_len(i) || chunk_hash(i, &c) != m.chunk_hashes[i as usize] { return Ok(None); }
            bytes += c.len() as u64;
        }
        // nothing else may be in the directory (the accounting must equal the disk)
        if self.fs.list(&dir)?.len() as u64 != u64::from(m.chunk_count) + 1 { return Ok(None); }
        Ok(Some((m.snapshot_id, Meta { cref, manifest: m, bytes })))
    }

    pub fn config(&self) -> &RetentionConfig { &self.cfg }
    /// Bytes retained, plus the `external` bytes the caller reserved (installer staging and generations).
    pub fn used(&self) -> u64 { self.retained.values().map(|m| m.bytes).sum::<u64>().saturating_add(self.external) }
    pub fn retained_bytes(&self) -> u64 { self.retained.values().map(|m| m.bytes).sum() }
    pub fn available(&self) -> u64 { self.cfg.disk_budget_bytes.saturating_sub(self.used()) }
    /// The installer's staging and generation bytes (never evicted by this store); the budget covers them.
    pub fn set_external_reserved(&mut self, bytes: u64) { self.external = bytes; }
    /// Retained snapshots, oldest first: (reference, snapshot id, bytes, pinned).
    pub fn retained(&self) -> Vec<(CheckpointRef, [u8; 32], u64, bool)> {
        let mut v: Vec<_> = self.retained.iter().map(|(id, m)| (m.cref, *id, m.bytes, self.pins.contains_key(id))).collect();
        v.sort_by_key(|x| x.0.height); v
    }

    pub fn pin(&mut self, id: &[u8; 32]) -> Result<(), RetentionError> { if !self.retained.contains_key(id) { return Err(RetentionError::Unknown); } *self.pins.entry(*id).or_insert(0) += 1; Ok(()) }
    pub fn unpin(&mut self, id: &[u8; 32]) { if let Some(c) = self.pins.get_mut(id) { *c -= 1; if *c == 0 { self.pins.remove(id); } } }
    pub fn manifest_for(&self, cref: &CheckpointRef) -> Option<Manifest> { self.retained.values().find(|m| m.cref == *cref).map(|m| m.manifest.clone()) }
    pub fn chunk(&self, id: &[u8; 32], index: u32) -> Option<Vec<u8>> { if !self.retained.contains_key(id) { return None; } self.fs.read(&format!("{DIR}/{}/chunk-{index:05}", hex(id))).ok().flatten() }

    fn remove(&mut self, id: &[u8; 32]) -> Result<(), RetentionError> {
        self.fs.remove_all(&format!("{DIR}/{}", hex(id)))?; self.fs.sync_dir(DIR)?;
        self.retained.remove(id); self.stats.evicted += 1; Ok(())
    }

    /// Capture an authenticated snapshot (the caller has already established that `cref` is final and attested; this store checks only the snapshot's own integrity).
    /// Eviction order: oldest UNPINNED first; pinned snapshots are never evicted. If the budget cannot hold the capture even then, NOTHING is evicted and the capture is
    /// deferred with `BudgetExhausted`.
    pub fn capture(&mut self, cref: CheckpointRef, manifest: &Manifest, chunks: &[Vec<u8>]) -> Result<Captured, RetentionError> {
        manifest.validate(&self.codec).map_err(|_| RetentionError::Invalid("manifest"))?;
        if manifest.compute_id(&self.genesis_hash, &cref) != manifest.snapshot_id { return Err(RetentionError::Invalid("snapshot id")); }
        if chunks.len() != manifest.chunk_count as usize { return Err(RetentionError::Invalid("chunk count")); }
        for (i, c) in chunks.iter().enumerate() {
            if Some(c.len() as u64) != manifest.chunk_len(i as u32) || chunk_hash(i as u32, c) != manifest.chunk_hashes[i] { return Err(RetentionError::Invalid("chunk")); }
        }
        let mf_bytes = encode(&RecoveryMsg::ManifestResp { request_id: 0, cref, body: ManifestBody::Ok(manifest.clone()) }).map_err(|_| RetentionError::Invalid("manifest encoding"))?;
        let need = manifest.total_bytes.checked_add(mf_bytes.len() as u64).ok_or(RetentionError::Invalid("size"))?;
        if need > self.cfg.max_snapshot_bytes { return Err(RetentionError::TooLarge { bytes: need, max: self.cfg.max_snapshot_bytes }); }
        if self.retained.contains_key(&manifest.snapshot_id) { return Ok(Captured::AlreadyRetained); }
        if self.retained.values().any(|m| m.cref.height >= cref.height) { return Err(RetentionError::NotForward); }
        // plan: evict oldest unpinned until the capture fits at its PEAK (retained + external + the temporary copy)
        let mut plan: Vec<[u8; 32]> = vec![];
        let mut used = self.used();
        let order: Vec<[u8; 32]> = self.retained().into_iter().filter(|r| !r.3).map(|r| r.1).collect();
        let mut it = order.into_iter();
        while used.saturating_add(need) > self.cfg.disk_budget_bytes {
            let Some(id) = it.next() else { self.stats.deferred += 1; return Err(RetentionError::BudgetExhausted { needed: need, available: self.cfg.disk_budget_bytes.saturating_sub(used) }); };
            used -= self.retained[&id].bytes; plan.push(id);
        }
        for id in &plan { self.remove(id)?; }
        // write to a temporary directory, make it durable, then publish it with one atomic rename
        let name = hex(&manifest.snapshot_id);
        let tmp = format!("{TMP}/{name}");
        self.fs.remove_all(&tmp)?; self.fs.mkdir_all(&tmp)?;
        self.stats.peak_bytes = self.stats.peak_bytes.max(self.used().saturating_add(need));
        for (i, c) in chunks.iter().enumerate() { let p = format!("{tmp}/chunk-{i:05}"); self.fs.write_file(&p, c)?; self.fs.sync_file(&p)?; }
        let mp = format!("{tmp}/manifest"); self.fs.write_file(&mp, &mf_bytes)?; self.fs.sync_file(&mp)?;
        self.fs.sync_dir(&tmp)?;
        self.fs.rename(&tmp, &format!("{DIR}/{name}"))?; self.fs.sync_dir(DIR)?; self.fs.sync_dir(TMP)?;
        self.retained.insert(manifest.snapshot_id, Meta { cref, manifest: manifest.clone(), bytes: need });
        self.stats.captured += 1;
        let mut evicted = plan;
        // the count target, after publication (oldest unpinned first; a pinned snapshot keeps the count above target rather than being evicted)
        while self.retained.len() > self.cfg.max_snapshots {
            let Some(id) = self.retained().into_iter().find(|r| !r.3 && r.1 != manifest.snapshot_id).map(|r| r.1) else { break };
            self.remove(&id)?; evicted.push(id);
        }
        Ok(Captured::Retained { evicted })
    }
}
