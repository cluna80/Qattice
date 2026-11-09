//! Staged, generation-bound snapshot installation (spec 4). DISABLED: nothing calls this from the operational node, and no snapshot arrives over the network.
//!
//! Layout under the filesystem root: `recovery.state`, `app-current` (pointer), `install-record.<generation>`, `generations/gen-<generation>/` (live state) and
//! `staging/<snapshot id>/` (`chunk-NNNNN` files and the shadow `state/` tree). `generations/` and `staging/` belong to the installer alone; garbage collection
//! removes ONLY names matching the exact patterns below and never touches anything else (for example the operational application or safety directories). The SafetyStore is not part of this and is never touched.
//!
//! Order of durable effects in `finish`: shadow tree assembled and its root compared with the independently authenticated reference; FLUSH BARRIER (every file,
//! then every directory bottom-up); rename into `app/gen-G`; install record `G`; `recovery.state = Verified(G)`; pointer to `G` (naming the record's digest);
//! `recovery.state = Published(G)`; (the caller seeds the engine); `recovery.state = Idle(G)` and garbage collection of older generations.
use std::collections::BTreeSet;

use super::codec::{chunk_hash, CheckpointRef, CodecLimits, Manifest};
use super::records::{AppPointer, Cursor, InstallRecord, Phase, RecoveryState};
use super::tree::{parent_of, FsError, TreeFs};
use crate::pq_hotstuff::certs::Cert;
use crate::pq_hotstuff::exec::InterimApp;
use crate::pq_hotstuff::header::ChainPoint;
use crate::pq_hotstuff::safety::{Storage, StorageError};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstallError {
    /// The node must not start or continue: the durable state is inconsistent. Nothing was changed or deleted.
    #[error("refusing: {0}")]
    Refuse(String),
    /// The install was discarded; the previous application state and pointer are intact.
    #[error("install aborted: {0}")]
    Aborted(String),
    /// The request itself was not acceptable; nothing started.
    #[error("rejected: {0}")]
    Rejected(&'static str),
    #[error("{0}")]
    Fs(String),
}
impl From<FsError> for InstallError { fn from(e: FsError) -> Self { InstallError::Fs(e.0) } }

/// How a snapshot's chunks become a state tree, and how a state tree is measured. `measure` must recompute from the files only.
pub trait ShadowApp {
    fn assemble(&self, fs: &mut dyn TreeFs, chunks_dir: &str, manifest: &Manifest, out_dir: &str) -> Result<(), String>;
    fn measure(&self, fs: &dyn TreeFs, state_dir: &str) -> Result<Cursor, String>;
}

pub type QcCheck = Box<dyn Fn(&Cert) -> Result<(), String>>;

pub struct InstallProof { pub carrier: ChainPoint, pub tip: ChainPoint, pub high_qc: Cert }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartOutcome {
    Idle { generation: u64 },
    /// The previous run published generation `record.generation` but did not finish seeding the engine.
    NeedsSeed { record: InstallRecord },
}

struct Staging { cref: CheckpointRef, manifest: Manifest, received: BTreeSet<u32>, generation: u64 }

pub struct Installer<F: TreeFs, A: ShadowApp> {
    pub fs: F,
    app: A,
    genesis_hash: [u8; 32],
    limits: CodecLimits,
    check_qc: QcCheck,
    generation: u64,
    pointer: Option<AppPointer>,
    staging: Option<Staging>,
    pending_seed: Option<InstallRecord>,
    started: bool,
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
const GENS: &str = "generations";
pub fn gen_dir(g: u64) -> String { format!("{GENS}/gen-{g:020}") }
pub fn record_path(g: u64) -> String { format!("install-record.{g:020}") }
fn stage_dir(id: &[u8; 32]) -> String { format!("staging/{}", hex(id)) }
fn is_digits20(s: &str) -> bool { s.len() == 20 && s.bytes().all(|b| b.is_ascii_digit()) }
fn is_gen_name(n: &str) -> bool { n.strip_prefix("gen-").map_or(false, is_digits20) }
fn is_record_name(n: &str) -> bool { n.strip_prefix("install-record.").map_or(false, is_digits20) }
fn is_hex64(n: &str) -> bool { n.len() == 64 && n.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
const STATE: &str = "recovery.state";
const POINTER: &str = "app-current";

impl<F: TreeFs, A: ShadowApp> Installer<F, A> {
    pub fn new(mut fs: F, app: A, genesis_hash: [u8; 32], limits: CodecLimits, check_qc: QcCheck) -> Result<Self, InstallError> {
        fs.mkdir_all(GENS)?;
        fs.mkdir_all("staging")?;
        if !fs.same_device("staging", GENS) { return Err(InstallError::Refuse("staging and generations are on different filesystems; an atomic rename is impossible".into())); }
        Ok(Installer { fs, app, genesis_hash, limits, check_qc, generation: 0, pointer: None, staging: None, pending_seed: None, started: false })
    }
    pub fn generation(&self) -> u64 { self.generation }
    pub fn pointer(&self) -> Option<AppPointer> { self.pointer }
    pub fn into_fs(self) -> F { self.fs }

    fn write_atomic(&mut self, path: &str, bytes: &[u8]) -> Result<(), InstallError> {
        let tmp = format!("{path}.tmp");
        self.fs.remove_all(&tmp)?;
        self.fs.write_file(&tmp, bytes)?;
        self.fs.sync_file(&tmp)?;
        self.fs.rename(&tmp, path)?;
        self.fs.sync_dir(parent_of(path))?;
        Ok(())
    }

    fn read_state(&self) -> Result<Option<RecoveryState>, InstallError> {
        match self.fs.read(STATE)? { None => Ok(None), Some(b) => RecoveryState::decode(&b).map(Some).map_err(|e| InstallError::Refuse(format!("{STATE}: {e}"))) }
    }
    fn read_pointer(&self) -> Result<Option<AppPointer>, InstallError> {
        match self.fs.read(POINTER)? { None => Ok(None), Some(b) => AppPointer::decode(&b).map(Some).map_err(|e| InstallError::Refuse(format!("{POINTER}: {e}"))) }
    }

    /// Static checks of a proof's QC and points. The QC is cryptographically re-verified (not merely integrity-tagged).
    fn check_proof(&self, cref: &CheckpointRef, carrier: &ChainPoint, tip: &ChainPoint, qc: &Cert) -> Result<(), String> {
        (self.check_qc)(qc).map_err(|e| format!("certificate: {e}"))?;
        if !matches!(qc, Cert::Qc(_)) { return Err("final certificate is not a QC".into()); }
        if qc.block_id() != tip.id || qc.round() != tip.round { return Err("certificate does not certify the tip".into()); }
        if carrier.height < cref.height || tip.height < carrier.height { return Err("heights are not ordered reference <= carrier <= tip".into()); }
        Ok(())
    }

    /// Everything that binds the published generation together: record generation, pointer digest, cursor, certificate, directory.
    fn validate_current(&self, p: &AppPointer) -> Result<InstallRecord, InstallError> {
        let bytes = self.fs.read(&record_path(p.generation))?.ok_or_else(|| InstallError::Refuse(format!("install record for generation {} is missing", p.generation)))?;
        let rec = InstallRecord::decode(&bytes).map_err(|e| InstallError::Refuse(format!("install record: {e}")))?;
        if rec.generation != p.generation { return Err(InstallError::Refuse(format!("install record is for generation {}, the pointer names generation {}", rec.generation, p.generation))); }
        if rec.digest() != p.record_digest { return Err(InstallError::Refuse("the pointer does not name this install record".into())); }
        if p.cursor != (Cursor { height: rec.cref.height, block_id: rec.cref.block_id, state_root: rec.cref.state_root }) { return Err(InstallError::Refuse("pointer cursor differs from the record's reference".into())); }
        self.check_proof(&rec.cref, &rec.carrier, &rec.tip, &rec.high_qc).map_err(|e| InstallError::Refuse(format!("install record: {e}")))?;
        if !self.fs.is_dir(&gen_dir(p.generation)) { return Err(InstallError::Refuse(format!("{} is missing", gen_dir(p.generation)))); }
        Ok(rec)
    }

    /// Remove staging areas, orphan generations and stale records: ONLY names matching the installer's own patterns. Called after the pointer was validated.
    fn gc(&mut self, keep: u64) -> Result<(), InstallError> {
        let keep_dir = format!("gen-{keep:020}");
        for n in self.fs.list(GENS)? { if is_gen_name(&n) && !(keep > 0 && n == keep_dir) { self.fs.remove_all(&format!("{GENS}/{n}"))?; } }
        for n in self.fs.list("staging")? { if is_hex64(&n) { self.fs.remove_all(&format!("staging/{n}"))?; } }
        let keep_rec = record_path(keep);
        for n in self.fs.list("")? {
            let stale_record = is_record_name(&n) && !(keep > 0 && n == keep_rec);
            let stale_tmp = n == format!("{STATE}.tmp") || n == format!("{POINTER}.tmp") || (is_record_name(&n[..n.len().saturating_sub(4)]) && n.ends_with(".tmp"));
            if stale_record || stale_tmp { self.fs.remove_all(&n)?; }
        }
        self.fs.sync_dir(GENS)?; self.fs.sync_dir("staging")?; self.fs.sync_dir("")?;
        Ok(())
    }

    /// Recover from whatever the previous run left. See the module comment and spec 4 for the crash matrix.
    pub fn start(&mut self) -> Result<StartOutcome, InstallError> {
        let ptr = self.read_pointer()?;
        let st = self.read_state()?;
        let rec = match &ptr { Some(p) => Some(self.validate_current(p)?), None => None };
        let g = ptr.map_or(0, |p| p.generation);
        let outcome = match (st, ptr) {
            (None, None) => StartOutcome::Idle { generation: 0 },
            (None, Some(_)) => return Err(InstallError::Refuse("pointer without recovery.state".into())),
            (Some(s), _) => match (s.phase, s.generation) {
                (Phase::Idle, sg) if sg == g => StartOutcome::Idle { generation: g },
                (Phase::Staging | Phase::Verified, sg) if g.checked_add(1) == Some(sg) => {
                    // an attempt that never published: discard everything it left, then record Idle
                    self.write_atomic(STATE, &RecoveryState::idle(g).encode())?;
                    StartOutcome::Idle { generation: g }
                }
                (Phase::Verified | Phase::Published, sg) if sg == g && g > 0 => {
                    // published but not marked Idle: re-measure the live tree before trusting it
                    let (p, r) = (ptr.unwrap(), rec.unwrap());
                    let m = self.app.measure(&self.fs, &gen_dir(g)).map_err(|e| InstallError::Refuse(format!("published state cannot be measured: {e}")))?;
                    if m != p.cursor { return Err(InstallError::Refuse("published state does not match the pointer's cursor".into())); }
                    self.generation = g; self.pointer = Some(p); self.pending_seed = Some(r.clone()); self.started = true;
                    return Ok(StartOutcome::NeedsSeed { record: r });
                }
                (ph, sg) => return Err(InstallError::Refuse(format!("recovery.state ({ph:?}, generation {sg}) is inconsistent with the pointer (generation {g})"))),
            },
        };
        self.gc(g)?;
        self.generation = g; self.pointer = ptr; self.started = true;
        Ok(outcome)
    }

    /// Start staging a snapshot for `cref`. Forward only: the reference must be above both the executor's current height and the installed cursor.
    pub fn begin(&mut self, cref: CheckpointRef, manifest: Manifest, current_height: u64) -> Result<(), InstallError> {
        if !self.started { return Err(InstallError::Rejected("start() has not run")); }
        if self.staging.is_some() || self.pending_seed.is_some() { return Err(InstallError::Rejected("an install is already in progress")); }
        if cref.height <= current_height || self.pointer.map_or(false, |p| cref.height <= p.cursor.height) { return Err(InstallError::Rejected("not forward: the reference is not above the current state")); }
        manifest.validate(&self.limits).map_err(|_| InstallError::Rejected("manifest"))?;
        if manifest.compute_id(&self.genesis_hash, &cref) != manifest.snapshot_id { return Err(InstallError::Rejected("snapshot id does not match the manifest and the reference")); }
        let generation = self.generation.checked_add(1).ok_or(InstallError::Rejected("generation overflow"))?;
        let st = RecoveryState { phase: Phase::Staging, generation, cref, snapshot_id: manifest.snapshot_id };
        self.write_atomic(STATE, &st.encode())?;
        let d = stage_dir(&manifest.snapshot_id);
        self.fs.mkdir_all(&d)?;
        self.fs.sync_dir("staging")?;
        self.staging = Some(Staging { cref, manifest, received: BTreeSet::new(), generation });
        Ok(())
    }

    /// Accept one chunk: exact length, hash from the manifest, not a duplicate; written and synced before it counts.
    pub fn put_chunk(&mut self, index: u32, data: &[u8]) -> Result<(), InstallError> {
        let s = self.staging.as_mut().ok_or(InstallError::Rejected("no install in progress"))?;
        let want = s.manifest.chunk_len(index).ok_or(InstallError::Rejected("chunk index"))?;
        if data.len() as u64 != want { return Err(InstallError::Rejected("chunk length")); }
        if chunk_hash(index, data) != s.manifest.chunk_hashes[index as usize] { return Err(InstallError::Rejected("chunk hash")); }
        if s.received.contains(&index) { return Err(InstallError::Rejected("duplicate chunk")); }
        let d = stage_dir(&s.manifest.snapshot_id);
        let p = format!("{d}/chunk-{index:05}");
        self.fs.write_file(&p, data)?;
        self.fs.sync_file(&p)?;
        self.fs.sync_dir(&d)?;
        if let Some(s) = self.staging.as_mut() { s.received.insert(index); }
        Ok(())
    }

    fn walk(&self, dir: &str, files: &mut Vec<String>, dirs: &mut Vec<String>) -> Result<(), FsError> {
        dirs.push(dir.to_string());
        for n in self.fs.list(dir)? {
            let p = format!("{dir}/{n}");
            if self.fs.is_dir(&p) { self.walk(&p, files, dirs)?; } else { files.push(p); }
        }
        Ok(())
    }

    fn discard(&mut self, reason: String) -> InstallError {
        let g = self.generation;
        self.staging = None;
        let r = self.gc(g).and_then(|_| self.write_atomic(STATE, &RecoveryState::idle(g).encode()));
        match r { Ok(()) => InstallError::Aborted(reason), Err(e) => InstallError::Aborted(format!("{reason} (cleanup incomplete: {e}; the next start finishes it)")) }
    }

    /// Steps 3 to 8 of the protocol. Returns the install record once the pointer is published; the caller seeds the engine and then calls `complete_seed`.
    pub fn finish(&mut self, proof: InstallProof) -> Result<InstallRecord, InstallError> { self.finish_with(proof, &mut || Ok(())) }

    /// [`Installer::finish`] with a hook that runs after the staged state has been measured against the authenticated reference and flushed, and BEFORE anything is
    /// published (no rename, record or pointer yet). The caller persists the seed evidence there, so every published generation already has durable, matching,
    /// re-authenticatable evidence. If the hook fails the install is discarded and nothing is published.
    pub fn finish_with(&mut self, proof: InstallProof, before_publish: &mut dyn FnMut() -> Result<(), String>) -> Result<InstallRecord, InstallError> {
        let (cref, manifest, generation, complete) = {
            let s = self.staging.as_ref().ok_or(InstallError::Rejected("no install in progress"))?;
            (s.cref, s.manifest.clone(), s.generation, s.received.len() == s.manifest.chunk_count as usize)
        };
        if !complete { return Err(InstallError::Rejected("not all chunks have arrived")); }
        if let Err(e) = self.check_proof(&cref, &proof.carrier, &proof.tip, &proof.high_qc) { return Err(self.discard(e)); }
        let stage = stage_dir(&manifest.snapshot_id);
        let state = format!("{stage}/state");
        // 3: build the shadow state and compare it with the independently authenticated reference BEFORE anything is published
        if let Err(e) = self.app.assemble(&mut self.fs, &stage, &manifest, &state) { return Err(self.discard(format!("assemble: {e}"))); }
        let m = match self.app.measure(&self.fs, &state) { Ok(m) => m, Err(e) => return Err(self.discard(format!("measure: {e}"))) };
        if m != (Cursor { height: cref.height, block_id: cref.block_id, state_root: cref.state_root }) { return Err(self.discard("the staged state does not match the authenticated reference".into())); }
        // 4: flush barrier: every file, then every directory of the shadow tree bottom-up. Nothing below starts until all of it has succeeded.
        let (mut files, mut dirs) = (vec![], vec![]);
        if let Err(e) = self.walk(&state, &mut files, &mut dirs) { return Err(self.discard(format!("walk: {e}"))); }
        for f in &files { if let Err(e) = self.fs.sync_file(f) { return Err(self.discard(format!("flush {f}: {e}"))); } }
        for d in dirs.iter().rev() { if let Err(e) = self.fs.sync_dir(d) { return Err(self.discard(format!("flush {d}: {e}"))); } }
        // 4b: the caller's durable evidence, BEFORE the application generation exists
        if let Err(e) = before_publish() { return Err(self.discard(format!("before publish: {e}"))); }
        // 5: into place as a new generation (directory entries made durable in `generations/` and the old parent)
        let live = gen_dir(generation);
        if let Err(e) = self.fs.rename(&state, &live).and_then(|_| self.fs.sync_dir(GENS)).and_then(|_| self.fs.sync_dir(&stage)) { return Err(self.discard(format!("rename: {e}"))); }
        // 6, 7: the generation-bound install record, then the Verified phase
        let rec = InstallRecord { generation, cref, carrier: proof.carrier, tip: proof.tip, high_qc: proof.high_qc };
        self.write_atomic(&record_path(generation), &rec.encode())?;
        self.write_atomic(STATE, &RecoveryState { phase: Phase::Verified, generation, cref, snapshot_id: manifest.snapshot_id }.encode())?;
        // 8: publish: state and cursor together, naming the record's digest
        let ptr = AppPointer { generation, cursor: Cursor { height: cref.height, block_id: cref.block_id, state_root: cref.state_root }, record_digest: rec.digest() };
        self.write_atomic(POINTER, &ptr.encode())?;
        self.write_atomic(STATE, &RecoveryState { phase: Phase::Published, generation, cref, snapshot_id: manifest.snapshot_id }.encode())?;
        self.generation = generation; self.pointer = Some(ptr); self.staging = None; self.pending_seed = Some(rec.clone());
        Ok(rec)
    }

    /// The engine has been seeded from the record: mark Idle and remove the previous generation and the staging area.
    pub fn complete_seed(&mut self) -> Result<(), InstallError> {
        if self.pending_seed.is_none() { return Err(InstallError::Rejected("nothing to complete")); }
        let g = self.generation;
        self.write_atomic(STATE, &RecoveryState::idle(g).encode())?;
        self.gc(g)?;
        self.pending_seed = None;
        Ok(())
    }

    /// Abandon an install in progress (before publication).
    pub fn abort(&mut self) -> Result<(), InstallError> {
        if self.staging.is_none() { return Err(InstallError::Rejected("no install in progress")); }
        match self.discard("aborted by the caller".into()) { InstallError::Aborted(_) => Ok(()), e => Err(e) }
    }
}

// ---------------------------------------------------------------------------------------------------------------- the interim application
struct TreeDir<'a> { fs: &'a dyn TreeFs, dir: String }
impl Storage for TreeDir<'_> {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StorageError> { self.fs.read(&format!("{}/{name}", self.dir)).map_err(|e| StorageError(e.0)) }
    fn write_tmp(&mut self, _: &str, _: &[u8]) -> Result<(), StorageError> { Err(StorageError("read-only".into())) }
    fn sync_file(&mut self, _: &str) -> Result<(), StorageError> { Err(StorageError("read-only".into())) }
    fn rename(&mut self, _: &str, _: &str) -> Result<(), StorageError> { Err(StorageError("read-only".into())) }
    fn sync_dir(&mut self) -> Result<(), StorageError> { Err(StorageError("read-only".into())) }
    fn remove(&mut self, _: &str) -> Result<(), StorageError> { Err(StorageError("read-only".into())) }
}

/// The DEVNET-INTERIM application's snapshot: the chunks, concatenated in order, ARE its `app-state` record; the measured cursor comes from opening that
/// record with the real [`InterimApp`] (checksum, header, genesis hash). Not transaction state.
#[derive(Debug, Clone, Copy)]
pub struct InterimShadow { pub genesis_hash: [u8; 32] }
impl ShadowApp for InterimShadow {
    fn assemble(&self, fs: &mut dyn TreeFs, chunks_dir: &str, manifest: &Manifest, out_dir: &str) -> Result<(), String> {
        let mut all = Vec::new();
        for i in 0..manifest.chunk_count {
            all.extend_from_slice(&fs.read(&format!("{chunks_dir}/chunk-{i:05}")).map_err(|e| e.0)?.ok_or("a chunk file is missing")?);
        }
        fs.mkdir_all(out_dir).map_err(|e| e.0)?;
        fs.write_file(&format!("{out_dir}/app-state"), &all).map_err(|e| e.0)
    }
    fn measure(&self, fs: &dyn TreeFs, state_dir: &str) -> Result<Cursor, String> {
        let app = InterimApp::open(TreeDir { fs, dir: state_dir.to_string() }, self.genesis_hash).map_err(|e| e.to_string())?;
        let c = crate::pq_hotstuff::exec::Executor::cursor(&app);
        if c.height == 0 { return Err("the snapshot holds no executed block".into()); }
        Ok(Cursor { height: c.height, block_id: c.block_id, state_root: c.state_digest })
    }
}
