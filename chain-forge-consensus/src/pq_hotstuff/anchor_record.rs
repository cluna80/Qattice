//! AN-1: the LOCAL anchor record and its crash-safe two-generation ring (docs/pq-hotstuff-2/phase11-anchored-evidence-scope.md, section 6A). Compiled only with the
//! `pq-anchored-evidence` feature (off by default). **Storage only**: nothing here verifies an anchor's finality proof, creates one from verification, audits, or lets a node START
//! from one. An anchor record is a LOCAL record: its checksum detects accidents and authenticates NOTHING; the binding it carries is compared with the values the node recomputes from
//! its OWN configuration, never trusted. The ring keeps two generations for crash recovery only; it never touches application state or signing floors.
use std::collections::BTreeMap;

use sha3::{Digest, Sha3_256};

use super::certs::Cert;
use super::checkpoint::{effective_genesis_hash, CheckpointRef};
use super::engine::EngineConfig;
use super::header::{Anchor, PayloadFreeBlock};
use super::netmsg::{decode_header, encode_header};
use super::recovery::tree::{FsError, TreeFs};

const TAG: &[u8] = b"CFH1|anchor-record|";
const VERSION: u16 = 1;
const PROGRESS_TAG: &[u8] = b"CFH1|anchor-audit|";
const DIR: &str = "anchors";
const TMP: &str = "anchors-tmp";
const PROGRESS: &str = "anchors/audit-progress";
const MAX_ANCESTORS: usize = 4096;
const MAX_NAME: usize = 256;

/// The values a record is bound to. The node recomputes these from ITS OWN configuration; the record's copy is only compared with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorBinding { pub genesis_hash: [u8; 32], pub profile: String, pub chain_id: String, pub valset_hash: [u8; 32], pub interval: u64, pub max_age: u64 }

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnchorError {
    #[error("anchors need a checkpoint-parameter (profile v3) configuration")] NoCheckpointParams,
    #[error("configuration: {0}")] Config(String),
    #[error("anchor record: {0}")] Record(&'static str),
    #[error("the record is bound to another genesis, profile, chain, validator set or checkpoint parameters")] BindingMismatch,
    #[error("the proof exceeds the configured limits ({headers} headers, {bytes} bytes)")] ProofTooLarge { headers: usize, bytes: u64 },
    #[error("generation {got} is not newer than {have}")] NotForward { have: u64, got: u64 },
    #[error("a limit is zero")] ZeroLimit,
    #[error("{0}")] Fs(String),
}
impl From<FsError> for AnchorError { fn from(e: FsError) -> Self { AnchorError::Fs(e.0) } }

impl AnchorBinding {
    /// Recompute the binding from this node's own engine configuration.
    pub fn of(cfg: &EngineConfig) -> Result<Self, AnchorError> {
        let cp = cfg.checkpoint.as_ref().ok_or(AnchorError::NoCheckpointParams)?;
        let genesis_hash = effective_genesis_hash(&cfg.protocol_profile, &cfg.genesis_hash, Some(&cp.params)).map_err(|e| AnchorError::Config(e.to_string()))?;
        Ok(AnchorBinding { genesis_hash, profile: cfg.protocol_profile.clone(), chain_id: cfg.chain_id.clone(), valset_hash: cfg.set.validator_set_hash(), interval: cp.params.interval, max_age: cp.params.max_age })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorLimits { pub max_proof_headers: usize, pub max_proof_bytes: u64 }
impl AnchorLimits {
    pub fn validate(&self) -> Result<(), AnchorError> { if self.max_proof_headers == 0 || self.max_proof_bytes == 0 { Err(AnchorError::ZeroLimit) } else { Ok(()) } }
}

impl AnchorLimits {
    /// A proof spans from the checkpoint block to a final carrier of its reference: at most `max_age + 3` headers (the freshness bound plus the finality lag). A genesis whose
    /// `max_age` cannot fit these limits makes anchored start UNSUPPORTED: refused here, locally, before any anchor is written or trusted.
    pub fn supports(&self, binding: &AnchorBinding, max_header_bytes: u64) -> Result<(), AnchorError> {
        self.validate()?;
        let headers = binding.max_age.checked_add(3).and_then(|h| usize::try_from(h).ok()).ok_or(AnchorError::Record("max_age overflow"))?;
        let bytes = (headers as u64).checked_mul(max_header_bytes).ok_or(AnchorError::Record("size overflow"))?;
        if headers > self.max_proof_headers || bytes > self.max_proof_bytes { return Err(AnchorError::ProofTooLarge { headers, bytes }); }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance { Genesis, Anchor(u64) }

/// The finality proof an anchor retains: the headers from the anchor block to a final carrier of its reference, and the certificate of the last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorProof { pub headers: Vec<PayloadFreeBlock>, pub final_qc: Option<Cert> }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRecord {
    pub generation: u64,
    pub binding: AnchorBinding,
    pub anchor: Anchor,
    pub reference: CheckpointRef,
    pub proof: AnchorProof,
    pub provenance: Provenance,
    /// The highest height this node has re-verified from genesis through this anchor's lineage (never above the anchor).
    pub audited_height: u64,
}

fn put_blob(o: &mut Vec<u8>, b: &[u8]) { o.extend_from_slice(&(b.len() as u32).to_be_bytes()); o.extend_from_slice(b); }
fn put_ref(o: &mut Vec<u8>, r: &CheckpointRef) { o.extend_from_slice(&r.height.to_be_bytes()); o.extend_from_slice(&r.block_id); o.extend_from_slice(&r.state_root); }

struct Cur<'a> { b: &'a [u8], p: usize }
impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AnchorError> { let e = self.p.checked_add(n).ok_or(AnchorError::Record("length"))?; let s = self.b.get(self.p..e).ok_or(AnchorError::Record("truncated"))?; self.p = e; Ok(s) }
    fn u64(&mut self) -> Result<u64, AnchorError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<usize, AnchorError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize) }
    fn h32(&mut self) -> Result<[u8; 32], AnchorError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn blob(&mut self) -> Result<&'a [u8], AnchorError> { let n = self.u32()?; self.take(n) }
    fn text(&mut self) -> Result<String, AnchorError> { let b = self.blob()?; if b.len() > MAX_NAME { return Err(AnchorError::Record("name length")); } String::from_utf8(b.to_vec()).map_err(|_| AnchorError::Record("name encoding")) }
    fn rf(&mut self) -> Result<CheckpointRef, AnchorError> { Ok(CheckpointRef { height: self.u64()?, block_id: self.h32()?, state_root: self.h32()? }) }
    fn flag(&mut self) -> Result<bool, AnchorError> { match self.take(1)?[0] { 0 => Ok(false), 1 => Ok(true), _ => Err(AnchorError::Record("flag")) } }
}

impl AnchorRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = TAG.to_vec();
        o.extend_from_slice(&VERSION.to_be_bytes());
        o.extend_from_slice(&self.generation.to_be_bytes());
        let b = &self.binding;
        o.extend_from_slice(&b.genesis_hash); put_blob(&mut o, b.profile.as_bytes()); put_blob(&mut o, b.chain_id.as_bytes()); o.extend_from_slice(&b.valset_hash);
        o.extend_from_slice(&b.interval.to_be_bytes()); o.extend_from_slice(&b.max_age.to_be_bytes());
        let a = &self.anchor;
        o.extend_from_slice(&a.id); o.extend_from_slice(&a.height.to_be_bytes()); o.extend_from_slice(&a.round.to_be_bytes()); o.extend_from_slice(&a.parent_round.to_be_bytes()); o.extend_from_slice(&a.final_height.to_be_bytes());
        match &a.last_ref { Some(r) => { o.push(1); put_ref(&mut o, r); } None => o.push(0) }
        o.extend_from_slice(&(a.ancestors.len() as u32).to_be_bytes());
        for (h, id) in &a.ancestors { o.extend_from_slice(&h.to_be_bytes()); o.extend_from_slice(id); }
        put_ref(&mut o, &self.reference);
        match self.provenance { Provenance::Genesis => o.push(0), Provenance::Anchor(g) => { o.push(1); o.extend_from_slice(&g.to_be_bytes()); } }
        o.extend_from_slice(&self.audited_height.to_be_bytes());
        o.extend_from_slice(&(self.proof.headers.len() as u32).to_be_bytes());
        for h in &self.proof.headers { put_blob(&mut o, &encode_header(h)); }
        match &self.proof.final_qc { Some(c) => { o.push(1); put_blob(&mut o, &c.encode()); } None => o.push(0) }
        let sum = Sha3_256::digest(&o);
        o.extend_from_slice(&sum);
        o
    }

    /// Strict. Wrong tag, version, checksum, length, trailing bytes, more headers or bytes than the limits, or an inconsistent field is an error; allocation is bounded by the input.
    pub fn decode(b: &[u8], lim: &AnchorLimits) -> Result<Self, AnchorError> {
        if b.len() < TAG.len() + 2 + 8 + 32 { return Err(AnchorError::Record("too short")); }
        let (body, sum) = b.split_at(b.len() - 32);
        if Sha3_256::digest(body)[..] != *sum { return Err(AnchorError::Record("checksum")); }
        let mut r = Cur { b: body, p: 0 };
        if r.take(TAG.len())? != TAG { return Err(AnchorError::Record("tag")); }
        if u16::from_be_bytes(r.take(2)?.try_into().unwrap()) != VERSION { return Err(AnchorError::Record("version")); }
        let generation = r.u64()?;
        let binding = AnchorBinding { genesis_hash: r.h32()?, profile: r.text()?, chain_id: r.text()?, valset_hash: r.h32()?, interval: r.u64()?, max_age: r.u64()? };
        let (id, height, round, parent_round, final_height) = (r.h32()?, r.u64()?, r.u64()?, r.u64()?, r.u64()?);
        let last_ref = if r.flag()? { Some(r.rf()?) } else { None };
        let na = r.u32()?;
        if na > MAX_ANCESTORS { return Err(AnchorError::Record("too many ancestors")); }
        let mut ancestors = Vec::with_capacity(na.min(body.len() / 40));
        for _ in 0..na { ancestors.push((r.u64()?, r.h32()?)); }
        let reference = r.rf()?;
        let provenance = match r.take(1)?[0] { 0 => Provenance::Genesis, 1 => Provenance::Anchor(r.u64()?), _ => return Err(AnchorError::Record("provenance")) };
        let audited_height = r.u64()?;
        let n = r.u32()?;
        if n > lim.max_proof_headers { return Err(AnchorError::ProofTooLarge { headers: n, bytes: 0 }); }
        let (mut headers, mut bytes) = (Vec::with_capacity(n.min(body.len() / 64)), 0u64);
        for _ in 0..n {
            let blob = r.blob()?; bytes += blob.len() as u64;
            if bytes > lim.max_proof_bytes { return Err(AnchorError::ProofTooLarge { headers: n, bytes }); }
            headers.push(decode_header(blob).map_err(|_| AnchorError::Record("header"))?);
        }
        let final_qc = if r.flag()? { let blob = r.blob()?; bytes += blob.len() as u64; if bytes > lim.max_proof_bytes { return Err(AnchorError::ProofTooLarge { headers: n, bytes }); } Some(Cert::decode(blob).map_err(|_| AnchorError::Record("certificate"))?) } else { None };
        if r.p != body.len() { return Err(AnchorError::Record("trailing bytes")); }
        // fields that must agree with each other (a decoder that accepts nonsense hands it to a verifier that may not look)
        if audited_height > height { return Err(AnchorError::Record("audited height above the anchor")); }
        if reference.height > height { return Err(AnchorError::Record("reference above the anchor")); }
        if let Provenance::Anchor(g) = provenance { if g >= generation { return Err(AnchorError::Record("provenance generation is not older")); } }
        if headers.is_empty() { return Err(AnchorError::Record("empty proof")); }
        Ok(AnchorRecord { generation, binding, anchor: Anchor { id, height, round, parent_round, final_height, last_ref, ancestors }, reference, proof: AnchorProof { headers, final_qc }, provenance, audited_height })
    }
}

fn gen_name(g: u64) -> String { format!("gen-{g:020}") }
fn parse_gen(n: &str) -> Option<u64> { n.strip_prefix("gen-").filter(|d| d.len() == 20 && d.bytes().all(|b| b.is_ascii_digit())).and_then(|d| d.parse().ok()) }

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RingStats { pub discarded_on_open: u64, pub published: u64 }

/// Two generations of anchor records, newest first. Forward-only, atomically replaced, re-checked on open against the node's OWN binding and limits.
pub struct AnchorRing<F: TreeFs> {
    pub fs: F,
    lim: AnchorLimits,
    binding: AnchorBinding,
    gens: BTreeMap<u64, AnchorRecord>,
    pub stats: RingStats,
}

impl<F: TreeFs> AnchorRing<F> {
    pub fn open(mut fs: F, lim: AnchorLimits, binding: AnchorBinding) -> Result<Self, AnchorError> {
        lim.validate()?;
        fs.mkdir_all(DIR)?; fs.mkdir_all(TMP)?;
        for n in fs.list(TMP)? { fs.remove_all(&format!("{TMP}/{n}"))?; } // an unpublished write is never read
        let mut ring = AnchorRing { fs, lim, binding, gens: BTreeMap::new(), stats: RingStats::default() };
        for n in ring.fs.list(DIR)? {
            if n == "audit-progress" { continue; }
            let path = format!("{DIR}/{n}");
            let rec = parse_gen(&n).and_then(|g| { let b = ring.fs.read(&path).ok().flatten()?; let r = AnchorRecord::decode(&b, &ring.lim).ok()?; (r.generation == g && r.binding == ring.binding).then_some(r) });
            match rec { Some(r) => { ring.gens.insert(r.generation, r); } None => { ring.fs.remove_all(&path)?; ring.stats.discarded_on_open += 1; } }
        }
        // audit progress only ever raises `audited_height` of the generation it names, and never above that anchor
        if let Some(b) = ring.fs.read(PROGRESS)? {
            match ring.read_progress(&b) {
                Some((g, h)) => { if let Some(r) = ring.gens.get_mut(&g) { if h <= r.anchor.height && h > r.audited_height { r.audited_height = h; } } }
                None => { ring.fs.remove_all(PROGRESS)?; ring.stats.discarded_on_open += 1; }
            }
        }
        // keep the two newest only (a crash between publishing g and removing g-2 leaves three)
        let keep: Vec<u64> = ring.gens.keys().rev().take(2).copied().collect();
        let drop: Vec<u64> = ring.gens.keys().filter(|g| !keep.contains(g)).copied().collect();
        for g in drop { ring.fs.remove_all(&format!("{DIR}/{}", gen_name(g)))?; ring.gens.remove(&g); }
        ring.fs.sync_dir(TMP)?; ring.fs.sync_dir(DIR)?; ring.fs.sync_dir("")?;
        Ok(ring)
    }

    fn read_progress(&self, b: &[u8]) -> Option<(u64, u64)> {
        if b.len() != PROGRESS_TAG.len() + 16 + 32 { return None; }
        let (body, sum) = b.split_at(b.len() - 32);
        if Sha3_256::digest(body)[..] != *sum || &body[..PROGRESS_TAG.len()] != PROGRESS_TAG { return None; }
        let r = &body[PROGRESS_TAG.len()..];
        Some((u64::from_be_bytes(r[..8].try_into().unwrap()), u64::from_be_bytes(r[8..16].try_into().unwrap())))
    }

    pub fn binding(&self) -> &AnchorBinding { &self.binding }
    pub fn limits(&self) -> &AnchorLimits { &self.lim }
    /// Newest first.
    pub fn generations(&self) -> Vec<&AnchorRecord> { self.gens.values().rev().collect() }
    pub fn newest(&self) -> Option<&AnchorRecord> { self.gens.values().next_back() }
    pub fn previous(&self) -> Option<&AnchorRecord> { let mut it = self.gens.values().rev(); it.next(); it.next() }

    /// Publish a new generation: temporary name, flush, one atomic rename, directory syncs; the older generation is removed only after this one is durable. Forward-only.
    pub fn publish(&mut self, rec: AnchorRecord) -> Result<(), AnchorError> {
        if rec.binding != self.binding { return Err(AnchorError::BindingMismatch); }
        if let Some(have) = self.newest().map(|r| r.generation) { if rec.generation <= have { return Err(AnchorError::NotForward { have, got: rec.generation }); } }
        let bytes = rec.encode();
        AnchorRecord::decode(&bytes, &self.lim).map(|_| ())?; // what is written is exactly what open would accept
        let name = gen_name(rec.generation);
        let tmp = format!("{TMP}/{name}");
        self.fs.remove_all(&tmp)?;
        self.fs.write_file(&tmp, &bytes)?; self.fs.sync_file(&tmp)?; self.fs.sync_dir(TMP)?;
        self.fs.rename(&tmp, &format!("{DIR}/{name}"))?; self.fs.sync_dir(DIR)?; self.fs.sync_dir(TMP)?;
        self.gens.insert(rec.generation, rec);
        self.stats.published += 1;
        let drop: Vec<u64> = self.gens.keys().rev().skip(2).copied().collect();
        for g in drop { self.fs.remove_all(&format!("{DIR}/{}", gen_name(g)))?; self.gens.remove(&g); self.fs.sync_dir(DIR)?; }
        Ok(())
    }

    /// Record audit progress for `generation` (forward-only, never above the anchor), atomically.
    pub fn set_audited(&mut self, generation: u64, height: u64) -> Result<(), AnchorError> {
        let Some(r) = self.gens.get(&generation) else { return Err(AnchorError::Record("no such generation")) };
        if height > r.anchor.height { return Err(AnchorError::Record("audited height above the anchor")); }
        if height <= r.audited_height { return Ok(()); }
        let mut o = PROGRESS_TAG.to_vec(); o.extend_from_slice(&generation.to_be_bytes()); o.extend_from_slice(&height.to_be_bytes());
        let sum = Sha3_256::digest(&o); o.extend_from_slice(&sum);
        let tmp = format!("{TMP}/audit-progress");
        self.fs.remove_all(&tmp)?; self.fs.write_file(&tmp, &o)?; self.fs.sync_file(&tmp)?; self.fs.sync_dir(TMP)?;
        self.fs.rename(&tmp, PROGRESS)?; self.fs.sync_dir(DIR)?;
        if let Some(r) = self.gens.get_mut(&generation) { r.audited_height = height; }
        Ok(())
    }
}

