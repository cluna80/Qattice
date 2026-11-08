//! Local durable records for snapshot installation (spec 4). Each ends with an INTEGRITY TAG (SHA3-256 over the preceding bytes). The tag detects torn
//! writes and accidental corruption ONLY; it is not authentication, since anyone who can write the data directory can recompute it.
//! **Generation binding:** the install record names its generation, the application pointer names the same generation AND the SHA3-256 digest of the install
//! record it publishes, and `recovery.state` carries the generation being installed (or the last published one when idle). A record from another generation,
//! even a perfectly well-formed one, is refused.
use super::codec::{sha3, CheckpointRef};
use crate::pq_hotstuff::certs::{BlockId, Cert};
use crate::pq_hotstuff::header::ChainPoint;

pub const VERSION: u16 = 1;
const TAG_STATE: &[u8] = b"CFH1|recovery|";
const TAG_RECORD: &[u8] = b"CFH1|install|";
const TAG_POINTER: &[u8] = b"CFH1|app-ptr|";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("record is damaged: {0}")]
    Damaged(&'static str),
}

fn seal(mut body: Vec<u8>) -> Vec<u8> { let t = sha3(&[b"CFH1|local-tag|", &body]); body.extend_from_slice(&t); body }
fn unseal<'a>(b: &'a [u8], tag: &[u8]) -> Result<&'a [u8], RecordError> {
    if b.len() < tag.len() + 2 + 32 { return Err(RecordError::Damaged("too short")); }
    let (body, t) = b.split_at(b.len() - 32);
    if sha3(&[b"CFH1|local-tag|", body]) != t { return Err(RecordError::Damaged("integrity tag")); }
    if &body[..tag.len()] != tag { return Err(RecordError::Damaged("tag")); }
    if u16::from_be_bytes([body[tag.len()], body[tag.len() + 1]]) != VERSION { return Err(RecordError::Damaged("version")); }
    Ok(&body[tag.len() + 2..])
}

struct Rd<'a> { b: &'a [u8], p: usize }
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], RecordError> { if n > self.b.len() - self.p { return Err(RecordError::Damaged("truncated")); } let s = &self.b[self.p..self.p + n]; self.p += n; Ok(s) }
    fn u8(&mut self) -> Result<u8, RecordError> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, RecordError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, RecordError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn h32(&mut self) -> Result<[u8; 32], RecordError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn done(&self) -> Result<(), RecordError> { if self.p == self.b.len() { Ok(()) } else { Err(RecordError::Damaged("trailing bytes")) } }
    fn cref(&mut self) -> Result<CheckpointRef, RecordError> { CheckpointRef::decode(self.take(72)?).map_err(|_| RecordError::Damaged("reference")) }
    fn point(&mut self) -> Result<ChainPoint, RecordError> { Ok(ChainPoint { id: self.h32()?, height: self.u64()?, round: self.u64()?, payload_hash: self.h32()? }) }
}
fn put_point(o: &mut Vec<u8>, p: &ChainPoint) { o.extend_from_slice(&p.id); o.extend_from_slice(&p.height.to_be_bytes()); o.extend_from_slice(&p.round.to_be_bytes()); o.extend_from_slice(&p.payload_hash); }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase { Idle = 0, Staging = 1, Verified = 2, Published = 3 }

/// `generation`: the generation being installed (Staging, Verified, Published) or the last published one (Idle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryState { pub phase: Phase, pub generation: u64, pub cref: CheckpointRef, pub snapshot_id: [u8; 32] }

impl RecoveryState {
    pub fn idle(generation: u64) -> Self { RecoveryState { phase: Phase::Idle, generation, cref: CheckpointRef { height: 0, block_id: [0; 32], state_root: [0; 32] }, snapshot_id: [0; 32] } }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = TAG_STATE.to_vec(); o.extend_from_slice(&VERSION.to_be_bytes());
        o.push(self.phase as u8); o.extend_from_slice(&self.generation.to_be_bytes()); o.extend_from_slice(&self.cref.encode()); o.extend_from_slice(&self.snapshot_id);
        seal(o)
    }
    pub fn decode(b: &[u8]) -> Result<Self, RecordError> {
        let mut r = Rd { b: unseal(b, TAG_STATE)?, p: 0 };
        let phase = match r.u8()? { 0 => Phase::Idle, 1 => Phase::Staging, 2 => Phase::Verified, 3 => Phase::Published, _ => return Err(RecordError::Damaged("phase")) };
        let s = RecoveryState { phase, generation: r.u64()?, cref: r.cref()?, snapshot_id: r.h32()? };
        r.done()?;
        Ok(s)
    }
}

/// A LOCAL trust record, written only after this node's own verification succeeded. It is not a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRecord { pub generation: u64, pub cref: CheckpointRef, pub carrier: ChainPoint, pub tip: ChainPoint, pub high_qc: Cert }

impl InstallRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = TAG_RECORD.to_vec(); o.extend_from_slice(&VERSION.to_be_bytes());
        o.extend_from_slice(&self.generation.to_be_bytes()); o.extend_from_slice(&self.cref.encode());
        put_point(&mut o, &self.carrier); put_point(&mut o, &self.tip);
        let q = self.high_qc.encode(); o.extend_from_slice(&(q.len() as u32).to_be_bytes()); o.extend_from_slice(&q);
        seal(o)
    }
    pub fn decode(b: &[u8]) -> Result<Self, RecordError> {
        let mut r = Rd { b: unseal(b, TAG_RECORD)?, p: 0 };
        let generation = r.u64()?; let cref = r.cref()?; let carrier = r.point()?; let tip = r.point()?;
        let n = r.u32()? as usize;
        let high_qc = Cert::decode(r.take(n)?).map_err(|_| RecordError::Damaged("certificate"))?;
        r.done()?;
        Ok(InstallRecord { generation, cref, carrier, tip, high_qc })
    }
    /// The digest the application pointer commits to (integrity binding, not authentication).
    pub fn digest(&self) -> [u8; 32] { sha3(&[b"CFH1|install-digest|", &self.encode()]) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor { pub height: u64, pub block_id: BlockId, pub state_root: [u8; 32] }

/// The pointer publishes application state AND cursor together; the state directory is derived from `generation` (never read from the file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppPointer { pub generation: u64, pub cursor: Cursor, pub record_digest: [u8; 32] }

impl AppPointer {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = TAG_POINTER.to_vec(); o.extend_from_slice(&VERSION.to_be_bytes());
        o.extend_from_slice(&self.generation.to_be_bytes()); o.extend_from_slice(&self.cursor.height.to_be_bytes()); o.extend_from_slice(&self.cursor.block_id); o.extend_from_slice(&self.cursor.state_root);
        o.extend_from_slice(&self.record_digest);
        seal(o)
    }
    pub fn decode(b: &[u8]) -> Result<Self, RecordError> {
        let mut r = Rd { b: unseal(b, TAG_POINTER)?, p: 0 };
        let p = AppPointer { generation: r.u64()?, cursor: Cursor { height: r.u64()?, block_id: r.h32()?, state_root: r.h32()? }, record_digest: r.h32()? };
        r.done()?;
        Ok(p)
    }
}
