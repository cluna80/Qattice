//! Codecs for the snapshot-recovery messages (kinds 7 to 12), spec section 3. Isolated: [`super::super::netmsg::decode`] does not know these kinds.
//! Big-endian. Every length and count is checked against the remaining input and its own maximum BEFORE anything is allocated; vectors grow by push.
use sha3::{Digest, Sha3_256};

use crate::pq_hotstuff::certs::{BlockId, Cert};
use crate::pq_hotstuff::header::PayloadFreeBlock;
use crate::pq_hotstuff::limits::{qc_max_bytes, tc_max_bytes};
use crate::pq_hotstuff::netmsg::{decode_header, encode_header, NET_VERSION, TAG_NET};

pub const KIND_HEADER_REQ: u8 = 7;
pub const KIND_HEADER_RESP: u8 = 8;
pub const KIND_MANIFEST_REQ: u8 = 9;
pub const KIND_MANIFEST_RESP: u8 = 10;
pub const KIND_CHUNK_REQ: u8 = 11;
pub const KIND_CHUNK_RESP: u8 = 12;
/// Reserved; unavailable here and in the operational node.
pub const RESERVED_KINDS: [u8; 2] = [13, 14];
pub const ENVELOPE: u64 = TAG_NET.len() as u64 + 2 + 1;
pub const MAX_CHUNK_COUNT: u32 = 65_536;
pub const MAX_CHUNK_SIZE: u32 = 1 << 20;
pub const MANIFEST_FIXED: u64 = 2 + 32 + 8 + 4 + 4;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("message of {len} bytes exceeds the limit {max}")]
    TooLarge { len: u64, max: u64 },
    #[error("malformed: {0}")]
    Malformed(&'static str),
    #[error("kind {0} is not a recovery message")]
    UnknownKind(u8),
    #[error("invalid: {0}")]
    Invalid(&'static str),
}

/// Everything a decoder needs to bound its work. `n` is the validator count (it bounds each header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecLimits {
    pub transport: u64,
    pub n: usize,
    pub max_headers: u32,
    pub max_chunk_size: u32,
    pub max_chunk_count: u32,
    pub max_snapshot_bytes: u64,
}

impl CodecLimits {
    /// Largest encoded header at the maximum permitted certificate size: `3410 + QC_MAX + 4 + TC_MAX`.
    pub fn header_max(&self) -> Option<u64> {
        3410u64.checked_add(qc_max_bytes(self.n)?)?.checked_add(4)?.checked_add(tc_max_bytes(self.n, self.n)?)
    }
    pub fn qc_max(&self) -> Option<u64> { qc_max_bytes(self.n) }
    /// Largest legal message of `kind` under these limits (never above the transport limit).
    pub fn max_len(&self, kind: u8) -> Option<u64> {
        let v = match kind {
            KIND_HEADER_REQ => ENVELOPE + 44,
            KIND_MANIFEST_REQ => ENVELOPE + 80,
            KIND_CHUNK_REQ => ENVELOPE + 44,
            KIND_HEADER_RESP => ENVELOPE.checked_add(8 + 1 + 32 + 4)?.checked_add(u64::from(self.max_headers).checked_mul(4u64.checked_add(self.header_max()?)?)?)?.checked_add(1 + 4)?.checked_add(self.qc_max()?)?.checked_add(8)?,
            KIND_MANIFEST_RESP => ENVELOPE.checked_add(8 + 1 + 72 + MANIFEST_FIXED)?.checked_add(32u64.checked_mul(u64::from(self.max_chunk_count))?)?,
            KIND_CHUNK_RESP => ENVELOPE.checked_add(8 + 1 + 32 + 4 + 4)?.checked_add(u64::from(self.max_chunk_size))?,
            _ => return None,
        };
        Some(v.min(self.transport))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CheckpointRef { pub height: u64, pub block_id: BlockId, pub state_root: [u8; 32] }

impl CheckpointRef {
    pub fn encode(&self) -> [u8; 72] {
        let mut o = [0u8; 72];
        o[..8].copy_from_slice(&self.height.to_be_bytes());
        o[8..40].copy_from_slice(&self.block_id);
        o[40..].copy_from_slice(&self.state_root);
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, CodecError> {
        if b.len() != 72 { return Err(CodecError::Malformed("reference length")); }
        Ok(CheckpointRef { height: u64::from_be_bytes(b[..8].try_into().unwrap()), block_id: b[8..40].try_into().unwrap(), state_root: b[40..].try_into().unwrap() })
    }
    /// `SHA3-256("CFH1|ckpt|" || reference)`.
    pub fn hash(&self) -> [u8; 32] { sha3(&[b"CFH1|ckpt|", &self.encode()]) }
}

pub fn sha3(parts: &[&[u8]]) -> [u8; 32] { let mut h = Sha3_256::new(); for p in parts { h.update(p); } h.finalize().into() }

/// `SHA3-256("CFH1|chunk|" || index u32 || data)`.
pub fn chunk_hash(index: u32, data: &[u8]) -> [u8; 32] { sha3(&[b"CFH1|chunk|", &index.to_be_bytes(), data]) }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest { pub format_version: u16, pub snapshot_id: [u8; 32], pub total_bytes: u64, pub chunk_size: u32, pub chunk_count: u32, pub chunk_hashes: Vec<[u8; 32]> }

impl Manifest {
    /// Structural constraints (spec 3): counts and sizes in range, `(count - 1) x size < total <= count x size`, one hash per chunk.
    pub fn validate(&self, lim: &CodecLimits) -> Result<(), CodecError> {
        if self.chunk_count == 0 || self.chunk_count > lim.max_chunk_count || self.chunk_count > MAX_CHUNK_COUNT { return Err(CodecError::Invalid("chunk count")); }
        if self.chunk_size == 0 || self.chunk_size > lim.max_chunk_size || self.chunk_size > MAX_CHUNK_SIZE { return Err(CodecError::Invalid("chunk size")); }
        if self.total_bytes == 0 || self.total_bytes > lim.max_snapshot_bytes { return Err(CodecError::Invalid("total bytes")); }
        let (c, s) = (u128::from(self.chunk_count), u128::from(self.chunk_size));
        let t = u128::from(self.total_bytes);
        if !((c - 1) * s < t && t <= c * s) { return Err(CodecError::Invalid("total bytes outside the chunk bounds")); }
        if self.chunk_hashes.len() != self.chunk_count as usize { return Err(CodecError::Invalid("chunk hash count")); }
        Ok(())
    }
    /// The exact length chunk `index` must have.
    pub fn chunk_len(&self, index: u32) -> Option<u64> {
        if index >= self.chunk_count { return None; }
        if index + 1 < self.chunk_count { Some(u64::from(self.chunk_size)) } else { self.total_bytes.checked_sub(u64::from(self.chunk_count - 1).checked_mul(u64::from(self.chunk_size))?) }
    }
    /// The content-addressed id: `SHA3-256("CFH1|snapshot|" || genesis_hash || ref || format_version || total_bytes || chunk_size || chunk_count || SHA3-256(hashes))`.
    pub fn compute_id(&self, genesis_hash: &[u8; 32], cref: &CheckpointRef) -> [u8; 32] {
        let mut all = Vec::with_capacity(self.chunk_hashes.len() * 32);
        for h in &self.chunk_hashes { all.extend_from_slice(h); }
        sha3(&[b"CFH1|snapshot|", genesis_hash, &cref.encode(), &self.format_version.to_be_bytes(), &self.total_bytes.to_be_bytes(), &self.chunk_size.to_be_bytes(), &self.chunk_count.to_be_bytes(), &sha3(&[&all])])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderBody {
    Ok { headers: Vec<PayloadFreeBlock>, final_qc: Option<Cert>, tip_height: u64 },
    NotFound,
    TooLarge { needed_bytes: u64, next_height: u64 },
    Busy { retry_after_ms: u32 },
    Unavailable,
    AtTip { tip_height: u64 },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestBody { Ok(Manifest), NotFound, TooLarge { needed_bytes: u64 }, Busy { retry_after_ms: u32 }, Unavailable }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkBody { Ok(Vec<u8>), NotFound, Busy { retry_after_ms: u32 }, Unavailable }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryMsg {
    HeaderReq { request_id: u64, after: BlockId, max_headers: u32 },
    HeaderResp { request_id: u64, after: BlockId, body: HeaderBody },
    ManifestReq { request_id: u64, cref: CheckpointRef },
    ManifestResp { request_id: u64, cref: CheckpointRef, body: ManifestBody },
    ChunkReq { request_id: u64, snapshot_id: [u8; 32], index: u32 },
    ChunkResp { request_id: u64, snapshot_id: [u8; 32], index: u32, body: ChunkBody },
}

impl RecoveryMsg {
    pub fn kind(&self) -> u8 {
        match self {
            RecoveryMsg::HeaderReq { .. } => KIND_HEADER_REQ, RecoveryMsg::HeaderResp { .. } => KIND_HEADER_RESP,
            RecoveryMsg::ManifestReq { .. } => KIND_MANIFEST_REQ, RecoveryMsg::ManifestResp { .. } => KIND_MANIFEST_RESP,
            RecoveryMsg::ChunkReq { .. } => KIND_CHUNK_REQ, RecoveryMsg::ChunkResp { .. } => KIND_CHUNK_RESP,
        }
    }
    pub fn request_id(&self) -> u64 {
        match self {
            RecoveryMsg::HeaderReq { request_id, .. } | RecoveryMsg::HeaderResp { request_id, .. } | RecoveryMsg::ManifestReq { request_id, .. }
            | RecoveryMsg::ManifestResp { request_id, .. } | RecoveryMsg::ChunkReq { request_id, .. } | RecoveryMsg::ChunkResp { request_id, .. } => *request_id,
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------- encoding
fn put_u32(o: &mut Vec<u8>, v: u32) { o.extend_from_slice(&v.to_be_bytes()); }
fn put_u64(o: &mut Vec<u8>, v: u64) { o.extend_from_slice(&v.to_be_bytes()); }
fn put_len(o: &mut Vec<u8>, n: usize) -> Result<(), CodecError> { put_u32(o, u32::try_from(n).map_err(|_| CodecError::Invalid("length above u32"))?); Ok(()) }

/// Encode a message. Refuses what the decoder would refuse (an `OK` header response with no headers).
pub fn encode(m: &RecoveryMsg) -> Result<Vec<u8>, CodecError> {
    let mut o = TAG_NET.to_vec();
    o.extend_from_slice(&NET_VERSION.to_be_bytes());
    o.push(m.kind());
    put_u64(&mut o, m.request_id());
    match m {
        RecoveryMsg::HeaderReq { after, max_headers, .. } => { o.extend_from_slice(after); put_u32(&mut o, *max_headers); }
        RecoveryMsg::HeaderResp { after, body, .. } => {
            match body {
                HeaderBody::Ok { headers, final_qc, tip_height } => {
                    if headers.is_empty() { return Err(CodecError::Invalid("OK with no headers")); }
                    o.push(0); o.extend_from_slice(after);
                    put_len(&mut o, headers.len())?;
                    for h in headers { let e = encode_header(h); put_len(&mut o, e.len())?; o.extend_from_slice(&e); }
                    match final_qc { None => o.push(0), Some(q) => { o.push(1); let e = q.encode(); put_len(&mut o, e.len())?; o.extend_from_slice(&e); } }
                    put_u64(&mut o, *tip_height);
                }
                HeaderBody::NotFound => { o.push(1); o.extend_from_slice(after); }
                HeaderBody::TooLarge { needed_bytes, next_height } => { o.push(2); o.extend_from_slice(after); put_u64(&mut o, *needed_bytes); put_u64(&mut o, *next_height); }
                HeaderBody::Busy { retry_after_ms } => { o.push(3); o.extend_from_slice(after); put_u32(&mut o, *retry_after_ms); }
                HeaderBody::Unavailable => { o.push(4); o.extend_from_slice(after); }
                HeaderBody::AtTip { tip_height } => { o.push(5); o.extend_from_slice(after); put_u64(&mut o, *tip_height); }
            }
        }
        RecoveryMsg::ManifestReq { cref, .. } => o.extend_from_slice(&cref.encode()),
        RecoveryMsg::ManifestResp { cref, body, .. } => {
            match body {
                ManifestBody::Ok(m) => {
                    o.push(0); o.extend_from_slice(&cref.encode());
                    o.extend_from_slice(&m.format_version.to_be_bytes()); o.extend_from_slice(&m.snapshot_id);
                    put_u64(&mut o, m.total_bytes); put_u32(&mut o, m.chunk_size); put_u32(&mut o, m.chunk_count);
                    for h in &m.chunk_hashes { o.extend_from_slice(h); }
                }
                ManifestBody::NotFound => { o.push(1); o.extend_from_slice(&cref.encode()); }
                ManifestBody::TooLarge { needed_bytes } => { o.push(2); o.extend_from_slice(&cref.encode()); put_u64(&mut o, *needed_bytes); }
                ManifestBody::Busy { retry_after_ms } => { o.push(3); o.extend_from_slice(&cref.encode()); put_u32(&mut o, *retry_after_ms); }
                ManifestBody::Unavailable => { o.push(4); o.extend_from_slice(&cref.encode()); }
            }
        }
        RecoveryMsg::ChunkReq { snapshot_id, index, .. } => { o.extend_from_slice(snapshot_id); put_u32(&mut o, *index); }
        RecoveryMsg::ChunkResp { snapshot_id, index, body, .. } => {
            let (status, extra): (u8, Option<&Vec<u8>>) = match body { ChunkBody::Ok(d) => (0, Some(d)), ChunkBody::NotFound => (1, None), ChunkBody::Busy { .. } => (3, None), ChunkBody::Unavailable => (4, None) };
            o.push(status); o.extend_from_slice(snapshot_id); put_u32(&mut o, *index);
            if let Some(d) = extra { put_len(&mut o, d.len())?; o.extend_from_slice(d); }
            if let ChunkBody::Busy { retry_after_ms } = body { put_u32(&mut o, *retry_after_ms); }
        }
    }
    Ok(o)
}

// ---------------------------------------------------------------------------------------------------------------- decoding
struct Rd<'a> { b: &'a [u8], p: usize }
impl<'a> Rd<'a> {
    fn left(&self) -> usize { self.b.len() - self.p }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if n > self.left() { return Err(CodecError::Malformed("truncated")); }
        let s = &self.b[self.p..self.p + n]; self.p += n; Ok(s)
    }
    fn u8(&mut self) -> Result<u8, CodecError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, CodecError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, CodecError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, CodecError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn h32(&mut self) -> Result<[u8; 32], CodecError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn cref(&mut self) -> Result<CheckpointRef, CodecError> { CheckpointRef::decode(self.take(72)?) }
}

/// Decode a recovery message. The whole length is checked against the kind's maximum first; nothing is allocated from a reported length.
pub fn decode(b: &[u8], lim: &CodecLimits) -> Result<RecoveryMsg, CodecError> {
    if b.len() as u64 > lim.transport { return Err(CodecError::TooLarge { len: b.len() as u64, max: lim.transport }); }
    let mut r = Rd { b, p: 0 };
    if r.take(TAG_NET.len())? != TAG_NET { return Err(CodecError::Malformed("wrong tag")); }
    if r.u16()? != NET_VERSION { return Err(CodecError::Malformed("version")); }
    let kind = r.u8()?;
    let max = lim.max_len(kind).ok_or(CodecError::UnknownKind(kind))?;
    if b.len() as u64 > max { return Err(CodecError::TooLarge { len: b.len() as u64, max }); }
    let request_id = r.u64()?;
    let m = match kind {
        KIND_HEADER_REQ => {
            let after = r.h32()?; let max_headers = r.u32()?;
            if max_headers == 0 || max_headers > lim.max_headers { return Err(CodecError::Invalid("max_headers")); }
            RecoveryMsg::HeaderReq { request_id, after, max_headers }
        }
        KIND_HEADER_RESP => {
            let status = r.u8()?; let after = r.h32()?;
            let body = match status {
                0 => {
                    let count = r.u32()?;
                    if count == 0 { return Err(CodecError::Invalid("OK with no headers")); }
                    if count > lim.max_headers { return Err(CodecError::Invalid("header count")); }
                    let hmax = lim.header_max().ok_or(CodecError::Invalid("header size"))?;
                    let mut headers = Vec::new();
                    for _ in 0..count {
                        let n = r.u32()? as usize;
                        if n as u64 > hmax { return Err(CodecError::TooLarge { len: n as u64, max: hmax }); }
                        headers.push(decode_header(r.take(n)?).map_err(|_| CodecError::Malformed("header"))?);
                    }
                    let final_qc = match r.u8()? {
                        0 => None,
                        1 => { let n = r.u32()? as usize; let qmax = lim.qc_max().ok_or(CodecError::Invalid("qc size"))?; if n as u64 > qmax { return Err(CodecError::TooLarge { len: n as u64, max: qmax }); }
                               Some(Cert::decode(r.take(n)?).map_err(|_| CodecError::Malformed("final certificate"))?) }
                        _ => return Err(CodecError::Malformed("option flag")),
                    };
                    HeaderBody::Ok { headers, final_qc, tip_height: r.u64()? }
                }
                1 => HeaderBody::NotFound,
                2 => HeaderBody::TooLarge { needed_bytes: r.u64()?, next_height: r.u64()? },
                3 => HeaderBody::Busy { retry_after_ms: r.u32()? },
                4 => HeaderBody::Unavailable,
                5 => HeaderBody::AtTip { tip_height: r.u64()? },
                _ => return Err(CodecError::Malformed("status")),
            };
            RecoveryMsg::HeaderResp { request_id, after, body }
        }
        KIND_MANIFEST_REQ => RecoveryMsg::ManifestReq { request_id, cref: r.cref()? },
        KIND_MANIFEST_RESP => {
            let status = r.u8()?; let cref = r.cref()?;
            let body = match status {
                0 => {
                    let format_version = r.u16()?; let snapshot_id = r.h32()?; let total_bytes = r.u64()?; let chunk_size = r.u32()?; let chunk_count = r.u32()?;
                    if chunk_count == 0 || chunk_count > lim.max_chunk_count { return Err(CodecError::Invalid("chunk count")); }
                    if (chunk_count as u64) * 32 > r.left() as u64 { return Err(CodecError::Malformed("truncated chunk hashes")); }
                    let mut chunk_hashes = Vec::new();
                    for _ in 0..chunk_count { chunk_hashes.push(r.h32()?); }
                    let m = Manifest { format_version, snapshot_id, total_bytes, chunk_size, chunk_count, chunk_hashes };
                    m.validate(lim)?;
                    ManifestBody::Ok(m)
                }
                1 => ManifestBody::NotFound,
                2 => ManifestBody::TooLarge { needed_bytes: r.u64()? },
                3 => ManifestBody::Busy { retry_after_ms: r.u32()? },
                4 => ManifestBody::Unavailable,
                _ => return Err(CodecError::Malformed("status")),
            };
            RecoveryMsg::ManifestResp { request_id, cref, body }
        }
        KIND_CHUNK_REQ => RecoveryMsg::ChunkReq { request_id, snapshot_id: r.h32()?, index: r.u32()? },
        KIND_CHUNK_RESP => {
            let status = r.u8()?; let snapshot_id = r.h32()?; let index = r.u32()?;
            let body = match status {
                0 => { let n = r.u32()?; if n == 0 || n > lim.max_chunk_size { return Err(CodecError::Invalid("chunk length")); } ChunkBody::Ok(r.take(n as usize)?.to_vec()) }
                1 => ChunkBody::NotFound,
                3 => ChunkBody::Busy { retry_after_ms: r.u32()? },
                4 => ChunkBody::Unavailable,
                _ => return Err(CodecError::Malformed("status")),
            };
            RecoveryMsg::ChunkResp { request_id, snapshot_id, index, body }
        }
        _ => return Err(CodecError::UnknownKind(kind)),
    };
    if r.left() != 0 { return Err(CodecError::Malformed("trailing bytes")); }
    Ok(m)
}
