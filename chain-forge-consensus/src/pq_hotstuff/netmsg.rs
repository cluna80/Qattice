//! Network message envelope for PQ-HotStuff-2 and the message-size limits derived from the proposal, QC and TC encodings.
//! **DRAFT layout (unapproved; the block wire layout is open item U18)**; payloads are `devnet-interim`.
//!
//! Every message is `tag "CFH1|net|" || version u16 || kind u8 || body`. A decoder checks the total length against the limit for
//! the message kind BEFORE it parses the body, and every inner length and count against the remaining input before it allocates.
//!
//! The limits are DERIVED, not defaulted ([`MessageLimits::derive`]): the repository defines no PQ-HotStuff-2 message-size limit, so
//! the transport path refuses to start until the owner has set `PqLimits::max_message_bytes` at or above the derived minimum.
use super::certs::{Block, Cert, Tc, ALG, MAX_CERT_VALIDATORS};
use super::engine::{Msg, TimeoutMsg, VoteMsg};
use super::header::PayloadFreeBlock;
use super::limits::{qc_max_bytes, tc_max_bytes, PqLimits};
use super::sync::{SyncRequest, SyncResponse};
use super::wire::{TimeoutMessage, VoteMessage, MAX_NAME_LEN, MLDSA65_SIGNATURE_LEN};

pub const TAG_NET: &[u8] = b"CFH1|net|";
pub const NET_VERSION: u16 = 1;
const HEADER: u64 = TAG_NET.len() as u64 + 2 + 1;
const K_PROPOSAL: u8 = 1;
const K_VOTE: u8 = 2;
const K_TIMEOUT: u8 = 3;
const K_TC: u8 = 4;
const K_SYNC_REQ: u8 = 5;
const K_SYNC_RESP: u8 = 6;
/// Owner-locked transport limit for PQ-HotStuff-2 messages: exactly 8 MiB. It is applied through `PqLimits::max_message_bytes`;
/// [`MessageLimits::derive`] still refuses to start when a chain's parameters need more (e.g. a 1,000-validator proposal carrying a TC
/// is about 9.96 MB even with an empty payload), so the constant can never silently under-size a message.
pub const MAX_MESSAGE_SIZE: u64 = 8_388_608;

/// Read a message from a stream incrementally, never allocating from a length the sender reported and dropping the stream as soon as
/// more than `max` bytes have arrived (the transport must close the connection on `TooLarge`). Counting uses checked arithmetic.
pub fn read_bounded<R: std::io::Read>(r: &mut R, max: u64) -> Result<Vec<u8>, NetError> {
    let mut out = Vec::new();
    let mut total: u64 = 0;
    let mut chunk = [0u8; 8192];
    loop {
        let n = match r.read(&mut chunk) { Ok(0) => return Ok(out), Ok(n) => n, Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue, Err(_) => return Err(NetError::Malformed("read error")) };
        total = total.checked_add(n as u64).ok_or(NetError::TooLarge { len: usize::MAX, max })?;
        if total > max { return Err(NetError::TooLarge { len: usize::try_from(total).unwrap_or(usize::MAX), max }); }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// Most blocks one sync response may carry, whatever the message limit allows.
pub const SYNC_BLOCKS_CEILING: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetMsg { Consensus(Msg), SyncRequest(SyncRequest), SyncResponse(SyncResponse) }

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("message of {len} bytes exceeds the limit {max} for its kind")]
    TooLarge { len: usize, max: u64 },
    #[error("malformed message: {0}")]
    Malformed(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetLimitError {
    #[error("max_message_bytes is not set; the owner must set it at or above {needed} (derived minimum) before the transport path runs")]
    LimitUnset { needed: u64 },
    #[error("max_message_bytes {limit} is below the derived minimum {needed}")]
    BelowMinimum { limit: u64, needed: u64 },
    #[error("a size computation overflowed")]
    Overflow,
    #[error("invalid parameters: {0}")]
    BadParams(&'static str),
}

/// Maximum encoded size of each message kind for a validator set of at most `n`, and the transport limit they fit under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageLimits {
    pub vote: u64,
    pub timeout: u64,
    pub tc: u64,
    pub proposal: u64,
    pub sync_request: u64,
    pub sync_response: u64,
    pub max_sync_blocks: usize,
    /// The owner-configured transport limit (every kind above is at most this).
    pub transport: u64,
}

fn ck(a: Option<u64>) -> Result<u64, NetLimitError> { a.ok_or(NetLimitError::Overflow) }

/// Largest encoded block: a QC and a TC (each with every signer), the payload limit, a proposer id and a signature.
fn block_max(limits: &PqLimits, n: usize) -> Result<u64, NetLimitError> {
    let qc = ck(qc_max_bytes(n))?;
    let tc = ck(tc_max_bytes(n, n))?;
    let sig = 4 + MLDSA65_SIGNATURE_LEN as u64;
    let payload = limits.max_block_payload_bytes.checked_add(4).ok_or(NetLimitError::Overflow)?;
    let parts = [8u64 + 8 + 8 + 32, 4 + qc, 1 + 4 + tc, payload, 4, sig];
    parts.iter().try_fold(0u64, |acc, p| acc.checked_add(*p)).ok_or(NetLimitError::Overflow)
}

impl MessageLimits {
    fn sizes(limits: &PqLimits, n: usize, chain_id_len: usize, sync_blocks: usize) -> Result<[u64; 6], NetLimitError> {
        if n == 0 || n > MAX_CERT_VALIDATORS { return Err(NetLimitError::BadParams("validator count")); }
        if chain_id_len == 0 || chain_id_len > MAX_NAME_LEN { return Err(NetLimitError::BadParams("chain id length")); }
        if sync_blocks == 0 || sync_blocks > SYNC_BLOCKS_CEILING { return Err(NetLimitError::BadParams("sync blocks")); }
        let chain = "x".repeat(chain_id_len);
        let vote_enc = VoteMessage { alg_id: ALG, chain_id: chain.clone(), epoch: u64::MAX, round: u64::MAX, block_id: [0; 32], parent_id: [0; 32], parent_round: u64::MAX }
            .encode().map_err(|_| NetLimitError::BadParams("vote"))?.len() as u64;
        let to_enc = TimeoutMessage { alg_id: ALG, chain_id: chain, epoch: u64::MAX, round: u64::MAX, high_qc_round: u64::MAX }
            .encode().map_err(|_| NetLimitError::BadParams("timeout"))?.len() as u64;
        let sig = 4 + MLDSA65_SIGNATURE_LEN as u64;
        let qc = ck(qc_max_bytes(n))?;
        let tc = ck(tc_max_bytes(n, n))?;
        let blk = block_max(limits, n)?;
        let add = |a: u64, b: u64| a.checked_add(b).ok_or(NetLimitError::Overflow);
        let vote = add(add(HEADER, 4)?, add(add(4, vote_enc)?, sig)?)?;
        let timeout = add(add(add(HEADER, 4)?, add(add(4, to_enc)?, sig)?)?, add(4, qc)?)?;
        let tcm = add(HEADER, tc)?;
        let proposal = add(HEADER, blk)?;
        let sreq = add(HEADER, 32 + 4)?;
        let per = add(4, blk)?;
        let sresp = add(add(HEADER, 32 + 4)?, per.checked_mul(sync_blocks as u64).ok_or(NetLimitError::Overflow)?)?;
        Ok([vote, timeout, tcm, proposal, sreq, sresp])
    }

    /// The smallest transport limit under which every message kind fits (for the owner to choose from; nothing is applied).
    pub fn minimum_transport_limit(limits: &PqLimits, n: usize, chain_id_len: usize, sync_blocks: usize) -> Result<u64, NetLimitError> {
        Ok(Self::sizes(limits, n, chain_id_len, sync_blocks)?.into_iter().max().unwrap())
    }

    /// The most blocks one sync response can carry under `transport` (at least 1, at most the ceiling), or `None` if not even one fits.
    pub fn max_sync_blocks_under(limits: &PqLimits, n: usize, chain_id_len: usize, transport: u64) -> Option<usize> {
        (1..=SYNC_BLOCKS_CEILING).rev().find(|k| Self::sizes(limits, n, chain_id_len, *k).map_or(false, |s| s.into_iter().max().unwrap() <= transport))
    }

    /// Derive the per-kind limits for a transport limit the OWNER configured. With no configured limit this is an error carrying the
    /// derived minimum: the transport path never runs on an invented default.
    pub fn derive(limits: &PqLimits, n: usize, chain_id_len: usize, sync_blocks: usize) -> Result<Self, NetLimitError> {
        let s = Self::sizes(limits, n, chain_id_len, sync_blocks)?;
        let needed = *s.iter().max().unwrap();
        let transport = limits.max_message_bytes.ok_or(NetLimitError::LimitUnset { needed })?;
        if transport < needed { return Err(NetLimitError::BelowMinimum { limit: transport, needed }); }
        Ok(MessageLimits { vote: s[0], timeout: s[1], tc: s[2], proposal: s[3], sync_request: s[4], sync_response: s[5], max_sync_blocks: sync_blocks, transport })
    }

    fn for_kind(&self, k: u8) -> Option<u64> {
        Some(match k { K_PROPOSAL => self.proposal, K_VOTE => self.vote, K_TIMEOUT => self.timeout, K_TC => self.tc, K_SYNC_REQ => self.sync_request, K_SYNC_RESP => self.sync_response, _ => return None })
    }
}

// ---------------------------------------------------------------------------------------------------------------- encoding

fn put_bytes(o: &mut Vec<u8>, b: &[u8]) { o.extend_from_slice(&(b.len() as u32).to_be_bytes()); o.extend_from_slice(b); }

fn put_block(o: &mut Vec<u8>, b: &Block) {
    o.extend_from_slice(&b.epoch.to_be_bytes());
    o.extend_from_slice(&b.round.to_be_bytes());
    o.extend_from_slice(&b.height.to_be_bytes());
    o.extend_from_slice(&b.parent_id);
    put_bytes(o, &b.qc.encode());
    match &b.tc { None => o.push(0), Some(t) => { o.push(1); put_bytes(o, &t.encode()); } }
    put_bytes(o, &b.payload);
    o.extend_from_slice(&(b.proposer as u32).to_be_bytes());
    put_bytes(o, &b.signature);
}

fn put_header(o: &mut Vec<u8>, h: &PayloadFreeBlock) {
    o.extend_from_slice(&h.epoch.to_be_bytes());
    o.extend_from_slice(&h.round.to_be_bytes());
    o.extend_from_slice(&h.height.to_be_bytes());
    o.extend_from_slice(&h.parent_id);
    put_bytes(o, &h.qc.encode());
    match &h.tc { None => o.push(0), Some(t) => { o.push(1); put_bytes(o, &t.encode()); } }
    o.extend_from_slice(&h.payload_hash);
    o.extend_from_slice(&(h.proposer as u32).to_be_bytes());
    put_bytes(o, &h.signature);
}

/// DRAFT canonical encoding of a payload-free header: the block layout with the length-prefixed payload replaced by its 32-byte hash. Not part of
/// the network envelope yet (message kinds and bounds for header sync are an open decision, S4).
pub fn encode_header(h: &PayloadFreeBlock) -> Vec<u8> { let mut o = vec![]; put_header(&mut o, h); o }

pub fn decode_header(b: &[u8]) -> Result<PayloadFreeBlock, NetError> {
    let mut r = Rd { b, p: 0 };
    let (epoch, round, height, parent_id) = (r.u64()?, r.u64()?, r.u64()?, r.h32()?);
    let qc = Cert::decode(r.bytes()?).map_err(|_| NetError::Malformed("parent certificate"))?;
    let tc = match r.u8()? {
        0 => None,
        1 => Some(Tc::decode(r.bytes()?).map_err(|_| NetError::Malformed("timeout certificate"))?),
        _ => return Err(NetError::Malformed("option flag")),
    };
    let payload_hash = r.h32()?;
    let proposer = r.u32()? as usize;
    let signature = r.bytes()?.to_vec();
    if signature.len() != MLDSA65_SIGNATURE_LEN { return Err(NetError::Malformed("signature length")); }
    if r.left() != 0 { return Err(NetError::Malformed("trailing bytes")); }
    Ok(PayloadFreeBlock { epoch, round, height, parent_id, qc, tc, payload_hash, proposer, signature })
}

/// The canonical encoding of a block (used by the network envelope and by the block store).
pub fn encode_block(b: &Block) -> Vec<u8> { let mut o = vec![]; put_block(&mut o, b); o }

pub fn decode_block(b: &[u8]) -> Result<Block, NetError> {
    let mut r = Rd { b, p: 0 };
    let blk = r.block()?;
    if r.left() != 0 { return Err(NetError::Malformed("trailing bytes")); }
    Ok(blk)
}

pub fn encode(m: &NetMsg) -> Vec<u8> {
    let mut o = TAG_NET.to_vec();
    o.extend_from_slice(&NET_VERSION.to_be_bytes());
    match m {
        NetMsg::Consensus(Msg::Proposal(b)) => { o.push(K_PROPOSAL); put_block(&mut o, b); }
        NetMsg::Consensus(Msg::Vote(v)) => {
            o.push(K_VOTE);
            o.extend_from_slice(&(v.voter as u32).to_be_bytes());
            put_bytes(&mut o, &v.msg.encode().expect("a vote message built by the engine encodes"));
            put_bytes(&mut o, &v.signature);
        }
        NetMsg::Consensus(Msg::Timeout(t)) => {
            o.push(K_TIMEOUT);
            o.extend_from_slice(&(t.voter as u32).to_be_bytes());
            put_bytes(&mut o, &t.msg.encode().expect("a timeout message built by the engine encodes"));
            put_bytes(&mut o, &t.signature);
            put_bytes(&mut o, &t.high_qc.encode());
        }
        NetMsg::Consensus(Msg::Tc(t)) => { o.push(K_TC); o.extend_from_slice(&t.encode()); }
        NetMsg::SyncRequest(r) => { o.push(K_SYNC_REQ); o.extend_from_slice(&r.want); o.extend_from_slice(&r.max_blocks.to_be_bytes()); }
        NetMsg::SyncResponse(r) => {
            o.push(K_SYNC_RESP);
            o.extend_from_slice(&r.want);
            o.extend_from_slice(&(r.blocks.len() as u32).to_be_bytes());
            for b in &r.blocks { put_bytes(&mut o, &encode_block(b)); }
        }
    }
    o
}

struct Rd<'a> { b: &'a [u8], p: usize }
impl<'a> Rd<'a> {
    fn left(&self) -> usize { self.b.len() - self.p }
    fn take(&mut self, n: usize) -> Result<&'a [u8], NetError> {
        if n > self.left() { return Err(NetError::Malformed("truncated")); }
        let s = &self.b[self.p..self.p + n]; self.p += n; Ok(s)
    }
    fn u8(&mut self) -> Result<u8, NetError> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, NetError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, NetError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn h32(&mut self) -> Result<[u8; 32], NetError> { Ok(self.take(32)?.try_into().unwrap()) }
    /// A `u32` length followed by that many bytes; the length is checked against the remaining input before anything is taken.
    fn bytes(&mut self) -> Result<&'a [u8], NetError> { let n = self.u32()? as usize; self.take(n) }
    fn block(&mut self) -> Result<Block, NetError> {
        let (epoch, round, height, parent_id) = (self.u64()?, self.u64()?, self.u64()?, self.h32()?);
        let qc = Cert::decode(self.bytes()?).map_err(|_| NetError::Malformed("parent certificate"))?;
        let tc = match self.u8()? {
            0 => None,
            1 => Some(Tc::decode(self.bytes()?).map_err(|_| NetError::Malformed("timeout certificate"))?),
            _ => return Err(NetError::Malformed("option flag")),
        };
        let payload = self.bytes()?.to_vec();
        let proposer = self.u32()? as usize;
        let signature = self.bytes()?.to_vec();
        if signature.len() != MLDSA65_SIGNATURE_LEN { return Err(NetError::Malformed("signature length")); }
        Ok(Block { epoch, round, height, parent_id, qc, tc, payload, proposer, signature })
    }
}

/// Decode a network message. The length is checked against the limit for the message's kind before the body is parsed.
pub fn decode(b: &[u8], lim: &MessageLimits) -> Result<NetMsg, NetError> {
    if b.len() as u64 > lim.transport { return Err(NetError::TooLarge { len: b.len(), max: lim.transport }); }
    let mut r = Rd { b, p: 0 };
    if r.take(TAG_NET.len())? != TAG_NET { return Err(NetError::Malformed("wrong tag")); }
    if u16::from_be_bytes(r.take(2)?.try_into().unwrap()) != NET_VERSION { return Err(NetError::Malformed("version")); }
    let kind = r.u8()?;
    let max = lim.for_kind(kind).ok_or(NetError::Malformed("unknown kind"))?;
    if b.len() as u64 > max { return Err(NetError::TooLarge { len: b.len(), max }); }
    let m = match kind {
        K_PROPOSAL => NetMsg::Consensus(Msg::Proposal(r.block()?)),
        K_VOTE => {
            let voter = r.u32()? as usize;
            let msg = VoteMessage::decode(r.bytes()?, ALG).map_err(|_| NetError::Malformed("vote message"))?;
            let signature = r.bytes()?.to_vec();
            if signature.len() != MLDSA65_SIGNATURE_LEN { return Err(NetError::Malformed("signature length")); }
            NetMsg::Consensus(Msg::Vote(VoteMsg { voter, msg, signature }))
        }
        K_TIMEOUT => {
            let voter = r.u32()? as usize;
            let msg = TimeoutMessage::decode(r.bytes()?, ALG).map_err(|_| NetError::Malformed("timeout message"))?;
            let signature = r.bytes()?.to_vec();
            if signature.len() != MLDSA65_SIGNATURE_LEN { return Err(NetError::Malformed("signature length")); }
            let high_qc = Cert::decode(r.bytes()?).map_err(|_| NetError::Malformed("high QC"))?;
            NetMsg::Consensus(Msg::Timeout(TimeoutMsg { voter, msg, signature, high_qc }))
        }
        K_TC => { let rest = r.take(r.left())?; NetMsg::Consensus(Msg::Tc(Tc::decode(rest).map_err(|_| NetError::Malformed("timeout certificate"))?)) }
        K_SYNC_REQ => {
            let want = r.h32()?;
            let max_blocks = r.u32()?;
            if max_blocks == 0 || max_blocks as usize > lim.max_sync_blocks { return Err(NetError::Malformed("sync block count")); }
            NetMsg::SyncRequest(SyncRequest { want, max_blocks })
        }
        K_SYNC_RESP => {
            let want = r.h32()?;
            let count = r.u32()? as usize;
            if count == 0 || count > lim.max_sync_blocks { return Err(NetError::Malformed("sync block count")); }
            let mut blocks = Vec::with_capacity(count.min(lim.max_sync_blocks));
            for _ in 0..count { blocks.push(decode_block(r.bytes()?)?); }
            NetMsg::SyncResponse(SyncResponse { want, blocks })
        }
        _ => unreachable!("for_kind accepted the kind"),
    };
    if r.left() != 0 { return Err(NetError::Malformed("trailing bytes")); }
    Ok(m)
}
