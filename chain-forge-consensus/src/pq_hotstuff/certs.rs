//! QC / TC / genesis certificate and block types for PQ-HotStuff-2, with the DRAFT canonical encodings of spec sections 3.4.4,
//! 3.4.5 and 3.4.7 and the validity checks of section 3.5.2. **The layouts are drafts (PR #130, unapproved); they are not a
//! finalized production specification.** The payload is opaque bytes hashed with SHA3-256 and is strictly `devnet-interim`
//! (the canonical payload codec is blocked on U5).
//!
//! Serialization is separate from validity: a decoded certificate is canonical, not valid; `verify_*` decides validity against the
//! verifier's own validator set and chain identity. Cheap structural and power checks run before any signature verification.
use sha3::{Digest, Sha3_256};

use super::safety::{ConsensusVerifier, Kind, CTX_TIMEOUT, CTX_VOTE};
use super::types::{EpochSet, ValidatorEntry};
use super::checkpoint::{is_v3, CheckpointRef};
use super::wire::{AlgId, BlockIdInput, BlockIdInputV3, TimeoutMessage, VoteMessage, HASH_LEN, MAX_NAME_LEN, MLDSA65_SIGNATURE_LEN};

pub type BlockId = [u8; HASH_LEN];

pub const TAG_QC: &[u8] = b"CFH1|qc|";
pub const TAG_TC: &[u8] = b"CFH1|tc|";
pub const TAG_GCERT: &[u8] = b"CFH1|gcert|";
pub const TAG_GBLOCK: &[u8] = b"CFH1|gblock|";
pub const TAG_VALSET: &[u8] = b"CFH1|valset|";
pub const CERT_VERSION: u16 = 1;
pub const ALG: AlgId = AlgId::MLDSA65_FIPS204;
/// Hard decoder ceiling on a bitmap before the epoch is known (spec 3.4.3).
pub const MAX_CERT_VALIDATORS: usize = 1024;
const ENVELOPE_LEN: usize = 2 + 4 + MLDSA65_SIGNATURE_LEN;

pub fn sha3(b: &[u8]) -> [u8; 32] { Sha3_256::digest(b).into() }

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    #[error("malformed encoding: {0}")]
    Malformed(&'static str),
    #[error("certificate invalid: {0}")]
    Invalid(&'static str),
}

// ---------------------------------------------------------------------------------------------------------------- codec

fn put_str(o: &mut Vec<u8>, s: &str) { o.extend_from_slice(&(s.len() as u32).to_be_bytes()); o.extend_from_slice(s.as_bytes()); }

struct Rd<'a> { b: &'a [u8], p: usize }
impl<'a> Rd<'a> {
    fn left(&self) -> usize { self.b.len() - self.p }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CertError> {
        if n > self.left() { return Err(CertError::Malformed("truncated")); }
        let s = &self.b[self.p..self.p + n]; self.p += n; Ok(s)
    }
    fn u16(&mut self) -> Result<u16, CertError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, CertError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, CertError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn h32(&mut self) -> Result<[u8; 32], CertError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn tag(&mut self, t: &[u8]) -> Result<(), CertError> { if self.take(t.len())? == t { Ok(()) } else { Err(CertError::Malformed("wrong tag")) } }
    fn string(&mut self) -> Result<String, CertError> {
        let n = self.u32()? as usize;
        if n == 0 || n > MAX_NAME_LEN { return Err(CertError::Malformed("string length")); }
        let s = self.take(n)?;
        if s.contains(&0) { return Err(CertError::Malformed("NUL in string")); }
        String::from_utf8(s.to_vec()).map_err(|_| CertError::Malformed("not UTF-8"))
    }
    fn bitmap(&mut self) -> Result<Vec<bool>, CertError> {
        let n = self.u32()? as usize;
        if n > MAX_CERT_VALIDATORS { return Err(CertError::Malformed("bitmap above the decoder ceiling")); }
        let bytes = self.take(n / 8 + usize::from(n % 8 != 0))?;
        let bits: Vec<bool> = (0..n).map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0).collect();
        if n % 8 != 0 && bytes[n / 8] & (0xffu8 >> (n % 8)) != 0 { return Err(CertError::Malformed("non-zero bitmap padding")); }
        Ok(bits)
    }
    /// A `list<signature envelope>`: a `u32` count that must equal the number of set bits, then the envelopes.
    fn sigs(&mut self, count: usize) -> Result<Vec<Vec<u8>>, CertError> {
        if self.u32()? as usize != count { return Err(CertError::Malformed("signature count differs from signer count")); }
        let need = count.checked_mul(ENVELOPE_LEN).ok_or(CertError::Malformed("signature count overflow"))?;
        if need > self.left() { return Err(CertError::Malformed("signature count exceeds input")); } // before any allocation
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if self.u16()? != ALG.get() { return Err(CertError::Malformed("alg_id")); }
            if self.u32()? as usize != MLDSA65_SIGNATURE_LEN { return Err(CertError::Malformed("signature length")); }
            out.push(self.take(MLDSA65_SIGNATURE_LEN)?.to_vec());
        }
        Ok(out)
    }
}

fn put_bitmap(o: &mut Vec<u8>, bits: &[bool]) {
    o.extend_from_slice(&(bits.len() as u32).to_be_bytes());
    let mut bytes = vec![0u8; bits.len() / 8 + usize::from(bits.len() % 8 != 0)];
    for (i, b) in bits.iter().enumerate() { if *b { bytes[i / 8] |= 0x80 >> (i % 8); } }
    o.extend_from_slice(&bytes);
}
fn put_sigs(o: &mut Vec<u8>, sigs: &[Vec<u8>]) {
    o.extend_from_slice(&(sigs.len() as u32).to_be_bytes());
    for s in sigs {
        o.extend_from_slice(&ALG.get().to_be_bytes());
        o.extend_from_slice(&(s.len() as u32).to_be_bytes());
        o.extend_from_slice(s);
    }
}
fn popcount(bits: &[bool]) -> usize { bits.iter().filter(|b| **b).count() }

// ---------------------------------------------------------------------------------------------------------------- types

/// QuorumCert v1 (draft 3.4.4): a signature list, one signature per set bit in ascending validator-index order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qc {
    pub epoch: u64,
    pub round: u64,
    pub block_id: BlockId,
    pub parent_id: BlockId,
    pub parent_round: u64,
    pub valset_hash: [u8; 32],
    pub signers: Vec<bool>,
    pub sigs: Vec<Vec<u8>>,
}

/// GenesisCert (draft 3.4.7): a distinct object, valid only by equality with the verifier's own genesis, never a QC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisCert {
    pub protocol_profile: String,
    pub chain_id: String,
    pub genesis_hash: [u8; 32],
    pub valset_hash: [u8; 32],
}

/// A certificate that can certify a parent: a QC, or the genesis certificate for the first block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cert { Genesis(GenesisCert), Qc(Qc) }

/// TimeoutCert v1 (draft 3.4.5): `high_qc_rounds` and `sigs` are aligned with the set bits in ascending index order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tc {
    pub epoch: u64,
    pub round: u64,
    pub valset_hash: [u8; 32],
    pub signers: Vec<bool>,
    pub high_qc_rounds: Vec<u64>,
    pub sigs: Vec<Vec<u8>>,
    pub high_qc: Cert,
}

/// A proposal. `payload` is opaque and `devnet-interim` (hashed with SHA3-256; the canonical payload codec is blocked on U5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub epoch: u64,
    pub round: u64,
    pub height: u64,
    pub parent_id: BlockId,
    pub qc: Cert,
    pub tc: Option<Tc>,
    pub payload: Vec<u8>,
    pub proposer: usize,
    pub signature: Vec<u8>,
    /// Profile v3 only: an optional checkpoint reference, committed to by the block id. Always `None` on profile v2.
    pub checkpoint: Option<CheckpointRef>,
}

impl GenesisCert {
    pub fn block_id(&self) -> BlockId { genesis_block_id(&self.protocol_profile, &self.chain_id, &self.genesis_hash) }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = TAG_GCERT.to_vec();
        o.extend_from_slice(&CERT_VERSION.to_be_bytes());
        o.extend_from_slice(&ALG.get().to_be_bytes());
        put_str(&mut o, &self.protocol_profile);
        put_str(&mut o, &self.chain_id);
        o.extend_from_slice(&self.genesis_hash);
        o.extend_from_slice(&self.valset_hash);
        o
    }
    fn read(r: &mut Rd) -> Result<Self, CertError> {
        r.tag(TAG_GCERT)?;
        if r.u16()? != CERT_VERSION { return Err(CertError::Malformed("version")); }
        if r.u16()? != ALG.get() { return Err(CertError::Malformed("alg_id")); }
        Ok(GenesisCert { protocol_profile: r.string()?, chain_id: r.string()?, genesis_hash: r.h32()?, valset_hash: r.h32()? })
    }
}

/// `genesis_block_id = SHA3-256("CFH1|gblock|" || alg_id || profile || chain_id || genesis_hash)` (draft 3.4.7).
pub fn genesis_block_id(protocol_profile: &str, chain_id: &str, genesis_hash: &[u8; 32]) -> BlockId {
    let mut o = TAG_GBLOCK.to_vec();
    o.extend_from_slice(&ALG.get().to_be_bytes());
    put_str(&mut o, protocol_profile);
    put_str(&mut o, chain_id);
    o.extend_from_slice(genesis_hash);
    sha3(&o)
}

impl Qc {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = TAG_QC.to_vec();
        o.extend_from_slice(&CERT_VERSION.to_be_bytes());
        o.extend_from_slice(&ALG.get().to_be_bytes());
        o.extend_from_slice(&self.epoch.to_be_bytes());
        o.extend_from_slice(&self.round.to_be_bytes());
        o.extend_from_slice(&self.block_id);
        o.extend_from_slice(&self.parent_id);
        o.extend_from_slice(&self.parent_round.to_be_bytes());
        o.extend_from_slice(&self.valset_hash);
        put_bitmap(&mut o, &self.signers);
        put_sigs(&mut o, &self.sigs);
        o
    }
    fn read(r: &mut Rd) -> Result<Self, CertError> {
        r.tag(TAG_QC)?;
        if r.u16()? != CERT_VERSION { return Err(CertError::Malformed("version")); }
        if r.u16()? != ALG.get() { return Err(CertError::Malformed("alg_id")); }
        let (epoch, round) = (r.u64()?, r.u64()?);
        let (block_id, parent_id, parent_round, valset_hash) = (r.h32()?, r.h32()?, r.u64()?, r.h32()?);
        let signers = r.bitmap()?;
        let sigs = r.sigs(popcount(&signers))?;
        Ok(Qc { epoch, round, block_id, parent_id, parent_round, valset_hash, signers, sigs })
    }
    pub fn decode(b: &[u8]) -> Result<Self, CertError> {
        let mut r = Rd { b, p: 0 };
        let q = Self::read(&mut r)?;
        if r.left() != 0 { return Err(CertError::Malformed("trailing bytes")); }
        Ok(q)
    }
}

impl Cert {
    pub fn round(&self) -> u64 { match self { Cert::Genesis(_) => 0, Cert::Qc(q) => q.round } }
    pub fn block_id(&self) -> BlockId { match self { Cert::Genesis(g) => g.block_id(), Cert::Qc(q) => q.block_id } }
    pub fn encode(&self) -> Vec<u8> { match self { Cert::Genesis(g) => g.encode(), Cert::Qc(q) => q.encode() } }
    pub fn hash(&self) -> [u8; 32] { sha3(&self.encode()) }
    fn read(r: &mut Rd) -> Result<Self, CertError> {
        if r.b[r.p..].starts_with(TAG_QC) { Qc::read(r).map(Cert::Qc) }
        else if r.b[r.p..].starts_with(TAG_GCERT) { GenesisCert::read(r).map(Cert::Genesis) }
        else { Err(CertError::Malformed("unknown certificate tag")) }
    }
    pub fn decode(b: &[u8]) -> Result<Self, CertError> {
        let mut r = Rd { b, p: 0 };
        let c = Self::read(&mut r)?;
        if r.left() != 0 { return Err(CertError::Malformed("trailing bytes")); }
        Ok(c)
    }
}

impl Tc {
    pub fn max_high_qc_round(&self) -> u64 { self.high_qc_rounds.iter().copied().max().unwrap_or(0) }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = TAG_TC.to_vec();
        o.extend_from_slice(&CERT_VERSION.to_be_bytes());
        o.extend_from_slice(&ALG.get().to_be_bytes());
        o.extend_from_slice(&self.epoch.to_be_bytes());
        o.extend_from_slice(&self.round.to_be_bytes());
        o.extend_from_slice(&self.valset_hash);
        put_bitmap(&mut o, &self.signers);
        o.extend_from_slice(&(self.high_qc_rounds.len() as u32).to_be_bytes());
        for r in &self.high_qc_rounds { o.extend_from_slice(&r.to_be_bytes()); }
        put_sigs(&mut o, &self.sigs);
        o.extend_from_slice(&self.high_qc.encode());
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, CertError> {
        let mut r = Rd { b, p: 0 };
        r.tag(TAG_TC)?;
        if r.u16()? != CERT_VERSION { return Err(CertError::Malformed("version")); }
        if r.u16()? != ALG.get() { return Err(CertError::Malformed("alg_id")); }
        let (epoch, round, valset_hash) = (r.u64()?, r.u64()?, r.h32()?);
        let signers = r.bitmap()?;
        let k = popcount(&signers);
        if r.u32()? as usize != k { return Err(CertError::Malformed("round count differs from signer count")); }
        if k.checked_mul(8).ok_or(CertError::Malformed("overflow"))? > r.left() { return Err(CertError::Malformed("round count exceeds input")); }
        let high_qc_rounds = (0..k).map(|_| r.u64()).collect::<Result<Vec<_>, _>>()?;
        let sigs = r.sigs(k)?;
        let high_qc = Cert::read(&mut r)?;
        if r.left() != 0 { return Err(CertError::Malformed("trailing bytes")); }
        Ok(Tc { epoch, round, valset_hash, signers, high_qc_rounds, sigs, high_qc })
    }
    pub fn hash(&self) -> [u8; 32] { sha3(&self.encode()) }
}

// ---------------------------------------------------------------------------------------------------------------- set commitment

impl EpochSet {
    /// `validator_set_hash` (draft 3.4.2): SHA3-256 over tag, version, alg_id, epoch and the entries in canonical order.
    pub fn validator_set_hash(&self) -> [u8; 32] {
        let mut o = TAG_VALSET.to_vec();
        o.extend_from_slice(&CERT_VERSION.to_be_bytes());
        o.extend_from_slice(&ALG.get().to_be_bytes());
        o.extend_from_slice(&self.epoch().to_be_bytes());
        o.extend_from_slice(&(self.len() as u32).to_be_bytes());
        for ValidatorEntry { address, public_key, power } in self.entries() {
            put_str(&mut o, address);
            o.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
            o.extend_from_slice(public_key);
            o.extend_from_slice(&power.to_be_bytes());
        }
        sha3(&o)
    }
}

// ---------------------------------------------------------------------------------------------------------------- validity

/// The verifier's own state: certificates are checked against this, never against fields the sender supplies.
pub struct VerifyCtx<'a> {
    pub chain_id: &'a str,
    pub set: &'a EpochSet,
    pub valset_hash: [u8; 32],
    pub genesis: &'a GenesisCert,
    pub verifier: &'a dyn ConsensusVerifier,
}

fn signer_indices(bits: &[bool]) -> Vec<usize> { bits.iter().enumerate().filter(|(_, b)| **b).map(|(i, _)| i).collect() }

/// Steps 1 to 4 of draft 3.5.2 for the parts shared by QC and TC; returns the signer indices. No signature is verified here.
fn check_header(ctx: &VerifyCtx, epoch: u64, round: u64, vh: &[u8; 32], bits: &[bool], nsigs: usize) -> Result<Vec<usize>, CertError> {
    if epoch != ctx.set.epoch() { return Err(CertError::Invalid("unknown epoch")); }
    if &ctx.valset_hash != vh { return Err(CertError::Invalid("validator_set_hash differs from the local commitment")); }
    if bits.len() != ctx.set.len() { return Err(CertError::Invalid("bitmap length differs from the validator count")); }
    if round == 0 { return Err(CertError::Invalid("round 0 is reserved for the genesis certificate")); }
    let idx = signer_indices(bits);
    if idx.len() != nsigs { return Err(CertError::Invalid("signature count differs from signer count")); }
    let power = ctx.set.signer_power(&idx).map_err(|_| CertError::Invalid("bad signer"))?;
    if !ctx.set.is_quorum(power) { return Err(CertError::Invalid("signer power is below the quorum")); }
    Ok(idx)
}

pub fn verify_qc(ctx: &VerifyCtx, q: &Qc) -> Result<(), CertError> {
    let idx = check_header(ctx, q.epoch, q.round, &q.valset_hash, &q.signers, q.sigs.len())?;
    if q.block_id == ctx.genesis.block_id() { return Err(CertError::Invalid("the genesis block is certified by derivation only")); }
    if q.parent_round >= q.round { return Err(CertError::Invalid("parent round is not below the round")); }
    let msg = VoteMessage { alg_id: ALG, chain_id: ctx.chain_id.to_string(), epoch: q.epoch, round: q.round, block_id: q.block_id, parent_id: q.parent_id, parent_round: q.parent_round }
        .encode().map_err(|_| CertError::Invalid("vote message"))?;
    for (j, i) in idx.iter().enumerate() {
        if q.sigs[j].len() != MLDSA65_SIGNATURE_LEN || !ctx.verifier.verify(&ctx.set.entries()[*i].public_key, CTX_VOTE, &msg, &q.sigs[j]) {
            return Err(CertError::Invalid("a vote signature does not verify"));
        }
    }
    Ok(())
}

pub fn verify_cert(ctx: &VerifyCtx, c: &Cert) -> Result<(), CertError> {
    match c {
        Cert::Qc(q) => verify_qc(ctx, q),
        Cert::Genesis(g) => if g == ctx.genesis { Ok(()) } else { Err(CertError::Invalid("genesis certificate differs from the local genesis")) },
    }
}

pub fn verify_tc(ctx: &VerifyCtx, t: &Tc) -> Result<(), CertError> {
    let idx = check_header(ctx, t.epoch, t.round, &t.valset_hash, &t.signers, t.sigs.len())?;
    if t.high_qc_rounds.len() != idx.len() { return Err(CertError::Invalid("round count differs from signer count")); }
    let max = t.max_high_qc_round();
    if t.high_qc.round() != max { return Err(CertError::Invalid("nested certificate round differs from the signed maximum")); }
    if t.high_qc.round() >= t.round { return Err(CertError::Invalid("nested certificate round is not below the TC round")); }
    if matches!(t.high_qc, Cert::Genesis(_)) && max != 0 { return Err(CertError::Invalid("genesis certificate with a non-zero round")); }
    for (j, i) in idx.iter().enumerate() {
        let msg = TimeoutMessage { alg_id: ALG, chain_id: ctx.chain_id.to_string(), epoch: t.epoch, round: t.round, high_qc_round: t.high_qc_rounds[j] }
            .encode().map_err(|_| CertError::Invalid("timeout message"))?;
        if t.sigs[j].len() != MLDSA65_SIGNATURE_LEN || !ctx.verifier.verify(&ctx.set.entries()[*i].public_key, CTX_TIMEOUT, &msg, &t.sigs[j]) {
            return Err(CertError::Invalid("a timeout signature does not verify"));
        }
    }
    verify_cert(ctx, &t.high_qc)
}

// ---------------------------------------------------------------------------------------------------------------- block identity

/// What `block_id` needs besides the block: the chain identity and the proposer's address.
pub struct IdCtx<'a> { pub protocol_profile: &'a str, pub chain_id: &'a str, pub set: &'a EpochSet }

/// `block_id` (spec 3.2 rule 6): commits to every consensus-critical field, the payload through `SHA3-256(payload)`, the parent
/// certificate through `H(qc)` and the timeout certificate through `H(tc)`.
pub fn block_id_of(b: &Block, ctx: &IdCtx) -> Result<BlockId, CertError> {
    let proposer = ctx.set.entries().get(b.proposer).ok_or(CertError::Invalid("proposer index"))?.address.clone();
    id_from_parts(ctx, b.epoch, b.round, b.height, b.parent_id, sha3(&b.payload), b.qc.hash(), b.tc.as_ref().map(Tc::hash), proposer, b.checkpoint.as_ref())
}

/// The block id from its parts. Profile v2: the original preimage, byte for byte (a reference there is invalid). Profile v3: the domain-separated preimage that also
/// commits to the optional checkpoint reference. Shared by [`block_id_of`] and the payload-free header form so the two cannot diverge.
#[allow(clippy::too_many_arguments)]
pub(crate) fn id_from_parts(ctx: &IdCtx, epoch: u64, round: u64, height: u64, parent_id: BlockId, payload_hash: [u8; 32], qc_hash: [u8; 32], tc_hash: Option<[u8; 32]>, proposer: String, checkpoint: Option<&CheckpointRef>) -> Result<BlockId, CertError> {
    let base = BlockIdInput { alg_id: ALG, protocol_profile: ctx.protocol_profile.to_string(), chain_id: ctx.chain_id.to_string(), epoch, round, height, parent_id, payload_hash, qc_hash, tc_hash, proposer };
    if is_v3(ctx.protocol_profile) {
        BlockIdInputV3 { base, checkpoint_hash: checkpoint.map(CheckpointRef::hash) }.block_id().map_err(|_| CertError::Invalid("block id input"))
    } else {
        if checkpoint.is_some() { return Err(CertError::Invalid("checkpoint reference on a profile without checkpoints")); }
        base.block_id().map_err(|_| CertError::Invalid("block id input"))
    }
}

/// Kind of the proposer's signature context (re-exported for callers building blocks).
pub fn proposal_context() -> &'static [u8] { Kind::Proposal.context() }
