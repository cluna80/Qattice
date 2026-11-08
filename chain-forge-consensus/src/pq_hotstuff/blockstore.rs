//! Persistent block storage and recovery. Blocks, commit markers and the highest QC / TC are small files, each replaced atomically
//! (temporary file, `fsync`, rename, directory `fsync`) through the same [`Storage`] abstraction the safety store uses. Every file
//! carries a magic, a version, its kind and a SHA3-256 checksum. This store holds NOTHING that signing safety depends on (that is the
//! safety store's job: the exact signed messages and the trusted counter); it holds the data needed to rebuild the block tree and the
//! committed history after a restart, and the engine re-validates all of it ([`super::engine::Engine::restore`]).
//!
//! Failure policy: a damaged or torn UNCOMMITTED block is dropped (sync can fetch it again). A damaged commit marker, or a gap in the
//! committed heights, is refused: committed history is never silently shortened.
use sha3::{Digest, Sha3_256};

use super::certs::{Block, BlockId, Cert, Tc};
use super::engine::Output;
use super::netmsg::{decode_block, encode_block};
use super::safety::{Storage, StorageError};

pub const STORE_MAGIC: &[u8] = b"CFH1|store|";
pub const STORE_VERSION: u16 = 1;
const K_BLOCK: u8 = b'B';
const K_COMMIT: u8 = b'C';
const K_HQC: u8 = b'Q';
const K_HTC: u8 = b'T';

/// A [`Storage`] that can also list its files (needed to find the blocks and commit markers on restart).
pub trait BlockFiles: Storage {
    fn names(&self) -> Result<Vec<String>, StorageError>;
}

impl BlockFiles for super::safety::FsStorage {
    fn names(&self) -> Result<Vec<String>, StorageError> { self.list_names() }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("storage: {0}")]
    Storage(String),
    #[error("a commit marker is damaged (height {0}); committed history cannot be trusted")]
    CommittedMarkerDamaged(u64),
    #[error("committed history has a gap: no marker for height {0}")]
    CommittedHistoryGap(u64),
}
impl From<StorageError> for StoreError { fn from(e: StorageError) -> Self { StoreError::Storage(e.0) } }

/// Everything found on disk, ready for [`super::engine::Engine::restore`].
#[derive(Debug, Clone, Default)]
pub struct Loaded {
    pub blocks: Vec<Block>,
    /// Commit markers `(height, id)`, contiguous from height 1.
    pub committed: Vec<(u64, BlockId)>,
    pub high_qc: Option<Cert>,
    pub high_tc: Option<Tc>,
    /// Block files that failed their checksum or decoding and were ignored.
    pub damaged_blocks: usize,
    /// `high_qc` / `high_tc` files that were damaged and ignored.
    pub damaged_hints: usize,
}

pub struct BlockStore<S: BlockFiles> { s: S }

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn seal(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut o = STORE_MAGIC.to_vec();
    o.extend_from_slice(&STORE_VERSION.to_be_bytes());
    o.push(kind);
    o.extend_from_slice(body);
    let sum = Sha3_256::digest(&o);
    o.extend_from_slice(&sum);
    o
}
/// The body of a sealed file of the expected kind, or `None` if anything about it is wrong.
fn unseal(bytes: &[u8], kind: u8) -> Option<&[u8]> {
    let head = STORE_MAGIC.len() + 2 + 1;
    if bytes.len() < head + 32 || &bytes[..STORE_MAGIC.len()] != STORE_MAGIC { return None; }
    if u16::from_be_bytes([bytes[STORE_MAGIC.len()], bytes[STORE_MAGIC.len() + 1]]) != STORE_VERSION || bytes[head - 1] != kind { return None; }
    let (body, sum) = bytes.split_at(bytes.len() - 32);
    if Sha3_256::digest(body)[..] != *sum { return None; }
    Some(&body[head..])
}

impl<S: BlockFiles> BlockStore<S> {
    pub fn new(s: S) -> Self { BlockStore { s } }
    pub fn into_inner(self) -> S { self.s }
    pub fn storage(&self) -> &S { &self.s }

    fn put(&mut self, name: &str, kind: u8, body: &[u8]) -> Result<(), StoreError> {
        let tmp = format!("{name}.tmp");
        let bytes = seal(kind, body);
        self.s.write_tmp(&tmp, &bytes)?;
        self.s.sync_file(&tmp)?;
        self.s.rename(&tmp, name)?;
        self.s.sync_dir()?;
        Ok(())
    }

    pub fn put_block(&mut self, id: &BlockId, b: &Block) -> Result<(), StoreError> { self.put(&format!("blk-{}", hex(id)), K_BLOCK, &encode_block(b)) }
    pub fn put_commit(&mut self, height: u64, id: &BlockId) -> Result<(), StoreError> {
        let mut body = height.to_be_bytes().to_vec();
        body.extend_from_slice(id);
        self.put(&format!("cmt-{height:016x}"), K_COMMIT, &body)
    }
    pub fn put_high_qc(&mut self, c: &Cert) -> Result<(), StoreError> { self.put("hqc", K_HQC, &c.encode()) }
    pub fn put_high_tc(&mut self, t: &Tc) -> Result<(), StoreError> { self.put("htc", K_HTC, &t.encode()) }

    /// Apply a durable-state request from the engine; every other output is ignored. The driver calls this IN ORDER, before it
    /// sends or executes anything that follows the request in the same output list.
    pub fn apply(&mut self, o: &Output, id_of: &dyn Fn(&Block) -> Option<BlockId>) -> Result<(), StoreError> {
        match o {
            Output::PersistBlock(b) => { if let Some(id) = id_of(b) { self.put_block(&id, b)?; } Ok(()) }
            Output::PersistCommit { height, id } => self.put_commit(*height, id),
            Output::PersistHighQc(c) => self.put_high_qc(c),
            Output::PersistHighTc(t) => self.put_high_tc(t),
            _ => Ok(()),
        }
    }

    /// Read everything. Leftover `.tmp` files are ignored.
    pub fn load(&self) -> Result<Loaded, StoreError> {
        let mut out = Loaded::default();
        let mut markers: Vec<(u64, Option<BlockId>)> = vec![];
        for name in self.s.names()? {
            if name.ends_with(".tmp") { continue; }
            let Some(bytes) = self.s.read(&name)? else { continue };
            if name.starts_with("blk-") {
                match unseal(&bytes, K_BLOCK).and_then(|b| decode_block(b).ok()) {
                    Some(b) => out.blocks.push(b),
                    None => out.damaged_blocks += 1,
                }
            } else if let Some(h) = name.strip_prefix("cmt-") {
                let Ok(height) = u64::from_str_radix(h, 16) else { continue };
                let parsed = unseal(&bytes, K_COMMIT).filter(|b| b.len() == 40 && u64::from_be_bytes(b[..8].try_into().unwrap()) == height)
                    .map(|b| <BlockId>::try_from(&b[8..]).unwrap());
                markers.push((height, parsed));
            } else if name == "hqc" {
                match unseal(&bytes, K_HQC).and_then(|b| Cert::decode(b).ok()) { Some(c) => out.high_qc = Some(c), None => out.damaged_hints += 1 }
            } else if name == "htc" {
                match unseal(&bytes, K_HTC).and_then(|b| Tc::decode(b).ok()) { Some(t) => out.high_tc = Some(t), None => out.damaged_hints += 1 }
            }
        }
        markers.sort_by_key(|m| m.0);
        for (i, (height, id)) in markers.iter().enumerate() {
            let expected = i as u64 + 1;
            if *height != expected { return Err(StoreError::CommittedHistoryGap(expected)); }
            match id { Some(id) => out.committed.push((*height, *id)), None => return Err(StoreError::CommittedMarkerDamaged(*height)) }
        }
        Ok(out)
    }
}
