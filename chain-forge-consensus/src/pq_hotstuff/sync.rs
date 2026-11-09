//! Block sync (sans-IO). A node that sees a block whose parent it does not have asks a peer for the missing chain; the response is
//! checked structurally here and every block in it is then validated by the engine exactly like a live proposal
//! ([`super::engine::Engine::on_sync_block`]): leader, proposer signature, certificates. Nothing in a response is trusted.
use std::collections::BTreeMap;

use super::certs::{block_id_of, Block, BlockId, IdCtx};

/// Ask for `want` and up to `max_blocks - 1` of its ancestors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequest { pub want: BlockId, pub max_blocks: u32 }

/// The explicit answer to a sync request that reaches BELOW this node's seeded checkpoint: the blocks the requester asked for are not held here. ADVICE ONLY: it
/// proves nothing and is never acted on; it tells the requester why no blocks come, and names the checkpoint the answering node is based on. `recovery_available` says
/// whether this node can offer the authenticated recovery path (checkpoint evidence + state); it is `false` while network snapshot installation is disabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BelowBase { pub want: BlockId, pub base_height: u64, pub base_id: BlockId, pub state_root: [u8; 32], pub recovery_available: bool }

/// The requested block and its ancestors, OLDEST FIRST, parent-linked, ending at `want`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResponse { pub want: BlockId, pub blocks: Vec<Block> }

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    #[error("the response answers a different request")]
    WrongTarget,
    #[error("the response carries no blocks")]
    Empty,
    #[error("the response carries {got} blocks, above the limit {max}")]
    TooManyBlocks { got: usize, max: usize },
    #[error("the blocks are not a parent-linked chain at position {0}")]
    NotLinked(usize),
    #[error("the response does not end at the requested block")]
    WrongEnd,
    #[error("a block cannot be identified")]
    BadBlock,
}

/// Structural check of a response against the request it answers; returns the parent id of the OLDEST block (what to ask for next
/// if the node still lacks it). Block contents (signatures, certificates) are checked by the engine, not here.
pub fn check_response(req: &SyncRequest, resp: &SyncResponse, ids: &IdCtx, max_blocks: usize) -> Result<BlockId, SyncError> {
    if resp.want != req.want { return Err(SyncError::WrongTarget); }
    if resp.blocks.is_empty() { return Err(SyncError::Empty); }
    let cap = (req.max_blocks as usize).min(max_blocks).max(1);
    if resp.blocks.len() > cap { return Err(SyncError::TooManyBlocks { got: resp.blocks.len(), max: cap }); }
    let mut prev: Option<(BlockId, u64)> = None;
    for (i, b) in resp.blocks.iter().enumerate() {
        let id = block_id_of(b, ids).map_err(|_| SyncError::BadBlock)?;
        if let Some((pid, ph)) = prev {
            if b.parent_id != pid || b.height != ph.checked_add(1).ok_or(SyncError::NotLinked(i))? { return Err(SyncError::NotLinked(i)); }
        }
        prev = Some((id, b.height));
    }
    if prev.map(|p| p.0) != Some(req.want) { return Err(SyncError::WrongEnd); }
    Ok(resp.blocks[0].parent_id)
}

/// Tracks outstanding requests so a missing ancestor is asked for once, not once per message that needs it, and so a peer cannot
/// make the node hold an unbounded number of pending requests.
#[derive(Debug, Clone)]
pub struct SyncClient { outstanding: BTreeMap<BlockId, u64>, ttl: u64, max_outstanding: usize }

impl SyncClient {
    pub fn new(ttl: u64, max_outstanding: usize) -> Self { SyncClient { outstanding: BTreeMap::new(), ttl, max_outstanding } }
    /// A request to send now, or `None` if this block is already being fetched (and not yet expired) or the table is full.
    pub fn want(&mut self, id: BlockId, now: u64, max_blocks: u32) -> Option<SyncRequest> {
        self.outstanding.retain(|_, deadline| *deadline > now);
        if self.outstanding.contains_key(&id) || self.outstanding.len() >= self.max_outstanding { return None; }
        self.outstanding.insert(id, now.saturating_add(self.ttl));
        Some(SyncRequest { want: id, max_blocks })
    }
    pub fn complete(&mut self, id: &BlockId) { self.outstanding.remove(id); }
    pub fn pending(&self) -> usize { self.outstanding.len() }
    /// Whether a request for `id` is outstanding (a response to anything else is unsolicited).
    pub fn is_pending(&self, id: &BlockId) -> bool { self.outstanding.contains_key(id) }
}
