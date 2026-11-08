//! Execution handoff between PQ-HotStuff-2 finality and an application (the executor).
//!
//! **What this is.** The consensus engine emits each finalized block exactly once, in height order. The node driver hands those blocks to
//! an [`Executor`]. The handoff is defined by four things:
//! * **Finalized block identity**: a block is handed over as a [`Committed`] (`id`, `round`, `height`, `payload`).
//! * **Durable execution cursor**: [`ExecCursor`] `(height, block id, application state digest)` is the last block whose effects are durable.
//!   The executor makes the effects AND the new cursor durable in ONE atomic step.
//! * **Acknowledgement**: `apply` returning `Ok` IS the acknowledgement; until then the block is not executed as far as consensus knows.
//! * **Replay**: on every start the driver reads the cursor and hands over `committed_after(cursor.height)`, so a block is applied exactly
//!   once, whether the crash was before the effects, between them and the driver noticing, or after.
//!
//! The executor refuses anything but the next height (`OutOfOrder`), and the driver refuses to start if the cursor does not match the
//! committed history it recovered (`Diverged`/`ExecutorAhead`): it fails closed instead of resetting either side.
//!
//! **What this is NOT.** [`InterimApp`] is a DEVNET-INTERIM application: it hash-chains the opaque payloads. It is not transaction execution.
//! The existing `chain-forge-execution::Executor` consumes `Transaction`s against a `StateStore`; it cannot run on an opaque payload until the
//! canonical payload codec (open item U5) exists, so the real adapter is blocked on U5 and tests here must not be presented as transaction-
//! execution validation.
use sha3::{Digest, Sha3_256};

use super::certs::BlockId;
use super::engine::Committed;
use super::safety::{Storage, StorageError};

/// The last block whose effects are durable. Height 0 is "nothing executed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecCursor {
    pub height: u64,
    pub block_id: BlockId,
    pub state_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecError {
    #[error("out of order: expected height {expected}, was handed {got}")]
    OutOfOrder { expected: u64, got: u64 },
    #[error("executor storage: {0}")]
    Storage(String),
    #[error("executor state is damaged ({0}); refusing to start from scratch")]
    Corrupt(&'static str),
    #[error("executor state belongs to another chain (genesis hash differs)")]
    ForeignChain,
}
impl From<StorageError> for ExecError { fn from(e: StorageError) -> Self { ExecError::Storage(e.0) } }

/// The application side of the handoff. `apply` must make the block's effects and the new cursor durable atomically before it returns `Ok`.
pub trait Executor {
    fn cursor(&self) -> ExecCursor;
    /// Apply the NEXT finalized block (height == cursor.height + 1). Anything else is `OutOfOrder` and changes nothing. An `Err` other than
    /// `OutOfOrder` leaves the on-disk state either entirely old or entirely new; the caller must stop and reopen (replay settles which).
    fn apply(&mut self, b: &Committed) -> Result<ExecCursor, ExecError>;
}

const TAG: &[u8] = b"CFH1|interim-app|";
const VERSION: u16 = 1;
const FILE: &str = "app-state";
const TMP: &str = "app-state.tmp";
const RECORD_LEN: usize = 17 + 2 + 32 + 8 + 32 + 32 + 32;

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts { h.update(p); }
    h.finalize().into()
}

/// DEVNET-INTERIM application: `state' = SHA3-256(tag || state || block id || SHA3-256(payload))`. A stand-in that lets the handoff, replay and
/// recovery be exercised; it has no accounts, balances or transactions.
pub struct InterimApp<S: Storage> {
    s: S,
    genesis_hash: [u8; 32],
    cur: ExecCursor,
}

impl<S: Storage> InterimApp<S> {
    fn initial(genesis_hash: &[u8; 32]) -> ExecCursor {
        ExecCursor { height: 0, block_id: [0; 32], state_digest: sha3(&[b"CFH1|interim-app|genesis|", genesis_hash]) }
    }

    /// Open the durable state. No file means a fresh application. A file that fails its checksum, has the wrong shape or names another chain is
    /// an error: it is NEVER treated as fresh, since re-executing from height 1 on top of lost state could repeat effects.
    pub fn open(s: S, genesis_hash: [u8; 32]) -> Result<Self, ExecError> {
        let cur = match s.read(FILE)? {
            None => Self::initial(&genesis_hash),
            Some(b) => {
                if b.len() != RECORD_LEN { return Err(ExecError::Corrupt("length")); }
                let (body, sum) = b.split_at(RECORD_LEN - 32);
                if sha3(&[body]) != sum { return Err(ExecError::Corrupt("checksum")); }
                if &body[..17] != TAG || u16::from_be_bytes([body[17], body[18]]) != VERSION { return Err(ExecError::Corrupt("header")); }
                if body[19..51] != genesis_hash { return Err(ExecError::ForeignChain); }
                let height = u64::from_be_bytes(body[51..59].try_into().unwrap());
                let block_id: BlockId = body[59..91].try_into().unwrap();
                let state_digest: [u8; 32] = body[91..123].try_into().unwrap();
                if height == 0 { return Err(ExecError::Corrupt("height zero")); }
                ExecCursor { height, block_id, state_digest }
            }
        };
        Ok(InterimApp { s, genesis_hash, cur })
    }

    pub fn into_inner(self) -> S { self.s }
    pub fn storage(&self) -> &S { &self.s }

    fn seal(&self, c: &ExecCursor) -> Vec<u8> {
        let mut b = Vec::with_capacity(RECORD_LEN);
        b.extend_from_slice(TAG);
        b.extend_from_slice(&VERSION.to_be_bytes());
        b.extend_from_slice(&self.genesis_hash);
        b.extend_from_slice(&c.height.to_be_bytes());
        b.extend_from_slice(&c.block_id);
        b.extend_from_slice(&c.state_digest);
        let sum = sha3(&[&b]);
        b.extend_from_slice(&sum);
        b
    }
}

impl<S: Storage> Executor for InterimApp<S> {
    fn cursor(&self) -> ExecCursor { self.cur }

    fn apply(&mut self, b: &Committed) -> Result<ExecCursor, ExecError> {
        let expected = self.cur.height.checked_add(1).ok_or(ExecError::Corrupt("height overflow"))?;
        if b.height != expected { return Err(ExecError::OutOfOrder { expected, got: b.height }); }
        let next = ExecCursor { height: b.height, block_id: b.id, state_digest: sha3(&[TAG, &self.cur.state_digest, &b.id, &sha3(&[&b.payload])]) };
        let bytes = self.seal(&next);
        // effects and cursor are ONE record, replaced atomically: write, sync, rename, sync the directory
        self.s.write_tmp(TMP, &bytes)?;
        self.s.sync_file(TMP)?;
        self.s.rename(TMP, FILE)?;
        self.s.sync_dir()?;
        self.cur = next;
        Ok(next)
    }
}
