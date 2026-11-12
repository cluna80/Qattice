//! QAT-07: SafetyStore integration for `PqHotStuffEngine`.
//!
//! Provides `EngineSigningContext` — a trait the engine calls to produce durable,
//! write-before-broadcast signatures — and `SafetyStoreSigningContext`, the
//! production implementation backed by a `SafetyStore<S, C>` + `ConsensusSigner`.
//!
//! # Write-before-broadcast guarantee (spec §7, EC-3)
//!
//! Every call to `sign_vote`, `sign_timeout`, or `sign_proposal` on the safety store
//! writes the signature to durable storage and advances the monotonic counter *before*
//! returning the bytes to the caller. The engine must not broadcast a message whose
//! signature bytes it has not yet obtained from this layer.
//!
//! # Restart anti-equivocation (EC-4)
//!
//! On restart the engine calls `EngineSigningContext::restore` to reload the highest
//! vote round (`hvr`) and lock QC round (`hqr`) from the durable record. The engine
//! then calls `set_floors` to restore `locked_qc` and `high_qc` to at least these
//! values. A validator that restarted can never sign a message at or below the round
//! it last signed before the crash.
//!
//! # Epoch transition (EC-6)
//!
//! When `on_commit` is called with a new validator set, the caller must call
//! `advance_epoch` on the signing context. This clears the per-epoch floors and
//! begins a fresh signing record for the new epoch.
//!
//! # What is NOT here yet
//!
//! - P2P broadcast integration (chain-forge-node)
//! - Key rotation (revocation list, next-block revocation — separate milestone)
//! - ML-DSA-only validator admission gate (QAT-08)

use crate::pq_hotstuff::{
    safety::{ConsensusSigner, MonotonicCounter, SafetyStore, Storage},
    wire::{AlgId, BlockSigningMessage, TimeoutMessage, VoteMessage, HASH_LEN},
};

// ── Signing context trait ──────────────────────────────────────────────────────

/// Floor information loaded from the safety store on restart.
#[derive(Debug, Clone, Default)]
pub struct RestoredFloors {
    /// Highest vote round the validator signed before the crash (hvr).
    /// The engine must not advance `high_qc` to a round below this value.
    pub hvr: Option<u64>,
    /// Highest QC round recorded (hqr / lock QC round).
    /// The engine must not unlock below this round.
    pub hqr: Option<u64>,
    /// Epoch at which these floors were recorded.
    pub epoch: u64,
}

/// A signed vote payload ready to put on the wire.
#[derive(Debug, Clone)]
pub struct SignedVote {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    /// True when the store returned the stored copy without re-signing (crash-window resend).
    pub resent: bool,
}

/// A signed timeout payload ready to put on the wire.
#[derive(Debug, Clone)]
pub struct SignedTimeout {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub resent: bool,
}

/// A signed proposal payload ready to put on the wire.
#[derive(Debug, Clone)]
pub struct SignedProposal {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub resent: bool,
}

/// The interface the engine uses to produce durable signatures.
///
/// Callers MUST NOT broadcast a message before `sign_*` returns `Ok`.
/// A returned `Err` means the safety store latched and the validator must halt.
pub trait EngineSigningContext: Send {
    /// Load highest vote round and lock QC round from the durable record.
    fn restore(&self) -> RestoredFloors;

    /// Sign a vote. `block_id` is 32 bytes (SHA3-256 of `BlockIdInput`). `qc_round`
    /// is the round of the QC the voted block carries (raises the hvr floor).
    fn sign_vote(
        &mut self,
        chain_id: &str,
        epoch: u64,
        round: u64,
        block_id: [u8; HASH_LEN],
        parent_id: [u8; HASH_LEN],
        parent_round: u64,
        qc_round: u64,
    ) -> Result<SignedVote, String>;

    /// Sign a timeout. `high_qc_round` is the highest QC round this validator knows.
    fn sign_timeout(
        &mut self,
        chain_id: &str,
        epoch: u64,
        round: u64,
        high_qc_round: u64,
    ) -> Result<SignedTimeout, String>;

    /// Sign a block as proposer. `block_id` is 32 bytes.
    fn sign_proposal(
        &mut self,
        epoch: u64,
        round: u64,
        block_id: [u8; HASH_LEN],
    ) -> Result<SignedProposal, String>;

    /// Write the epoch seal (R2 step 2). `old_epoch` is the epoch being sealed; `seal_round` is QC_child.round (= z+1).
    /// Must be called after the CommitCertificate is durable in the block store and before `advance_epoch_record`.
    fn write_seal(&mut self, old_epoch: u64, seal_round: u64) -> Result<(), String>;

    /// Advance the epoch record (R2 steps 3-4). `set_hash` = SHA3-256 of V_new; `handoff_cert_hash` = SHA3-256 of cert.
    /// Must be called after `write_seal` succeeds.
    fn advance_epoch_record(
        &mut self,
        new_epoch: u64,
        set_hash: [u8; HASH_LEN],
        handoff_cert_hash: [u8; HASH_LEN],
    ) -> Result<(), String>;
}

// ── Production implementation ─────────────────────────────────────────────────

/// Production signing context: a `SafetyStore` + `ConsensusSigner`.
///
/// The signer holds the validator's ML-DSA-65 private key. The store guarantees
/// write-before-broadcast and byte-for-byte retransmission after a crash.
pub struct SafetyStoreSigningContext<S: Storage, C: MonotonicCounter> {
    store: SafetyStore<S, C>,
    signer: Box<dyn ConsensusSigner + Send>,
    epoch: u64,
}

impl<S: Storage, C: MonotonicCounter> SafetyStoreSigningContext<S, C> {
    pub fn new(store: SafetyStore<S, C>, signer: Box<dyn ConsensusSigner + Send>, epoch: u64) -> Self {
        SafetyStoreSigningContext { store, signer, epoch }
    }
}

impl<S: Storage + Send, C: MonotonicCounter + Send> EngineSigningContext for SafetyStoreSigningContext<S, C> {
    fn restore(&self) -> RestoredFloors {
        // SafetyStore exposes the durable record via its current state.
        // `rec()` returns the committed record; floors are `hvr` and `hqr`.
        let rec = self.store.record();
        RestoredFloors {
            hvr: rec.hvr,
            hqr: rec.hqr,
            epoch: rec.epoch,
        }
    }

    fn sign_vote(
        &mut self,
        chain_id: &str,
        epoch: u64,
        round: u64,
        block_id: [u8; HASH_LEN],
        parent_id: [u8; HASH_LEN],
        parent_round: u64,
        qc_round: u64,
    ) -> Result<SignedVote, String> {
        let msg = VoteMessage {
            alg_id: AlgId::MLDSA65_FIPS204,
            chain_id: chain_id.to_owned(),
            epoch,
            round,
            block_id,
            parent_id,
            parent_round,
        };
        self.store.sign_vote(&msg, qc_round, self.signer.as_mut())
            .map(|s| SignedVote { message: s.message, signature: s.envelope.signature, resent: s.resent })
            .map_err(|e| e.to_string())
    }

    fn sign_timeout(
        &mut self,
        chain_id: &str,
        epoch: u64,
        round: u64,
        high_qc_round: u64,
    ) -> Result<SignedTimeout, String> {
        let msg = TimeoutMessage {
            alg_id: AlgId::MLDSA65_FIPS204,
            chain_id: chain_id.to_owned(),
            epoch,
            round,
            high_qc_round,
        };
        self.store.sign_timeout(&msg, self.signer.as_mut())
            .map(|s| SignedTimeout { message: s.message, signature: s.envelope.signature, resent: s.resent })
            .map_err(|e| e.to_string())
    }

    fn sign_proposal(
        &mut self,
        epoch: u64,
        round: u64,
        block_id: [u8; HASH_LEN],
    ) -> Result<SignedProposal, String> {
        let msg = BlockSigningMessage {
            alg_id: AlgId::MLDSA65_FIPS204,
            block_id,
        };
        self.store.sign_proposal(epoch, round, &msg, self.signer.as_mut())
            .map(|s| SignedProposal { message: s.message, signature: s.envelope.signature, resent: s.resent })
            .map_err(|e| e.to_string())
    }

    fn write_seal(&mut self, old_epoch: u64, seal_round: u64) -> Result<(), String> {
        self.store.write_seal(old_epoch, seal_round).map_err(|e| e.to_string())
    }

    fn advance_epoch_record(
        &mut self,
        new_epoch: u64,
        set_hash: [u8; HASH_LEN],
        handoff_cert_hash: [u8; HASH_LEN],
    ) -> Result<(), String> {
        self.store.advance_epoch_record(new_epoch, set_hash, handoff_cert_hash)
            .map_err(|e| e.to_string())?;
        self.epoch = new_epoch;
        Ok(())
    }
}
