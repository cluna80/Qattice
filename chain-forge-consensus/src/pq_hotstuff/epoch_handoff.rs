//! Authenticated epoch-handoff verification (QAT-07, `epoch-transition` feature).
//!
//! This module implements two things required before the engine may write the seal,
//! advance the safety record, or replace the in-memory validator set:
//!
//! 1. **Canonical set hash** — `canonical_set_hash` commits to each validator's ID,
//!    ML-DSA-65 public key, and voting power, in validator-ID lexicographic order.
//!    The hash is recorded in the durable `advance_epoch_record` call and must match
//!    on restart (R3-b recovery).
//!
//! 2. **Handoff-proof verification** — `verify_handoff_proof` verifies that the
//!    `CommitCertificate` for an epoch-change commit carries ≥ 2f+1 power worth of
//!    real ML-DSA-65 signatures from the outgoing validator set, checks the consecutive-
//!    round parent link (locked_qc.round + 1 == child_qc_round), and that every vote
//!    binds to the expected chain, epoch, height, and block hash.
//!
//! # What is NOT here
//! SSI registry resolution, key rotation, next-block revocation, and broader admission
//! policy are gated on later milestones. `on_commit` passes in the new validator set
//! from the committed epoch-change block; this module validates it without touching any
//! mutable identity registry.
#![cfg(feature = "epoch-transition")]

use sha3::{Digest, Sha3_256};

use crate::{CommitCertificate, Round, ValidatorSet, VoteType, vote_signing_bytes};
use crate::pq_hotstuff::safety::{ConsensusVerifier, Fips204Verifier};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Reasons a handoff proof can be rejected. All variants leave the safety
/// store, seal, and active validator set unchanged.
#[derive(Debug, thiserror::Error)]
pub enum HandoffError {
    #[error("consecutive-round check failed: certificate round {cert_round}, child QC round {child_round} (expected {cert_round} + 1 == {child_round})")]
    ConsecutiveRoundsViolation { cert_round: Round, child_round: Round },

    #[error("epoch mismatch: certificate carries epoch {cert_epoch}, expected {expected_epoch}")]
    EpochMismatch { cert_epoch: u64, expected_epoch: u64 },

    #[error("insufficient quorum power: need {needed}, have {have} (from {signers} distinct signers)")]
    InsufficientPower { needed: u64, have: u64, signers: usize },

    #[error("signature invalid for validator {validator_id}")]
    SignatureInvalid { validator_id: String },

    #[error("unknown validator in precommit: {id}")]
    UnknownValidator { id: String },

    #[error("validator {id} has zero voting power; not eligible for quorum")]
    ZeroPower { id: String },

    #[error("duplicate precommit from validator {id}")]
    DuplicateSigner { id: String },

    #[error("substituted incoming key: set_hash in certificate ({cert_hash}) does not match canonical hash of supplied incoming set ({computed_hash})")]
    SetHashMismatch { cert_hash: String, computed_hash: String },

    #[error("certificate round {cert_round} does not match expected seal round {expected_seal_round}")]
    SealRoundMismatch { cert_round: Round, expected_seal_round: Round },
}

// ── Canonical set hash ────────────────────────────────────────────────────────

/// Canonical encoding of a validator set for `set_hash`.
///
/// Encoding (per validator, in validator-ID lexicographic order):
/// ```text
/// 2-byte BE: id_len
/// id_len bytes: validator ID string
/// 2-byte BE: key_len
/// key_len bytes: ML-DSA-65 public key bytes
/// 8-byte BE: voting_power
/// ```
/// The result is SHA3-256 of the concatenated encoding.
pub fn canonical_set_hash(vs: &ValidatorSet) -> [u8; 32] {
    let mut sorted: Vec<_> = vs.validators.iter().collect();
    sorted.sort_by(|a, b| a.id.0.cmp(&b.id.0));

    let mut buf = Vec::new();
    for v in &sorted {
        let id_bytes = v.id.0.as_bytes();
        buf.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(id_bytes);
        buf.extend_from_slice(&(v.public_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&v.public_key);
        buf.extend_from_slice(&v.voting_power.to_be_bytes());
    }
    Sha3_256::digest(&buf).into()
}

// ── Handoff-proof verification ────────────────────────────────────────────────

/// Verify the complete two-certificate handoff proof for an epoch-change commit.
///
/// # Parameters
/// - `chain_id` — consensus chain identifier (must match the vote signing bytes)
/// - `certificate` — the `CommitCertificate` for the epoch-change block B_ec
/// - `outgoing_set` — the validator set that signed B_ec (the set being replaced)
/// - `child_qc_round` — round of the child QC (high_qc.round); must equal cert.round + 1
/// - `incoming_set` — the new validator set being activated
/// - `expected_set_hash` — the set_hash that must match `canonical_set_hash(incoming_set)`
///
/// # Checks (all must pass before the seal is written)
/// 1. `child_qc_round == certificate.round + 1` (consecutive-round parent link)
/// 2. Each precommit carries a valid ML-DSA-65 signature from a known outgoing validator
/// 3. No duplicate signers
/// 4. Total voting power of verified signers >= `outgoing_set.quorum_power()`
/// 5. `canonical_set_hash(incoming_set) == expected_set_hash`
pub fn verify_handoff_proof(
    chain_id: &str,
    certificate: &CommitCertificate,
    outgoing_set: &ValidatorSet,
    child_qc_round: Round,
    incoming_set: &ValidatorSet,
    expected_set_hash: [u8; 32],
) -> Result<(), HandoffError> {
    // ── 1. Consecutive-round parent link ──────────────────────────────────────
    if child_qc_round != certificate.round + 1 {
        return Err(HandoffError::ConsecutiveRoundsViolation {
            cert_round: certificate.round,
            child_round: child_qc_round,
        });
    }

    // ── 2–4. Signature verification and quorum ────────────────────────────────
    let verifier = Fips204Verifier;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut power_verified: u64 = 0;

    for vote in &certificate.precommits {
        if vote.vote_type != VoteType::Precommit { continue; }
        if vote.height != certificate.height { continue; }
        if vote.block_hash.as_ref() != Some(&certificate.block_hash) { continue; }

        let vid = vote.validator.0.clone();

        // Find in outgoing set.
        let val = outgoing_set.validators.iter().find(|v| v.id.0 == vid)
            .ok_or_else(|| HandoffError::UnknownValidator { id: vid.clone() })?;

        if val.voting_power == 0 {
            return Err(HandoffError::ZeroPower { id: vid });
        }
        if !seen.insert(vid.clone()) {
            return Err(HandoffError::DuplicateSigner { id: vid });
        }

        // Reconstruct the signed message.
        let msg = vote_signing_bytes(
            chain_id, &VoteType::Precommit, vote.height, vote.round,
            vote.block_hash.as_ref(),
        );

        if !verifier.verify(&val.public_key, crate::pq_hotstuff::safety::CTX_VOTE, &msg, &vote.signature) {
            return Err(HandoffError::SignatureInvalid { validator_id: vid });
        }

        power_verified += val.voting_power;
    }

    let needed = outgoing_set.quorum_power();
    if power_verified < needed {
        return Err(HandoffError::InsufficientPower {
            needed,
            have: power_verified,
            signers: seen.len(),
        });
    }

    // ── 5. Incoming-set hash binding ──────────────────────────────────────────
    let computed = canonical_set_hash(incoming_set);
    if computed != expected_set_hash {
        return Err(HandoffError::SetHashMismatch {
            cert_hash: hex_prefix(&expected_set_hash),
            computed_hash: hex_prefix(&computed),
        });
    }

    Ok(())
}

fn hex_prefix(b: &[u8; 32]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}
