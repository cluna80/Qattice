//! Cross-chain replay protection for institutional transactions.
//!
//! # Design
//! This module provides `TransactionDomain`, which binds a signing context to a
//! specific institutional chain. It is intentionally isolated to this crate and
//! does NOT modify any existing Qattice transaction types, signing paths, or
//! consensus rules. Existing chain-forge-* transaction signing is not changed.
//!
//! For future institutional transactions, signers MUST prepend
//! `TransactionDomain::signing_context()` to the payload bytes before signing.
//! Verifiers MUST call `TransactionDomain::accepts()` before accepting a tx.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Cross-chain transaction domain separator.
///
/// Binds every signed institutional payload to a specific chain, genesis
/// commitment, and protocol version so that a valid signature on one chain
/// cannot be replayed on another.
///
/// This type is used only by institutional chain tooling. It does not interact
/// with existing Qattice or Chain Forge node transaction paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionDomain {
    /// The chain's unique identifier.
    pub chain_id: String,
    /// SHA-256 hash of the chain's genesis commitment (32 bytes).
    pub genesis_hash: [u8; 32],
    /// Protocol version. Increment when the signing format changes incompatibly.
    pub protocol_version: u32,
    /// Human-readable domain label, e.g. "institutional-tx-v1".
    pub domain_label: String,
}

impl TransactionDomain {
    /// Construct from a genesis hash hex string.
    pub fn from_genesis_hex(
        chain_id: impl Into<String>,
        genesis_hash_hex: &str,
        protocol_version: u32,
        domain_label: impl Into<String>,
    ) -> Result<Self, String> {
        let bytes = hex::decode(genesis_hash_hex)
            .map_err(|e| format!("invalid genesis hash hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("genesis hash must be 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            chain_id: chain_id.into(),
            genesis_hash: arr,
            protocol_version,
            domain_label: domain_label.into(),
        })
    }

    /// Canonical signing context bytes.
    ///
    /// These bytes MUST be prepended to the transaction payload before signing
    /// and MUST be included in the data passed to the verifier.
    ///
    /// Format:
    ///   domain_separator(32 bytes) || chain_id_len(4 bytes LE) || chain_id(UTF-8) || genesis_hash(32 bytes) || protocol_version(4 bytes LE)
    pub fn signing_context(&self) -> Vec<u8> {
        let separator = self.domain_separator();
        let chain_id_bytes = self.chain_id.as_bytes();
        let chain_id_len = (chain_id_bytes.len() as u32).to_le_bytes();
        let protocol_version_bytes = self.protocol_version.to_le_bytes();

        let mut ctx = Vec::with_capacity(
            32 + 4 + chain_id_bytes.len() + 32 + 4,
        );
        ctx.extend_from_slice(&separator);
        ctx.extend_from_slice(&chain_id_len);
        ctx.extend_from_slice(chain_id_bytes);
        ctx.extend_from_slice(&self.genesis_hash);
        ctx.extend_from_slice(&protocol_version_bytes);
        ctx
    }

    /// Compute the domain separator for this transaction domain.
    ///
    /// `SHA-256(domain_label || "|" || chain_id || "|" || protocol_version)`
    pub fn domain_separator(&self) -> [u8; 32] {
        let input = format!("{}|{}|{}", self.domain_label, self.chain_id, self.protocol_version);
        Sha256::digest(input.as_bytes()).into()
    }

    /// Whether this domain accepts a transaction tagged with `tx_domain`.
    ///
    /// Returns `true` only when chain_id, genesis_hash, AND protocol_version
    /// all match exactly. Any mismatch is a cross-chain replay attempt.
    pub fn accepts(&self, tx_domain: &TransactionDomain) -> bool {
        self.chain_id == tx_domain.chain_id
            && self.genesis_hash == tx_domain.genesis_hash
            && self.protocol_version == tx_domain.protocol_version
    }
}

#[cfg(test)]
mod domain_tests {
    use super::*;

    fn make_domain(chain_id: &str, genesis_hash_byte: u8) -> TransactionDomain {
        TransactionDomain {
            chain_id: chain_id.to_string(),
            genesis_hash: [genesis_hash_byte; 32],
            protocol_version: 1,
            domain_label: "institutional-tx-v1".to_string(),
        }
    }

    #[test]
    fn accepts_matching_domain() {
        let d = make_domain("hospital-a", 0xAA);
        assert!(d.accepts(&d.clone()));
    }

    #[test]
    fn rejects_different_chain_id() {
        let a = make_domain("hospital-a", 0xAA);
        let b = make_domain("hospital-b", 0xAA);
        assert!(!a.accepts(&b));
    }

    #[test]
    fn rejects_different_genesis_hash() {
        let a = make_domain("hospital-a", 0xAA);
        let b = make_domain("hospital-a", 0xBB);
        assert!(!a.accepts(&b));
    }

    #[test]
    fn signing_context_differs_across_chains() {
        let a = make_domain("hospital-a", 0xAA);
        let b = make_domain("hospital-b", 0xBB);
        assert_ne!(a.signing_context(), b.signing_context());
    }

    #[test]
    fn signing_context_is_deterministic() {
        let d = make_domain("hospital-a", 0xAA);
        assert_eq!(d.signing_context(), d.signing_context());
    }
}
