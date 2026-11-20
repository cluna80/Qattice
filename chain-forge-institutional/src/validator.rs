//! Validator public-key identity for institutional chains.
//!
//! Wraps public key bytes with their type and validates byte-length correctness.
//! No private keys are ever accepted or stored here.
//!
//! Key-length constants mirror `chain-forge-crypto::SchemeId::public_key_size_bytes()`.
//! They are kept here as named constants so this crate compiles without
//! depending on chain-forge-crypto at runtime.

use crate::{InstError, InstResult};
use serde::{Deserialize, Serialize};

/// Expected byte length of an ML-DSA-65 (Dilithium3 / FIPS 204) public key.
/// Source: `chain-forge-crypto::SchemeId::MlDsa.public_key_size_bytes()` → 1952.
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;

/// Expected byte length of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;

/// Supported validator key types for institutional chains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidatorKeyType {
    /// FIPS 204 ML-DSA-65 (Dilithium3). Institutional default.
    MlDsa65,
    /// Ed25519. Legacy compatibility only; not recommended for new deployments.
    Ed25519,
}

impl ValidatorKeyType {
    pub fn expected_bytes(&self) -> usize {
        match self {
            Self::MlDsa65 => ML_DSA_65_PUBLIC_KEY_BYTES,
            Self::Ed25519 => ED25519_PUBLIC_KEY_BYTES,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml-dsa-65",
            Self::Ed25519 => "ed25519",
        }
    }
}

/// A validator's public key commitment.
///
/// Private keys are never accepted, stored, or transmitted by this type.
/// For structural tests only, use `ValidatorPublicKey::test_key_*` constructors
/// which are explicitly labelled as invalid production keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorPublicKey {
    pub key_type: ValidatorKeyType,
    /// Raw public key bytes. Length must match `key_type.expected_bytes()`.
    pub raw_bytes: Vec<u8>,
}

impl ValidatorPublicKey {
    /// Create from explicit bytes and type.
    pub fn new(key_type: ValidatorKeyType, raw_bytes: Vec<u8>) -> Self {
        Self { key_type, raw_bytes }
    }

    /// Validate byte-length correctness.
    ///
    /// This confirms the key is structurally the right size for its declared type.
    /// It does not perform algebraic validity checks (those require the full
    /// crypto crate and an actual key-generation path).
    pub fn validate(&self) -> InstResult<()> {
        let expected = self.key_type.expected_bytes();
        if self.raw_bytes.len() != expected {
            return Err(InstError::InvalidValidatorKey {
                key_type: self.key_type.as_str().to_string(),
                expected_bytes: expected,
                actual_bytes: self.raw_bytes.len(),
            });
        }
        Ok(())
    }

    /// Fixed-pattern ML-DSA-65 test key A (1952 bytes of 0x01).
    ///
    /// **NOT a valid production key.** For structural/isolation tests only.
    pub fn test_mldsa_key_a() -> Self {
        Self {
            key_type: ValidatorKeyType::MlDsa65,
            raw_bytes: vec![0x01u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        }
    }

    /// Fixed-pattern ML-DSA-65 test key B (1952 bytes of 0x02).
    ///
    /// **NOT a valid production key.** For structural/isolation tests only.
    pub fn test_mldsa_key_b() -> Self {
        Self {
            key_type: ValidatorKeyType::MlDsa65,
            raw_bytes: vec![0x02u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        }
    }

    /// Fixed-pattern ML-DSA-65 test key for validator index i (byte fill = i+1).
    ///
    /// **NOT a valid production key.** For structural/isolation tests only.
    pub fn test_mldsa_key_for_index(i: u8) -> Self {
        Self {
            key_type: ValidatorKeyType::MlDsa65,
            raw_bytes: vec![i.saturating_add(1); ML_DSA_65_PUBLIC_KEY_BYTES],
        }
    }

    /// Hex-encoded public key (truncated to first 16 bytes for display).
    pub fn hex_prefix(&self) -> String {
        hex::encode(&self.raw_bytes[..self.raw_bytes.len().min(16)])
    }
}
