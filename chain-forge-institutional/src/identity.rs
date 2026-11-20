//! Institutional Identity Framework (CF-INST-003)
//!
//! Provides domain-separated identifiers, role credentials, and key registries
//! for institutional blockchain participants. All identifiers are deterministic
//! SHA-256 hashes of their inputs — no random ID generation.
//!
//! # Security invariants
//! - Private keys are NEVER accepted or stored by any type in this module.
//! - `CredentialVerifier` performs structural (key-length) validation.
//!   Full algebraic ML-DSA-65 verification requires the `chain-forge-crypto`
//!   crate's `verify_consensus` function; see the TODO in `CredentialVerifier`.
//! - `KeyRegistry` enforces one active key per identity and audit-logs rotations.
//! - `IdentityRegistry` enforces unique org IDs and prevents re-enrollment of
//!   suspended organizations without explicit reinstatement.
//! - No patient, student, correctional, or enterprise-sensitive data is stored
//!   or used in test fixtures. Test IDs are opaque numeric strings only.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use crate::{InstError, InstResult};
use crate::validator::ML_DSA_65_PUBLIC_KEY_BYTES;

// ── Domain-separated identity types ───────────────────────────────────────────

/// Unique identifier for an institution (hospital, corrections facility, etc.).
///
/// Constructed from a human-readable label and chain ID via SHA-256 to produce
/// a stable, collision-resistant ID that is scoped to a specific chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrganizationId(pub String);

impl OrganizationId {
    /// Derive from a canonical label and chain scope.
    ///
    /// `SHA-256("org" | "|" | chain_id | "|" | label)` — hex-encoded.
    pub fn derive(chain_id: &str, label: &str) -> Self {
        let input = format!("org|{}|{}", chain_id, label);
        OrganizationId(hex::encode(Sha256::digest(input.as_bytes())))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

/// Unique identifier for a human participant within an institutional chain.
///
/// Scoped to a chain and org to prevent cross-chain/cross-org replay.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HumanId(pub String);

impl HumanId {
    /// `SHA-256("human" | "|" | chain_id | "|" | org_id | "|" | label)` — hex.
    pub fn derive(chain_id: &str, org_id: &OrganizationId, label: &str) -> Self {
        let input = format!("human|{}|{}|{}", chain_id, org_id.as_str(), label);
        HumanId(hex::encode(Sha256::digest(input.as_bytes())))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

/// Unique identifier for a registered device (medical device, scanner, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub String);

impl DeviceId {
    /// `SHA-256("device" | "|" | chain_id | "|" | org_id | "|" | label)` — hex.
    pub fn derive(chain_id: &str, org_id: &OrganizationId, label: &str) -> Self {
        let input = format!("device|{}|{}|{}", chain_id, org_id.as_str(), label);
        DeviceId(hex::encode(Sha256::digest(input.as_bytes())))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

/// Unique identifier for an automated agent (compliance bot, audit service).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl AgentId {
    /// `SHA-256("agent" | "|" | chain_id | "|" | org_id | "|" | label)` — hex.
    pub fn derive(chain_id: &str, org_id: &OrganizationId, label: &str) -> Self {
        let input = format!("agent|{}|{}|{}", chain_id, org_id.as_str(), label);
        AgentId(hex::encode(Sha256::digest(input.as_bytes())))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

// ── Role credentials ──────────────────────────────────────────────────────────

/// A role-based credential binding an identity to a permission set on a chain.
///
/// Credentials are chain-scoped and expire. They bind a public key (not private
/// key) to allow offline signature verification by chain nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleCredential {
    /// The chain this credential is valid on.
    pub chain_id: String,
    /// Org the holder belongs to.
    pub org_id: OrganizationId,
    /// Role name, e.g. "physician", "compliance-officer", "auditor".
    pub role: String,
    /// ML-DSA-65 public key bytes (1952 bytes). Never a private key.
    pub public_key_bytes: Vec<u8>,
    /// Unix epoch seconds: credential becomes valid at this time.
    pub valid_from: u64,
    /// Unix epoch seconds: credential expires at this time.
    pub valid_until: u64,
    /// Whether this credential has been explicitly revoked.
    pub revoked: bool,
    /// SHA-256 of the canonical credential fields (hex). Computed at creation.
    pub credential_id: String,
}

impl RoleCredential {
    /// Create and validate a new role credential.
    ///
    /// Validates key length (1952 bytes for ML-DSA-65), expiry ordering,
    /// and that no private key material is embedded (structural check only —
    /// algebraic key validity requires the chain-forge-crypto verify path).
    pub fn new(
        chain_id: impl Into<String>,
        org_id: OrganizationId,
        role: impl Into<String>,
        public_key_bytes: Vec<u8>,
        valid_from: u64,
        valid_until: u64,
    ) -> InstResult<Self> {
        let chain_id = chain_id.into();
        let role = role.into();

        // Structural checks — no algebraic verify here (see CredentialVerifier).
        if public_key_bytes.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
            return Err(InstError::InvalidConfig(format!(
                "credential public key must be {} bytes (ML-DSA-65), got {}",
                ML_DSA_65_PUBLIC_KEY_BYTES,
                public_key_bytes.len()
            )));
        }
        if valid_until <= valid_from {
            return Err(InstError::InvalidConfig(
                "valid_until must be strictly after valid_from".into()
            ));
        }

        // Deterministic credential ID: SHA-256 of canonical fields.
        let id_input = format!(
            "{}|{}|{}|{}|{}|{}",
            chain_id,
            org_id.as_str(),
            role,
            hex::encode(&public_key_bytes),
            valid_from,
            valid_until,
        );
        let credential_id = hex::encode(Sha256::digest(id_input.as_bytes()));

        Ok(Self {
            chain_id,
            org_id,
            role,
            public_key_bytes,
            valid_from,
            valid_until,
            revoked: false,
            credential_id,
        })
    }

    /// Whether the credential is currently valid at `now_unix`.
    pub fn is_valid_at(&self, now_unix: u64) -> bool {
        !self.revoked && now_unix >= self.valid_from && now_unix < self.valid_until
    }
}

// ── CredentialVerifier ────────────────────────────────────────────────────────

/// Verifies role credentials for a specific chain.
///
/// Performs structural checks (key length, expiry, revocation, chain binding).
/// Full algebraic ML-DSA-65 signature verification is left as a TODO pending
/// integration with `chain-forge-crypto::verify_consensus`.
pub struct CredentialVerifier {
    chain_id: String,
}

impl CredentialVerifier {
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self { chain_id: chain_id.into() }
    }

    /// Verify a credential structurally at `now_unix`.
    ///
    /// Checks:
    /// 1. Chain ID binding: credential.chain_id == this verifier's chain_id.
    /// 2. Expiry: now_unix is within [valid_from, valid_until).
    /// 3. Revocation: credential is not revoked.
    /// 4. Key length: public_key_bytes.len() == 1952 (ML-DSA-65).
    ///
    /// # Note
    /// Does NOT perform algebraic ML-DSA-65 verification. For production nodes,
    /// pass credential.public_key_bytes and the payload signature to
    /// `chain_forge_crypto::verify_consensus(message, signature, public_key)`.
    pub fn verify_structural(&self, cred: &RoleCredential, now_unix: u64) -> InstResult<()> {
        // 1. Chain binding.
        if cred.chain_id != self.chain_id {
            return Err(InstError::InvalidConfig(format!(
                "credential chain_id '{}' does not match verifier chain_id '{}'",
                cred.chain_id, self.chain_id
            )));
        }

        // 2. Expiry.
        if !cred.is_valid_at(now_unix) {
            if cred.revoked {
                return Err(InstError::InvalidConfig(
                    "credential has been revoked".into()
                ));
            }
            return Err(InstError::InvalidConfig(format!(
                "credential is not valid at t={now_unix} (valid_from={}, valid_until={})",
                cred.valid_from, cred.valid_until
            )));
        }

        // 3. Key length (redundant with RoleCredential::new but defence-in-depth).
        if cred.public_key_bytes.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
            return Err(InstError::InvalidConfig(format!(
                "public key length {} does not match ML-DSA-65 ({} bytes)",
                cred.public_key_bytes.len(),
                ML_DSA_65_PUBLIC_KEY_BYTES
            )));
        }

        // TODO(CF-INST-003-CRYPTO): Call chain_forge_crypto::verify_consensus(
        //   payload_bytes, signature_bytes, &cred.public_key_bytes
        // ) once chain-forge-crypto is a dependency of this crate.

        Ok(())
    }
}

// ── KeyRegistry ───────────────────────────────────────────────────────────────

/// Audit log entry for key operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAuditEntry {
    pub operation: KeyOperation,
    pub identity_id: String,
    pub key_hex_prefix: String,
    pub timestamp_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyOperation {
    Enrolled,
    Rotated,
    Revoked,
}

/// Registry of active public keys per identity.
///
/// Enforces one active key per identity at a time. Rotations are audit-logged.
/// Revoked keys are retained in the audit log but removed from the active set.
pub struct KeyRegistry {
    chain_id: String,
    /// identity_id → active public key bytes.
    active_keys: HashMap<String, Vec<u8>>,
    /// Revoked key bytes (hex of full key).
    revoked_keys: std::collections::HashSet<String>,
    audit_log: Vec<KeyAuditEntry>,
}

impl KeyRegistry {
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
            active_keys: HashMap::new(),
            revoked_keys: std::collections::HashSet::new(),
            audit_log: Vec::new(),
        }
    }

    /// Enroll a new key for an identity. Fails if the identity already has an
    /// active key (use `rotate` to replace it).
    pub fn enroll(&mut self, identity_id: &str, public_key: Vec<u8>, now_unix: u64) -> InstResult<()> {
        Self::check_key_length(&public_key)?;
        if self.active_keys.contains_key(identity_id) {
            return Err(InstError::InvalidConfig(format!(
                "identity '{}' already has an enrolled key; use rotate() to replace it",
                identity_id
            )));
        }
        let prefix = hex::encode(&public_key[..8]);
        self.active_keys.insert(identity_id.to_string(), public_key);
        self.audit_log.push(KeyAuditEntry {
            operation: KeyOperation::Enrolled,
            identity_id: identity_id.to_string(),
            key_hex_prefix: prefix,
            timestamp_unix: now_unix,
        });
        Ok(())
    }

    /// Rotate an existing key. The old key is moved to the revoked set.
    pub fn rotate(&mut self, identity_id: &str, new_key: Vec<u8>, now_unix: u64) -> InstResult<()> {
        Self::check_key_length(&new_key)?;
        let old_key = self.active_keys.remove(identity_id).ok_or_else(|| {
            InstError::InvalidConfig(format!(
                "identity '{}' has no active key to rotate", identity_id
            ))
        })?;
        let old_hex = hex::encode(&old_key);
        self.revoked_keys.insert(old_hex);
        let prefix = hex::encode(&new_key[..8]);
        self.active_keys.insert(identity_id.to_string(), new_key);
        self.audit_log.push(KeyAuditEntry {
            operation: KeyOperation::Rotated,
            identity_id: identity_id.to_string(),
            key_hex_prefix: prefix,
            timestamp_unix: now_unix,
        });
        Ok(())
    }

    /// Revoke the active key for an identity.
    pub fn revoke(&mut self, identity_id: &str, now_unix: u64) -> InstResult<()> {
        let key = self.active_keys.remove(identity_id).ok_or_else(|| {
            InstError::InvalidConfig(format!(
                "identity '{}' has no active key to revoke", identity_id
            ))
        })?;
        let prefix = hex::encode(&key[..8]);
        self.revoked_keys.insert(hex::encode(&key));
        self.audit_log.push(KeyAuditEntry {
            operation: KeyOperation::Revoked,
            identity_id: identity_id.to_string(),
            key_hex_prefix: prefix,
            timestamp_unix: now_unix,
        });
        Ok(())
    }

    /// Look up the active key for an identity.
    pub fn active_key(&self, identity_id: &str) -> Option<&Vec<u8>> {
        self.active_keys.get(identity_id)
    }

    /// Whether a key (by full bytes) has been revoked.
    pub fn is_revoked(&self, public_key: &[u8]) -> bool {
        self.revoked_keys.contains(&hex::encode(public_key))
    }

    pub fn audit_log(&self) -> &[KeyAuditEntry] { &self.audit_log }

    fn check_key_length(key: &[u8]) -> InstResult<()> {
        if key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
            return Err(InstError::InvalidConfig(format!(
                "key must be {} bytes (ML-DSA-65), got {}",
                ML_DSA_65_PUBLIC_KEY_BYTES,
                key.len()
            )));
        }
        Ok(())
    }

    pub fn chain_id(&self) -> &str { &self.chain_id }
}

// ── IdentityRegistry ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrgStatus {
    Active,
    Suspended,
}

/// A registered organization entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgEntry {
    pub org_id: OrganizationId,
    pub label: String,
    pub status: OrgStatus,
    pub enrolled_at: u64,
}

/// Registry of organizations enrolled on an institutional chain.
pub struct IdentityRegistry {
    chain_id: String,
    orgs: HashMap<String, OrgEntry>,
}

impl IdentityRegistry {
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self { chain_id: chain_id.into(), orgs: HashMap::new() }
    }

    /// Enroll a new organization. Rejects duplicate org IDs and re-enrollment
    /// of suspended orgs (must reinstate first).
    pub fn enroll_org(&mut self, label: &str, now_unix: u64) -> InstResult<OrganizationId> {
        let org_id = OrganizationId::derive(&self.chain_id, label);
        if let Some(existing) = self.orgs.get(org_id.as_str()) {
            match existing.status {
                OrgStatus::Active => return Err(InstError::InvalidConfig(format!(
                    "org '{}' (id={}) is already enrolled", label, org_id.as_str()
                ))),
                OrgStatus::Suspended => return Err(InstError::InvalidConfig(format!(
                    "org '{}' is suspended; call reinstate_org() first", label
                ))),
            }
        }
        self.orgs.insert(org_id.as_str().to_string(), OrgEntry {
            org_id: org_id.clone(),
            label: label.to_string(),
            status: OrgStatus::Active,
            enrolled_at: now_unix,
        });
        Ok(org_id)
    }

    /// Suspend an active organization (they may not issue new credentials).
    pub fn suspend_org(&mut self, org_id: &OrganizationId) -> InstResult<()> {
        let entry = self.orgs.get_mut(org_id.as_str()).ok_or_else(|| {
            InstError::InvalidConfig(format!("org '{}' not found", org_id.as_str()))
        })?;
        entry.status = OrgStatus::Suspended;
        Ok(())
    }

    /// Reinstate a suspended organization.
    pub fn reinstate_org(&mut self, org_id: &OrganizationId) -> InstResult<()> {
        let entry = self.orgs.get_mut(org_id.as_str()).ok_or_else(|| {
            InstError::InvalidConfig(format!("org '{}' not found", org_id.as_str()))
        })?;
        entry.status = OrgStatus::Active;
        Ok(())
    }

    pub fn get_org(&self, org_id: &OrganizationId) -> Option<&OrgEntry> {
        self.orgs.get(org_id.as_str())
    }

    pub fn chain_id(&self) -> &str { &self.chain_id }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod identity_tests {
    use super::*;


    fn test_key(byte: u8) -> Vec<u8> {
        vec![byte; ML_DSA_65_PUBLIC_KEY_BYTES]
    }

    // ── ID derivation ─────────────────────────────────────────────────────────

    #[test]
    fn org_id_is_deterministic() {
        let a = OrganizationId::derive("chain-a", "org-1");
        let b = OrganizationId::derive("chain-a", "org-1");
        assert_eq!(a, b);
    }

    #[test]
    fn org_id_differs_across_chains() {
        let a = OrganizationId::derive("chain-a", "org-1");
        let b = OrganizationId::derive("chain-b", "org-1");
        assert_ne!(a, b, "same label on different chains must yield different IDs");
    }

    #[test]
    fn human_id_scoped_to_org() {
        let org_a = OrganizationId::derive("chain-x", "org-a");
        let org_b = OrganizationId::derive("chain-x", "org-b");
        let h_a = HumanId::derive("chain-x", &org_a, "user-1");
        let h_b = HumanId::derive("chain-x", &org_b, "user-1");
        assert_ne!(h_a, h_b, "same label under different orgs must differ");
    }

    #[test]
    fn device_and_agent_ids_differ_from_human() {
        let org = OrganizationId::derive("chain-x", "org-1");
        let h = HumanId::derive("chain-x", &org, "id-1");
        let d = DeviceId::derive("chain-x", &org, "id-1");
        let a = AgentId::derive("chain-x", &org, "id-1");
        assert_ne!(h.as_str(), d.as_str());
        assert_ne!(h.as_str(), a.as_str());
        assert_ne!(d.as_str(), a.as_str());
    }

    // ── RoleCredential ────────────────────────────────────────────────────────

    #[test]
    fn role_credential_accepts_valid_key() {
        let org = OrganizationId::derive("hosp-chain", "org-1");
        let cred = RoleCredential::new(
            "hosp-chain", org, "physician",
            test_key(0x01), 1000, 9000,
        );
        assert!(cred.is_ok(), "valid credential should be accepted");
    }

    #[test]
    fn role_credential_rejects_wrong_key_length() {
        let org = OrganizationId::derive("hosp-chain", "org-1");
        let cred = RoleCredential::new(
            "hosp-chain", org, "physician",
            vec![0x01; 32],   // Ed25519 length — wrong
            1000, 9000,
        );
        assert!(cred.is_err(), "wrong key length must be rejected");
    }

    #[test]
    fn role_credential_rejects_inverted_expiry() {
        let org = OrganizationId::derive("hosp-chain", "org-1");
        let cred = RoleCredential::new(
            "hosp-chain", org, "physician",
            test_key(0x01), 9000, 1000,   // valid_until < valid_from
        );
        assert!(cred.is_err(), "inverted expiry must be rejected");
    }

    #[test]
    fn credential_id_is_deterministic() {
        let org = OrganizationId::derive("hosp-chain", "org-1");
        let c1 = RoleCredential::new("hosp-chain", org.clone(), "physician", test_key(0x01), 1000, 9000).unwrap();
        let c2 = RoleCredential::new("hosp-chain", org, "physician", test_key(0x01), 1000, 9000).unwrap();
        assert_eq!(c1.credential_id, c2.credential_id);
    }

    // ── CredentialVerifier ────────────────────────────────────────────────────

    #[test]
    fn verifier_accepts_valid_credential() {
        let chain_id = "hosp-chain";
        let org = OrganizationId::derive(chain_id, "org-1");
        let cred = RoleCredential::new(chain_id, org, "physician", test_key(0x01), 1000, 9000).unwrap();
        let v = CredentialVerifier::new(chain_id);
        assert!(v.verify_structural(&cred, 5000).is_ok());
    }

    #[test]
    fn verifier_rejects_wrong_chain() {
        let org = OrganizationId::derive("chain-a", "org-1");
        let cred = RoleCredential::new("chain-a", org, "officer", test_key(0x02), 1000, 9000).unwrap();
        let v = CredentialVerifier::new("chain-b");
        assert!(v.verify_structural(&cred, 5000).is_err());
    }

    #[test]
    fn verifier_rejects_expired() {
        let chain = "hosp-chain";
        let org = OrganizationId::derive(chain, "org-1");
        let cred = RoleCredential::new(chain, org, "physician", test_key(0x03), 1000, 2000).unwrap();
        let v = CredentialVerifier::new(chain);
        assert!(v.verify_structural(&cred, 5000).is_err());   // past valid_until
    }

    #[test]
    fn verifier_rejects_revoked() {
        let chain = "hosp-chain";
        let org = OrganizationId::derive(chain, "org-1");
        let mut cred = RoleCredential::new(chain, org, "physician", test_key(0x04), 1000, 9000).unwrap();
        cred.revoked = true;
        let v = CredentialVerifier::new(chain);
        assert!(v.verify_structural(&cred, 5000).is_err());
    }

    // ── KeyRegistry ───────────────────────────────────────────────────────────

    #[test]
    fn key_registry_enroll_and_lookup() {
        let mut reg = KeyRegistry::new("chain-x");
        reg.enroll("identity-1", test_key(0x0A), 100).unwrap();
        assert_eq!(reg.active_key("identity-1"), Some(&test_key(0x0A)));
    }

    #[test]
    fn key_registry_rejects_double_enroll() {
        let mut reg = KeyRegistry::new("chain-x");
        reg.enroll("identity-1", test_key(0x0A), 100).unwrap();
        let result = reg.enroll("identity-1", test_key(0x0B), 101);
        assert!(result.is_err(), "double enroll must be rejected");
    }

    #[test]
    fn key_registry_rotate_revokes_old() {
        let mut reg = KeyRegistry::new("chain-x");
        let old_key = test_key(0x0A);
        reg.enroll("identity-1", old_key.clone(), 100).unwrap();
        reg.rotate("identity-1", test_key(0x0B), 200).unwrap();
        assert!(reg.is_revoked(&old_key), "old key must be revoked after rotation");
        assert_eq!(reg.active_key("identity-1"), Some(&test_key(0x0B)));
    }

    #[test]
    fn key_registry_audit_log() {
        let mut reg = KeyRegistry::new("chain-x");
        reg.enroll("identity-1", test_key(0x0A), 100).unwrap();
        reg.rotate("identity-1", test_key(0x0B), 200).unwrap();
        reg.revoke("identity-1", 300).unwrap();
        assert_eq!(reg.audit_log().len(), 3);
    }

    // ── IdentityRegistry ──────────────────────────────────────────────────────

    #[test]
    fn identity_registry_enroll_org() {
        let mut reg = IdentityRegistry::new("edu-chain");
        let org_id = reg.enroll_org("school-district-1", 100).unwrap();
        assert_eq!(reg.get_org(&org_id).unwrap().status, OrgStatus::Active);
    }

    #[test]
    fn identity_registry_rejects_duplicate_org() {
        let mut reg = IdentityRegistry::new("edu-chain");
        reg.enroll_org("district-1", 100).unwrap();
        assert!(reg.enroll_org("district-1", 200).is_err());
    }

    #[test]
    fn identity_registry_suspend_and_reinstate() {
        let mut reg = IdentityRegistry::new("edu-chain");
        let org_id = reg.enroll_org("district-1", 100).unwrap();
        reg.suspend_org(&org_id).unwrap();
        assert_eq!(reg.get_org(&org_id).unwrap().status, OrgStatus::Suspended);
        assert!(reg.enroll_org("district-1", 200).is_err(), "suspended org cannot re-enroll");
        reg.reinstate_org(&org_id).unwrap();
        assert_eq!(reg.get_org(&org_id).unwrap().status, OrgStatus::Active);
    }
}
