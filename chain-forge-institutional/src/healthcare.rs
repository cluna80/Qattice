//! Healthcare L1 transaction types and executor.
//!
//! # Privacy requirement
//! NO real patient data, PHI, or HL7 FHIR resource content may appear in
//! transactions or state. Only commitment hashes (hex SHA-256) are stored
//! on-chain. The off-chain system retains the actual medical records.
//! This is a structural requirement, not a guideline.

use serde::{Deserialize, Serialize};
use crate::execution::{ExecutionContext, StateEntry, TemplateState, TxResult};

// ── State key namespace ───────────────────────────────────────────────────────

const NS: &str = "hc/";

fn key(suffix: &str) -> String {
    format!("{}{}", NS, suffix)
}

// ── Transaction types ─────────────────────────────────────────────────────────

/// Healthcare L1 transaction variants.
///
/// All commitment fields are hex-encoded SHA-256 hashes of off-chain data.
/// No plaintext medical content is included.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HealthcareTx {
    /// Anchor a FHIR resource commitment on-chain.
    /// `commitment` = SHA-256(FHIR resource JSON), hex-encoded.
    AnchorFhirCommitment {
        resource_type: String,
        commitment: String,
    },
    /// Register a clinician credential anchor.
    /// `credential_hash` = SHA-256(credential JSON), hex-encoded.
    RegisterClinicianCredential {
        clinician_id: String,
        credential_hash: String,
    },
    /// Record an emergency access event (break-glass audit anchor).
    /// `access_commitment` = SHA-256(access event metadata), hex-encoded.
    RecordEmergencyAccess {
        clinician_id: String,
        access_commitment: String,
    },
    /// Revoke a clinician credential.
    RevokeClinicianCredential {
        clinician_id: String,
        reason_code: String,
    },
}

// ── Executor ──────────────────────────────────────────────────────────────────

/// Applies `HealthcareTx` transactions to `TemplateState`.
pub struct HealthcareExecutor;

impl HealthcareExecutor {
    pub fn apply(
        tx: &HealthcareTx,
        ctx: &ExecutionContext,
        state: &mut TemplateState,
    ) -> TxResult {
        match ctx.template {
            crate::templates::InstitutionalTemplate::Healthcare(_) => {}
            _ => return TxResult::cross_template_rejected(),
        }

        match tx {
            HealthcareTx::AnchorFhirCommitment { resource_type, commitment } => {
                if commitment.len() != 64 || !commitment.chars().all(|c| c.is_ascii_hexdigit()) {
                    return TxResult::err("commitment must be a 64-char hex SHA-256");
                }
                let k = key(&format!("fhir/{}/{}", resource_type, commitment));
                let entry = StateEntry::new(k.clone(), commitment.clone());
                state.set(k, commitment.clone());
                TxResult::ok(vec![entry])
            }

            HealthcareTx::RegisterClinicianCredential { clinician_id, credential_hash } => {
                if clinician_id.is_empty() {
                    return TxResult::err("clinician_id must not be empty");
                }
                if credential_hash.len() != 64 || !credential_hash.chars().all(|c| c.is_ascii_hexdigit()) {
                    return TxResult::err("credential_hash must be a 64-char hex SHA-256");
                }
                let k = key(&format!("credential/{}", clinician_id));
                // Reject duplicate unless revoked.
                if state.contains_key(&k) {
                    return TxResult::err("credential already registered; revoke first");
                }
                let entry = StateEntry::new(k.clone(), credential_hash.clone());
                state.set(k, credential_hash.clone());
                TxResult::ok(vec![entry])
            }

            HealthcareTx::RecordEmergencyAccess { clinician_id, access_commitment } => {
                if clinician_id.is_empty() {
                    return TxResult::err("clinician_id must not be empty");
                }
                if access_commitment.len() != 64 || !access_commitment.chars().all(|c| c.is_ascii_hexdigit()) {
                    return TxResult::err("access_commitment must be a 64-char hex SHA-256");
                }
                // Audit log: keyed by block height to allow multiple events.
                let k = key(&format!("emergency/{}/{}", clinician_id, ctx.block_height));
                let entry = StateEntry::new(k.clone(), access_commitment.clone());
                state.set(k, access_commitment.clone());
                TxResult::ok(vec![entry])
            }

            HealthcareTx::RevokeClinicianCredential { clinician_id, reason_code } => {
                if clinician_id.is_empty() {
                    return TxResult::err("clinician_id must not be empty");
                }
                let k = key(&format!("credential/{}", clinician_id));
                if !state.contains_key(&k) {
                    return TxResult::err("no credential registered for this clinician_id");
                }
                let revoke_key = key(&format!("revoked/{}", clinician_id));
                state.remove(&k);
                let entry = StateEntry::new(revoke_key.clone(), reason_code.clone());
                state.set(revoke_key, reason_code.clone());
                TxResult::ok(vec![entry])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::{HealthcareConfig, InstitutionalTemplate};

    fn ctx() -> ExecutionContext {
        ExecutionContext::new(
            "hc-test-chain",
            1,
            "clinician-01",
            InstitutionalTemplate::Healthcare(HealthcareConfig::default()),
        )
    }

    fn dummy_hash(byte: u8) -> String {
        format!("{:0>64}", format!("{:x}", byte).repeat(2))
    }

    #[test]
    fn anchor_fhir_commitment_ok() {
        let mut state = TemplateState::new();
        let tx = HealthcareTx::AnchorFhirCommitment {
            resource_type: "Observation".into(),
            commitment: dummy_hash(0xab),
        };
        let r = HealthcareExecutor::apply(&tx, &ctx(), &mut state);
        assert!(r.success);
        assert_eq!(r.mutations.len(), 1);
        assert!(r.mutations[0].key.starts_with("hc/fhir/"));
    }

    #[test]
    fn register_and_revoke_credential() {
        let mut state = TemplateState::new();
        let hash = dummy_hash(0x11);
        let reg = HealthcareTx::RegisterClinicianCredential {
            clinician_id: "dr-smith".into(),
            credential_hash: hash.clone(),
        };
        let r = HealthcareExecutor::apply(&reg, &ctx(), &mut state);
        assert!(r.success);
        assert!(state.contains_key("hc/credential/dr-smith"));

        let rev = HealthcareTx::RevokeClinicianCredential {
            clinician_id: "dr-smith".into(),
            reason_code: "LICENSE_EXPIRED".into(),
        };
        let r2 = HealthcareExecutor::apply(&rev, &ctx(), &mut state);
        assert!(r2.success);
        assert!(!state.contains_key("hc/credential/dr-smith"));
        assert!(state.contains_key("hc/revoked/dr-smith"));
    }

    #[test]
    fn reject_bad_commitment_hash() {
        let mut state = TemplateState::new();
        let tx = HealthcareTx::AnchorFhirCommitment {
            resource_type: "Patient".into(),
            commitment: "not-a-hash".into(),
        };
        let r = HealthcareExecutor::apply(&tx, &ctx(), &mut state);
        assert!(!r.success);
    }
}
