//! Education L1 transaction types and executor.
//!
//! # Privacy requirement (FERPA / equivalent)
//! Student education records must remain off-chain.
//! On-chain state stores ONLY verifiable credential anchors and revocation
//! markers. No student names, identifiers, grades, or other FERPA-covered
//! information may appear in transactions or state.

use serde::{Deserialize, Serialize};
use crate::execution::{ExecutionContext, StateEntry, TemplateState, TxResult};

const NS: &str = "edu/";

fn key(suffix: &str) -> String {
    format!("{}{}", NS, suffix)
}

// ── Transaction types ─────────────────────────────────────────────────────────

/// Education L1 transaction variants.
///
/// All `commitment` fields are hex-encoded SHA-256 of off-chain VC documents.
/// Credential subject identifiers must be opaque tokens (DIDs or hashed IDs),
/// not plain student names or institutional record numbers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum EducationTx {
    /// Issue a verifiable credential anchor on-chain.
    /// `credential_hash` = SHA-256(signed W3C VC or CF-native credential JSON).
    IssueCredential {
        credential_id: String,
        issuer_id: String,
        credential_hash: String,
    },
    /// Revoke a previously issued credential.
    RevokeCredential {
        credential_id: String,
        reason_code: String,
    },
    /// Register an accreditation body identity anchor.
    RegisterAccreditation {
        accreditor_id: String,
        accreditor_key_hash: String,
    },
    /// Anchor a batch credential issuance event (Merkle root of credential hashes).
    AnchorBatchCredentials {
        batch_id: String,
        merkle_root: String,
        count: u32,
    },
}

// ── Executor ──────────────────────────────────────────────────────────────────

pub struct EducationExecutor;

impl EducationExecutor {
    pub fn apply(
        tx: &EducationTx,
        ctx: &ExecutionContext,
        state: &mut TemplateState,
    ) -> TxResult {
        match ctx.template {
            crate::templates::InstitutionalTemplate::Education(_) => {}
            _ => return TxResult::cross_template_rejected(),
        }

        match tx {
            EducationTx::IssueCredential { credential_id, issuer_id, credential_hash } => {
                if credential_id.is_empty() || issuer_id.is_empty() {
                    return TxResult::err("credential_id and issuer_id must not be empty");
                }
                if !is_valid_hex64(credential_hash) {
                    return TxResult::err("credential_hash must be a 64-char hex SHA-256");
                }
                let k = key(&format!("credential/{}", credential_id));
                if state.contains_key(&k) {
                    return TxResult::err("credential already issued; revoke first to reissue");
                }
                // Check not revoked.
                let rev_k = key(&format!("revoked/{}", credential_id));
                if state.contains_key(&rev_k) {
                    return TxResult::err("credential was revoked; cannot reissue");
                }
                let v = format!("{}:{}", issuer_id, credential_hash);
                let entry = StateEntry::new(k.clone(), v.clone());
                state.set(k, v);
                TxResult::ok(vec![entry])
            }

            EducationTx::RevokeCredential { credential_id, reason_code } => {
                if credential_id.is_empty() {
                    return TxResult::err("credential_id must not be empty");
                }
                let k = key(&format!("credential/{}", credential_id));
                if !state.contains_key(&k) {
                    return TxResult::err("no such credential to revoke");
                }
                state.remove(&k);
                let rev_k = key(&format!("revoked/{}", credential_id));
                let entry = StateEntry::new(rev_k.clone(), reason_code.clone());
                state.set(rev_k, reason_code.clone());
                TxResult::ok(vec![entry])
            }

            EducationTx::RegisterAccreditation { accreditor_id, accreditor_key_hash } => {
                if accreditor_id.is_empty() {
                    return TxResult::err("accreditor_id must not be empty");
                }
                if !is_valid_hex64(accreditor_key_hash) {
                    return TxResult::err("accreditor_key_hash must be a 64-char hex SHA-256");
                }
                let k = key(&format!("accreditor/{}", accreditor_id));
                if state.contains_key(&k) {
                    return TxResult::err("accreditor already registered");
                }
                let entry = StateEntry::new(k.clone(), accreditor_key_hash.clone());
                state.set(k, accreditor_key_hash.clone());
                TxResult::ok(vec![entry])
            }

            EducationTx::AnchorBatchCredentials { batch_id, merkle_root, count } => {
                if batch_id.is_empty() {
                    return TxResult::err("batch_id must not be empty");
                }
                if !is_valid_hex64(merkle_root) {
                    return TxResult::err("merkle_root must be a 64-char hex SHA-256");
                }
                if *count == 0 {
                    return TxResult::err("batch count must be at least 1");
                }
                let k = key(&format!("batch/{}", batch_id));
                if state.contains_key(&k) {
                    return TxResult::err("batch already anchored");
                }
                let v = format!("{}:{}", merkle_root, count);
                let entry = StateEntry::new(k.clone(), v.clone());
                state.set(k, v);
                TxResult::ok(vec![entry])
            }
        }
    }
}

fn is_valid_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::{EducationConfig, InstitutionalTemplate};

    fn ctx() -> ExecutionContext {
        ExecutionContext::new(
            "edu-test-chain",
            1,
            "registrar-01",
            InstitutionalTemplate::Education(EducationConfig::default()),
        )
    }

    fn dummy_hash(b: u8) -> String {
        format!("{:0>64x}", b as u64)
    }

    #[test]
    fn issue_and_revoke_credential() {
        let mut state = TemplateState::new();
        let tx = EducationTx::IssueCredential {
            credential_id: "cred-001".into(),
            issuer_id: "univ-a".into(),
            credential_hash: dummy_hash(0xcc),
        };
        let r = EducationExecutor::apply(&tx, &ctx(), &mut state);
        assert!(r.success, "{:?}", r.error);
        assert!(state.contains_key("edu/credential/cred-001"));

        let rev = EducationTx::RevokeCredential {
            credential_id: "cred-001".into(),
            reason_code: "FRAUDULENT".into(),
        };
        let r2 = EducationExecutor::apply(&rev, &ctx(), &mut state);
        assert!(r2.success);
        assert!(!state.contains_key("edu/credential/cred-001"));
        assert!(state.contains_key("edu/revoked/cred-001"));
    }

    #[test]
    fn batch_anchor_idempotency_guard() {
        let mut state = TemplateState::new();
        let tx = EducationTx::AnchorBatchCredentials {
            batch_id: "batch-2026-05".into(),
            merkle_root: dummy_hash(0xdd),
            count: 100,
        };
        let r1 = EducationExecutor::apply(&tx, &ctx(), &mut state);
        assert!(r1.success);
        let r2 = EducationExecutor::apply(&tx, &ctx(), &mut state);
        assert!(!r2.success);
    }
}
