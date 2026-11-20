//! Corrections L1 transaction types and executor.
//!
//! # Privacy requirement
//! No identifiable custody records, case information, or personal data
//! may appear in transactions or state. Only commitment hashes and
//! anonymous chain-of-custody event markers are stored on-chain.
//! All plaintext records remain off-chain.

use serde::{Deserialize, Serialize};
use crate::execution::{ExecutionContext, StateEntry, TemplateState, TxResult};

const NS: &str = "cor/";

fn key(suffix: &str) -> String {
    format!("{}{}", NS, suffix)
}

// ── Transaction types ─────────────────────────────────────────────────────────

/// Corrections L1 transaction variants.
///
/// Custody record identifiers are opaque tokens, not names or case numbers.
/// All `commitment` fields are hex-encoded SHA-256 of off-chain records.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CorrectionsTx {
    /// Anchor a chain-of-custody transfer event.
    /// `custody_id` is an opaque token; `commitment` = SHA-256(transfer record).
    AnchorCustodyTransfer {
        custody_id: String,
        from_facility: String,
        to_facility: String,
        commitment: String,
    },
    /// Record an acknowledgment of custody receipt.
    /// `commitment` = SHA-256(receipt record).
    AcknowledgeCustody {
        custody_id: String,
        acknowledging_facility: String,
        commitment: String,
    },
    /// Anchor a chain-of-custody evidence record.
    /// `commitment` = SHA-256(evidence metadata).
    AnchorEvidence {
        evidence_id: String,
        commitment: String,
    },
    /// Register an oversight node identity anchor.
    OversightNodeRegistration {
        node_id: String,
        node_public_key_hash: String,
    },
}

// ── Executor ──────────────────────────────────────────────────────────────────

pub struct CorrectionsExecutor;

impl CorrectionsExecutor {
    pub fn apply(
        tx: &CorrectionsTx,
        ctx: &ExecutionContext,
        state: &mut TemplateState,
    ) -> TxResult {
        match ctx.template {
            crate::templates::InstitutionalTemplate::Corrections(_) => {}
            _ => return TxResult::cross_template_rejected(),
        }

        match tx {
            CorrectionsTx::AnchorCustodyTransfer { custody_id, from_facility, to_facility, commitment } => {
                if custody_id.is_empty() || from_facility.is_empty() || to_facility.is_empty() {
                    return TxResult::err("custody_id, from_facility, and to_facility must not be empty");
                }
                if !is_valid_hex64(commitment) {
                    return TxResult::err("commitment must be a 64-char hex SHA-256");
                }
                // Key includes block height for audit completeness.
                let k = key(&format!("custody/{}/{}", custody_id, ctx.block_height));
                let v = format!("{}->{}:{}", from_facility, to_facility, commitment);
                let entry = StateEntry::new(k.clone(), v.clone());
                state.set(k, v);
                TxResult::ok(vec![entry])
            }

            CorrectionsTx::AcknowledgeCustody { custody_id, acknowledging_facility, commitment } => {
                if custody_id.is_empty() || acknowledging_facility.is_empty() {
                    return TxResult::err("custody_id and acknowledging_facility must not be empty");
                }
                if !is_valid_hex64(commitment) {
                    return TxResult::err("commitment must be a 64-char hex SHA-256");
                }
                let k = key(&format!("ack/{}/{}", custody_id, ctx.block_height));
                let v = format!("{}:{}", acknowledging_facility, commitment);
                let entry = StateEntry::new(k.clone(), v.clone());
                state.set(k, v);
                TxResult::ok(vec![entry])
            }

            CorrectionsTx::AnchorEvidence { evidence_id, commitment } => {
                if evidence_id.is_empty() {
                    return TxResult::err("evidence_id must not be empty");
                }
                if !is_valid_hex64(commitment) {
                    return TxResult::err("commitment must be a 64-char hex SHA-256");
                }
                let k = key(&format!("evidence/{}", evidence_id));
                if state.contains_key(&k) {
                    return TxResult::err("evidence anchor already exists; evidence is immutable");
                }
                let entry = StateEntry::new(k.clone(), commitment.clone());
                state.set(k, commitment.clone());
                TxResult::ok(vec![entry])
            }

            CorrectionsTx::OversightNodeRegistration { node_id, node_public_key_hash } => {
                if node_id.is_empty() {
                    return TxResult::err("node_id must not be empty");
                }
                if !is_valid_hex64(node_public_key_hash) {
                    return TxResult::err("node_public_key_hash must be a 64-char hex SHA-256");
                }
                let k = key(&format!("oversight/{}", node_id));
                if state.contains_key(&k) {
                    return TxResult::err("oversight node already registered");
                }
                let entry = StateEntry::new(k.clone(), node_public_key_hash.clone());
                state.set(k, node_public_key_hash.clone());
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
    use crate::templates::{CorrectionsConfig, InstitutionalTemplate};

    fn ctx() -> ExecutionContext {
        ExecutionContext::new(
            "cor-test-chain",
            1,
            "facility-officer-01",
            InstitutionalTemplate::Corrections(CorrectionsConfig::default()),
        )
    }

    fn dummy_hash(b: u8) -> String {
        format!("{:0>64x}", b as u64)
    }

    #[test]
    fn anchor_custody_transfer_ok() {
        let mut state = TemplateState::new();
        let tx = CorrectionsTx::AnchorCustodyTransfer {
            custody_id: "token-001".into(),
            from_facility: "facility-a".into(),
            to_facility: "facility-b".into(),
            commitment: dummy_hash(0x22),
        };
        let r = CorrectionsExecutor::apply(&tx, &ctx(), &mut state);
        assert!(r.success, "{:?}", r.error);
        assert_eq!(r.mutations.len(), 1);
        assert!(r.mutations[0].key.starts_with("cor/custody/"));
    }

    #[test]
    fn evidence_immutable() {
        let mut state = TemplateState::new();
        let tx = CorrectionsTx::AnchorEvidence {
            evidence_id: "ev-001".into(),
            commitment: dummy_hash(0x33),
        };
        let r1 = CorrectionsExecutor::apply(&tx, &ctx(), &mut state);
        assert!(r1.success);
        let r2 = CorrectionsExecutor::apply(&tx, &ctx(), &mut state);
        assert!(!r2.success);
    }
}
