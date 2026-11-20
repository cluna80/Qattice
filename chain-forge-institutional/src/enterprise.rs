//! Enterprise L1 transaction types and executor.
//!
//! Enterprise chains support multi-org consortium governance, AI agent
//! authorization, and supply chain provenance anchoring. All sensitive
//! business data remains off-chain; only commitment hashes and authorization
//! anchors are written to chain state.

use serde::{Deserialize, Serialize};
use crate::execution::{ExecutionContext, StateEntry, TemplateState, TxResult};

const NS: &str = "ent/";

fn key(suffix: &str) -> String {
    format!("{}{}", NS, suffix)
}

// ── Role and capability types ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseRole {
    Admin,
    Member,
    Auditor,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCapability {
    ReadState,
    AnchorProvenance,
    SubmitProposals,
}

// ── Transaction types ─────────────────────────────────────────────────────────

/// Enterprise L1 transaction variants.
///
/// All `commitment` fields are hex-encoded SHA-256 of off-chain records.
/// Organization and agent identifiers are opaque tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum EnterpriseTx {
    /// Enroll a new organization member with a role.
    EnrollMember {
        org_id: String,
        member_id: String,
        role: EnterpriseRole,
        key_hash: String,
    },
    /// Authorize an AI agent with explicit capability grants.
    AuthorizeAgent {
        agent_id: String,
        org_id: String,
        capabilities: Vec<AgentCapability>,
        key_hash: String,
    },
    /// Anchor a supply chain provenance event.
    /// `commitment` = SHA-256(provenance record JSON).
    AnchorProvenance {
        item_id: String,
        event_type: String,
        commitment: String,
    },
    /// Submit a governance proposal commitment.
    /// `commitment` = SHA-256(proposal body).
    SubmitGovernanceProposal {
        proposal_id: String,
        proposer_id: String,
        commitment: String,
    },
}

// ── Executor ──────────────────────────────────────────────────────────────────

pub struct EnterpriseExecutor;

impl EnterpriseExecutor {
    pub fn apply(
        tx: &EnterpriseTx,
        ctx: &ExecutionContext,
        state: &mut TemplateState,
    ) -> TxResult {
        match ctx.template {
            crate::templates::InstitutionalTemplate::Enterprise(_) => {}
            _ => return TxResult::cross_template_rejected(),
        }

        match tx {
            EnterpriseTx::EnrollMember { org_id, member_id, role, key_hash } => {
                if org_id.is_empty() || member_id.is_empty() {
                    return TxResult::err("org_id and member_id must not be empty");
                }
                if !is_valid_hex64(key_hash) {
                    return TxResult::err("key_hash must be a 64-char hex SHA-256");
                }
                let k = key(&format!("member/{}/{}", org_id, member_id));
                let v = format!("{:?}:{}", role, key_hash);
                let entry = StateEntry::new(k.clone(), v.clone());
                state.set(k, v);
                TxResult::ok(vec![entry])
            }

            EnterpriseTx::AuthorizeAgent { agent_id, org_id, capabilities, key_hash } => {
                if agent_id.is_empty() || org_id.is_empty() {
                    return TxResult::err("agent_id and org_id must not be empty");
                }
                if !is_valid_hex64(key_hash) {
                    return TxResult::err("key_hash must be a 64-char hex SHA-256");
                }
                if capabilities.is_empty() {
                    return TxResult::err("at least one capability must be granted");
                }
                let k = key(&format!("agent/{}/{}", org_id, agent_id));
                let caps: Vec<String> = capabilities.iter().map(|c| format!("{:?}", c)).collect();
                let v = format!("{}:{}", key_hash, caps.join(","));
                let entry = StateEntry::new(k.clone(), v.clone());
                state.set(k, v);
                TxResult::ok(vec![entry])
            }

            EnterpriseTx::AnchorProvenance { item_id, event_type, commitment } => {
                if item_id.is_empty() || event_type.is_empty() {
                    return TxResult::err("item_id and event_type must not be empty");
                }
                if !is_valid_hex64(commitment) {
                    return TxResult::err("commitment must be a 64-char hex SHA-256");
                }
                let k = key(&format!("provenance/{}/{}", item_id, ctx.block_height));
                let v = format!("{}:{}", event_type, commitment);
                let entry = StateEntry::new(k.clone(), v.clone());
                state.set(k, v);
                TxResult::ok(vec![entry])
            }

            EnterpriseTx::SubmitGovernanceProposal { proposal_id, proposer_id, commitment } => {
                if proposal_id.is_empty() || proposer_id.is_empty() {
                    return TxResult::err("proposal_id and proposer_id must not be empty");
                }
                if !is_valid_hex64(commitment) {
                    return TxResult::err("commitment must be a 64-char hex SHA-256");
                }
                let k = key(&format!("proposal/{}", proposal_id));
                if state.contains_key(&k) {
                    return TxResult::err("proposal_id already exists");
                }
                let v = format!("{}:{}", proposer_id, commitment);
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
    use crate::templates::{EnterpriseConfig, InstitutionalTemplate};

    fn ctx() -> ExecutionContext {
        ExecutionContext::new(
            "ent-test-chain",
            1,
            "admin-01",
            InstitutionalTemplate::Enterprise(EnterpriseConfig::default()),
        )
    }

    fn dummy_hash(b: u8) -> String {
        format!("{:0>64x}", b as u64)
    }

    #[test]
    fn enroll_member_ok() {
        let mut state = TemplateState::new();
        let tx = EnterpriseTx::EnrollMember {
            org_id: "org-a".into(),
            member_id: "user-01".into(),
            role: EnterpriseRole::Member,
            key_hash: dummy_hash(0x44),
        };
        let r = EnterpriseExecutor::apply(&tx, &ctx(), &mut state);
        assert!(r.success, "{:?}", r.error);
        assert!(state.contains_key("ent/member/org-a/user-01"));
    }

    #[test]
    fn authorize_agent_requires_capability() {
        let mut state = TemplateState::new();
        let tx = EnterpriseTx::AuthorizeAgent {
            agent_id: "agent-01".into(),
            org_id: "org-a".into(),
            capabilities: vec![],
            key_hash: dummy_hash(0x55),
        };
        let r = EnterpriseExecutor::apply(&tx, &ctx(), &mut state);
        assert!(!r.success);
    }
}
