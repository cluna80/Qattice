//! Phase 4 integration tests: institutional template execution framework.
//!
//! 25 tests total:
//!   5 Healthcare template tests
//!   5 Corrections template tests
//!   5 Education template tests
//!   5 Enterprise template tests
//!   5 Cross-template isolation tests
//!
//! No real patient, student, inmate, or employee data is used.
//! All commitment values are synthetic hex strings.

use chain_forge_institutional::{
    execution::{ExecutionContext, TemplateState},
    healthcare::HealthcareTx,
    corrections::CorrectionsTx,
    education::EducationTx,
    enterprise::{EnterpriseTx, EnterpriseRole, AgentCapability},
    templates::{
        HealthcareConfig, CorrectionsConfig, EducationConfig, EnterpriseConfig,
        InstitutionalTemplate,
    },
};
use chain_forge_institutional::healthcare::HealthcareExecutor;
use chain_forge_institutional::corrections::CorrectionsExecutor;
use chain_forge_institutional::education::EducationExecutor;
use chain_forge_institutional::enterprise::EnterpriseExecutor;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// 64-char hex string with every byte set to `b`.
fn hex64(b: u8) -> String {
    format!("{:0>64}", format!("{:02x}", b).repeat(32))
}

fn hc_ctx(height: u64) -> ExecutionContext {
    ExecutionContext::new("hc-chain-01", height, "test-submitter",
        InstitutionalTemplate::Healthcare(HealthcareConfig::default()))
}

fn cor_ctx(height: u64) -> ExecutionContext {
    ExecutionContext::new("cor-chain-01", height, "test-submitter",
        InstitutionalTemplate::Corrections(CorrectionsConfig::default()))
}

fn edu_ctx(height: u64) -> ExecutionContext {
    ExecutionContext::new("edu-chain-01", height, "test-submitter",
        InstitutionalTemplate::Education(EducationConfig::default()))
}

fn ent_ctx(height: u64) -> ExecutionContext {
    ExecutionContext::new("ent-chain-01", height, "test-submitter",
        InstitutionalTemplate::Enterprise(EnterpriseConfig::default()))
}

// ── Healthcare template (5 tests) ────────────────────────────────────────────

#[test]
fn hc_01_anchor_fhir_commitment_stores_correct_key() {
    let mut state = TemplateState::new();
    let tx = HealthcareTx::AnchorFhirCommitment {
        resource_type: "Observation".into(),
        commitment: hex64(0x01),
    };
    let r = HealthcareExecutor::apply(&tx, &hc_ctx(1), &mut state);
    assert!(r.success, "expected success: {:?}", r.error);
    assert_eq!(r.mutations.len(), 1);
    assert!(r.mutations[0].key.starts_with("hc/fhir/Observation/"));
}

#[test]
fn hc_02_register_then_revoke_clinician() {
    let mut state = TemplateState::new();
    let hash = hex64(0x02);
    let reg = HealthcareTx::RegisterClinicianCredential {
        clinician_id: "cln-001".into(),
        credential_hash: hash.clone(),
    };
    assert!(HealthcareExecutor::apply(&reg, &hc_ctx(1), &mut state).success);
    assert!(state.contains_key("hc/credential/cln-001"));

    let rev = HealthcareTx::RevokeClinicianCredential {
        clinician_id: "cln-001".into(),
        reason_code: "LEFT_PRACTICE".into(),
    };
    let r = HealthcareExecutor::apply(&rev, &hc_ctx(2), &mut state);
    assert!(r.success, "{:?}", r.error);
    assert!(!state.contains_key("hc/credential/cln-001"));
    assert!(state.contains_key("hc/revoked/cln-001"));
}

#[test]
fn hc_03_duplicate_credential_registration_rejected() {
    let mut state = TemplateState::new();
    let tx = HealthcareTx::RegisterClinicianCredential {
        clinician_id: "cln-002".into(),
        credential_hash: hex64(0x03),
    };
    assert!(HealthcareExecutor::apply(&tx, &hc_ctx(1), &mut state).success);
    let r2 = HealthcareExecutor::apply(&tx, &hc_ctx(2), &mut state);
    assert!(!r2.success);
}

#[test]
fn hc_04_emergency_access_audit_per_block() {
    let mut state = TemplateState::new();
    let tx1 = HealthcareTx::RecordEmergencyAccess {
        clinician_id: "cln-003".into(),
        access_commitment: hex64(0x04),
    };
    let tx2 = HealthcareTx::RecordEmergencyAccess {
        clinician_id: "cln-003".into(),
        access_commitment: hex64(0x05),
    };
    // Different block heights → different keys → both succeed.
    assert!(HealthcareExecutor::apply(&tx1, &hc_ctx(10), &mut state).success);
    assert!(HealthcareExecutor::apply(&tx2, &hc_ctx(11), &mut state).success);
    assert!(state.contains_key("hc/emergency/cln-003/10"));
    assert!(state.contains_key("hc/emergency/cln-003/11"));
}

#[test]
fn hc_05_invalid_commitment_hash_rejected() {
    let mut state = TemplateState::new();
    let tx = HealthcareTx::AnchorFhirCommitment {
        resource_type: "Condition".into(),
        commitment: "not-hex".into(),
    };
    let r = HealthcareExecutor::apply(&tx, &hc_ctx(1), &mut state);
    assert!(!r.success);
    assert!(r.error.unwrap().contains("64-char hex"));
}

// ── Corrections template (5 tests) ───────────────────────────────────────────

#[test]
fn cor_01_custody_transfer_stores_route() {
    let mut state = TemplateState::new();
    let tx = CorrectionsTx::AnchorCustodyTransfer {
        custody_id: "tok-001".into(),
        from_facility: "facility-a".into(),
        to_facility: "facility-b".into(),
        commitment: hex64(0x11),
    };
    let r = CorrectionsExecutor::apply(&tx, &cor_ctx(1), &mut state);
    assert!(r.success, "{:?}", r.error);
    let v = state.get("cor/custody/tok-001/1").expect("state entry missing");
    assert!(v.contains("facility-a->facility-b"));
}

#[test]
fn cor_02_acknowledge_custody_ok() {
    let mut state = TemplateState::new();
    let tx = CorrectionsTx::AcknowledgeCustody {
        custody_id: "tok-002".into(),
        acknowledging_facility: "facility-b".into(),
        commitment: hex64(0x12),
    };
    let r = CorrectionsExecutor::apply(&tx, &cor_ctx(5), &mut state);
    assert!(r.success, "{:?}", r.error);
    assert!(state.contains_key("cor/ack/tok-002/5"));
}

#[test]
fn cor_03_evidence_immutable_after_anchor() {
    let mut state = TemplateState::new();
    let tx = CorrectionsTx::AnchorEvidence {
        evidence_id: "ev-001".into(),
        commitment: hex64(0x13),
    };
    assert!(CorrectionsExecutor::apply(&tx, &cor_ctx(1), &mut state).success);
    let r2 = CorrectionsExecutor::apply(&tx, &cor_ctx(2), &mut state);
    assert!(!r2.success);
    assert!(r2.error.unwrap().contains("immutable"));
}

#[test]
fn cor_04_oversight_node_registration_idempotency_guard() {
    let mut state = TemplateState::new();
    let tx = CorrectionsTx::OversightNodeRegistration {
        node_id: "oversight-01".into(),
        node_public_key_hash: hex64(0x14),
    };
    assert!(CorrectionsExecutor::apply(&tx, &cor_ctx(1), &mut state).success);
    let r2 = CorrectionsExecutor::apply(&tx, &cor_ctx(2), &mut state);
    assert!(!r2.success);
}

#[test]
fn cor_05_empty_custody_id_rejected() {
    let mut state = TemplateState::new();
    let tx = CorrectionsTx::AnchorCustodyTransfer {
        custody_id: "".into(),
        from_facility: "fa".into(),
        to_facility: "fb".into(),
        commitment: hex64(0x15),
    };
    let r = CorrectionsExecutor::apply(&tx, &cor_ctx(1), &mut state);
    assert!(!r.success);
}

// ── Education template (5 tests) ─────────────────────────────────────────────

#[test]
fn edu_01_issue_credential_ok() {
    let mut state = TemplateState::new();
    let tx = EducationTx::IssueCredential {
        credential_id: "cred-001".into(),
        issuer_id: "univ-a".into(),
        credential_hash: hex64(0x21),
    };
    let r = EducationExecutor::apply(&tx, &edu_ctx(1), &mut state);
    assert!(r.success, "{:?}", r.error);
    assert!(state.contains_key("edu/credential/cred-001"));
}

#[test]
fn edu_02_revoke_credential_then_cannot_reissue() {
    let mut state = TemplateState::new();
    let issue = EducationTx::IssueCredential {
        credential_id: "cred-002".into(),
        issuer_id: "univ-b".into(),
        credential_hash: hex64(0x22),
    };
    assert!(EducationExecutor::apply(&issue, &edu_ctx(1), &mut state).success);

    let rev = EducationTx::RevokeCredential {
        credential_id: "cred-002".into(),
        reason_code: "ERROR".into(),
    };
    assert!(EducationExecutor::apply(&rev, &edu_ctx(2), &mut state).success);

    // Reissuing a revoked credential must be rejected.
    let reissue = EducationTx::IssueCredential {
        credential_id: "cred-002".into(),
        issuer_id: "univ-b".into(),
        credential_hash: hex64(0x23),
    };
    let r = EducationExecutor::apply(&reissue, &edu_ctx(3), &mut state);
    assert!(!r.success);
}

#[test]
fn edu_03_batch_credential_anchor_ok() {
    let mut state = TemplateState::new();
    let tx = EducationTx::AnchorBatchCredentials {
        batch_id: "batch-2026-05".into(),
        merkle_root: hex64(0x24),
        count: 50,
    };
    let r = EducationExecutor::apply(&tx, &edu_ctx(1), &mut state);
    assert!(r.success, "{:?}", r.error);
    let v = state.get("edu/batch/batch-2026-05").expect("batch missing");
    assert!(v.contains("50"));
}

#[test]
fn edu_04_register_accreditor_ok() {
    let mut state = TemplateState::new();
    let tx = EducationTx::RegisterAccreditation {
        accreditor_id: "accred-regional-01".into(),
        accreditor_key_hash: hex64(0x25),
    };
    let r = EducationExecutor::apply(&tx, &edu_ctx(1), &mut state);
    assert!(r.success, "{:?}", r.error);
    assert!(state.contains_key("edu/accreditor/accred-regional-01"));
}

#[test]
fn edu_05_zero_count_batch_rejected() {
    let mut state = TemplateState::new();
    let tx = EducationTx::AnchorBatchCredentials {
        batch_id: "batch-empty".into(),
        merkle_root: hex64(0x26),
        count: 0,
    };
    let r = EducationExecutor::apply(&tx, &edu_ctx(1), &mut state);
    assert!(!r.success);
}

// ── Enterprise template (5 tests) ────────────────────────────────────────────

#[test]
fn ent_01_enroll_member_ok() {
    let mut state = TemplateState::new();
    let tx = EnterpriseTx::EnrollMember {
        org_id: "org-a".into(),
        member_id: "user-001".into(),
        role: EnterpriseRole::Member,
        key_hash: hex64(0x31),
    };
    let r = EnterpriseExecutor::apply(&tx, &ent_ctx(1), &mut state);
    assert!(r.success, "{:?}", r.error);
    assert!(state.contains_key("ent/member/org-a/user-001"));
}

#[test]
fn ent_02_authorize_agent_with_capabilities() {
    let mut state = TemplateState::new();
    let tx = EnterpriseTx::AuthorizeAgent {
        agent_id: "agent-001".into(),
        org_id: "org-a".into(),
        capabilities: vec![AgentCapability::ReadState, AgentCapability::AnchorProvenance],
        key_hash: hex64(0x32),
    };
    let r = EnterpriseExecutor::apply(&tx, &ent_ctx(1), &mut state);
    assert!(r.success, "{:?}", r.error);
    assert!(state.contains_key("ent/agent/org-a/agent-001"));
}

#[test]
fn ent_03_anchor_provenance_per_block() {
    let mut state = TemplateState::new();
    let tx = EnterpriseTx::AnchorProvenance {
        item_id: "item-001".into(),
        event_type: "SHIPPED".into(),
        commitment: hex64(0x33),
    };
    let r = EnterpriseExecutor::apply(&tx, &ent_ctx(42), &mut state);
    assert!(r.success, "{:?}", r.error);
    assert!(state.contains_key("ent/provenance/item-001/42"));
}

#[test]
fn ent_04_governance_proposal_idempotency_guard() {
    let mut state = TemplateState::new();
    let tx = EnterpriseTx::SubmitGovernanceProposal {
        proposal_id: "prop-001".into(),
        proposer_id: "admin-01".into(),
        commitment: hex64(0x34),
    };
    assert!(EnterpriseExecutor::apply(&tx, &ent_ctx(1), &mut state).success);
    let r2 = EnterpriseExecutor::apply(&tx, &ent_ctx(2), &mut state);
    assert!(!r2.success);
}

#[test]
fn ent_05_agent_requires_at_least_one_capability() {
    let mut state = TemplateState::new();
    let tx = EnterpriseTx::AuthorizeAgent {
        agent_id: "agent-002".into(),
        org_id: "org-b".into(),
        capabilities: vec![],
        key_hash: hex64(0x35),
    };
    let r = EnterpriseExecutor::apply(&tx, &ent_ctx(1), &mut state);
    assert!(!r.success);
    assert!(r.error.unwrap().contains("capability"));
}

// ── Cross-template isolation (5 tests) ───────────────────────────────────────

#[test]
fn iso_01_healthcare_tx_rejected_by_corrections_executor() {
    let mut state = TemplateState::new();
    let hc_tx = HealthcareTx::AnchorFhirCommitment {
        resource_type: "Observation".into(),
        commitment: hex64(0x41),
    };
    // Build a Corrections context but submit a Healthcare tx.
    let r = HealthcareExecutor::apply(&hc_tx, &cor_ctx(1), &mut state);
    assert!(!r.success);
    assert_eq!(r.error.as_deref(), Some("cross-template transaction rejected"));
}

#[test]
fn iso_02_corrections_tx_rejected_by_healthcare_executor() {
    let mut state = TemplateState::new();
    let cor_tx = CorrectionsTx::AnchorEvidence {
        evidence_id: "ev-x".into(),
        commitment: hex64(0x42),
    };
    let r = CorrectionsExecutor::apply(&cor_tx, &hc_ctx(1), &mut state);
    assert!(!r.success);
    assert_eq!(r.error.as_deref(), Some("cross-template transaction rejected"));
}

#[test]
fn iso_03_education_tx_rejected_by_enterprise_executor() {
    let mut state = TemplateState::new();
    let edu_tx = EducationTx::IssueCredential {
        credential_id: "cred-x".into(),
        issuer_id: "univ-x".into(),
        credential_hash: hex64(0x43),
    };
    let r = EducationExecutor::apply(&edu_tx, &ent_ctx(1), &mut state);
    assert!(!r.success);
    assert_eq!(r.error.as_deref(), Some("cross-template transaction rejected"));
}

#[test]
fn iso_04_enterprise_tx_rejected_by_education_executor() {
    let mut state = TemplateState::new();
    let ent_tx = EnterpriseTx::EnrollMember {
        org_id: "org-x".into(),
        member_id: "user-x".into(),
        role: EnterpriseRole::Admin,
        key_hash: hex64(0x44),
    };
    let r = EnterpriseExecutor::apply(&ent_tx, &edu_ctx(1), &mut state);
    assert!(!r.success);
    assert_eq!(r.error.as_deref(), Some("cross-template transaction rejected"));
}

#[test]
fn iso_05_cross_template_rejection_leaves_state_unchanged() {
    let mut state = TemplateState::new();
    // Pre-populate state with a healthcare entry.
    let valid_hc = HealthcareTx::AnchorFhirCommitment {
        resource_type: "Observation".into(),
        commitment: hex64(0x45),
    };
    assert!(HealthcareExecutor::apply(&valid_hc, &hc_ctx(1), &mut state).success);
    let initial_entries = state.entries();

    // Now try to apply a Corrections tx through the Healthcare executor.
    let cor_tx = CorrectionsTx::AnchorEvidence {
        evidence_id: "ev-y".into(),
        commitment: hex64(0x46),
    };
    let r = CorrectionsExecutor::apply(&cor_tx, &hc_ctx(2), &mut state);
    assert!(!r.success);

    // State must be unchanged.
    assert_eq!(state.entries(), initial_entries);
}
