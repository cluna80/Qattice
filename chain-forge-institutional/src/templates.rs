//! Four institutional template configurations.
//!
//! Each template captures the institutional-specific policy settings that
//! differ between chain types. These are build-time configuration values;
//! they do not store any real institutional data.

use serde::{Deserialize, Serialize};

// ── Template enum ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InstitutionalTemplate {
    Healthcare(HealthcareConfig),
    Corrections(CorrectionsConfig),
    Education(EducationConfig),
    Enterprise(EnterpriseConfig),
}

impl InstitutionalTemplate {
    pub fn template_id_str(&self) -> &'static str {
        match self {
            Self::Healthcare(_)  => "healthcare-l1",
            Self::Corrections(_) => "corrections-l1",
            Self::Education(_)   => "education-l1",
            Self::Enterprise(_)  => "enterprise-l1",
        }
    }

    /// Genesis modules appropriate for this template.
    /// All institutional chains include bank, identity, and governance.
    pub fn genesis_modules(&self) -> Vec<String> {
        let mut modules = vec![
            "bank".to_string(),
            "identity".to_string(),
            "governance".to_string(),
        ];
        match self {
            Self::Enterprise(cfg) if cfg.ai_agent_support => {
                modules.push("agents".to_string());
            }
            _ => {}
        }
        modules
    }
}

// ── Template A: Healthcare L1 ─────────────────────────────────────────────────

/// Healthcare L1 configuration.
///
/// Actual medical records must remain off-chain.
/// Only commitments (hashes, Merkle roots, audit anchors) are written on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcareConfig {
    /// Whether the chain supports HL7 FHIR commitment anchors.
    /// Commitment = SHA-256(FHIR resource JSON), not raw FHIR data.
    pub fhir_integration: bool,
    /// Emergency access policy: who can read a patient's credential anchor
    /// in a declared emergency without the patient's online consent.
    pub emergency_access_policy: EmergencyAccessPolicy,
    /// Audit log policy: how long audit anchors are retained on-chain.
    pub audit_log_policy: AuditPolicy,
    /// Whether clinician role credentials require on-chain institutional attestation.
    pub clinician_credential_attestation: bool,
}

impl Default for HealthcareConfig {
    fn default() -> Self {
        Self {
            fhir_integration: true,
            emergency_access_policy: EmergencyAccessPolicy::BreakGlass,
            audit_log_policy: AuditPolicy::RetainIndefinitely,
            clinician_credential_attestation: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyAccessPolicy {
    /// Break-glass: emergency access is logged but not blocked. The access
    /// event is committed to chain as an audit anchor.
    BreakGlass,
    /// Multi-party: requires attestation from N authorized parties before
    /// emergency access is granted.
    MultiParty { required_approvers: u32 },
    /// No emergency override: the chain enforces normal access controls even
    /// in emergencies. Use only where operational continuity is not required.
    NoOverride,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPolicy {
    /// Retain audit anchors indefinitely (append-only, no pruning).
    RetainIndefinitely,
    /// Retain for N blocks, then prune (requires state pruning support).
    RetainForBlocks(u64),
    /// Retain for a fixed number of epochs.
    RetainForEpochs(u64),
}

// ── Template B: Corrections L1 ───────────────────────────────────────────────

/// Corrections L1 configuration.
///
/// Identifiable custody records and sensitive case information must remain
/// off-chain. Only commitments and custody chain-of-custody hashes are
/// written to blockchain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrectionsConfig {
    /// Whether authorized interagency record transfers are supported.
    pub interagency_transfer: bool,
    /// Number of independent oversight nodes (read-only validators) that
    /// receive the full block stream but do not vote.
    pub oversight_nodes: u32,
    /// Whether chain-of-custody evidence anchoring is enabled.
    pub chain_of_custody: bool,
    /// Whether record correction and appeals proposals are supported
    /// through on-chain governance.
    pub record_appeals: bool,
}

impl Default for CorrectionsConfig {
    fn default() -> Self {
        Self {
            interagency_transfer: true,
            oversight_nodes: 1,
            chain_of_custody: true,
            record_appeals: true,
        }
    }
}

// ── Template C: Education L1 ──────────────────────────────────────────────────

/// Education L1 configuration.
///
/// Student education records (FERPA-covered or equivalent) must remain
/// off-chain. On-chain state stores only verifiable credential anchors
/// and revocation markers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EducationConfig {
    /// Verifiable credential standard used for diplomas and transcripts.
    pub vc_standard: VcStandard,
    /// Whether FERPA-compatible privacy protections are enforced.
    /// When true, the chain rejects transactions that would write
    /// identifiable student record data to on-chain state.
    pub ferpa_mode: bool,
    /// Whether credential revocation anchors are supported.
    pub credential_revocation: bool,
    /// Whether institutional accreditation identity is supported.
    pub accreditation_identity: bool,
}

impl Default for EducationConfig {
    fn default() -> Self {
        Self {
            vc_standard: VcStandard::W3cVc,
            ferpa_mode: true,
            credential_revocation: true,
            accreditation_identity: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VcStandard {
    /// W3C Verifiable Credentials (https://www.w3.org/TR/vc-data-model/).
    W3cVc,
    /// Chain Forge native credential format (simpler, on-chain only).
    ChainForgeNative,
}

// ── Template D: Enterprise L1 ─────────────────────────────────────────────────

/// Enterprise L1 configuration.
///
/// Enterprise-specific business records must remain protected from
/// unauthorized consortium participants.
/// Only commitment hashes and authorization anchors are written on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseConfig {
    /// Whether multi-organization consortium governance is supported.
    pub multi_org_governance: bool,
    /// Whether AI agent authorization is supported (requires `agents` module).
    pub ai_agent_support: bool,
    /// Whether supply chain provenance anchoring is supported.
    pub supply_chain_provenance: bool,
    /// Whether privacy-preserving audit evidence (commitment-only) is enforced.
    pub privacy_audit: bool,
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self {
            multi_org_governance: true,
            ai_agent_support: true,
            supply_chain_provenance: true,
            privacy_audit: true,
        }
    }
}
