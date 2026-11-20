//! chain-forge-institutional
//!
//! Institutional Blockchain Creation Framework for Chain Forge.
//!
//! Provides versioned templates for permissioned institutional Layer-1
//! blockchains: Healthcare, Corrections, Education, and Enterprise.
//!
//! Each template validates a `ChainSpec` and produces a `GenesisArtifact`
//! whose JSON is compatible with `chain-forge-core::GenesisConfig`.
//! No private keys are ever included in generated artifacts.
//!
//! # Design rules (non-negotiable)
//! - Additive only: does not modify any existing Chain Forge crate.
//! - No real institutional data in tests.
//! - No native token or staking economics on institutional chains.
//! - Domain separator provides cross-chain isolation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod error;
pub mod templates;
pub mod genesis;
pub mod validator;
pub mod domain;
pub mod quorum;
pub mod identity;

pub use error::{InstError, InstResult};
pub use templates::{
    InstitutionalTemplate, HealthcareConfig, CorrectionsConfig,
    EducationConfig, EnterpriseConfig, EmergencyAccessPolicy,
    AuditPolicy, VcStandard,
};
pub use genesis::{GenesisBuilder, GenesisArtifact, GenesisCommitment, ValidatorCommitment};
pub use validator::{ValidatorPublicKey, ValidatorKeyType, ML_DSA_65_PUBLIC_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES};
pub use domain::TransactionDomain;
pub use quorum::{bft_quorum, BftParams};
pub use identity::{
    OrganizationId, HumanId, DeviceId, AgentId,
    RoleCredential, CredentialVerifier,
    KeyRegistry, KeyAuditEntry, KeyOperation,
    IdentityRegistry, OrgEntry, OrgStatus,
};

// ── Template identity ─────────────────────────────────────────────────────────

/// Opaque template identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateId(pub String);

impl TemplateId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Semantic version for a template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl TemplateVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    pub fn as_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ── Consensus and crypto policies ────────────────────────────────────────────

/// Consensus profile supported for institutional chains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusProfile {
    /// PQ-HotStuff-2 with ML-DSA-65 validator signatures.
    /// Requires `CryptoPolicy::MlDsa65` or `CryptoPolicy::Hybrid`.
    PqHotStuff2,
    /// Tendermint-style BFT (default for initial institutional chains).
    TendermintBft,
}

impl ConsensusProfile {
    /// Genesis JSON value for the `consensus.type` field.
    pub fn genesis_type_str(&self) -> &'static str {
        // Institutional chains always use proof-of-authority — the validator
        // set is defined at genesis and admission is governance-controlled.
        "proof-of-authority"
    }

    /// Genesis JSON value for the `consensus.bft_variant` field.
    pub fn bft_variant_str(&self) -> Option<&'static str> {
        match self {
            Self::PqHotStuff2 => Some("pq-hotstuff"),
            Self::TendermintBft => None, // Tendermint is the default; omit field.
        }
    }

    /// Whether this consensus profile requires ML-DSA-65 or Hybrid crypto.
    pub fn requires_pq_crypto(&self) -> bool {
        matches!(self, Self::PqHotStuff2)
    }
}

/// Cryptographic policy for institutional chains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoPolicy {
    /// FIPS 204 ML-DSA-65. Institutional default: post-quantum secure.
    /// Maps to genesis `signature_scheme = "pqc-native"`.
    MlDsa65,
    /// Ed25519 only. Legacy compatibility path; not recommended for
    /// new institutional deployments.
    Ed25519,
    /// Ed25519 + ML-DSA-65 combined. Transition policy.
    Hybrid,
}

impl CryptoPolicy {
    pub fn genesis_scheme_str(&self) -> &'static str {
        match self {
            Self::MlDsa65 => "pqc-native",
            Self::Ed25519 => "classical",
            Self::Hybrid  => "hybrid",
        }
    }

    pub fn genesis_pqc_algorithm_str(&self) -> Option<&'static str> {
        match self {
            Self::MlDsa65 | Self::Hybrid => Some("ml-dsa"),
            Self::Ed25519 => None,
        }
    }

    /// Expected public key size in bytes for placeholder generation.
    pub fn placeholder_key_bytes(&self) -> usize {
        match self {
            Self::MlDsa65 => crate::validator::ML_DSA_65_PUBLIC_KEY_BYTES,
            Self::Ed25519 => crate::validator::ED25519_PUBLIC_KEY_BYTES,
            Self::Hybrid  => crate::validator::ML_DSA_65_PUBLIC_KEY_BYTES,
        }
    }

    /// Key type string for the genesis validator commitment.
    pub fn key_type_str(&self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml-dsa-65",
            Self::Ed25519 => "ed25519",
            Self::Hybrid  => "hybrid",
        }
    }
}

// ── Governance and network configs ────────────────────────────────────────────

/// Governance configuration for an institutional chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Minimum fraction of validators required to pass a proposal (0–100).
    pub approval_threshold_pct: u32,
    /// Minimum number of blocks a passed proposal must wait before execution.
    pub execution_delay_blocks: u64,
    /// Whether constitutional (supermajority) governance is enabled.
    pub constitutional_governance: bool,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            approval_threshold_pct: 67,   // two-thirds
            execution_delay_blocks: 100,
            constitutional_governance: true,
        }
    }
}

/// Network configuration for an institutional chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// P2P listen port base. Validators use base + index for multi-node local setups.
    pub p2p_port: u16,
    /// RPC/API port base.
    pub rpc_port: u16,
    /// Maximum peer connections per node.
    pub max_peers: u32,
    /// Peer discovery strategy.
    pub discovery: PeerDiscovery,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            p2p_port: 27000,
            rpc_port: 8080,
            max_peers: 50,
            discovery: PeerDiscovery::Bootstrap,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerDiscovery {
    Mdns,
    Bootstrap,
    Both,
}

// ── Validator enrollment config ───────────────────────────────────────────────

/// A validator enrollment slot: a named slot with an optional public key
/// placeholder. Private keys are never included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEnrollment {
    pub label: String,
    /// Placeholder address derived from the label for genesis. Real deployments
    /// replace this with an actual ML-DSA-65 or Ed25519 public key commitment.
    pub address: String,
    /// Initial staking balance placeholder (institutional chains may use 0).
    pub balance: u64,
}

// ── ChainSpec ─────────────────────────────────────────────────────────────────

/// A fully specified institutional chain configuration.
/// Call `validate()` before passing to `GenesisBuilder`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSpec {
    pub template: InstitutionalTemplate,
    /// Globally unique chain identifier. Must be non-empty, ≤64 chars,
    /// and match `[a-z0-9][a-z0-9\-]{0,63}`.
    pub chain_id: String,
    /// Human-readable chain name.
    pub chain_name: String,
    /// Number of validators. Must satisfy 3f+1 BFT quorum (minimum 4).
    pub validator_count: u32,
    pub consensus: ConsensusProfile,
    pub crypto: CryptoPolicy,
    pub governance: GovernanceConfig,
    pub network: NetworkConfig,
    /// Block time in milliseconds. Institutional default: 3000ms.
    pub block_time_ms: u64,
}

impl ChainSpec {
    /// Validate the spec. Returns `Ok(())` if the spec is safe to build from.
    pub fn validate(&self) -> InstResult<()> {
        validate_chain_id(&self.chain_id)?;

        // BFT quorum: n >= 3f+1. With f=1 (tolerate 1 Byzantine), n >= 4.
        if self.validator_count < 4 {
            return Err(InstError::InvalidValidatorCount {
                count: self.validator_count,
                reason: "minimum 4 validators required (3f+1 with f=1 Byzantine fault tolerance)".into(),
            });
        }

        // PQ-HotStuff-2 requires post-quantum crypto.
        if self.consensus.requires_pq_crypto() && self.crypto == CryptoPolicy::Ed25519 {
            return Err(InstError::IncompatibleCryptoConsensus {
                consensus: format!("{:?}", self.consensus),
                crypto: format!("{:?}", self.crypto),
            });
        }

        // Governance threshold sanity.
        if self.governance.approval_threshold_pct == 0 || self.governance.approval_threshold_pct > 100 {
            return Err(InstError::InvalidGovernanceConfig(
                "approval_threshold_pct must be 1–100".into(),
            ));
        }

        // Block time sanity.
        if self.block_time_ms == 0 {
            return Err(InstError::InvalidConfig("block_time_ms must be > 0".into()));
        }

        Ok(())
    }

    /// Template identifier string for domain separator computation.
    pub fn template_id(&self) -> TemplateId {
        TemplateId(self.template.template_id_str().to_string())
    }

    /// Template version for domain separator computation.
    pub fn template_version(&self) -> TemplateVersion {
        TemplateVersion::new(0, 1, 0)
    }

    /// Compute the domain separator for this chain.
    ///
    /// `domain_separator = SHA-256(chain_id || "|" || template_id || "|" || version)`
    ///
    /// This value must be included in the signing context for all transactions
    /// and validator credentials on this chain, providing cross-chain replay
    /// protection.
    pub fn domain_separator(&self) -> [u8; 32] {
        let input = format!(
            "{}|{}|{}",
            self.chain_id,
            self.template_id().as_str(),
            self.template_version().as_string(),
        );
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hasher.finalize().into()
    }

    /// Hex-encoded domain separator.
    pub fn domain_separator_hex(&self) -> String {
        hex::encode(self.domain_separator())
    }

    /// Generate validator enrollment slots (no private keys).
    pub fn validator_enrollments(&self) -> Vec<ValidatorEnrollment> {
        (0..self.validator_count)
            .map(|i| ValidatorEnrollment {
                label: format!("{}-validator-{}", self.chain_id, i),
                address: format!("{}1validator{}", self.address_prefix(), i),
                balance: 0,
            })
            .collect()
    }

    fn address_prefix(&self) -> &'static str {
        match &self.template {
            InstitutionalTemplate::Healthcare(_) => "hlth",
            InstitutionalTemplate::Corrections(_) => "corr",
            InstitutionalTemplate::Education(_)   => "edu",
            InstitutionalTemplate::Enterprise(_)  => "ent",
        }
    }
}

/// Validate a chain ID: lowercase alphanumeric and hyphens, 1–64 chars,
/// must start with a letter or digit.
pub fn validate_chain_id(id: &str) -> InstResult<()> {
    if id.is_empty() {
        return Err(InstError::InvalidChainId("chain_id must not be empty".into()));
    }
    if id.len() > 64 {
        return Err(InstError::InvalidChainId(format!(
            "chain_id too long: {} chars (max 64)", id.len()
        )));
    }
    if !id.chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase() || c == '-') {
        return Err(InstError::InvalidChainId(format!(
            "chain_id '{}' contains invalid characters (only a-z, 0-9, '-' allowed)", id
        )));
    }
    if id.starts_with('-') || id.ends_with('-') {
        return Err(InstError::InvalidChainId(format!(
            "chain_id '{}' must not start or end with '-'", id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::*;

    fn healthcare_spec(chain_id: &str, validators: u32) -> ChainSpec {
        ChainSpec {
            template: InstitutionalTemplate::Healthcare(HealthcareConfig::default()),
            chain_id: chain_id.to_string(),
            chain_name: "Test Hospital Network".to_string(),
            validator_count: validators,
            consensus: ConsensusProfile::TendermintBft,
            crypto: CryptoPolicy::MlDsa65,
            governance: GovernanceConfig::default(),
            network: NetworkConfig::default(),
            block_time_ms: 3000,
        }
    }

    #[test]
    fn test_validate_valid_healthcare_spec() {
        let spec = healthcare_spec("hospital-network-1", 7);
        assert!(spec.validate().is_ok(), "7-validator healthcare spec must pass validation");
    }

    #[test]
    fn test_validate_rejects_low_validator_count() {
        let spec = healthcare_spec("hospital-network-low", 2);
        let result = spec.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            InstError::InvalidValidatorCount { count, .. } => assert_eq!(count, 2),
            e => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_genesis_determinism() {
        let spec = healthcare_spec("hospital-determinism-1", 4);
        spec.validate().expect("spec must be valid");
        // Use explicit timestamp for determinism.
        let artifact1 = GenesisBuilder::new(spec.clone()).with_explicit_timestamp(0).build().expect("build 1");
        let artifact2 = GenesisBuilder::new(spec).with_explicit_timestamp(0).build().expect("build 2");
        assert_eq!(
            artifact1.genesis_hash, artifact2.genesis_hash,
            "same spec+timestamp must produce identical genesis hash"
        );
    }

    #[test]
    fn test_chain_isolation() {
        let spec_a = healthcare_spec("hospital-a", 4);
        let spec_b = healthcare_spec("hospital-b", 4);
        spec_a.validate().expect("spec_a valid");
        spec_b.validate().expect("spec_b valid");

        let artifact_a = GenesisBuilder::new(spec_a.clone()).with_explicit_timestamp(0).build().expect("build a");
        let artifact_b = GenesisBuilder::new(spec_b.clone()).with_explicit_timestamp(0).build().expect("build b");

        assert_ne!(artifact_a.genesis_hash, artifact_b.genesis_hash,
            "different chain IDs must produce different genesis hashes");
        assert_ne!(spec_a.domain_separator_hex(), spec_b.domain_separator_hex(),
            "different chain IDs must produce different domain separators");
    }

    #[test]
    fn test_cross_chain_domain_separation() {
        let healthcare = ChainSpec {
            template: InstitutionalTemplate::Healthcare(HealthcareConfig::default()),
            chain_id: "shared-id-1".to_string(),
            chain_name: "Healthcare".to_string(),
            validator_count: 4,
            consensus: ConsensusProfile::TendermintBft,
            crypto: CryptoPolicy::MlDsa65,
            governance: GovernanceConfig::default(),
            network: NetworkConfig::default(),
            block_time_ms: 3000,
        };
        let corrections = ChainSpec {
            template: InstitutionalTemplate::Corrections(CorrectionsConfig::default()),
            chain_id: "shared-id-1".to_string(), // same chain_id on purpose
            chain_name: "Corrections".to_string(),
            validator_count: 4,
            consensus: ConsensusProfile::TendermintBft,
            crypto: CryptoPolicy::MlDsa65,
            governance: GovernanceConfig::default(),
            network: NetworkConfig::default(),
            block_time_ms: 3000,
        };
        // Even with the same chain_id, different templates produce different domain separators
        // because the template_id is part of the separator input.
        assert_ne!(
            healthcare.domain_separator_hex(),
            corrections.domain_separator_hex(),
            "different templates with same chain_id must produce different domain separators"
        );
    }

    #[test]
    fn test_all_four_templates_validate() {
        let specs = vec![
            ChainSpec {
                template: InstitutionalTemplate::Healthcare(HealthcareConfig::default()),
                chain_id: "test-healthcare-1".to_string(),
                chain_name: "Test Healthcare".to_string(),
                validator_count: 4,
                consensus: ConsensusProfile::TendermintBft,
                crypto: CryptoPolicy::MlDsa65,
                governance: GovernanceConfig::default(),
                network: NetworkConfig::default(),
                block_time_ms: 3000,
            },
            ChainSpec {
                template: InstitutionalTemplate::Corrections(CorrectionsConfig::default()),
                chain_id: "test-corrections-1".to_string(),
                chain_name: "Test Corrections".to_string(),
                validator_count: 4,
                consensus: ConsensusProfile::TendermintBft,
                crypto: CryptoPolicy::MlDsa65,
                governance: GovernanceConfig::default(),
                network: NetworkConfig::default(),
                block_time_ms: 3000,
            },
            ChainSpec {
                template: InstitutionalTemplate::Education(EducationConfig::default()),
                chain_id: "test-education-1".to_string(),
                chain_name: "Test Education".to_string(),
                validator_count: 4,
                consensus: ConsensusProfile::TendermintBft,
                crypto: CryptoPolicy::MlDsa65,
                governance: GovernanceConfig::default(),
                network: NetworkConfig::default(),
                block_time_ms: 3000,
            },
            ChainSpec {
                template: InstitutionalTemplate::Enterprise(EnterpriseConfig::default()),
                chain_id: "test-enterprise-1".to_string(),
                chain_name: "Test Enterprise".to_string(),
                validator_count: 4,
                consensus: ConsensusProfile::TendermintBft,
                crypto: CryptoPolicy::MlDsa65,
                governance: GovernanceConfig::default(),
                network: NetworkConfig::default(),
                block_time_ms: 3000,
            },
        ];

        for spec in &specs {
            assert!(
                spec.validate().is_ok(),
                "template {:?} must pass validation",
                spec.template.template_id_str()
            );
        }
    }

    // ── Phase 2 tests ─────────────────────────────────────────────────────────

    /// P2-1: Identical spec+timestamp must produce identical genesis hash.
    #[test]
    fn test_p2_genesis_determinism() {
        let spec = healthcare_spec("p2-determinism", 4);
        let a1 = GenesisBuilder::new(spec.clone()).with_explicit_timestamp(1000).build().unwrap();
        let a2 = GenesisBuilder::new(spec).with_explicit_timestamp(1000).build().unwrap();
        assert_eq!(a1.genesis_hash, a2.genesis_hash, "identical inputs must hash identically");
    }

    /// P2-2: Changing any consensus-relevant field must change the genesis hash.
    #[test]
    fn test_p2_genesis_mutation_detection() {
        let base = healthcare_spec("p2-mutation", 4);
        let base_hash = GenesisBuilder::new(base.clone()).with_explicit_timestamp(0).build().unwrap().genesis_hash;

        // Change chain_id.
        let mut s = base.clone(); s.chain_id = "p2-mutation-alt".to_string();
        let h = GenesisBuilder::new(s).with_explicit_timestamp(0).build().unwrap().genesis_hash;
        assert_ne!(base_hash, h, "changing chain_id must change genesis hash");

        // Change validator count (uses placeholder keys — count changes commitment).
        let mut s = base.clone(); s.validator_count = 7;
        let h = GenesisBuilder::new(s).with_explicit_timestamp(0).build().unwrap().genesis_hash;
        assert_ne!(base_hash, h, "changing validator_count must change genesis hash");

        // Change consensus profile.
        let mut s = base.clone();
        s.consensus = ConsensusProfile::PqHotStuff2;
        s.crypto = CryptoPolicy::MlDsa65; // compatible
        let h = GenesisBuilder::new(s).with_explicit_timestamp(0).build().unwrap().genesis_hash;
        assert_ne!(base_hash, h, "changing consensus must change genesis hash");

        // Change timestamp.
        let h = GenesisBuilder::new(base).with_explicit_timestamp(999).build().unwrap().genesis_hash;
        assert_ne!(base_hash, h, "changing timestamp must change genesis hash");
    }

    /// P2-3: Invalid chain IDs must be rejected.
    #[test]
    fn test_p2_invalid_chain_id_rejection() {
        // Empty.
        assert!(validate_chain_id("").is_err(), "empty chain_id must be rejected");
        // Too long (65 chars).
        let long: String = "a".repeat(65);
        assert!(validate_chain_id(&long).is_err(), "65-char chain_id must be rejected");
        // 64 chars: valid.
        let ok64: String = "a".repeat(64);
        assert!(validate_chain_id(&ok64).is_ok(), "64-char chain_id must be accepted");
        // Invalid chars.
        assert!(validate_chain_id("HospitalA").is_err(), "uppercase must be rejected");
        assert!(validate_chain_id("hospital_a").is_err(), "underscore must be rejected");
        assert!(validate_chain_id("hospital a").is_err(), "space must be rejected");
        // Leading/trailing hyphen.
        assert!(validate_chain_id("-hospital").is_err(), "leading hyphen must be rejected");
        assert!(validate_chain_id("hospital-").is_err(), "trailing hyphen must be rejected");
        // Valid.
        assert!(validate_chain_id("hospital-network-1").is_ok());
    }

    /// P2-4: Duplicate validator IDs and duplicate key bytes must be rejected.
    #[test]
    fn test_p2_duplicate_validator_rejection() {
        use crate::validator::ValidatorPublicKey;
        let spec = healthcare_spec("p2-dup-val", 4);

        // Duplicate ID.
        let result = GenesisBuilder::new(spec.clone())
            .with_explicit_timestamp(0)
            .with_validator("v0".into(), ValidatorPublicKey::test_mldsa_key_a()).unwrap()
            .with_validator("v0".into(), ValidatorPublicKey::test_mldsa_key_b()); // same ID
        assert!(result.is_err(), "duplicate validator_id must be rejected");

        // Duplicate key bytes.
        let result = GenesisBuilder::new(spec)
            .with_explicit_timestamp(0)
            .with_validator("v0".into(), ValidatorPublicKey::test_mldsa_key_a()).unwrap()
            .with_validator("v1".into(), ValidatorPublicKey::test_mldsa_key_a()); // same key
        assert!(result.is_err(), "duplicate public key bytes must be rejected");
    }

    /// P2-5: ML-DSA-65 key byte-length validation.
    #[test]
    fn test_p2_ml_dsa_key_length_validation() {
        use crate::validator::{ValidatorPublicKey, ValidatorKeyType, ML_DSA_65_PUBLIC_KEY_BYTES};

        // Correct size: accepted.
        let good = ValidatorPublicKey::new(ValidatorKeyType::MlDsa65, vec![0x01; ML_DSA_65_PUBLIC_KEY_BYTES]);
        assert!(good.validate().is_ok(), "1952-byte ML-DSA-65 key must be accepted");

        // One byte short: rejected.
        let short = ValidatorPublicKey::new(ValidatorKeyType::MlDsa65, vec![0x01; ML_DSA_65_PUBLIC_KEY_BYTES - 1]);
        assert!(short.validate().is_err(), "1951-byte ML-DSA-65 key must be rejected");

        // One byte over: rejected.
        let long = ValidatorPublicKey::new(ValidatorKeyType::MlDsa65, vec![0x01; ML_DSA_65_PUBLIC_KEY_BYTES + 1]);
        assert!(long.validate().is_err(), "1953-byte ML-DSA-65 key must be rejected");
    }

    /// P2-6: Cross-chain replay rejection via TransactionDomain.
    #[test]
    fn test_p2_cross_chain_replay_rejection() {
        use crate::domain::TransactionDomain;

        let domain_a = TransactionDomain {
            chain_id: "hospital-a".into(),
            genesis_hash: [0xAAu8; 32],
            protocol_version: 1,
            domain_label: "institutional-tx-v1".into(),
        };
        let domain_b = TransactionDomain {
            chain_id: "hospital-b".into(),
            genesis_hash: [0xBBu8; 32],
            protocol_version: 1,
            domain_label: "institutional-tx-v1".into(),
        };
        let domain_a_diff_genesis = TransactionDomain {
            chain_id: "hospital-a".into(),
            genesis_hash: [0xCCu8; 32],
            protocol_version: 1,
            domain_label: "institutional-tx-v1".into(),
        };

        // Same domain: accepted.
        assert!(domain_a.accepts(&domain_a.clone()));
        // Different chain_id: rejected.
        assert!(!domain_a.accepts(&domain_b), "different chain_id must be rejected");
        // Same chain_id but different genesis_hash: rejected.
        assert!(!domain_a.accepts(&domain_a_diff_genesis), "different genesis_hash must be rejected");
    }

    /// P2-7: BFT quorum table verification.
    #[test]
    fn test_p2_bft_quorum_table() {
        use crate::quorum::bft_quorum;
        let cases = [(4u32, 1u32, 3u32), (7, 2, 5), (10, 3, 7)];
        for (n, expected_f, expected_quorum) in cases {
            let p = bft_quorum(n).unwrap_or_else(|e| panic!("bft_quorum({n}) failed: {e}"));
            assert_eq!(p.f, expected_f, "n={n}: f");
            assert_eq!(p.quorum, expected_quorum, "n={n}: quorum");
        }
        for n in [1u32, 2, 3] {
            assert!(bft_quorum(n).is_err(), "n={n} should be rejected");
        }
    }

    /// P2-8: All four templates produce distinct genesis hashes for the same chain_id.
    #[test]
    fn test_p2_all_four_templates_genesis() {
        let chain_id = "shared-chain-id-p2";
        let make = |template: InstitutionalTemplate| {
            let spec = ChainSpec {
                template,
                chain_id: chain_id.to_string(),
                chain_name: "Test".into(),
                validator_count: 4,
                consensus: ConsensusProfile::TendermintBft,
                crypto: CryptoPolicy::MlDsa65,
                governance: GovernanceConfig::default(),
                network: NetworkConfig::default(),
                block_time_ms: 3000,
            };
            GenesisBuilder::new(spec).with_explicit_timestamp(0).build().unwrap().genesis_hash
        };

        let hashes = [
            make(InstitutionalTemplate::Healthcare(HealthcareConfig::default())),
            make(InstitutionalTemplate::Corrections(CorrectionsConfig::default())),
            make(InstitutionalTemplate::Education(EducationConfig::default())),
            make(InstitutionalTemplate::Enterprise(EnterpriseConfig::default())),
        ];

        for i in 0..hashes.len() {
            for j in (i+1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j],
                    "templates {} and {} must produce different genesis hashes", i, j);
            }
        }
    }

    /// P2-9: ChainSpec::validate() rejects invalid configurations.
    #[test]
    fn test_p2_cli_validation_errors() {
        // Too few validators.
        let bad = healthcare_spec("p2-cli-val", 2);
        assert!(bad.validate().is_err());

        // PQ-HotStuff with Ed25519: incompatible.
        let incompatible = ChainSpec {
            consensus: ConsensusProfile::PqHotStuff2,
            crypto: CryptoPolicy::Ed25519,
            ..healthcare_spec("p2-cli-incompat", 4)
        };
        assert!(incompatible.validate().is_err());

        // Zero block time.
        let bad_time = ChainSpec { block_time_ms: 0, ..healthcare_spec("p2-cli-time", 4) };
        assert!(bad_time.validate().is_err());
    }

    /// P2-10: Genesis JSON must not contain private key material.
    #[test]
    fn test_p2_genesis_no_private_keys() {
        let spec = healthcare_spec("p2-no-privkey", 4);
        let artifact = GenesisBuilder::new(spec).with_explicit_timestamp(0).build().unwrap();
        let json_str = artifact.to_json_string().unwrap();
        let lower = json_str.to_lowercase();
        assert!(!lower.contains("private"), "genesis JSON must not contain 'private'");
        assert!(!lower.contains("\"secret\""), "genesis JSON must not contain 'secret'");
        assert!(!lower.contains("sk_"), "genesis JSON must not contain 'sk_'");
        assert!(!lower.contains("\"private_key\""), "genesis JSON must not contain 'private_key'");
    }
}
