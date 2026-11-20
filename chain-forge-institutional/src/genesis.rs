//! Genesis artifact builder for institutional chains.
//!
//! Produces a JSON genesis document compatible with chain-forge-core's
//! GenesisConfig schema. The genesis hash is deterministic: the same
//! inputs always produce the same hash.
//!
//! # Determinism
//! Use `GenesisBuilder::with_explicit_timestamp(ts)` to fix the genesis
//! timestamp for reproducible hashes. Without it, the builder uses
//! `chrono::Utc::now()` which changes the hash on each call.
//!
//! # Validator keys
//! Use `GenesisBuilder::with_validator(id, key)` to bind real (or test-vector)
//! public keys. Duplicate IDs or duplicate key bytes are rejected. Private keys
//! are never accepted.
//!
//! # Canonical serialization
//! The genesis commitment is serialized to JSON with lexicographically sorted
//! keys via serde_json (which sorts object keys by default). Validator
//! commitments are sorted by validator_id before hashing.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use crate::{ChainSpec, InstError, InstResult};
use crate::validator::ValidatorPublicKey;

// ── Commitment types ──────────────────────────────────────────────────────────

/// A single validator's cryptographic commitment in the genesis.
/// Private keys are never stored here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorCommitment {
    /// Unique validator identifier within this chain.
    pub validator_id: String,
    /// Raw public key bytes (ML-DSA-65 = 1952 bytes, Ed25519 = 32 bytes).
    pub public_key_bytes: Vec<u8>,
    /// Key type string: "ml-dsa-65" or "ed25519".
    pub public_key_type: String,
    /// Voting weight. Institutional chains use equal weight (1) by default.
    pub voting_weight: u64,
}

/// The complete, consensus-relevant genesis commitment.
///
/// All fields are included in the genesis hash. Changing any field changes
/// the hash, subject to SHA-256 collision resistance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisCommitment {
    pub chain_id: String,
    pub template_id: String,
    pub template_version: String,
    pub consensus_profile: String,
    pub crypto_policy: String,
    pub protocol_version: String,
    /// Unix epoch seconds. Must be set explicitly for reproducible hashes.
    pub genesis_timestamp: u64,
    /// Sorted by validator_id for canonical ordering.
    pub validator_commitments: Vec<ValidatorCommitment>,
    /// SHA-256 of serialized governance config (hex).
    pub governance_config_hash: String,
    /// SHA-256 of initial state (all-zero for empty state, hex).
    pub initial_state_root: String,
    /// Domain separator for this chain (hex).
    pub domain_separator: String,
}

impl GenesisCommitment {
    /// Canonical JSON bytes for hashing.
    ///
    /// Validator commitments are sorted by validator_id. serde_json preserves
    /// insertion order for objects, so we serialize the struct fields in
    /// declaration order (which is deterministic) after sorting validators.
    pub fn canonical_bytes(&self) -> InstResult<Vec<u8>> {
        // Rebuild with sorted validators for canonical ordering.
        let mut sorted = self.clone();
        sorted.validator_commitments.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        serde_json::to_vec(&sorted)
            .map_err(|e| InstError::GenesisBuildError(format!("canonical serialization failed: {e}")))
    }

    /// SHA-256 hash of the canonical commitment bytes (hex).
    pub fn hash(&self) -> InstResult<String> {
        let bytes = self.canonical_bytes()?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
}

// ── GenesisArtifact ───────────────────────────────────────────────────────────

/// A fully built genesis artifact.
#[derive(Debug, Clone)]
pub struct GenesisArtifact {
    /// The genesis document as a JSON value (chain-forge-core compatible).
    pub genesis_json: Value,
    /// The structured commitment that was hashed.
    pub commitment: GenesisCommitment,
    /// SHA-256 hex hash of the canonical commitment.
    pub genesis_hash: String,
    /// Hex-encoded domain separator for this chain.
    pub domain_separator: String,
}

impl GenesisArtifact {
    /// Serialize the genesis document to a pretty-printed JSON string.
    pub fn to_json_string(&self) -> InstResult<String> {
        serde_json::to_string_pretty(&self.genesis_json)
            .map_err(|e| InstError::SerializationError(e.to_string()))
    }

    /// Serialize the full artifact (commitment + genesis JSON) for deployment.
    pub fn to_deployment_json(&self) -> InstResult<String> {
        let obj = json!({
            "genesis_hash": self.genesis_hash,
            "domain_separator": self.domain_separator,
            "commitment": self.commitment,
            "genesis": self.genesis_json,
        });
        serde_json::to_string_pretty(&obj)
            .map_err(|e| InstError::SerializationError(e.to_string()))
    }
}

// ── GenesisBuilder ────────────────────────────────────────────────────────────

/// Builds a `GenesisArtifact` from a validated `ChainSpec`.
///
/// # Usage
/// ```rust,ignore
/// let artifact = GenesisBuilder::new(spec)
///     .with_explicit_timestamp(0)
///     .with_validator("v0".into(), ValidatorPublicKey::test_mldsa_key_a())
///     .build()?;
/// ```
pub struct GenesisBuilder {
    spec: ChainSpec,
    explicit_timestamp: Option<u64>,
    validators: Vec<(String, ValidatorPublicKey)>,
}

impl GenesisBuilder {
    pub fn new(spec: ChainSpec) -> Self {
        Self {
            spec,
            explicit_timestamp: None,
            validators: Vec::new(),
        }
    }

    /// Fix the genesis timestamp to `ts` (Unix seconds).
    ///
    /// Required for deterministic hashes. Without this, the builder uses
    /// the current time, which changes the hash on every call.
    pub fn with_explicit_timestamp(mut self, ts: u64) -> Self {
        self.explicit_timestamp = Some(ts);
        self
    }

    /// Add a validator with a public key commitment.
    ///
    /// Rejects:
    /// - Duplicate validator IDs.
    /// - Duplicate public key bytes (even under a different ID).
    /// - Keys with incorrect byte length for their declared type.
    pub fn with_validator(
        mut self,
        id: String,
        key: ValidatorPublicKey,
    ) -> InstResult<Self> {
        // Validate key length.
        key.validate()?;

        // Reject duplicate IDs.
        if self.validators.iter().any(|(existing_id, _)| existing_id == &id) {
            return Err(InstError::DuplicateValidator(format!(
                "validator_id '{}' already registered", id
            )));
        }

        // Reject duplicate key bytes.
        if self.validators.iter().any(|(_, existing_key)| existing_key.raw_bytes == key.raw_bytes) {
            return Err(InstError::DuplicateValidator(format!(
                "public key bytes for validator '{}' are identical to an already-registered validator", id
            )));
        }

        self.validators.push((id, key));
        Ok(self)
    }

    /// Build the genesis artifact.
    ///
    /// If validators were added via `with_validator`, those are used.
    /// Otherwise, placeholder enrollments from `ChainSpec::validator_enrollments()`
    /// are used (suitable for development; production deployments must use
    /// `with_validator` with real key commitments).
    pub fn build(self) -> InstResult<GenesisArtifact> {
        let spec = &self.spec;
        let template_id = spec.template_id();
        let template_version = spec.template_version();
        let domain_separator = spec.domain_separator_hex();

        // Timestamp: explicit for reproducibility, or current time.
        let genesis_timestamp: u64 = self.explicit_timestamp.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });

        let genesis_time_str = format_unix_timestamp(genesis_timestamp);

        // Build validator commitments.
        let validator_commitments: Vec<ValidatorCommitment> = if !self.validators.is_empty() {
            // Check we have enough validators.
            if self.validators.len() < spec.validator_count as usize {
                return Err(InstError::InvalidValidatorCount {
                    count: self.validators.len() as u32,
                    reason: format!(
                        "spec requires {} validators but only {} were provided",
                        spec.validator_count,
                        self.validators.len()
                    ),
                });
            }
            self.validators.iter().map(|(id, key)| ValidatorCommitment {
                validator_id: id.clone(),
                public_key_bytes: key.raw_bytes.clone(),
                public_key_type: key.key_type.as_str().to_string(),
                voting_weight: 1,
            }).collect()
        } else {
            // Placeholder enrollments (development only).
            spec.validator_enrollments().iter().map(|e| ValidatorCommitment {
                validator_id: e.label.clone(),
                public_key_bytes: vec![0xFFu8; spec.crypto.placeholder_key_bytes()],
                public_key_type: spec.crypto.key_type_str().to_string(),
                voting_weight: 1,
            }).collect()
        };

        // Governance hash: SHA-256 of canonical governance JSON.
        let governance_json = serde_json::to_string(&json!({
            "approval_threshold_pct": spec.governance.approval_threshold_pct,
            "execution_delay_blocks": spec.governance.execution_delay_blocks,
            "constitutional_governance": spec.governance.constitutional_governance,
        })).map_err(|e| InstError::GenesisBuildError(e.to_string()))?;
        let governance_config_hash = hex::encode(Sha256::digest(governance_json.as_bytes()));

        // Initial state root: all-zero SHA-256 for empty state.
        let initial_state_root = hex::encode([0u8; 32]);

        // Build the commitment.
        let mut commitment = GenesisCommitment {
            chain_id: spec.chain_id.clone(),
            template_id: template_id.as_str().to_string(),
            template_version: template_version.as_string(),
            consensus_profile: format!("{:?}", spec.consensus).to_lowercase(),
            crypto_policy: spec.crypto.genesis_scheme_str().to_string(),
            protocol_version: "0.1.0".to_string(),
            genesis_timestamp,
            validator_commitments,
            governance_config_hash,
            initial_state_root,
            domain_separator: domain_separator.clone(),
        };
        // Sort validators for canonical ordering before hashing.
        commitment.validator_commitments.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));

        let genesis_hash = commitment.hash()?;

        // Build the full genesis JSON document (chain-forge-core compatible).
        let genesis_accounts: Vec<Value> = commitment.validator_commitments.iter().map(|vc| {
            json!({
                "address": format!("{}1{}", spec.address_prefix(), &vc.validator_id),
                "balance": "0",
                "role": "validator",
                "label": vc.validator_id,
                "public_key_type": vc.public_key_type,
                "public_key_hex": hex::encode(&vc.public_key_bytes),
            })
        }).collect();

        let mut consensus_json = json!({
            "type": spec.consensus.genesis_type_str(),
            "validator_set_size": spec.validator_count,
            "block_time_ms": spec.block_time_ms,
            "personhood_weighted": false,
        });
        if let Some(variant) = spec.consensus.bft_variant_str() {
            consensus_json["bft_variant"] = json!(variant);
        }

        let mut cryptography = json!({
            "signature_scheme": spec.crypto.genesis_scheme_str(),
            "hash_width": 256,
            "require_signatures": true,
        });
        if let Some(pqc) = spec.crypto.genesis_pqc_algorithm_str() {
            cryptography["pqc_algorithm"] = json!(pqc);
        }

        let governance_meta = json!({
            "approval_threshold_pct": spec.governance.approval_threshold_pct,
            "execution_delay_blocks": spec.governance.execution_delay_blocks,
            "constitutional_governance": spec.governance.constitutional_governance,
        });

        let network = json!({
            "network_id": spec.chain_id,
            "p2p_port": spec.network.p2p_port,
            "rpc_port": spec.network.rpc_port,
            "bootstrap_nodes": "",
            "peer_discovery": format!("{:?}", spec.network.discovery).to_lowercase(),
            "max_peers": spec.network.max_peers,
        });

        let modules = spec.template.genesis_modules();

        let genesis_json = json!({
            "chain_id": spec.chain_id,
            "chain_name": spec.chain_name,
            "engine_version": "0.1.0",
            "genesis_time": genesis_time_str,
            "environment": {
                "mode": "devnet",
                "faucet_enabled": false,
                "relaxed_limits": false,
            },
            "native_token": {
                "name": format!("{} Token", spec.chain_name),
                "symbol": "INST",
                "denom": "uinst",
            },
            "address_prefix": spec.address_prefix(),
            "consensus": consensus_json,
            "execution": {
                "state_model": "account",
                "parallel_execution": false,
                "gas_model": "fixed",
                "require_signatures": true,
            },
            "cryptography": cryptography,
            "network": network,
            "limits": {
                "max_block_bytes": 4194304,
                "max_tx_bytes": 65536,
                "block_gas_limit": 10000000,
                "mempool_size": 5000,
                "mempool_ttl_seconds": 300,
            },
            "modules": modules,
            "custom_modules": [],
            "genesis_accounts": genesis_accounts,
            // Institutional extension fields. Ignored by chain-forge-node via
            // serde unknown-field tolerance.
            "institutional": {
                "template_id": template_id.as_str(),
                "template_version": template_version.as_string(),
                "domain_separator": domain_separator,
                "genesis_hash": genesis_hash,
                "governance": governance_meta,
                "protocol_version": "0.1.0",
            },
        });

        Ok(GenesisArtifact {
            genesis_json,
            commitment,
            genesis_hash,
            domain_separator: spec.domain_separator_hex(),
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn format_unix_timestamp(ts: u64) -> String {
    // Simple RFC3339-like formatting without chrono dependency on the hot path.
    // For the genesis_time display field only — the hash uses the integer ts.
    use std::time::{Duration, UNIX_EPOCH};
    let _dt = UNIX_EPOCH + Duration::from_secs(ts);
    // chrono is in Cargo.toml already; use it for formatting.
    let secs = ts as i64;
    let naive = chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or_else(|| chrono::DateTime::UNIX_EPOCH);
    naive.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
