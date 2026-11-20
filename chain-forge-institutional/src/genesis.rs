//! Genesis artifact builder for institutional chains.
//!
//! Produces a JSON genesis document compatible with chain-forge-core's
//! GenesisConfig schema. The genesis hash is deterministic: the same
//! ChainSpec always produces the same hash.
//!
//! # Test-mode determinism
//! Set `GenesisBuilder::test_mode(true)` to fix `genesis_time` to the
//! Unix epoch (1970-01-01T00:00:00Z). In production mode, `genesis_time`
//! is the current UTC timestamp, which changes the hash.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{ChainSpec, InstResult, InstError};

/// A built genesis artifact.
#[derive(Debug, Clone)]
pub struct GenesisArtifact {
    /// The genesis document as a JSON value.
    pub genesis_json: Value,
    /// SHA-256 hex hash of the canonical genesis JSON.
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
}

/// Builds a `GenesisArtifact` from a validated `ChainSpec`.
pub struct GenesisBuilder {
    spec: ChainSpec,
    test_mode: bool,
}

impl GenesisBuilder {
    pub fn new(spec: ChainSpec) -> Self {
        Self { spec, test_mode: false }
    }

    /// Fix `genesis_time` to the Unix epoch for deterministic test output.
    pub fn test_mode(mut self, enabled: bool) -> Self {
        self.test_mode = enabled;
        self
    }

    /// Build the genesis artifact. The spec must have been validated before
    /// calling this method.
    pub fn build(self) -> InstResult<GenesisArtifact> {
        let spec = &self.spec;
        let template_id = spec.template_id();
        let template_version = spec.template_version();
        let domain_separator = spec.domain_separator_hex();

        let genesis_time = if self.test_mode {
            "1970-01-01T00:00:00Z".to_string()
        } else {
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
        };

        // Validator enrollments (public key slots, no private keys).
        let enrollments = spec.validator_enrollments();
        let genesis_accounts: Vec<Value> = enrollments.iter().map(|e| json!({
            "address": e.address,
            "balance": e.balance.to_string(),
            "role": "validator",
            "label": e.label,
        })).collect();

        // Consensus section.
        let mut consensus = json!({
            "type": spec.consensus.genesis_type_str(),
            "validator_set_size": spec.validator_count,
            "block_time_ms": spec.block_time_ms,
            "personhood_weighted": false,
        });
        if let Some(variant) = spec.consensus.bft_variant_str() {
            consensus["bft_variant"] = json!(variant);
        }

        // Cryptography section.
        let mut cryptography = json!({
            "signature_scheme": spec.crypto.genesis_scheme_str(),
            "hash_width": 256,
            "require_signatures": true,
        });
        if let Some(pqc) = spec.crypto.genesis_pqc_algorithm_str() {
            cryptography["pqc_algorithm"] = json!(pqc);
        }

        // Governance metadata (stored as a custom field; the node reads
        // institutional_governance from the genesis JSON extension).
        let governance_meta = json!({
            "approval_threshold_pct": spec.governance.approval_threshold_pct,
            "execution_delay_blocks": spec.governance.execution_delay_blocks,
            "constitutional_governance": spec.governance.constitutional_governance,
        });

        // Network section.
        let network = json!({
            "network_id": spec.chain_id,
            "p2p_port": spec.network.p2p_port,
            "rpc_port": spec.network.rpc_port,
            "bootstrap_nodes": "",
            "peer_discovery": format!("{:?}", spec.network.discovery).to_lowercase(),
            "max_peers": spec.network.max_peers,
        });

        // Modules.
        let modules = spec.template.genesis_modules();

        // Assemble the full genesis document.
        // The structure matches chain-forge-core::GenesisConfig field names.
        let genesis_json = json!({
            "chain_id": spec.chain_id,
            "chain_name": spec.chain_name,
            "engine_version": "0.1.0",
            "genesis_time": genesis_time,
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
            "consensus": consensus,
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
            // Institutional extension fields (read by chain-forge-institutional
            // tooling; ignored by existing chain-forge-node with unknown field
            // tolerance via serde default).
            "institutional": {
                "template_id": template_id.as_str(),
                "template_version": template_version.as_string(),
                "domain_separator": domain_separator,
                "governance": governance_meta,
            },
        });

        // Deterministic hash: canonical JSON (sorted keys via serde_json).
        let canonical = serde_json::to_string(&genesis_json)
            .map_err(|e| InstError::GenesisBuildError(e.to_string()))?;
        let hash = hex::encode(Sha256::digest(canonical.as_bytes()));

        Ok(GenesisArtifact {
            genesis_json,
            genesis_hash: hash,
            domain_separator: spec.domain_separator_hex(),
        })
    }
}
