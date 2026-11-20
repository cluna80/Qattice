//! chain-forge-institutional-cli
//!
//! Sovereign institutional blockchain generator.
//!
//! USAGE:
//!   chain-forge-institutional-cli create \
//!     --template healthcare \
//!     --name hospital-network \
//!     --validators 7 \
//!     --consensus tendermint \
//!     --out-dir ./hospital-network-artifacts
//!
//! Outputs four artifacts to --out-dir:
//!   genesis.json              Full genesis document
//!   validator-enrollment.json Per-validator configuration and quorum params
//!   deployment-manifest.json  Chain ID, template, consensus, genesis hash
//!   validation-report.json    All validated fields and any warnings
//!
//! Artifacts use test-vector public keys (placeholder patterns).
//! Production deployments must replace these with real ML-DSA-65 public keys
//! via a secure key-provisioning process before launching the chain.

use chain_forge_institutional::{
    ChainSpec, ConsensusProfile, CryptoPolicy, GovernanceConfig, NetworkConfig,
    InstitutionalTemplate, HealthcareConfig, CorrectionsConfig, EducationConfig, EnterpriseConfig,
    ValidatorPublicKey, bft_quorum,
    genesis::GenesisBuilder,
};
use serde_json::json;
use std::path::PathBuf;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "create" => {
            if let Err(e) = run_create(&args[2..]) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            print_usage();
            process::exit(1);
        }
    }
}

fn print_usage() {
    println!("chain-forge-institutional-cli");
    println!();
    println!("USAGE:");
    println!("  chain-forge-institutional-cli create [OPTIONS]");
    println!();
    println!("SUBCOMMANDS:");
    println!("  create   Generate a new institutional blockchain");
    println!();
    println!("OPTIONS (create):");
    println!("  --template <healthcare|corrections|education|enterprise>  (required)");
    println!("  --name <chain-name>              Human-readable name (required)");
    println!("  --validators <n>                 Number of validators (default: 4, min: 4)");
    println!("  --consensus <tendermint|pq-hotstuff>  (default: tendermint)");
    println!("  --crypto <ml-dsa-65|ed25519|hybrid>   (default: ml-dsa-65)");
    println!("  --timestamp <unix-secs>          Fix genesis timestamp for reproducibility");
    println!("  --out-dir <path>                 Output directory (default: ./<chain-id>)");
    println!();
    println!("EXIT CODES:");
    println!("  0  Success");
    println!("  1  Validation error or I/O failure");
    println!();
    println!("EXAMPLE:");
    println!("  chain-forge-institutional-cli create \\");
    println!("    --template healthcare \\");
    println!("    --name hospital-network \\");
    println!("    --validators 7 \\");
    println!("    --consensus tendermint \\");
    println!("    --out-dir ./hospital-network");
    println!();
    println!("NOTE: Generated artifacts use placeholder test-vector public keys.");
    println!("      Replace with real ML-DSA-65 keys before launching a production chain.");
}

fn run_create(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse flags.
    let mut template_str: Option<String> = None;
    let mut name: Option<String> = None;
    let mut validators: u32 = 4;
    let mut consensus_str = "tendermint".to_string();
    let mut crypto_str = "ml-dsa-65".to_string();
    let mut timestamp: Option<u64> = None;
    let mut out_dir: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--template"   => { i += 1; template_str = args.get(i).cloned(); }
            "--name"       => { i += 1; name = args.get(i).cloned(); }
            "--validators" => { i += 1; if let Some(v) = args.get(i) { validators = v.parse()?; } }
            "--consensus"  => { i += 1; if let Some(v) = args.get(i) { consensus_str = v.clone(); } }
            "--crypto"     => { i += 1; if let Some(v) = args.get(i) { crypto_str = v.clone(); } }
            "--timestamp"  => { i += 1; if let Some(v) = args.get(i) { timestamp = Some(v.parse()?); } }
            "--out-dir"    => { i += 1; out_dir = args.get(i).cloned(); }
            other => return Err(format!("unknown flag: {other}").into()),
        }
        i += 1;
    }

    let template_name = template_str.ok_or("--template is required")?;
    let chain_name = name.ok_or("--name is required")?;
    let chain_id = chain_name.to_lowercase()
        .replace(' ', "-").replace('_', "-");

    let template: InstitutionalTemplate = match template_name.as_str() {
        "healthcare"  => InstitutionalTemplate::Healthcare(HealthcareConfig::default()),
        "corrections" => InstitutionalTemplate::Corrections(CorrectionsConfig::default()),
        "education"   => InstitutionalTemplate::Education(EducationConfig::default()),
        "enterprise"  => InstitutionalTemplate::Enterprise(EnterpriseConfig::default()),
        other => return Err(format!(
            "unknown template: {other} (use healthcare|corrections|education|enterprise)"
        ).into()),
    };

    let consensus: ConsensusProfile = match consensus_str.as_str() {
        "tendermint"  => ConsensusProfile::TendermintBft,
        "pq-hotstuff" => ConsensusProfile::PqHotStuff2,
        other => return Err(format!("unknown consensus: {other} (use tendermint|pq-hotstuff)").into()),
    };

    let crypto: CryptoPolicy = match crypto_str.as_str() {
        "ml-dsa-65" => CryptoPolicy::MlDsa65,
        "ed25519"   => CryptoPolicy::Ed25519,
        "hybrid"    => CryptoPolicy::Hybrid,
        other => return Err(format!("unknown crypto: {other} (use ml-dsa-65|ed25519|hybrid)").into()),
    };

    let spec = ChainSpec {
        template,
        chain_id: chain_id.clone(),
        chain_name: chain_name.clone(),
        validator_count: validators,
        consensus,
        crypto,
        governance: GovernanceConfig::default(),
        network: NetworkConfig::default(),
        block_time_ms: 3000,
    };

    // Validate — exit 1 with message on failure.
    spec.validate().map_err(|e| format!("validation failed: {e}"))?;

    // Quorum params.
    let quorum = bft_quorum(validators)
        .map_err(|e| format!("quorum validation failed: {e}"))?;

    // Build with placeholder test-vector keys (one per validator slot).
    let mut builder = GenesisBuilder::new(spec.clone());
    if let Some(ts) = timestamp {
        builder = builder.with_explicit_timestamp(ts);
    }
    // Add placeholder validator keys.
    for idx in 0..validators {
        let key = ValidatorPublicKey::test_mldsa_key_for_index(idx as u8);
        builder = builder
            .with_validator(format!("{chain_id}-validator-{idx}"), key)
            .map_err(|e| format!("validator registration failed: {e}"))?;
    }

    let artifact = builder.build()
        .map_err(|e| format!("genesis build failed: {e}"))?;

    // Prepare output directory.
    let dir = PathBuf::from(out_dir.unwrap_or_else(|| chain_id.clone()));
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create output directory {}: {e}", dir.display()))?;

    // 1. genesis.json
    let genesis_path = dir.join("genesis.json");
    std::fs::write(&genesis_path, artifact.to_json_string()?)
        .map_err(|e| format!("could not write genesis.json: {e}"))?;

    // 2. validator-enrollment.json
    let enrollment: Vec<serde_json::Value> = artifact.commitment.validator_commitments.iter().map(|vc| {
        json!({
            "validator_id": vc.validator_id,
            "public_key_type": vc.public_key_type,
            "public_key_hex_prefix": hex::encode(&vc.public_key_bytes[..8.min(vc.public_key_bytes.len())]),
            "voting_weight": vc.voting_weight,
            "note": "PLACEHOLDER KEY — replace with real ML-DSA-65 public key before production deployment",
        })
    }).collect();
    let enrollment_json = json!({
        "chain_id": chain_id,
        "quorum": {
            "n": quorum.n,
            "f": quorum.f,
            "quorum": quorum.quorum,
        },
        "validators": enrollment,
    });
    std::fs::write(dir.join("validator-enrollment.json"),
        serde_json::to_string_pretty(&enrollment_json)?)
        .map_err(|e| format!("could not write validator-enrollment.json: {e}"))?;

    // 3. deployment-manifest.json
    let manifest = json!({
        "chain_id": chain_id,
        "chain_name": chain_name,
        "template": template_name,
        "consensus": consensus_str,
        "crypto": crypto_str,
        "validator_count": validators,
        "genesis_hash": artifact.genesis_hash,
        "domain_separator": artifact.domain_separator,
        "quorum": {
            "n": quorum.n,
            "f": quorum.f,
            "quorum": quorum.quorum,
        },
        "deployment_status": "DEVELOPMENT — NOT PRODUCTION READY",
        "note": "Replace placeholder validator keys before any production or testnet deployment.",
    });
    std::fs::write(dir.join("deployment-manifest.json"),
        serde_json::to_string_pretty(&manifest)?)
        .map_err(|e| format!("could not write deployment-manifest.json: {e}"))?;

    // 4. validation-report.json
    let warnings: Vec<&str> = {
        let mut w = Vec::new();
        w.push("Validator keys are test-vector placeholders (not real ML-DSA-65 keys).");
        if timestamp.is_none() {
            w.push("No --timestamp provided; genesis hash is time-dependent and not reproducible.");
        }
        w
    };
    let report = json!({
        "chain_id": chain_id,
        "validation": "passed",
        "fields_validated": [
            "chain_id format",
            "validator_count >= 4 (BFT quorum)",
            "consensus/crypto compatibility",
            "governance threshold (1-100%)",
            "block_time_ms > 0",
        ],
        "warnings": warnings,
        "genesis_hash": artifact.genesis_hash,
    });
    std::fs::write(dir.join("validation-report.json"),
        serde_json::to_string_pretty(&report)?)
        .map_err(|e| format!("could not write validation-report.json: {e}"))?;

    // Summary to stdout.
    println!("chain_id:          {chain_id}");
    println!("genesis_hash:      {}", artifact.genesis_hash);
    println!("domain_separator:  {}", artifact.domain_separator);
    println!("validators:        {validators} (f={}, quorum={})", quorum.f, quorum.quorum);
    println!("output:            {}", dir.display());

    Ok(())
}
