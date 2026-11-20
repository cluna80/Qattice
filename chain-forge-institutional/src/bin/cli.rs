//! chain-forge-institutional-cli
//!
//! Command-line interface for the institutional chain generator.
//!
//! Usage:
//!   chain-forge-institutional-cli create \
//!     --template healthcare \
//!     --name hospital-network \
//!     --validators 7 \
//!     --consensus tendermint
//!
//! Outputs the validated genesis JSON to stdout and writes
//! <chain-id>-genesis.json to the current directory.

use chain_forge_institutional::{
    ChainSpec, ConsensusProfile, CryptoPolicy, GovernanceConfig, NetworkConfig,
    InstitutionalTemplate, HealthcareConfig, CorrectionsConfig, EducationConfig, EnterpriseConfig,
    genesis::GenesisBuilder,
};
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
    println!("OPTIONS:");
    println!("  --template <healthcare|corrections|education|enterprise>  (required)");
    println!("  --name <chain-name>                                        (required)");
    println!("  --validators <n>   Number of validators (default: 4, min: 4)");
    println!("  --consensus <tendermint|pq-hotstuff>                      (default: tendermint)");
    println!("  --crypto <ml-dsa-65|ed25519|hybrid>                       (default: ml-dsa-65)");
    println!("  --out <path>       Write genesis JSON to this file (default: <chain-id>-genesis.json)");
    println!();
    println!("EXAMPLE:");
    println!("  chain-forge-institutional-cli create \\");
    println!("    --template healthcare \\");
    println!("    --name hospital-network \\");
    println!("    --validators 7 \\");
    println!("    --consensus tendermint");
}

fn run_create(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut template_str: Option<String> = None;
    let mut name: Option<String> = None;
    let mut validators: u32 = 4;
    let mut consensus_str = "tendermint".to_string();
    let mut crypto_str = "ml-dsa-65".to_string();
    let mut out_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--template"   => { i += 1; template_str = args.get(i).cloned(); }
            "--name"       => { i += 1; name = args.get(i).cloned(); }
            "--validators" => { i += 1; if let Some(v) = args.get(i) { validators = v.parse()?; } }
            "--consensus"  => { i += 1; if let Some(v) = args.get(i) { consensus_str = v.clone(); } }
            "--crypto"     => { i += 1; if let Some(v) = args.get(i) { crypto_str = v.clone(); } }
            "--out"        => { i += 1; out_path = args.get(i).cloned(); }
            other => {
                return Err(format!("unknown flag: {other}").into());
            }
        }
        i += 1;
    }

    let template_name = template_str.ok_or("--template is required")?;
    let chain_name = name.ok_or("--name is required")?;

    // Derive chain_id from name: lowercase, replace spaces/underscores with hyphens.
    let chain_id = chain_name.to_lowercase().replace(' ', "-").replace('_', "-");

    let template: InstitutionalTemplate = match template_name.as_str() {
        "healthcare"  => InstitutionalTemplate::Healthcare(HealthcareConfig::default()),
        "corrections" => InstitutionalTemplate::Corrections(CorrectionsConfig::default()),
        "education"   => InstitutionalTemplate::Education(EducationConfig::default()),
        "enterprise"  => InstitutionalTemplate::Enterprise(EnterpriseConfig::default()),
        other => return Err(format!("unknown template: {other} (use healthcare|corrections|education|enterprise)").into()),
    };

    let consensus: ConsensusProfile = match consensus_str.as_str() {
        "tendermint"   => ConsensusProfile::TendermintBft,
        "pq-hotstuff"  => ConsensusProfile::PqHotStuff2,
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
        chain_name,
        validator_count: validators,
        consensus,
        crypto,
        governance: GovernanceConfig::default(),
        network: NetworkConfig::default(),
        block_time_ms: 3000,
    };

    spec.validate()?;

    let artifact = GenesisBuilder::new(spec).build()?;
    let json_str = artifact.to_json_string()?;

    // Write to file.
    let path = out_path.unwrap_or_else(|| format!("{chain_id}-genesis.json"));
    std::fs::write(&path, &json_str)?;

    eprintln!("chain_id:          {chain_id}");
    eprintln!("genesis_hash:      {}", artifact.genesis_hash);
    eprintln!("domain_separator:  {}", artifact.domain_separator);
    eprintln!("written to:        {path}");

    // Print genesis JSON to stdout for piping.
    println!("{json_str}");

    Ok(())
}
