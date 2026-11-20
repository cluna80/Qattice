//! chain-forge-service -- the Chain Forge wizard's local backend.
//!
//!   chain-forge-service [--port 7700] [--data-dir <dir>] [--allow-origin http://localhost:5173]
//!
//! Endpoints (all JSON):
//!   GET  /api/health                         service + node binary status
//!   POST /api/chains                         body: wizard genesis -> starts a local chain
//!   GET  /api/chains                         running chains with live node status
//!   GET  /api/chains/{id}                    one chain
//!   POST /api/chains/{id}/stop               stop its nodes (files are kept)
//!   GET  /api/chains/{id}/logs/{validator}   last 200 log lines of one node
//!
//! Listens on 127.0.0.1 only and accepts browser requests only from the
//! wizard's origin: this service writes files, holds private keys and
//! starts processes. Private keys are written under the data directory
//! and never returned over HTTP.

use chain_forge_crypto::MlDsaScheme;
use chain_forge_institutional::{ChainSpec, GenesisBuilder};
use chain_forge_service::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

struct Node {
    validator: String,
    api_port:  u16,
    p2p_port:  u16,
    log_path:  PathBuf,
    child:     Child,
}

struct Chain {
    dir:   PathBuf,
    nodes: Vec<Node>,
}

type Chains = Arc<Mutex<HashMap<String, Chain>>>;

struct Config {
    port:         u16,
    data_dir:     PathBuf,
    allow_origin: String,
    node_bin:     PathBuf,
}

fn parse_args() -> Config {
    let exe_dir = std::env::current_exe().ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let mut cfg = Config {
        port: 7700,
        data_dir: home.join(".chain-forge"),
        allow_origin: "http://localhost:5173".into(),
        node_bin: exe_dir.join(format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX)),
    };
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        let next = args.get(i + 1).cloned();
        match args[i].as_str() {
            "--port"         => { cfg.port = next.and_then(|v| v.parse().ok()).unwrap_or(7700); i += 1; }
            "--data-dir"     => { if let Some(v) = next { cfg.data_dir = v.into(); } i += 1; }
            "--allow-origin" => { if let Some(v) = next { cfg.allow_origin = v; } i += 1; }
            "--node-bin"     => { if let Some(v) = next { cfg.node_bin = v.into(); } i += 1; }
            "--help" | "-h"  => {
                println!("chain-forge-service [--port 7700] [--data-dir <dir>] [--allow-origin <url>] [--node-bin <path>]");
                std::process::exit(0);
            }
            other => { eprintln!("unknown argument: {other}"); std::process::exit(2); }
        }
        i += 1;
    }
    cfg
}

/// A free local port, found by letting the OS pick one.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_target(false).with_env_filter(filter).init();

    let cfg = Arc::new(parse_args());
    if !cfg.node_bin.exists() {
        tracing::warn!(path = %cfg.node_bin.display(),
            "chain-forge-node not found next to the service; chains can't start until it's built");
    }
    let listener = match TcpListener::bind(("127.0.0.1", cfg.port)).await {
        Ok(l) => l,
        Err(e) => { eprintln!("cannot listen on 127.0.0.1:{}: {e}", cfg.port); std::process::exit(1); }
    };
    tracing::info!(port = cfg.port, data_dir = %cfg.data_dir.display(),
        allow_origin = %cfg.allow_origin, "chain-forge-service listening");

    let chains: Chains = Arc::new(Mutex::new(HashMap::new()));
    let shutdown_chains = chains.clone();

    tokio::select! {
        _ = accept_loop(listener, cfg, chains) => {}
        _ = tokio::signal::ctrl_c() => {
            // Dropping each Child (kill_on_drop) stops its node.
            let n = shutdown_chains.lock().unwrap().drain().count();
            tracing::info!(chains = n, "shutting down; stopping local chains");
        }
    }
}

async fn accept_loop(listener: TcpListener, cfg: Arc<Config>, chains: Chains) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let cfg = cfg.clone();
        let chains = chains.clone();
        tokio::spawn(async move { handle(stream, cfg, chains).await });
    }
}

async fn handle(mut stream: TcpStream, cfg: Arc<Config>, chains: Chains) {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 { break; }
            buf.extend_from_slice(&chunk[..n]);
            if request_complete(&buf) || buf.len() > 1_048_576 { break; }
        }
        Ok::<(), std::io::Error>(())
    }).await;
    if !matches!(read, Ok(Ok(()))) || buf.is_empty() { return; }

    let end = header_end(&buf).unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let body = String::from_utf8_lossy(&buf[end..]).to_string();
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();
    let origin = header_value(&head, "origin").map(str::to_string);

    let response = if !origin_allowed(origin.as_deref(), &cfg.allow_origin) {
        tracing::warn!(?origin, %path, "refused request from another origin");
        respond(403, &json!({ "error": "origin not allowed" }), None)
    } else if method == "OPTIONS" {
        format!("HTTP/1.1 204 No Content\r\n{}\r\n", cors(origin.as_deref()))
    } else {
        let (status, value) = route(&method, &path, &body, &cfg, &chains).await;
        respond(status, &value, origin.as_deref())
    };
    let _ = stream.write_all(response.as_bytes()).await;
}

fn cors(origin: Option<&str>) -> String {
    match origin {
        Some(o) => format!(
            "Access-Control-Allow-Origin: {o}\r\nVary: Origin\r\n\
             Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n"
        ),
        None => String::new(),
    }
}

fn respond(status: u16, body: &Value, origin: Option<&str>) -> String {
    let text = body.to_string();
    let reason = match status { 200 => "OK", 400 => "Bad Request", 403 => "Forbidden", 404 => "Not Found",
                                409 => "Conflict", _ => "Internal Server Error" };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{text}",
        cors(origin), text.len()
    )
}

async fn route(method: &str, path: &str, body: &str, cfg: &Config, chains: &Chains) -> (u16, Value) {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (method, parts.as_slice()) {
        ("GET", ["api", "health"]) => (200, json!({
            "service": "chain-forge-service",
            "version": env!("CARGO_PKG_VERSION"),
            "node_binary": cfg.node_bin.display().to_string(),
            "node_binary_found": cfg.node_bin.exists(),
            "data_dir": cfg.data_dir.display().to_string(),
        })),
        ("POST", ["api", "chains"]) => create_chain(body, cfg, chains).await,
        ("GET", ["api", "chains"]) => {
            let ids: Vec<String> = chains.lock().unwrap().keys().cloned().collect();
            let mut out = Vec::new();
            for id in ids { if let Some(v) = describe(&id, chains).await { out.push(v); } }
            (200, json!(out))
        }
        ("GET", ["api", "chains", id]) => match describe(id, chains).await {
            Some(v) => (200, v),
            None => (404, json!({ "error": format!("no running chain \"{id}\"") })),
        },
        ("POST", ["api", "chains", id, "stop"]) => {
            let removed = chains.lock().unwrap().remove(*id);
            match removed {
            Some(chain) => {
                let n = chain.nodes.len();
                drop(chain); // kill_on_drop stops every node
                tracing::info!(chain_id = %id, nodes = n, "chain stopped");
                (200, json!({ "status": "stopped", "chain_id": id }))
            }
            None => (404, json!({ "error": format!("no running chain \"{id}\"") })),
            }
        }
        ("GET", ["api", "chains", id, "logs", validator]) => {
            let path = chains.lock().unwrap().get(*id)
                .and_then(|c| c.nodes.iter().find(|n| n.validator == *validator))
                .map(|n| n.log_path.clone());
            match path {
                Some(p) => {
                    let text = strip_ansi(&std::fs::read_to_string(&p).unwrap_or_default());
                    let lines: Vec<&str> = text.lines().collect();
                    let tail = lines[lines.len().saturating_sub(200)..].join("\n");
                    (200, json!({ "validator": validator, "log": tail }))
                }
                None => (404, json!({ "error": "no such chain or validator" })),
            }
        }
        // ── Qattice PQ-HotStuff-2 devnet ─────────────────────────────────
        ("POST", ["api", "qattice-devnets"]) => create_qattice_devnet(body, cfg, chains).await,

        // ── Institutional Builder API ─────────────────────────────────────
        ("GET", ["api", "institutional", "templates"]) => institutional_templates(),
        ("POST", ["api", "institutional", "validate"]) => institutional_validate(body),
        ("POST", ["api", "institutional", "generate"]) => institutional_generate(body, cfg).await,
        ("GET", ["api", "institutional", "artifacts", chain_id, filename]) =>
            institutional_artifact(chain_id, filename, cfg),

        _ => (404, json!({ "error": format!("no route for {method} {path}") })),
    }
}

// ── Qattice PQ-HotStuff-2 devnet launcher ────────────────────────────────────

// Addresses must match genesis_accounts[0..3].address in the template.
const PQHS2_VALIDATORS: &[(&str, &str)] = &[
    ("pqdev-alice", "qcb1alice"),
    ("pqdev-bob",   "qcb1bob"),
    ("pqdev-carol", "qcb1carol"),
    ("pqdev-dave",  "qcb1dave"),
];
const PQHS2_GENESIS_TEMPLATE: &str = include_str!("../../tests/devnet/genesis-4node-pqhs2.json");

async fn create_qattice_devnet(body: &str, cfg: &Config, chains: &Chains) -> (u16, Value) {
    // Parse the chain_id from the request body.
    let chain_id: String = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => match v.get("chain_id").and_then(|v| v.as_str()).map(str::to_owned) {
            Some(id) => id,
            None => return (400, json!({ "error": "missing chain_id" })),
        },
        Err(e) => return (400, json!({ "error": e.to_string() })),
    };
    if let Err(e) = validate_chain_id(&chain_id) {
        return (400, json!({ "error": e }));
    }
    if chains.lock().unwrap().contains_key(&chain_id) {
        return (409, json!({ "error": format!("chain \"{chain_id}\" is already running") }));
    }
    if !cfg.node_bin.exists() {
        return (500, json!({ "error": format!(
            "chain-forge-node not found at {}; build with: cargo build -p chain-forge-node --features pq-hotstuff",
            cfg.node_bin.display()
        )}));
    }

    // Generate 4 fresh ML-DSA-65 keypairs.
    let scheme = MlDsaScheme;
    let mut keypairs = Vec::new();
    for _ in PQHS2_VALIDATORS.iter() {
        match scheme.generate_random() {
            Ok(kp) => keypairs.push(kp),
            Err(e) => return (500, json!({ "error": format!("key generation failed: {e}") })),
        }
    }

    // Parse the genesis template and patch chain_id + validator public keys.
    let mut genesis: serde_json::Value = match serde_json::from_str(PQHS2_GENESIS_TEMPLATE) {
        Ok(v) => v,
        Err(e) => return (500, json!({ "error": format!("genesis template parse error: {e}") })),
    };
    genesis["chain_id"] = json!(chain_id);
    // Patch only the validator accounts (first 4 rows with role=validator).
    if let Some(accounts) = genesis["genesis_accounts"].as_array_mut() {
        let mut kp_iter = keypairs.iter();
        for account in accounts.iter_mut() {
            if account["role"].as_str() == Some("validator") {
                if let Some(kp) = kp_iter.next() {
                    account["public_key"] = json!(kp.public_key_hex());
                }
            }
        }
    }

    // Write files: <data>/<chain_id>/genesis.json + keys/<validator>.key.json
    let dir = cfg.data_dir.join(&chain_id);
    let write_result = (|| -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(dir.join("keys"))?;
        std::fs::create_dir_all(dir.join("logs"))?;
        for ((label, address), kp) in PQHS2_VALIDATORS.iter().zip(keypairs.iter()) {
            let sk_hex: String = kp.private_key.iter().map(|b| format!("{b:02x}")).collect();
            let key_json = serde_json::to_string_pretty(&json!({
                "address":     address,
                "scheme":      "ml-dsa-65",
                "public_key":  kp.public_key_hex(),
                "private_key": sk_hex,
            })).unwrap();
            std::fs::write(dir.join("keys").join(format!("{label}.key.json")), key_json)?;
        }
        let genesis_path = dir.join("genesis.json");
        std::fs::write(&genesis_path, serde_json::to_string_pretty(&genesis).unwrap() + "\n")?;
        Ok(genesis_path)
    })();
    let genesis_path = match write_result {
        Ok(p) => p,
        Err(e) => return (500, json!({ "error": format!("could not write devnet files: {e}") })),
    };

    // Spawn 4 node processes with fresh keys.
    let mut nodes = Vec::new();
    for ((label, address), _kp) in PQHS2_VALIDATORS.iter().zip(keypairs.iter()) {
        let api_port = free_port();
        let p2p_port = free_port();
        let key_path = dir.join("keys").join(format!("{label}.key.json"));
        let log_path = dir.join("logs").join(format!("{label}.log"));
        let spawned = std::fs::File::create(&log_path).and_then(|log| {
            let err = log.try_clone()?;
            Command::new(&cfg.node_bin)
                .arg("--genesis").arg(&genesis_path)
                .arg("--validator").arg(address)
                .arg("--api-port").arg(api_port.to_string())
                .arg("--p2p-port").arg(p2p_port.to_string())
                .arg("--key-file").arg(&key_path)
                .arg("--data-dir").arg(dir.join(format!("data-{label}")))
                .env("RUST_LOG", "info")
                .env("NO_COLOR", "1")
                .stdout(log).stderr(err)
                .kill_on_drop(true)
                .spawn()
        });
        match spawned {
            Ok(child) => nodes.push(Node { validator: address.to_string(), api_port, p2p_port, log_path, child }),
            Err(e) => {
                drop(nodes);
                return (500, json!({ "error": format!("could not start {label}: {e}") }));
            }
        }
    }
    tracing::info!(chain_id = %chain_id, nodes = nodes.len(), dir = %dir.display(), "Qattice PQ-HotStuff-2 devnet started");
    chains.lock().unwrap().insert(chain_id.clone(), Chain { dir, nodes });

    let mut v = describe(&chain_id, chains).await.unwrap_or(json!({}));
    v["genesis"] = genesis;
    (200, v)
}

fn institutional_templates() -> (u16, Value) {
    (200, json!([
        {
            "id": "healthcare-l1",
            "name": "Healthcare L1",
            "description": "HIPAA-ready permissioned chain. Stores FHIR commitment anchors only. No patient data on-chain.",
            "default_validator_count": 4,
            "default_crypto": "ml_dsa_65",
            "default_consensus": "tendermint_bft",
            "modules": ["bank", "identity", "governance"],
        },
        {
            "id": "corrections-l1",
            "name": "Corrections L1",
            "description": "Custody chain for correctional facilities. Evidence immutability, custody event commitments only. No inmate identifiers on-chain.",
            "default_validator_count": 4,
            "default_crypto": "ml_dsa_65",
            "default_consensus": "tendermint_bft",
            "modules": ["bank", "identity", "governance"],
        },
        {
            "id": "education-l1",
            "name": "Education L1",
            "description": "Verifiable credentials for academic institutions. W3C VC anchoring. No student PII on-chain.",
            "default_validator_count": 4,
            "default_crypto": "ml_dsa_65",
            "default_consensus": "tendermint_bft",
            "modules": ["bank", "identity", "governance"],
        },
        {
            "id": "enterprise-l1",
            "name": "Enterprise L1",
            "description": "Permissioned enterprise chain with AI agent capability grants and role-based governance. No confidential contracts on-chain.",
            "default_validator_count": 4,
            "default_crypto": "ml_dsa_65",
            "default_consensus": "tendermint_bft",
            "modules": ["bank", "identity", "governance"],
        },
    ]))
}

fn institutional_validate(body: &str) -> (u16, Value) {
    let spec: ChainSpec = match serde_json::from_str(body) {
        Ok(s) => s,
        Err(e) => return (400, json!({ "valid": false, "error": format!("invalid JSON: {e}") })),
    };
    match spec.validate() {
        Ok(()) => (200, json!({
            "valid": true,
            "chain_id": spec.chain_id,
            "template": spec.template.template_id_str(),
            "validator_count": spec.validator_count,
            "domain_separator": spec.domain_separator_hex(),
        })),
        Err(e) => (200, json!({ "valid": false, "error": e.to_string() })),
    }
}

async fn institutional_generate(body: &str, cfg: &Config) -> (u16, Value) {
    let spec: ChainSpec = match serde_json::from_str(body) {
        Ok(s) => s,
        Err(e) => return (400, json!({ "error": format!("invalid JSON: {e}") })),
    };
    if let Err(e) = spec.validate() {
        return (400, json!({ "error": e.to_string() }));
    }
    if let Err(e) = chain_forge_service::validate_chain_id(&spec.chain_id) {
        return (400, json!({ "error": e }));
    }

    let artifact = match GenesisBuilder::new(spec.clone()).build() {
        Ok(a) => a,
        Err(e) => return (500, json!({ "error": format!("genesis build failed: {e}") })),
    };

    // Write artifacts to <data_dir>/<chain_id>/institutional/
    let dir = cfg.data_dir.join(&spec.chain_id).join("institutional");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return (500, json!({ "error": format!("could not create artifact dir: {e}") }));
    }

    let genesis_json = match artifact.to_deployment_json() {
        Ok(s) => s,
        Err(e) => return (500, json!({ "error": format!("genesis serialization failed: {e}") })),
    };
    let genesis_path = dir.join("genesis.json");
    if let Err(e) = std::fs::write(&genesis_path, &genesis_json) {
        return (500, json!({ "error": format!("could not write genesis.json: {e}") }));
    }

    // Deployment manifest (chain metadata, no private keys)
    let manifest = json!({
        "chain_id": spec.chain_id,
        "chain_name": spec.chain_name,
        "template": spec.template.template_id_str(),
        "validator_count": spec.validator_count,
        "domain_separator": spec.domain_separator_hex(),
        "genesis_hash": artifact.commitment.hash().unwrap_or_default(),
        "artifacts": {
            "genesis": "genesis.json",
            "manifest": "manifest.json",
        },
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "note": "No private keys are included. Validators must supply their own ML-DSA-65 public keys before deployment.",
    });
    let manifest_path = dir.join("manifest.json");
    if let Err(e) = std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap_or_default()) {
        return (500, json!({ "error": format!("could not write manifest.json: {e}") }));
    }

    tracing::info!(chain_id = %spec.chain_id, template = %spec.template.template_id_str(),
        dir = %dir.display(), "institutional genesis generated");

    (200, json!({
        "chain_id": spec.chain_id,
        "template": spec.template.template_id_str(),
        "domain_separator": spec.domain_separator_hex(),
        "genesis_hash": artifact.commitment.hash().unwrap_or_default(),
        "artifacts_dir": dir.display().to_string(),
        "artifacts": ["genesis.json", "manifest.json"],
    }))
}

fn institutional_artifact(chain_id: &str, filename: &str, cfg: &Config) -> (u16, Value) {
    // Validate chain_id to prevent path traversal
    if let Err(e) = chain_forge_service::validate_chain_id(chain_id) {
        return (400, json!({ "error": e }));
    }
    // Only allow safe filenames
    let allowed = ["genesis.json", "manifest.json"];
    if !allowed.contains(&filename) {
        return (404, json!({ "error": format!("artifact \"{filename}\" not found; available: genesis.json, manifest.json") }));
    }

    let path = cfg.data_dir.join(chain_id).join("institutional").join(filename);
    match std::fs::read_to_string(&path) {
        Ok(contents) => match serde_json::from_str::<Value>(&contents) {
            Ok(v) => (200, v),
            Err(_) => (500, json!({ "error": "artifact is not valid JSON" })),
        },
        Err(_) => (404, json!({ "error": format!("artifact not found for chain \"{chain_id}\"") })),
    }
}

async fn create_chain(body: &str, cfg: &Config, chains: &Chains) -> (u16, Value) {
    if !cfg.node_bin.exists() {
        return (500, json!({ "error": format!(
            "chain-forge-node not found at {}; build it with: cargo build --release --features real-network -p chain-forge-node",
            cfg.node_bin.display()) }));
    }
    let prepared = match prepare_local_chain(body, free_port) {
        Ok(p) => p,
        Err(e) => return (400, json!({ "error": e })),
    };
    let id = prepared.chain_id.clone();
    if chains.lock().unwrap().contains_key(&id) {
        return (409, json!({ "error": format!("chain \"{id}\" is already running; stop it first") }));
    }

    // Files: <data>/<chain_id>/{genesis.json, keys/, logs/}
    let dir = cfg.data_dir.join(&id);
    let write = || -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(dir.join("keys"))?;
        std::fs::create_dir_all(dir.join("logs"))?;
        for (address, key) in &prepared.key_files {
            std::fs::write(dir.join("keys").join(format!("{address}.key.json")),
                serde_json::to_string_pretty(key).unwrap())?;
        }
        let genesis_path = dir.join("genesis.json");
        std::fs::write(&genesis_path, serde_json::to_string_pretty(&prepared.genesis).unwrap() + "\n")?;
        Ok(genesis_path)
    };
    let genesis_path = match write() {
        Ok(p) => p,
        Err(e) => return (500, json!({ "error": format!("could not write chain files: {e}") })),
    };

    let mut nodes = Vec::new();
    for (validator, p2p_port) in &prepared.validators {
        let api_port = free_port();
        let log_path = dir.join("logs").join(format!("{validator}.log"));
        let spawned = std::fs::File::create(&log_path).and_then(|log| {
            let err = log.try_clone()?;
            Command::new(&cfg.node_bin)
                .arg("--genesis").arg(&genesis_path)
                .arg("--validator").arg(validator)
                .arg("--api-port").arg(api_port.to_string())
                .arg("--p2p-port").arg(p2p_port.to_string())
                // Pass the key file if the service generated one for this validator.
                .args({
                    let key_path = dir.join("keys").join(format!("{validator}.key.json"));
                    if key_path.exists() { vec!["--key-file".into(), key_path.to_string_lossy().to_string()] }
                    else { vec![] }
})
                // State persistence: each validator stores state in its own
                // subfolder so a restart resumes from the last committed block.
                .arg("--data-dir").arg(dir.join(format!("data-{validator}")))
                .env("RUST_LOG", "info")
                .env("NO_COLOR", "1")
                .stdout(log).stderr(err)
                .kill_on_drop(true)
                .spawn()
        });
        match spawned {
            Ok(child) => nodes.push(Node {
                validator: validator.clone(), api_port, p2p_port: *p2p_port, log_path, child,
            }),
            Err(e) => {
                drop(nodes); // stop any already started
                return (500, json!({ "error": format!("could not start node for {validator}: {e}") }));
            }
        }
    }
    tracing::info!(chain_id = %id, nodes = nodes.len(), dir = %dir.display(), "local chain started");
    chains.lock().unwrap().insert(id.clone(), Chain { dir, nodes });

    let mut v = describe(&id, chains).await.unwrap_or(json!({}));
    v["genesis"] = prepared.genesis;
    (200, v)
}

/// A chain's nodes with live status from each node's own API.
async fn describe(id: &str, chains: &Chains) -> Option<Value> {
    let (dir, snapshot): (PathBuf, Vec<(String, u16, u16, Option<i32>)>) = {
        let mut map = chains.lock().unwrap();
        let chain = map.get_mut(id)?;
        let snap = chain.nodes.iter_mut().map(|n| {
            let exit = n.child.try_wait().ok().flatten().map(|s| s.code().unwrap_or(-1));
            (n.validator.clone(), n.api_port, n.p2p_port, exit)
        }).collect();
        (chain.dir.clone(), snap)
    };
    let mut nodes = Vec::new();
    for (validator, api_port, p2p_port, exited) in snapshot {
        let status = match exited {
            Some(code) => json!({ "running": false, "exit_code": code }),
            None => node_status(api_port).await
                .map(|s| { let mut s = s; s["running"] = json!(true); s })
                .unwrap_or(json!({ "running": true, "api": "starting" })),
        };
        nodes.push(json!({
            "validator": validator,
            "api_url": format!("http://127.0.0.1:{api_port}"),
            "p2p_port": p2p_port,
            "status": status,
        }));
    }
    Some(json!({ "chain_id": id, "dir": dir.display().to_string(), "nodes": nodes }))
}

async fn node_status(api_port: u16) -> Option<Value> {
    let fetch = async {
        let mut s = TcpStream::connect(("127.0.0.1", api_port)).await.ok()?;
        s.write_all(format!(
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{api_port}\r\nConnection: close\r\n\r\n").as_bytes()
        ).await.ok()?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).await.ok()?;
        let end = header_end(&raw)?;
        serde_json::from_slice::<Value>(&raw[end..]).ok()
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), fetch).await.ok().flatten()
}
