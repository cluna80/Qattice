//! Generate ML-DSA-65 key files for devnet validators.
//!
//! Run:
//!   cargo run -p chain-forge-crypto --bin gen-mldsa-keys -- <label>
//!
//! Example (add Eve):
//!   cargo run -p chain-forge-crypto --bin gen-mldsa-keys -- eve qcb1eve
//!
//! Outputs tests/devnet/keys/mldsa/<label>.key.json with a fresh ML-DSA-65 keypair.

use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: gen-mldsa-keys <label> <address>");
        eprintln!("  e.g. gen-mldsa-keys eve qcb1eve");
        std::process::exit(1);
    }
    let label   = &args[1];
    let address = &args[2];

    let kp = MlDsaScheme.generate_keypair(address).expect("ML-DSA keygen");

    let key_json = serde_json::json!({
        "scheme":      "ml-dsa-65",
        "address":     address,
        "public_key":  hex(&kp.public_key),
        "private_key": hex(&kp.private_key),
    });

    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().to_path_buf();
    let keys_dir = repo_root.join("tests").join("devnet").join("keys").join("mldsa");
    std::fs::create_dir_all(&keys_dir).unwrap();

    let out = keys_dir.join(format!("{label}.key.json"));
    std::fs::write(&out, serde_json::to_string_pretty(&key_json).unwrap()).unwrap();
    println!("{address}");
    println!("  public_key:  {}", hex(&kp.public_key));
    println!("  written to:  {}", out.display());
}
