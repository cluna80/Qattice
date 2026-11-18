//! Live tests run on ML-DSA-65 consensus keys (owner decision 2026-10-28;
//! Ed25519 retired 2026-10-30): the test's genesis is copied with every
//! validator key replaced by the committed devnet ML-DSA key
//! (`tests/devnet/keys/mldsa/`) and `validator_scheme = "ml-dsa-65"`, and
//! validators load those key files. There is no classical opt-out.

use std::path::{Path, PathBuf};

#[allow(dead_code)]
pub fn mldsa() -> bool { true }

fn mldsa_key_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .join("tests").join("devnet").join("keys").join("mldsa")
}

/// `short` is the validator name without `qcb1` ("alice").
fn mldsa_key(short: &str) -> PathBuf {
    mldsa_key_dir().join(format!("{short}.key.json"))
}

/// The genesis file to run: `path` itself, or its ML-DSA-65 copy.
pub fn genesis(path: &Path) -> PathBuf {
    let mut g: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    g["cryptography"]["validator_scheme"] = "ml-dsa-65".into();
    for a in g["genesis_accounts"].as_array_mut().unwrap() {
        if a["role"] != "validator" {
            continue;
        }
        let addr = a["address"].as_str().unwrap().to_string();
        let short = addr.strip_prefix("qcb1").unwrap_or(&addr);
        let key_path = mldsa_key(short);
        let k: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&key_path)
            .unwrap_or_else(|e| panic!("no ML-DSA devnet key for {addr} at {key_path:?}: {e}"))).unwrap();
        assert_eq!(k["address"], addr.as_str(), "{key_path:?}");
        a["public_key"] = k["public_key"].clone();
    }
    let out = std::env::temp_dir().join(format!(
        "mldsa-{}-{}", std::process::id(), path.file_name().unwrap().to_string_lossy()));
    // Tests call this once per spawned node: write a fresh file and rename
    // it into place, so a starting node never reads a half-written genesis.
    let tmp = out.with_extension(format!("tmp{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::write(&tmp, g.to_string()).unwrap();
    std::fs::rename(&tmp, &out).unwrap();
    out
}

/// The ML-DSA key file for validator `short` ("alice"); `_default` is ignored.
pub fn validator_key(short: &str, _default: PathBuf) -> PathBuf {
    mldsa_key(short)
}
