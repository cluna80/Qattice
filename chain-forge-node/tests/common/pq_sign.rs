//! ML-DSA-65 signing for live tests that post raw transaction JSON.
//!
//! On a `pqc-native` chain every transaction must carry an ML-DSA-65 signature.
//! Genesis validators sign with their committed key (`tests/devnet/keys/mldsa/`).
//! Accounts a test creates must be the address derived from their own key (a named
//! account with no key bound in genesis is refused), so `new_account` returns that
//! derived address and keeps its key for signing.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use chain_forge_crypto::{KeyPair, MlDsaScheme, SchemeId, SignatureScheme, mldsa_tx_prehash};
use chain_forge_execution::Transaction;

static ACCOUNTS: Mutex<Option<HashMap<String, KeyPair>>> = Mutex::new(None);

fn key_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
        .join("tests").join("devnet").join("keys").join("mldsa")
}

fn hex_decode(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

#[allow(dead_code)]
/// A new key-derived account; `tag` only makes the key unique within this process.
pub fn new_account(tag: &str) -> String {
    let kp = MlDsaScheme.generate_keypair(&format!("live-test-account-{tag}-0000000000000000000000"))
        .expect("ML-DSA keygen");
    let addr = chain_forge_core::Address::from_public_key_schemed(
        &kp.public_key, "qcb", chain_forge_core::HashWidth::Bits256,
        chain_forge_core::AddressScheme::PostQuantum,
    ).as_str().to_string();
    ACCOUNTS.lock().unwrap().get_or_insert_with(HashMap::new).insert(addr.clone(), kp);
    addr
}

/// Sign transactions from `addr` with `kp` (for accounts whose key the test made itself).
#[allow(dead_code)]
pub fn register(addr: &str, kp: &KeyPair) {
    ACCOUNTS.lock().unwrap().get_or_insert_with(HashMap::new).insert(addr.to_string(), kp.clone());
}

/// The signing key for `sender`: one made by `new_account`, else the committed devnet key.
pub fn key_for(sender: &str) -> KeyPair {
    if let Some(kp) = ACCOUNTS.lock().unwrap().as_ref().and_then(|m| m.get(sender)) {
        return kp.clone();
    }
    let label = sender.strip_prefix("qcb1").unwrap_or(sender);
    let path = key_dir().join(format!("{label}.key.json"));
    let k: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("no key for {sender}: neither new_account() nor {path:?} ({e})"))).unwrap();
    KeyPair {
        scheme: SchemeId::MlDsa,
        public_key: hex_decode(k["public_key"].as_str().unwrap()),
        private_key: hex_decode(k["private_key"].as_str().unwrap()),
    }
}

/// Sign a transaction as its sender.
pub fn sign(mut tx: Transaction, chain_id: &str) -> Transaction {
    let kp = key_for(&tx.sender);
    let body_json = serde_json::to_string(&tx.body).unwrap();
    let sig = MlDsaScheme.sign(&mldsa_tx_prehash(chain_id, body_json.as_bytes()), &kp).unwrap();
    tx.pq_signatures = vec![format!("mldsa65:{}", sig.bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())];
    tx.sig_scheme = Some(SchemeId::MlDsa);
    tx.pq_public_key = kp.public_key;
    tx.signature = vec![];
    tx.public_key = vec![];
    tx
}

/// Sign raw transaction JSON (as a test would POST it) and return the signed JSON.
pub fn sign_json(tx_json: &str, chain_id: &str) -> String {
    let tx: Transaction = serde_json::from_str(tx_json)
        .unwrap_or_else(|e| panic!("not a Transaction ({e}): {tx_json}"));
    serde_json::to_string(&sign(tx, chain_id)).unwrap()
}

/// The chain id of a genesis file.
pub fn chain_id_of(genesis: &std::path::Path) -> String {
    let g: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(genesis).unwrap()).unwrap();
    g["chain_id"].as_str().unwrap().to_string()
}
