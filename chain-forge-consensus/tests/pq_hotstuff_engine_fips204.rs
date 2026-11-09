//! The PQ-HotStuff-2 engine, certificate verifier and safety store with REAL FIPS 204 ML-DSA-65 signatures (the `fips204` backend
//! through the existing `Fips204Signer` / `Fips204Verifier` adapter). It runs the SAME test body as tests/pq_hotstuff_engine.rs
//! (tests/common/pq_engine_suite.rs), so no assertion is weaker here; only the signature scheme differs. The storage and counter
//! are the same test doubles as the safety tests (not trusted mechanisms).
//!
//! Test keys: each validator's 32-byte seed is drawn from the operating-system RNG once per process, kept in memory only, and never
//! written to disk, committed or printed. Signing is hedged (fresh randomness per signature), so signature bytes differ between runs.
//!
//! This is a REQUIRED validation suite. Run it in release mode (ML-DSA and SHA3 are slow in debug):
//!   cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204
#![cfg(feature = "pq-hotstuff-fips204")]

#[path = "common/pq_safety_doubles.rs"]
mod base;

/// The suite expects `doubles::*`: the storage/counter/fault doubles from `base`, with the signer, verifier and key helper replaced.
mod doubles {
    pub use super::base::*;
    pub use super::real::{test_public_key, TestSigner, TestVerifier};
}

mod real {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    use chain_forge_consensus::pq_hotstuff::safety::{ConsensusSigner, ConsensusVerifier, Fips204Signer, Fips204Verifier, SignerError};
    use chain_forge_crypto::fips204_backend::MlDsa65Fips204;

    fn seeds() -> &'static Mutex<HashMap<u8, ([u8; 32], Vec<u8>)>> {
        static S: OnceLock<Mutex<HashMap<u8, ([u8; 32], Vec<u8>)>>> = OnceLock::new();
        S.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// (seed, public key) of test validator `sk`: a fresh random key per process, generated on first use.
    fn key_of(sk: u8) -> ([u8; 32], Vec<u8>) {
        let mut m = seeds().lock().unwrap();
        m.entry(sk).or_insert_with(|| {
            let (seed, kp) = MlDsa65Fips204::generate().expect("operating-system RNG");
            (seed, kp.public_key)
        }).clone()
    }

    pub fn test_public_key(sk: u8) -> Vec<u8> { key_of(sk).1 }

    /// A real ML-DSA-65 signer for test validator `sk`.
    pub struct TestSigner(Fips204Signer);
    impl TestSigner {
        pub fn new(sk: u8) -> Self { TestSigner(Fips204Signer::from_seed(&key_of(sk).0)) }
    }
    impl ConsensusSigner for TestSigner {
        fn public_key(&self) -> &[u8] { self.0.public_key() }
        fn sign(&mut self, context: &[u8], message: &[u8]) -> Result<Vec<u8>, SignerError> { self.0.sign(context, message) }
    }

    pub struct TestVerifier;
    impl ConsensusVerifier for TestVerifier {
        fn verify(&self, public_key: &[u8], context: &[u8], message: &[u8], signature: &[u8]) -> bool {
            Fips204Verifier.verify(public_key, context, message, signature)
        }
    }
}

/// Seeds per simulation campaign with real signatures (raise with PQHS_SEEDS for a longer soak).
const DEFAULT_SEEDS: u64 = 10;
/// Whether the test keys are deterministic (the test doubles): golden byte values are only asserted when they are.
const DETERMINISTIC_KEYS: bool = false;
include!("common/pq_engine_suite.rs");
#[path = "common/pq_tree_doubles.rs"]
mod tree_doubles;
include!("common/pq_recovery_suite.rs");
include!("common/pq_checkpoint_suite.rs");
include!("common/pq_seed_suite.rs");
