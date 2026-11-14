//! Property tests for ML-DSA-65 sign/verify (P5, P6).
//!
//! P5 — sign_consensus / verify_consensus round-trip:
//!   - Any message signed with a keypair verifies with that keypair.
//!   - The same message signed with a different keypair fails verification.
//!
//! P6 — Bit-flip rejection:
//!   - Flipping any single bit in a valid signature causes verify_consensus to
//!     return Err. Uses a bit index to identify the exact bit, not random bytes,
//!     so failures are reproducible and the failing bit can be diagnosed.
//!
//! Run (requires real ML-DSA-65 via pqcrypto-dilithium):
//!   cargo test -p chain-forge-crypto --features real-pqc \
//!     --test prop_sign_verify -- --nocapture
#![cfg(feature = "real-pqc")]

use chain_forge_crypto::{MlDsaScheme, sign_consensus, verify_consensus};
use proptest::prelude::*;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// A fixed keypair generated once for property tests that need a valid signature
/// without needing to generate a fresh key on every run.
fn fixed_keypair() -> chain_forge_crypto::KeyPair {
    // We call generate_random() once; proptest will re-use the resulting keypair
    // across generated inputs in P6, keeping test runtime reasonable.
    MlDsaScheme.generate_random().expect("fixed keygen")
}

// ── P5: Round-trip ────────────────────────────────────────────────────────────

proptest! {
    /// sign then verify with the SAME keypair always succeeds.
    #[test]
    fn p5_roundtrip(msg in proptest::collection::vec(0u8..=255u8, 0usize..512usize)) {
        let kp = MlDsaScheme.generate_random().expect("keygen");
        let sig = sign_consensus(&msg, &kp).expect("sign");
        prop_assert!(
            verify_consensus(&msg, &sig, &kp.public_key).is_ok(),
            "verify must succeed for the same key"
        );
    }

    /// sign with key A, verify with key B: must fail (with high probability).
    #[test]
    fn p5_wrong_key_fails(msg in proptest::collection::vec(0u8..=255u8, 1usize..256usize)) {
        let kp_a = MlDsaScheme.generate_random().expect("keygen a");
        let kp_b = MlDsaScheme.generate_random().expect("keygen b");
        // Key collision probability is negligible; treat as impossible.
        let sig = sign_consensus(&msg, &kp_a).expect("sign");
        prop_assert!(
            verify_consensus(&msg, &sig, &kp_b.public_key).is_err(),
            "verify must fail with a different key"
        );
    }

    /// Verifying a valid signature against a mutated message must fail.
    #[test]
    fn p5_mutated_message_fails(
        mut msg in proptest::collection::vec(0u8..=255u8, 1usize..256usize),
        flip_idx in 0usize..256usize,
    ) {
        let kp = MlDsaScheme.generate_random().expect("keygen");
        let sig = sign_consensus(&msg, &kp).expect("sign");

        let idx = flip_idx % msg.len();
        msg[idx] ^= 0xFF;

        prop_assert!(
            verify_consensus(&msg, &sig, &kp.public_key).is_err(),
            "verify must fail when message is mutated"
        );
    }
}

// ── P6: Bit-flip rejection ────────────────────────────────────────────────────

proptest! {
    /// Flipping any single bit in a valid dilithium3 signature causes
    /// verify_consensus to return Err.
    ///
    /// Uses a bit index (not random bytes) so the failing case is reproducible:
    /// the proptest shrink output names the exact bit position.
    #[test]
    fn p6_single_bit_flip_in_signature_fails(
        msg in proptest::collection::vec(0u8..=255u8, 1usize..128usize),
        bit_idx in 0usize..19360usize,  // dilithium3 signature = 2420 bytes = 19360 bits
    ) {
        let kp = fixed_keypair();
        let mut sig = sign_consensus(&msg, &kp).expect("sign");

        // Only attempt the flip if the bit index is in-range for this signature.
        let total_bits = sig.len() * 8;
        let bit = bit_idx % total_bits;
        sig[bit / 8] ^= 1 << (bit % 8);

        prop_assert!(
            verify_consensus(&msg, &sig, &kp.public_key).is_err(),
            "verify must fail after flipping bit {bit} in signature"
        );
    }
}

/// Explicit boundary check: flip the first bit, the last bit, and a mid-range bit.
#[test]
fn p6_bit_flip_boundaries() {
    let kp = MlDsaScheme.generate_random().expect("keygen");
    let msg = b"boundary bit-flip test message";

    for &bit in &[0usize, 1, 100, 500, 1000, 2419 * 8 + 7] {
        let mut sig = sign_consensus(msg, &kp).expect("sign");
        if bit / 8 < sig.len() {
            sig[bit / 8] ^= 1 << (bit % 8);
            assert!(
                verify_consensus(msg, &sig, &kp.public_key).is_err(),
                "verify must fail after flipping bit {bit}"
            );
        }
    }
}

/// Truncated signature is rejected.
#[test]
fn p6_truncated_signature_rejected() {
    let kp = MlDsaScheme.generate_random().expect("keygen");
    let msg = b"truncation test";
    let sig = sign_consensus(msg, &kp).expect("sign");

    // Try truncating to various lengths: 0, 1, half, one-short.
    for &len in &[0, 1, sig.len() / 2, sig.len() - 1] {
        let truncated = &sig[..len];
        assert!(
            verify_consensus(msg, truncated, &kp.public_key).is_err(),
            "truncated signature (len={len}) must be rejected"
        );
    }
}
