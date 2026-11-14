//! Property tests for vote signing-bytes format (P1, P2, P4).
//!
//! P1 — Field binding: every signed field, when mutated, changes the output bytes.
//!      Covers all VoteType variants, epoch, validator-set commitment (set_hash),
//!      and the absent/present distinction for block_hash. Boundary values exercised.
//!
//! P2 — Cross-version signature rejection: v1 bytes ≠ v2 bytes for any inputs.
//!      With real FIPS 204 ML-DSA-65, a signature over v1 bytes fails the v2
//!      verifier, and vice versa. Prevents a verifier that falls back to the
//!      legacy format from silently accepting a cross-version signature.
//!
//! P4 — canonical_set_hash: order-independent (sort stability), sensitive to
//!      validator ID, public key content, and voting power.
//!
//! Run:
//!   cargo test -p chain-forge-consensus --features pq-hotstuff \
//!     --test prop_vote_format -- --nocapture
//!
//! For P2 (FIPS 204 cross-version rejection), add --features pq-hotstuff-fips204.

use chain_forge_consensus::{
    vote_signing_bytes, vote_signing_bytes_v2, BlockHash, ValidatorId, ValidatorSet,
    VoteType,
};
use chain_forge_core::ValidatorInfo;
use proptest::prelude::*;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn all_vote_types() -> Vec<VoteType> {
    vec![VoteType::Prevote, VoteType::Precommit, VoteType::Nil]
}

fn zero_set_hash() -> [u8; 32] { [0u8; 32] }

fn block_hash(s: &str) -> BlockHash { BlockHash(s.to_string()) }

/// Strategy: boundary-biased u64 — 0, 1, MAX-1, MAX, plus uniform mid-range.
fn boundary_u64() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1u64),
        Just(2u64),
        Just(u64::MAX - 1),
        Just(u64::MAX),
        0u64..1_000_000u64,
    ]
}

fn boundary_u32() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        Just(1u32),
        Just(u32::MAX - 1),
        Just(u32::MAX),
        0u32..10_000u32,
    ]
}

fn chain_id_strategy() -> impl Strategy<Value = String> {
    // Include a chain_id containing '|' to verify the v1 delimiter cannot spoof v2.
    prop_oneof![
        "[a-zA-Z0-9\\-]{1,32}".prop_map(|s| s),
        Just("chain|with|pipes".to_string()),
        Just("".to_string()),
        Just("a".to_string()),
    ]
}

fn set_hash_strategy() -> impl Strategy<Value = [u8; 32]> {
    proptest::array::uniform32(0u8..=255u8)
}

fn opt_block_hash_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        "[0-9a-f]{64}".prop_map(Some),
        "[0-9a-f]{1,10}".prop_map(Some),  // short hash — tests length sensitivity
    ]
}

// ── P1: Field binding ─────────────────────────────────────────────────────────

/// Changing vote_type always changes the bytes for all three variants.
#[test]
fn p1_all_vote_types_distinct() {
    let sh = zero_set_hash();
    let bh = Some(block_hash("aa"));
    for height in [0u64, 1, u64::MAX] {
        for round in [0u32, 1, u32::MAX] {
            for epoch in [0u64, 1, u64::MAX] {
                let prev    = vote_signing_bytes_v2("chain", &VoteType::Prevote,   height, round, epoch, &sh, bh.as_ref());
                let precom  = vote_signing_bytes_v2("chain", &VoteType::Precommit, height, round, epoch, &sh, bh.as_ref());
                let nil     = vote_signing_bytes_v2("chain", &VoteType::Nil,       height, round, epoch, &sh, None);
                assert_ne!(prev, precom, "Prevote == Precommit at h={height} r={round} e={epoch}");
                assert_ne!(prev, nil,    "Prevote == Nil at h={height} r={round} e={epoch}");
                assert_ne!(precom, nil,  "Precommit == Nil at h={height} r={round} e={epoch}");
            }
        }
    }
}

proptest! {
    /// Mutating epoch by 1 always changes the bytes.
    #[test]
    fn p1_epoch_binding(
        chain in chain_id_strategy(),
        height in boundary_u64(),
        round in boundary_u32(),
        epoch in 0u64..u64::MAX,  // leave room for epoch+1
        sh in set_hash_strategy(),
        bh_str in opt_block_hash_strategy(),
    ) {
        let bh = bh_str.as_deref().map(|s| BlockHash(s.to_string()));
        let base  = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round, epoch,     &sh, bh.as_ref());
        let plus1 = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round, epoch + 1, &sh, bh.as_ref());
        prop_assert_ne!(base, plus1);
    }

    /// Mutating height by 1 always changes the bytes.
    #[test]
    fn p1_height_binding(
        chain in chain_id_strategy(),
        height in 0u64..u64::MAX,
        round in boundary_u32(),
        epoch in boundary_u64(),
        sh in set_hash_strategy(),
    ) {
        let sh_ref = &sh;
        let base  = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height,     round, epoch, sh_ref, None);
        let plus1 = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height + 1, round, epoch, sh_ref, None);
        prop_assert_ne!(base, plus1);
    }

    /// Mutating round by 1 always changes the bytes.
    #[test]
    fn p1_round_binding(
        chain in chain_id_strategy(),
        height in boundary_u64(),
        round in 0u32..u32::MAX,
        epoch in boundary_u64(),
        sh in set_hash_strategy(),
    ) {
        let sh_ref = &sh;
        let base  = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round,     epoch, sh_ref, None);
        let plus1 = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round + 1, epoch, sh_ref, None);
        prop_assert_ne!(base, plus1);
    }

    /// Mutating a single byte anywhere in set_hash always changes the bytes.
    #[test]
    fn p1_set_hash_binding(
        chain in chain_id_strategy(),
        height in boundary_u64(),
        round in boundary_u32(),
        epoch in boundary_u64(),
        mut sh in set_hash_strategy(),
        idx in 0usize..32,
    ) {
        let base = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round, epoch, &sh, None);
        sh[idx] ^= 0xFF;
        let mutated = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round, epoch, &sh, None);
        prop_assert_ne!(base, mutated);
    }

    /// A set_hash that differs only in the last byte produces different bytes.
    #[test]
    fn p1_set_hash_last_byte(
        chain in chain_id_strategy(),
        height in boundary_u64(),
        round in boundary_u32(),
        epoch in boundary_u64(),
        sh_base in proptest::array::uniform31(0u8..=255u8),
        b0 in 0u8..=254u8,
    ) {
        let mut sh_a = [0u8; 32];
        let mut sh_b = [0u8; 32];
        sh_a[..31].copy_from_slice(&sh_base);
        sh_b[..31].copy_from_slice(&sh_base);
        sh_a[31] = b0;
        sh_b[31] = b0 + 1;
        let a = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round, epoch, &sh_a, None);
        let b = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round, epoch, &sh_b, None);
        prop_assert_ne!(a, b);
    }

    /// Absent block_hash ≠ any present block_hash.
    #[test]
    fn p1_absent_vs_present_block_hash(
        chain in chain_id_strategy(),
        height in boundary_u64(),
        round in boundary_u32(),
        epoch in boundary_u64(),
        sh in set_hash_strategy(),
        bh_str in "[0-9a-f]{1,128}",
    ) {
        let sh_ref = &sh;
        let absent  = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round, epoch, sh_ref, None);
        let present = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round, epoch, sh_ref, Some(&BlockHash(bh_str)));
        prop_assert_ne!(absent, present);
    }

    /// Two distinct block hashes produce distinct bytes.
    #[test]
    fn p1_distinct_block_hashes(
        chain in chain_id_strategy(),
        height in boundary_u64(),
        round in boundary_u32(),
        epoch in boundary_u64(),
        sh in set_hash_strategy(),
        bh1 in "[0-9a-f]{64}",
        bh2 in "[0-9a-f]{64}",
    ) {
        prop_assume!(bh1 != bh2);
        let sh_ref = &sh;
        let a = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round, epoch, sh_ref, Some(&BlockHash(bh1)));
        let b = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round, epoch, sh_ref, Some(&BlockHash(bh2)));
        prop_assert_ne!(a, b);
    }

    /// chain_id binding: two distinct chain_ids produce distinct bytes.
    #[test]
    fn p1_chain_id_binding(
        c1 in "[a-zA-Z0-9]{1,16}",
        c2 in "[a-zA-Z0-9]{1,16}",
        height in boundary_u64(),
        round in boundary_u32(),
        epoch in boundary_u64(),
        sh in set_hash_strategy(),
    ) {
        prop_assume!(c1 != c2);
        let sh_ref = &sh;
        let a = vote_signing_bytes_v2(&c1, &VoteType::Precommit, height, round, epoch, sh_ref, None);
        let b = vote_signing_bytes_v2(&c2, &VoteType::Precommit, height, round, epoch, sh_ref, None);
        prop_assert_ne!(a, b);
    }
}

// ── P2: Cross-version byte inequality ────────────────────────────────────────

proptest! {
    /// v1 bytes are NEVER equal to v2 bytes for the same logical vote inputs.
    /// Structural: v1 starts with b"CFV|", v2 with b"CFV2\x00" — they cannot match.
    #[test]
    fn p2_v1_v2_byte_inequality(
        chain in chain_id_strategy(),
        height in boundary_u64(),
        round in boundary_u32(),
        epoch in boundary_u64(),
        sh in set_hash_strategy(),
        bh_str in opt_block_hash_strategy(),
    ) {
        let bh = bh_str.as_deref().map(|s| BlockHash(s.to_string()));
        let v1 = vote_signing_bytes(&chain, &VoteType::Precommit, height, round, bh.as_ref());
        let v2 = vote_signing_bytes_v2(&chain, &VoteType::Precommit, height, round, epoch, &sh, bh.as_ref());
        prop_assert_ne!(v1, v2);
    }
}

/// Fixed encoding test vector — guards against silent format regressions.
///
/// Input: chain="qattice-test", Precommit, height=1, round=0, epoch=0,
///        set_hash=[0;32], block_hash=Some("aabb")
///
/// Any change to vote_signing_bytes_v2's encoding invalidates this vector and
/// must be a deliberate, reviewed protocol change.
#[test]
fn p2_fixed_v2_encoding_vector() {
    let chain   = "qattice-test";
    let vtype   = VoteType::Precommit;
    let height  = 1u64;
    let round   = 0u32;
    let epoch   = 0u64;
    let sh      = [0u8; 32];
    let bh      = BlockHash("aabb".to_string());

    let got = vote_signing_bytes_v2(chain, &vtype, height, round, epoch, &sh, Some(&bh));

    // Reconstruct the expected bytes deterministically from the documented format.
    let mut expected = Vec::new();
    expected.extend_from_slice(b"CFV2\x00");                            // prefix
    let cb = b"qattice-test";
    expected.extend_from_slice(&(cb.len() as u16).to_be_bytes());       // chain_id len u16 BE
    expected.extend_from_slice(cb);                                      // chain_id
    expected.push(1u8);                                                  // Precommit = 1
    expected.extend_from_slice(&1u64.to_le_bytes());                    // height
    expected.extend_from_slice(&0u32.to_le_bytes());                    // round
    expected.extend_from_slice(&0u64.to_le_bytes());                    // epoch
    expected.extend_from_slice(&[0u8; 32]);                             // set_hash
    expected.push(0x01u8);                                               // block_hash present
    let bhb = b"aabb";
    expected.extend_from_slice(&(bhb.len() as u16).to_be_bytes());      // block_hash len
    expected.extend_from_slice(bhb);                                     // block_hash

    assert_eq!(
        got, expected,
        "v2 encoding changed — update the protocol version and this vector together"
    );
}

/// v1 test vector — guards the legacy format.
#[test]
fn p2_fixed_v1_encoding_vector() {
    let got = vote_signing_bytes(
        "qattice-test", &VoteType::Precommit, 1u64, 0u32, Some(&BlockHash("aabb".to_string())),
    );
    let mut expected = Vec::new();
    expected.extend_from_slice(b"CFV|");
    expected.extend_from_slice(b"qattice-test");
    expected.push(b'|');
    expected.push(1u8);                          // Precommit
    expected.extend_from_slice(&1u64.to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.extend_from_slice(b"aabb");
    assert_eq!(got, expected, "v1 encoding changed unexpectedly");
}

// ── P2: FIPS 204 cross-version signature rejection ───────────────────────────

#[cfg(feature = "pq-hotstuff-fips204")]
mod fips204_cross_version {
    use super::*;
    use chain_forge_consensus::pq_hotstuff::safety::{ConsensusSigner, ConsensusVerifier, Fips204Signer, Fips204Verifier};

    const CTX: &[u8] = b"";  // empty context for direct-signing tests

    /// A valid v1 signature FAILS under the v2 verifier (different signed bytes).
    #[test]
    fn p2_v1_sig_rejected_by_v2_verifier() {
        let mut signer = Fips204Signer::generate().expect("keygen");
        let pk = signer.public_key().to_vec();
        let verifier = Fips204Verifier;

        let v1 = vote_signing_bytes(
            "qattice-pq-test", &VoteType::Precommit, 10, 2, Some(&BlockHash("deadbeef".to_string())),
        );
        let v2 = vote_signing_bytes_v2(
            "qattice-pq-test", &VoteType::Precommit, 10, 2, 1, &[0u8; 32],
            Some(&BlockHash("deadbeef".to_string())),
        );

        let sig_v1 = signer.sign(CTX, &v1).expect("sign v1");

        // sig_v1 is over v1_bytes; verifying against v2_bytes must fail.
        assert!(
            !verifier.verify(&pk, CTX, &v2, &sig_v1),
            "v1 signature must not verify against v2 bytes"
        );
    }

    /// A valid v2 signature FAILS under the v1 verifier (different signed bytes).
    #[test]
    fn p2_v2_sig_rejected_by_v1_verifier() {
        let mut signer = Fips204Signer::generate().expect("keygen");
        let pk = signer.public_key().to_vec();
        let verifier = Fips204Verifier;

        let v1 = vote_signing_bytes(
            "qattice-pq-test", &VoteType::Precommit, 10, 2, Some(&BlockHash("deadbeef".to_string())),
        );
        let v2 = vote_signing_bytes_v2(
            "qattice-pq-test", &VoteType::Precommit, 10, 2, 1, &[0u8; 32],
            Some(&BlockHash("deadbeef".to_string())),
        );

        let sig_v2 = signer.sign(CTX, &v2).expect("sign v2");

        // sig_v2 is over v2_bytes; verifying against v1_bytes must fail.
        assert!(
            !verifier.verify(&pk, CTX, &v1, &sig_v2),
            "v2 signature must not verify against v1 bytes"
        );
    }

    /// Round-trip: v2 signature verifies correctly against v2 bytes.
    #[test]
    fn p2_v2_sig_verifies_against_v2_bytes() {
        let mut signer = Fips204Signer::generate().expect("keygen");
        let pk = signer.public_key().to_vec();
        let verifier = Fips204Verifier;

        let v2 = vote_signing_bytes_v2(
            "qattice-pq-test", &VoteType::Precommit, 10, 2, 1, &[0u8; 32],
            Some(&BlockHash("deadbeef".to_string())),
        );
        let sig = signer.sign(CTX, &v2).expect("sign");
        assert!(verifier.verify(&pk, CTX, &v2, &sig), "v2 sig must verify against v2 bytes");
    }
}

// ── P4: canonical_set_hash ────────────────────────────────────────────────────

#[cfg(feature = "epoch-transition")]
mod set_hash_props {
    use super::*;
    use chain_forge_consensus::pq_hotstuff::epoch_handoff::canonical_set_hash;

    fn make_vs(entries: Vec<(&str, Vec<u8>, u64)>) -> ValidatorSet {
        ValidatorSet {
            height: 0,
            validators: entries.into_iter().map(|(id, pk, power)| ValidatorInfo {
                id: ValidatorId(id.into()),
                voting_power: power,
                pop_verified: true,
                public_key: pk,
            }).collect(),
        }
    }

    /// Same set in any order produces the same hash.
    #[test]
    fn p4_order_independence() {
        let pk_a = vec![0xAA; 32];
        let pk_b = vec![0xBB; 32];

        let vs_ab = make_vs(vec![("alice", pk_a.clone(), 1), ("bob", pk_b.clone(), 1)]);
        let vs_ba = make_vs(vec![("bob", pk_b.clone(), 1), ("alice", pk_a.clone(), 1)]);
        assert_eq!(canonical_set_hash(&vs_ab), canonical_set_hash(&vs_ba));

        // Three validators, two permutations.
        let pk_c = vec![0xCC; 32];
        let vs_abc = make_vs(vec![("alice", pk_a.clone(), 1), ("bob", pk_b.clone(), 1), ("carol", pk_c.clone(), 1)]);
        let vs_cab = make_vs(vec![("carol", pk_c.clone(), 1), ("alice", pk_a.clone(), 1), ("bob", pk_b.clone(), 1)]);
        assert_eq!(canonical_set_hash(&vs_abc), canonical_set_hash(&vs_cab));
    }

    proptest! {
        /// Changing validator ID changes the hash.
        #[test]
        fn p4_id_sensitivity(
            id1 in "[a-z]{3,10}",
            id2 in "[a-z]{3,10}",
            power in 1u64..1000,
        ) {
            prop_assume!(id1 != id2);
            let pk = vec![0x01u8; 32];
            let vs1 = make_vs(vec![(id1.as_str(), pk.clone(), power)]);
            let vs2 = make_vs(vec![(id2.as_str(), pk.clone(), power)]);
            prop_assert_ne!(canonical_set_hash(&vs1), canonical_set_hash(&vs2));
        }

        /// Changing voting power changes the hash.
        #[test]
        fn p4_power_sensitivity(
            id in "[a-z]{3,10}",
            p1 in 1u64..1000,
            p2 in 1u64..1000,
        ) {
            prop_assume!(p1 != p2);
            let pk = vec![0x01u8; 32];
            let vs1 = make_vs(vec![(id.as_str(), pk.clone(), p1)]);
            let vs2 = make_vs(vec![(id.as_str(), pk.clone(), p2)]);
            prop_assert_ne!(canonical_set_hash(&vs1), canonical_set_hash(&vs2));
        }

        /// Flipping one byte in a validator's public key changes the hash.
        #[test]
        fn p4_pubkey_sensitivity(
            id in "[a-z]{3,10}",
            power in 1u64..1000,
            mut pk in proptest::collection::vec(0u8..=255u8, 32usize..33usize),
            idx in 0usize..32,
        ) {
            let vs_base = make_vs(vec![(id.as_str(), pk.clone(), power)]);
            pk[idx] ^= 0xFF;
            let vs_mutated = make_vs(vec![(id.as_str(), pk, power)]);
            prop_assert_ne!(canonical_set_hash(&vs_base), canonical_set_hash(&vs_mutated));
        }
    }
}
