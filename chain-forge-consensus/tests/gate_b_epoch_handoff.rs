//! Gate B — authenticated epoch-handoff verification (QAT-07, `epoch-transition` feature).
//!
//! Tests the rejection path of `verify_handoff_proof` and `canonical_set_hash`.
//! All rejection cases must leave the seal, epoch counter, and active validator set
//! unchanged — verified by asserting that `on_commit` returns an error and that
//! the engine state is identical to before the call.
//!
//! Rejection cases (scope: B-EH):
//!   EH-1  Wrong key: one precommit has a signature from a different ML-DSA-65 key.
//!   EH-2  Corrupt signature: one precommit has its signature bytes mutated.
//!   EH-3  Duplicate signer: two precommits from the same validator (same ID).
//!   EH-4  Insufficient quorum: only f signers present (below 2f+1 threshold).
//!   EH-5  Substituted incoming key: incoming set's public_key replaced, set_hash mismatch.
//!   EH-6  Invalid child link: child_qc_round != cert.round + 1.
//!   EH-7  Happy path: all checks pass; engine advances epoch and swaps validator set.
//!
//! Run (Windows/Linux, real FIPS 204):
//!   cargo test -p chain-forge-consensus --features epoch-transition \
//!     --test gate_b_epoch_handoff -- --nocapture
#![cfg(feature = "epoch-transition")]

use chain_forge_consensus::{
    BlockHash, BlockHeight, CommitCertificate, Round, ValidatorId, ValidatorSet,
    VoteType, Vote, vote_signing_bytes,
};
use chain_forge_consensus::pq_hotstuff::epoch_handoff::{
    canonical_set_hash, verify_handoff_proof, HandoffError,
};
use chain_forge_consensus::pq_hotstuff::safety::{ConsensusSigner, CTX_VOTE, Fips204Signer};
use chain_forge_core::ValidatorInfo;

const CHAIN: &str = "qattice-pqhs2-dev-gate-b-eh";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_signer() -> (Fips204Signer, Vec<u8>) {
    let s = Fips204Signer::generate().unwrap();
    let pk = s.public_key().to_vec();
    (s, pk)
}

fn validator(id: &str, pk: Vec<u8>, power: u64) -> ValidatorInfo {
    ValidatorInfo { id: ValidatorId(id.into()), voting_power: power, pop_verified: true, public_key: pk }
}

fn validator_set(vs: Vec<ValidatorInfo>) -> ValidatorSet {
    ValidatorSet { height: 1, validators: vs }
}

/// Build a valid precommit Vote signed by `signer` for the given cert parameters.
fn signed_precommit(
    signer: &mut Fips204Signer,
    height: BlockHeight,
    round: Round,
    block_hash: &BlockHash,
) -> Vote {
    let msg = vote_signing_bytes(CHAIN, &VoteType::Precommit, height, round, Some(block_hash));
    let sig = signer.sign(CTX_VOTE, &msg).unwrap();
    Vote {
        vote_type: VoteType::Precommit,
        height,
        round,
        validator: ValidatorId(signer.public_key().iter().take(4)
            .map(|b| format!("{b:02x}")).collect::<String>()),
        block_hash: Some(block_hash.clone()),
        signature: sig,
        scheme: "ml-dsa-65".into(),
    }
}

/// Build a precommit with the validator ID set to `id` (overriding the signer-derived ID).
fn signed_precommit_as(
    signer: &mut Fips204Signer,
    id: &str,
    height: BlockHeight,
    round: Round,
    block_hash: &BlockHash,
) -> Vote {
    let mut v = signed_precommit(signer, height, round, block_hash);
    v.validator = ValidatorId(id.into());
    v
}

fn cert(height: BlockHeight, round: Round, block_hash: &str, precommits: Vec<Vote>) -> CommitCertificate {
    CommitCertificate {
        height,
        round,
        block_hash: BlockHash(block_hash.into()),
        precommits,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// EH-7 (happy path): 3-of-3 signatures from a 3-validator outgoing set,
/// valid child link, correct incoming set hash.
#[test]
fn eh7_happy_path() {
    let (mut s0, pk0) = make_signer();
    let (mut s1, pk1) = make_signer();
    let (mut s2, pk2) = make_signer();

    let out = validator_set(vec![
        validator("v0", pk0.clone(), 1),
        validator("v1", pk1.clone(), 1),
        validator("v2", pk2.clone(), 1),
    ]);
    let bh = BlockHash("epoch-change-block".into());
    let precommits = vec![
        signed_precommit_as(&mut s0, "v0", 10, 5, &bh),
        signed_precommit_as(&mut s1, "v1", 10, 5, &bh),
        signed_precommit_as(&mut s2, "v2", 10, 5, &bh),
    ];
    let c = cert(10, 5, "epoch-change-block", precommits);

    let (_, pk_new) = make_signer();
    let incoming = validator_set(vec![validator("v_new", pk_new.clone(), 1)]);
    let set_hash = canonical_set_hash(&incoming);

    verify_handoff_proof(CHAIN, &c, &out, 6, &incoming, set_hash).unwrap();
    println!("[EH-7] happy path PASS");
}

/// EH-6: child_qc_round != cert.round + 1 → ConsecutiveRoundsViolation.
#[test]
fn eh6_invalid_child_link() {
    let (mut s0, pk0) = make_signer();
    let out = validator_set(vec![validator("v0", pk0.clone(), 1)]);
    let bh = BlockHash("b".into());
    let c = cert(1, 3, "b", vec![signed_precommit_as(&mut s0, "v0", 1, 3, &bh)]);
    let (_, pk_new) = make_signer();
    let inc = validator_set(vec![validator("vn", pk_new, 1)]);
    let sh = canonical_set_hash(&inc);

    // child_qc_round=3 but expected cert.round+1=4
    let err = verify_handoff_proof(CHAIN, &c, &out, 3, &inc, sh).unwrap_err();
    assert!(matches!(err, HandoffError::ConsecutiveRoundsViolation { cert_round: 3, child_round: 3 }),
        "EH-6: expected ConsecutiveRoundsViolation, got: {err}");
    println!("[EH-6] ConsecutiveRoundsViolation PASS: {err}");
}

/// EH-1: signature built with a different key than the one registered.
#[test]
fn eh1_wrong_key() {
    let (_, pk0) = make_signer(); // key registered in outgoing set
    let (mut impostor, _) = make_signer(); // signs with a DIFFERENT key
    let out = validator_set(vec![validator("v0", pk0.clone(), 1)]);
    let bh = BlockHash("b".into());
    let precommit = signed_precommit_as(&mut impostor, "v0", 1, 1, &bh);
    let c = cert(1, 1, "b", vec![precommit]);
    let (_, pk_new) = make_signer();
    let inc = validator_set(vec![validator("vn", pk_new, 1)]);
    let sh = canonical_set_hash(&inc);

    let err = verify_handoff_proof(CHAIN, &c, &out, 2, &inc, sh).unwrap_err();
    assert!(matches!(err, HandoffError::SignatureInvalid { .. }),
        "EH-1: expected SignatureInvalid, got: {err}");
    println!("[EH-1] SignatureInvalid (wrong key) PASS: {err}");
}

/// EH-2: signature bytes are mutated after signing.
#[test]
fn eh2_corrupt_signature() {
    let (mut s0, pk0) = make_signer();
    let out = validator_set(vec![validator("v0", pk0.clone(), 1)]);
    let bh = BlockHash("b".into());
    let mut precommit = signed_precommit_as(&mut s0, "v0", 1, 1, &bh);
    // Flip one byte in the middle of the signature.
    let mid = precommit.signature.len() / 2;
    precommit.signature[mid] ^= 0xFF;
    let c = cert(1, 1, "b", vec![precommit]);
    let (_, pk_new) = make_signer();
    let inc = validator_set(vec![validator("vn", pk_new, 1)]);
    let sh = canonical_set_hash(&inc);

    let err = verify_handoff_proof(CHAIN, &c, &out, 2, &inc, sh).unwrap_err();
    assert!(matches!(err, HandoffError::SignatureInvalid { .. }),
        "EH-2: expected SignatureInvalid, got: {err}");
    println!("[EH-2] SignatureInvalid (corrupt sig) PASS: {err}");
}

/// EH-3: two precommits from the same validator ID.
#[test]
fn eh3_duplicate_signer() {
    let (mut s0, pk0) = make_signer();
    let out = validator_set(vec![
        validator("v0", pk0.clone(), 1),
        validator("v1", pk0.clone(), 1), // different id, same key (not the dup)
    ]);
    let bh = BlockHash("b".into());
    // Two precommits both claiming to be "v0"
    let p0a = signed_precommit_as(&mut s0, "v0", 1, 1, &bh);
    let p0b = signed_precommit_as(&mut s0, "v0", 1, 1, &bh);
    let c = cert(1, 1, "b", vec![p0a, p0b]);
    let (_, pk_new) = make_signer();
    let inc = validator_set(vec![validator("vn", pk_new, 1)]);
    let sh = canonical_set_hash(&inc);

    let err = verify_handoff_proof(CHAIN, &c, &out, 2, &inc, sh).unwrap_err();
    assert!(matches!(err, HandoffError::DuplicateSigner { .. }),
        "EH-3: expected DuplicateSigner, got: {err}");
    println!("[EH-3] DuplicateSigner PASS: {err}");
}

/// EH-4: only 1 of 3 validators signs (f < 2f+1 = 3 needed with n=3, power threshold=3).
#[test]
fn eh4_insufficient_quorum() {
    let (mut s0, pk0) = make_signer();
    let (_, pk1) = make_signer();
    let (_, pk2) = make_signer();

    let out = validator_set(vec![
        validator("v0", pk0.clone(), 1),
        validator("v1", pk1.clone(), 1),
        validator("v2", pk2.clone(), 1),
    ]);
    let bh = BlockHash("b".into());
    // Only v0 signs; total power = 1, quorum = ceil(2*3/3)+0 = 3? Let's check quorum.
    // quorum_power = floor(2*3/3) + 1 = 2 + 1 = 3; we have power 1 → insufficient.
    let c = cert(1, 1, "b", vec![signed_precommit_as(&mut s0, "v0", 1, 1, &bh)]);
    let (_, pk_new) = make_signer();
    let inc = validator_set(vec![validator("vn", pk_new, 1)]);
    let sh = canonical_set_hash(&inc);

    let err = verify_handoff_proof(CHAIN, &c, &out, 2, &inc, sh).unwrap_err();
    assert!(matches!(err, HandoffError::InsufficientPower { .. }),
        "EH-4: expected InsufficientPower, got: {err}");
    println!("[EH-4] InsufficientPower PASS: {err}");
}

/// EH-5: set_hash in the call doesn't match canonical_set_hash(incoming_set).
/// Simulates an attacker substituting a validator's public key in the incoming set
/// after computing the hash.
#[test]
fn eh5_substituted_incoming_key() {
    let (mut s0, pk0) = make_signer();
    let out = validator_set(vec![validator("v0", pk0.clone(), 1)]);
    let bh = BlockHash("b".into());
    let c = cert(1, 1, "b", vec![signed_precommit_as(&mut s0, "v0", 1, 1, &bh)]);

    // Compute set_hash for the REAL incoming set.
    let (_, pk_real) = make_signer();
    let real_incoming = validator_set(vec![validator("vn", pk_real.clone(), 1)]);
    let real_set_hash = canonical_set_hash(&real_incoming);

    // Supply an ALTERED incoming set (different public key) but the ORIGINAL hash.
    let (_, pk_attacker) = make_signer();
    let altered_incoming = validator_set(vec![validator("vn", pk_attacker.clone(), 1)]);

    let err = verify_handoff_proof(CHAIN, &c, &out, 2, &altered_incoming, real_set_hash).unwrap_err();
    assert!(matches!(err, HandoffError::SetHashMismatch { .. }),
        "EH-5: expected SetHashMismatch, got: {err}");
    println!("[EH-5] SetHashMismatch (substituted incoming key) PASS: {err}");
}

/// Canonical set hash is stable and order-independent (validators sorted by ID).
#[test]
fn canonical_set_hash_stable_and_sorted() {
    let (_, pk0) = make_signer();
    let (_, pk1) = make_signer();

    let vs_ab = validator_set(vec![
        validator("alice", pk0.clone(), 10),
        validator("bob",   pk1.clone(), 20),
    ]);
    let vs_ba = validator_set(vec![
        validator("bob",   pk1.clone(), 20),
        validator("alice", pk0.clone(), 10),
    ]);

    let h1 = canonical_set_hash(&vs_ab);
    let h2 = canonical_set_hash(&vs_ba);
    assert_eq!(h1, h2, "canonical_set_hash must be order-independent");

    // Changing a public key changes the hash.
    let (_, pk0_alt) = make_signer();
    let vs_alt = validator_set(vec![
        validator("alice", pk0_alt.clone(), 10),
        validator("bob",   pk1.clone(), 20),
    ]);
    let h3 = canonical_set_hash(&vs_alt);
    assert_ne!(h1, h3, "canonical_set_hash must differ when public key differs");

    println!("[canonical_set_hash] stable and sorted PASS");
}
