//! Gate B — key rotation and next-block revocation (QAT-07, `epoch-transition` feature).
//!
//! Tests `rotate_consensus_key`, `revoke_validator`, and the interaction between
//! rotation, revocation, and `admit_pq_native` / `verify_handoff_proof`.
//!
//! Locked rules under test:
//!   - Rotation is applied to finalized registry state before `admit_pq_native` is called.
//!   - Revocation finalized at H excludes the validator from the set at H+1.
//!   - `on_commit` verifies the exact admitted set without filtering it again.
//!   - Revoked wins over rotated: a revoked entry with a valid new key is still excluded.
//!
//! Cases:
//!   KR-1  Rotate to a valid ML-DSA-65 key → admitted set has the NEW key.
//!   KR-2  Rotate to ML-DSA-87 key (2592 bytes) → WrongKeySlot.
//!   KR-3  Rotate unknown validator → UnknownValidator.
//!   KR-4  Revocation at H → validator absent from admitted set at H+1.
//!   KR-5  Revoked + rotated in same epoch → revoked wins (excluded from set).
//!   KR-6  End-to-end: rotate → admit → canonical_set_hash → verify_handoff_proof → Ok.
//!
//! Run (Windows/Linux, real FIPS 204):
//!   cargo test -p chain-forge-consensus --features epoch-transition \
//!     --test gate_b_rotation -- --nocapture
#![cfg(feature = "epoch-transition")]

use chain_forge_consensus::pq_hotstuff::epoch_handoff::{
    admit_pq_native, canonical_set_hash, verify_handoff_proof, AdmissionError,
};
use chain_forge_consensus::pq_hotstuff::safety::{ConsensusSigner, CTX_VOTE, Fips204Signer};
use chain_forge_consensus::{
    BlockHash, BlockHeight, CommitCertificate, Round, VoteType, Vote, vote_signing_bytes_v2,
};
use chain_forge_vca_pq::{
    ContributionScore, IdentityHandle, PersonhoodFactor, StakeAmount,
    VcaRegistry, WeightConfig,
    MLDSA65_PUBKEY_LEN, MLDSA87_PUBKEY_LEN,
};
use chain_forge_core::ValidatorId;

const CHAIN: &str = "qattice-pqhs2-dev-gate-b-rotation";
const HEIGHT: BlockHeight = 30;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn wc() -> WeightConfig { WeightConfig::default() }

fn add_validator(reg: &mut VcaRegistry, id: &str, consensus_key: Vec<u8>) {
    reg.upsert(
        ValidatorId(id.into()),
        IdentityHandle(format!("handle_{id}")),
        ContributionScore(1.0),
        PersonhoodFactor::new(1.0).unwrap(),
        StakeAmount(1_000_000),
        vec![1u8; 32],
        vec![],
    ).expect("upsert ok");
    if !consensus_key.is_empty() {
        let record = reg.records.get_mut(&ValidatorId(id.into())).unwrap();
        record.consensus_ml_dsa_65_pubkey = consensus_key;
    }
}

fn mldsa65_key(seed: u8) -> Vec<u8> {
    let mut v = vec![0u8; MLDSA65_PUBKEY_LEN];
    v[0] = seed;
    v
}

fn mldsa87_key() -> Vec<u8> { vec![0u8; MLDSA87_PUBKEY_LEN] }

fn sign_precommit(
    signer: &mut Fips204Signer,
    id: &str,
    height: BlockHeight,
    round: Round,
    epoch: u64,
    set_hash: &[u8; 32],
    bh: &BlockHash,
) -> Vote {
    let msg = vote_signing_bytes_v2(CHAIN, &VoteType::Precommit, height, round, epoch, set_hash, Some(bh));
    let sig = signer.sign(CTX_VOTE, &msg).unwrap();
    Vote {
        vote_type: VoteType::Precommit,
        height,
        round,
        validator: ValidatorId(id.into()),
        block_hash: Some(bh.clone()),
        signature: sig,
        scheme: "ml-dsa-65".into(),
        epoch,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// KR-1: rotate to a valid ML-DSA-65 key → admitted set carries the NEW key.
#[test]
fn kr1_rotate_valid_key() {
    let mut reg = VcaRegistry::new(1, wc());
    add_validator(&mut reg, "alice", mldsa65_key(0x01)); // initial key

    let new_key = mldsa65_key(0x02);
    reg.rotate_consensus_key(&ValidatorId("alice".into()), new_key.clone()).unwrap();

    let vs = admit_pq_native(&reg, HEIGHT).unwrap();
    let alice = vs.validators.iter().find(|v| v.id.0 == "alice").expect("alice admitted");
    assert_eq!(alice.public_key, new_key, "KR-1: admitted key must be the rotated key");
    println!("[KR-1] rotate to valid key PASS");
}

/// KR-2: rotate to ML-DSA-87 key (2592 bytes) → WrongKeySlot.
#[test]
fn kr2_rotate_mldsa87_key() {
    let mut reg = VcaRegistry::new(1, wc());
    add_validator(&mut reg, "alice", mldsa65_key(0x01));

    let err = reg.rotate_consensus_key(&ValidatorId("alice".into()), mldsa87_key()).unwrap_err();
    assert!(matches!(err, AdmissionError::WrongKeySlot { supplied_len: 2592, .. }),
        "KR-2: expected WrongKeySlot, got: {err}");
    println!("[KR-2] WrongKeySlot on ML-DSA-87 rotation PASS: {err}");
}

/// KR-3: rotate unknown validator → UnknownValidator.
#[test]
fn kr3_rotate_unknown_validator() {
    let mut reg = VcaRegistry::new(1, wc());
    // "carol" was never upserted
    let err = reg.rotate_consensus_key(&ValidatorId("carol".into()), mldsa65_key(0x01)).unwrap_err();
    assert!(matches!(err, AdmissionError::UnknownValidator { .. }),
        "KR-3: expected UnknownValidator, got: {err}");
    println!("[KR-3] UnknownValidator PASS: {err}");
}

/// KR-4: revocation at H → validator absent from admitted set at H+1.
#[test]
fn kr4_revocation_excludes_validator() {
    let mut reg = VcaRegistry::new(1, wc());
    add_validator(&mut reg, "alice", mldsa65_key(0x01));
    add_validator(&mut reg, "bob",   mldsa65_key(0x02));

    // Revoke alice (finalized at H; set at H+1 must not include her).
    reg.revoke_validator(&ValidatorId("alice".into())).unwrap();

    let vs = admit_pq_native(&reg, HEIGHT + 1).unwrap();
    assert_eq!(vs.validators.len(), 1, "KR-4: only bob should be admitted");
    assert_eq!(vs.validators[0].id.0, "bob");
    println!("[KR-4] revocation excludes alice PASS");
}

/// KR-5: revoked + rotated in same epoch → revoked wins.
#[test]
fn kr5_revoked_wins_over_rotated() {
    let mut reg = VcaRegistry::new(1, wc());
    add_validator(&mut reg, "alice", mldsa65_key(0x01));

    // Rotate first, then revoke.
    reg.rotate_consensus_key(&ValidatorId("alice".into()), mldsa65_key(0x99)).unwrap();
    reg.revoke_validator(&ValidatorId("alice".into())).unwrap();

    let vs = admit_pq_native(&reg, HEIGHT + 1).unwrap();
    assert!(vs.validators.iter().all(|v| v.id.0 != "alice"),
        "KR-5: alice must not appear after revocation");
    println!("[KR-5] revoked wins over rotated PASS");
}

/// KR-6: end-to-end — rotate incoming validator's key, derive set via admit_pq_native,
/// compute canonical_set_hash, verify against a valid CommitCertificate.
#[test]
fn kr6_end_to_end_rotation() {
    // Outgoing set: one signer with a real Fips204Signer key.
    let mut outgoing_signer = Fips204Signer::generate().unwrap();
    let out_pk = outgoing_signer.public_key().to_vec();
    let out = chain_forge_consensus::ValidatorSet {
        height: 10,
        validators: vec![chain_forge_core::ValidatorInfo {
            id: ValidatorId("outgoing".into()),
            voting_power: 1,
            pop_verified: true,
            public_key: out_pk,
        }],
    };

    // Incoming registry: alice starts with key 0x01, then rotates to key 0x02.
    let mut reg = VcaRegistry::new(2, wc());
    add_validator(&mut reg, "alice", mldsa65_key(0x01));
    reg.rotate_consensus_key(&ValidatorId("alice".into()), mldsa65_key(0x02)).unwrap();

    let incoming = admit_pq_native(&reg, HEIGHT).unwrap();
    assert_eq!(incoming.validators[0].public_key, mldsa65_key(0x02));
    let set_hash = canonical_set_hash(&incoming);

    let bh = BlockHash("epoch-rotate-test".into());
    let precommit = sign_precommit(&mut outgoing_signer, "outgoing", 10, 5, 0, &set_hash, &bh);
    let cert = CommitCertificate {
        height: 10,
        round: 5,
        block_hash: bh,
        precommits: vec![precommit],
        epoch: 0,
    };

    verify_handoff_proof(CHAIN, &cert, &out, 6, &incoming, set_hash, 0).unwrap();
    println!("[KR-6] end-to-end rotation PASS");
}
