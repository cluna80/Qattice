//! Property tests for the authenticated epoch handoff (P3/P7).
//!
//! P3/P7 — Verify the handoff as a pair:
//!   - A valid h2/h3 pair certified by the outgoing set in epoch 0 passes
//!     both `verify_handoff_proof` calls.
//!   - A single mixed-epoch vote (epoch ≠ 0 in one precommit) is exercised
//!     independently of signature corruption and must trigger an epoch-related
//!     failure (SignatureInvalid — the signed bytes mismatch — or a future
//!     EpochMismatch variant).
//!   - A child certificate built under the wrong epoch fails independently.
//!
//! All tests use the FIPS 204 ML-DSA-65 backend (`Fips204Signer`) because that
//! is the signer path for `verify_handoff_proof` under `not(real-crypto)`.
//!
//! Run:
//!   cargo test -p chain-forge-consensus --features epoch-transition \
//!     --test prop_handoff -- --nocapture
#![cfg(feature = "epoch-transition")]

use chain_forge_consensus::{
    vote_signing_bytes_v2, BlockHash, BlockHeight, CommitCertificate, Round, ValidatorId,
    ValidatorSet, Vote, VoteType,
};
use chain_forge_consensus::pq_hotstuff::epoch_handoff::{
    canonical_set_hash, verify_handoff_proof, HandoffError,
};
use chain_forge_consensus::pq_hotstuff::safety::{ConsensusSigner, CTX_VOTE, Fips204Signer};
use chain_forge_core::ValidatorInfo;

const CHAIN: &str = "qattice-pq-prop-test";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_signer_and_info(id: &str, power: u64) -> (Fips204Signer, ValidatorInfo) {
    let mut s = Fips204Signer::generate().expect("keygen");
    let pk = s.public_key().to_vec();
    let info = ValidatorInfo {
        id: ValidatorId(id.into()),
        voting_power: power,
        pop_verified: true,
        public_key: pk,
    };
    (s, info)
}

fn sign_precommit(
    signer: &mut Fips204Signer,
    id: &str,
    height: BlockHeight,
    round: Round,
    epoch: u64,
    bh: &BlockHash,
    set_hash: &[u8; 32],
) -> Vote {
    let msg = vote_signing_bytes_v2(CHAIN, &VoteType::Precommit, height, round, epoch, set_hash, Some(bh));
    let sig = signer.sign(CTX_VOTE, &msg).expect("sign");
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

fn build_cert(
    signers: &mut Vec<(Fips204Signer, ValidatorInfo)>,
    height: BlockHeight,
    round: Round,
    epoch: u64,
    bh: &BlockHash,
    set_hash: &[u8; 32],
) -> CommitCertificate {
    let precommits: Vec<Vote> = signers.iter_mut()
        .map(|(s, info)| sign_precommit(s, &info.id.0.clone(), height, round, epoch, bh, set_hash))
        .collect();
    CommitCertificate { height, round, block_hash: bh.clone(), precommits, epoch }
}

fn outgoing_set(signers: &[(Fips204Signer, ValidatorInfo)]) -> ValidatorSet {
    ValidatorSet {
        height: 0,
        validators: signers.iter().map(|(_, info)| info.clone()).collect(),
    }
}

fn fresh_incoming_set() -> ValidatorSet {
    // Same 4 validators (same-validator-set transition), distinct keys.
    let ids = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
    ValidatorSet {
        height: 3,
        validators: ids.iter().enumerate().map(|(i, id)| ValidatorInfo {
            id: ValidatorId((*id).into()),
            voting_power: 1,
            pop_verified: true,
            public_key: vec![(i + 1) as u8; 1952],  // 1952-byte placeholder (pqc-native key length)
        }).collect(),
    }
}

// ── P3/P7: Valid pair ─────────────────────────────────────────────────────────

/// Happy-path: a valid h2/h3 pair certified by the outgoing set in epoch 0
/// passes both verify_handoff_proof calls. This corresponds to the devnet trace:
///   h2 cert (round r)   — epoch-change block, certified by outgoing set
///   h3 cert (round r+1) — boundary child, also certified by outgoing set
#[test]
fn p3_p7_valid_pair_epoch_0() {
    let mut signers: Vec<_> = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"]
        .iter().map(|id| make_signer_and_info(id, 1)).collect();

    let out = outgoing_set(&signers);
    let inc = fresh_incoming_set();
    let set_hash = canonical_set_hash(&inc);

    let bh2 = BlockHash("epoch-change-block-h2".to_string());
    let bh3 = BlockHash("boundary-child-h3".to_string());

    let cert_h2 = build_cert(&mut signers, 2, 5, 0, &bh2, &set_hash);
    let cert_h3 = build_cert(&mut signers, 3, 6, 0, &bh3, &set_hash);

    // h2 cert: child_qc_round = cert_h2.round + 1 = 6
    verify_handoff_proof(CHAIN, &cert_h2, &out, 6, &inc, set_hash, 0)
        .expect("h2 cert must pass verify_handoff_proof");

    // h3 cert: child_qc_round = cert_h3.round + 1 = 7
    verify_handoff_proof(CHAIN, &cert_h3, &out, 7, &inc, set_hash, 0)
        .expect("h3 cert must pass verify_handoff_proof");
}

// ── P3/P7: Mixed-epoch vote (epoch-independent failure) ───────────────────────

/// A certificate where one precommit is re-signed with epoch=1 v2 bytes while
/// the rest use epoch=0 v2 bytes fails signature verification. The verifier
/// reconstructs v2 bytes with epoch=0, so the epoch=1 vote fails.
#[test]
fn p3_p7_mixed_epoch_vote_fails() {
    let mut signers: Vec<_> = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"]
        .iter().map(|id| make_signer_and_info(id, 1)).collect();

    let out = outgoing_set(&signers);
    let inc = fresh_incoming_set();
    let set_hash = canonical_set_hash(&inc);

    let bh = BlockHash("epoch-change-block".to_string());

    // Build a valid epoch=0 cert.
    let mut cert = build_cert(&mut signers, 2, 5, 0, &bh, &set_hash);

    // Replace alice's signature with one signed under epoch=1 v2 bytes.
    let corrupt_msg = vote_signing_bytes_v2(CHAIN, &VoteType::Precommit, 2, 5, 1, &set_hash, Some(&bh));
    let corrupt_sig = signers[0].0.sign(CTX_VOTE, &corrupt_msg).expect("sign corrupt");
    cert.precommits[0].signature = corrupt_sig;

    let err = verify_handoff_proof(CHAIN, &cert, &out, 6, &inc, set_hash, 0)
        .expect_err("epoch-1 vote in epoch-0 cert must fail");
    assert!(
        matches!(err, HandoffError::SignatureInvalid { .. }),
        "expected SignatureInvalid, got: {err}"
    );
}

// ── P3/P7: Wrong child QC round ───────────────────────────────────────────────

/// If child_qc_round ≠ cert.round + 1, verify_handoff_proof returns
/// ConsecutiveRoundsViolation regardless of signature validity.
#[test]
fn p3_p7_wrong_child_qc_round() {
    let mut signers: Vec<_> = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"]
        .iter().map(|id| make_signer_and_info(id, 1)).collect();

    let out = outgoing_set(&signers);
    let inc = fresh_incoming_set();
    let set_hash = canonical_set_hash(&inc);

    let bh = BlockHash("epoch-change-block".to_string());
    let cert = build_cert(&mut signers, 2, 5, 0, &bh, &set_hash);

    // child_qc_round = 5, but cert.round + 1 = 6 — gap of 1.
    let err = verify_handoff_proof(CHAIN, &cert, &out, 5, &inc, set_hash, 0)
        .expect_err("wrong child_qc_round must fail");
    assert!(
        matches!(err, HandoffError::ConsecutiveRoundsViolation { cert_round: 5, child_round: 5 }),
        "expected ConsecutiveRoundsViolation, got: {err}"
    );

    // child_qc_round = 10 (too far ahead).
    let err2 = verify_handoff_proof(CHAIN, &cert, &out, 10, &inc, set_hash, 0)
        .expect_err("wrong child_qc_round must fail");
    assert!(
        matches!(err2, HandoffError::ConsecutiveRoundsViolation { cert_round: 5, child_round: 10 }),
        "expected ConsecutiveRoundsViolation, got: {err2}"
    );
}

// ── P3/P7: Wrong child cert epoch (future v2 path) ───────────────────────────

/// A certificate where cert.epoch=1 but expected_epoch=0 fails with EpochMismatch.
#[test]
fn p3_p7_wrong_cert_epoch() {
    let mut signers: Vec<_> = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"]
        .iter().map(|id| make_signer_and_info(id, 1)).collect();

    let out = outgoing_set(&signers);
    let inc = fresh_incoming_set();
    let set_hash = canonical_set_hash(&inc);

    let bh = BlockHash("epoch-change-block".to_string());
    let mut cert = build_cert(&mut signers, 2, 5, 0, &bh, &set_hash);
    cert.epoch = 1;  // cert claims epoch=1 but expected_epoch=0

    let err = verify_handoff_proof(CHAIN, &cert, &out, 6, &inc, set_hash, 0)
        .expect_err("wrong cert.epoch must fail");
    assert!(
        matches!(err, HandoffError::EpochMismatch { cert_epoch: 1, expected_epoch: 0 }),
        "expected EpochMismatch, got: {err}"
    );
}

// ── P3/P7: Insufficient quorum ────────────────────────────────────────────────

/// A certificate with only 1-of-4 signatures (below the 3-of-4 quorum) is rejected.
#[test]
fn p3_p7_insufficient_quorum() {
    let mut signers: Vec<_> = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"]
        .iter().map(|id| make_signer_and_info(id, 1)).collect();

    let out = outgoing_set(&signers);
    let inc = fresh_incoming_set();
    let set_hash = canonical_set_hash(&inc);

    let bh = BlockHash("epoch-change-block".to_string());
    let mut cert = build_cert(&mut signers, 2, 5, 0, &bh, &set_hash);
    // Keep only the first precommit.
    cert.precommits.truncate(1);

    let err = verify_handoff_proof(CHAIN, &cert, &out, 6, &inc, set_hash, 0)
        .expect_err("1-of-4 quorum must fail");
    assert!(
        matches!(err, HandoffError::InsufficientPower { .. }),
        "expected InsufficientPower, got: {err}"
    );
}

// ── P3/P7: Set hash mismatch ──────────────────────────────────────────────────

/// If the expected_set_hash does not match canonical_set_hash(incoming_set),
/// verify_handoff_proof returns SetHashMismatch.
#[test]
fn p3_p7_set_hash_mismatch() {
    let mut signers: Vec<_> = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"]
        .iter().map(|id| make_signer_and_info(id, 1)).collect();

    let out = outgoing_set(&signers);
    let inc = fresh_incoming_set();
    let set_hash = canonical_set_hash(&inc);

    let bh = BlockHash("epoch-change-block".to_string());
    let cert = build_cert(&mut signers, 2, 5, 0, &bh, &set_hash);

    // Pass a wrong set_hash (all zeros).
    let wrong_hash = [0u8; 32];
    let err = verify_handoff_proof(CHAIN, &cert, &out, 6, &inc, wrong_hash, 0)
        .expect_err("wrong set_hash must fail");
    assert!(
        matches!(err, HandoffError::SetHashMismatch { .. }),
        "expected SetHashMismatch, got: {err}"
    );
}
