//! Gate B — `pqc-native` validator admission (QAT-07, `epoch-transition` feature).
//!
//! Tests `admit_pq_native` and the `VcaValidatorRecord::to_validator_info_pq` path.
//! Each test corresponds to a named rule locked in QAT-07:
//!
//!   AD-1  Valid credential binding: ML-DSA-65 key present, correct length → admitted.
//!   AD-2  Substituted key: incoming set's key differs from registry binding → SetHashMismatch.
//!   AD-3  Missing key: `consensus_ml_dsa_65_pubkey` is empty → NoPqConsensusKey.
//!   AD-4  ML-DSA-87 key in ML-DSA-65 slot: 2592-byte key → WrongKeySlot.
//!   AD-5  Malformed length: not 1952 and not 2592 → WrongKeyLength.
//!   AD-6  Zero-weight validator excluded silently.
//!   AD-7  Happy path: admitted set matches canonical_set_hash used by verify_handoff_proof.
//!
//! Run (Windows/Linux, real FIPS 204):
//!   cargo test -p chain-forge-consensus --features epoch-transition \
//!     --test gate_b_admission -- --nocapture
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
use chain_forge_core::ValidatorId as CoreValidatorId;

const CHAIN: &str = "qattice-pqhs2-dev-gate-b-admission";
const HEIGHT: BlockHeight = 20;

// ── Registry helpers ──────────────────────────────────────────────────────────

fn wc() -> WeightConfig { WeightConfig::default() }

fn make_registry() -> VcaRegistry {
    VcaRegistry::new(1, wc())
}

/// Add a validator with the given personhood and contribution, then set an ML-DSA-65
/// consensus key (1952 bytes, all zeroes except for the first byte which encodes the index).
fn add_validator(
    reg: &mut VcaRegistry,
    id: &str,
    pk: Vec<u8>,   // consensus_ml_dsa_65_pubkey to set (empty = skip)
    p: f64,
    c: f64,
) {
    reg.upsert(
        CoreValidatorId(id.into()),
        IdentityHandle(format!("handle_{id}")),
        ContributionScore(c),
        PersonhoodFactor::new(p).unwrap(),
        StakeAmount(1_000_000),
        vec![1u8; 32],  // classical key — not used by pqc-native path
        vec![],         // pq_pubkey (ML-DSA-87 slot) — not used here
    ).expect("upsert ok");

    if !pk.is_empty() {
        let record = reg.records.get_mut(&CoreValidatorId(id.into())).unwrap();
        record.consensus_ml_dsa_65_pubkey = pk;
    }
}

fn mldsa65_key(seed: u8) -> Vec<u8> {
    let mut v = vec![0u8; MLDSA65_PUBKEY_LEN];
    v[0] = seed;
    v
}

fn mldsa87_key() -> Vec<u8> {
    vec![0u8; MLDSA87_PUBKEY_LEN]
}

fn malformed_key() -> Vec<u8> {
    vec![0u8; 100] // not 1952, not 2592
}

// ── Signing helpers ───────────────────────────────────────────────────────────

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
        validator: CoreValidatorId(id.into()),
        block_hash: Some(bh.clone()),
        signature: sig,
        scheme: "ml-dsa-65".into(),
        epoch,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// AD-3: empty consensus key → NoPqConsensusKey.
#[test]
fn ad3_missing_key() {
    let mut reg = make_registry();
    add_validator(&mut reg, "alice", vec![], 1.0, 1.0); // no consensus key set
    let err = admit_pq_native(&reg, HEIGHT).unwrap_err();
    assert!(matches!(err, AdmissionError::NoPqConsensusKey { .. }),
        "AD-3: expected NoPqConsensusKey, got: {err}");
    println!("[AD-3] NoPqConsensusKey PASS: {err}");
}

/// AD-4: ML-DSA-87 key (2592 bytes) supplied in ML-DSA-65 slot → WrongKeySlot.
#[test]
fn ad4_mldsa87_in_mldsa65_slot() {
    let mut reg = make_registry();
    add_validator(&mut reg, "alice", mldsa87_key(), 1.0, 1.0);
    let err = admit_pq_native(&reg, HEIGHT).unwrap_err();
    assert!(matches!(err, AdmissionError::WrongKeySlot { supplied_len: 2592, .. }),
        "AD-4: expected WrongKeySlot(2592), got: {err}");
    println!("[AD-4] WrongKeySlot PASS: {err}");
}

/// AD-5: key of unexpected length (not 1952, not 2592) → WrongKeyLength.
#[test]
fn ad5_malformed_length() {
    let mut reg = make_registry();
    add_validator(&mut reg, "alice", malformed_key(), 1.0, 1.0);
    let err = admit_pq_native(&reg, HEIGHT).unwrap_err();
    assert!(
        matches!(err, AdmissionError::WrongKeyLength { got: 100, expected: 1952, .. }),
        "AD-5: expected WrongKeyLength(100), got: {err}"
    );
    println!("[AD-5] WrongKeyLength PASS: {err}");
}

/// AD-6: zero-weight validator excluded silently; registry has one valid + one zero-weight.
#[test]
fn ad6_zero_weight_excluded() {
    let mut reg = make_registry();
    add_validator(&mut reg, "alice", mldsa65_key(1), 1.0, 1.0); // positive weight
    add_validator(&mut reg, "bob",   mldsa65_key(2), 0.0, 1.0); // zero personhood → zero weight

    let vs = admit_pq_native(&reg, HEIGHT).unwrap();
    assert_eq!(vs.validators.len(), 1, "AD-6: only alice should be admitted");
    assert_eq!(vs.validators[0].id.0, "alice");
    println!("[AD-6] zero-weight excluded PASS");
}

/// AD-1: valid credential binding — correct 1952-byte key, positive weight → admitted.
#[test]
fn ad1_valid_credential_binding() {
    let mut reg = make_registry();
    add_validator(&mut reg, "alice", mldsa65_key(1), 1.0, 1.0);
    add_validator(&mut reg, "bob",   mldsa65_key(2), 1.0, 1.0);

    let vs = admit_pq_native(&reg, HEIGHT).unwrap();
    assert_eq!(vs.validators.len(), 2, "AD-1: both validators admitted");
    // Keys must match what was registered.
    for info in &vs.validators {
        assert_eq!(info.public_key.len(), MLDSA65_PUBKEY_LEN,
            "AD-1: admitted key must be 1952 bytes");
    }
    println!("[AD-1] valid credential binding PASS");
}

/// AD-2: substituted key — admitted set has the registry's key, but `verify_handoff_proof`
/// is called with a set_hash computed from an ALTERED set → SetHashMismatch.
/// This confirms that substituting a key after `admit_pq_native` is detected.
#[test]
fn ad2_substituted_key() {
    // Build outgoing set (the validators who sign the commit certificate).
    let (mut s0, pk0) = {
        let s = Fips204Signer::generate().unwrap();
        let pk = s.public_key().to_vec();
        (s, pk)
    };

    // Real incoming set: alice with key from registry.
    let mut reg = make_registry();
    add_validator(&mut reg, "alice", mldsa65_key(0xAA), 1.0, 1.0);
    let real_incoming = admit_pq_native(&reg, HEIGHT).unwrap();
    let real_hash = canonical_set_hash(&real_incoming);

    // Build a valid commit certificate from the outgoing set (single validator for simplicity).
    let out = {
        use chain_forge_core::ValidatorInfo;
        chain_forge_consensus::ValidatorSet {
            height: 10,
            validators: vec![ValidatorInfo {
                id: CoreValidatorId("v0".into()),
                voting_power: 1,
                pop_verified: true,
                public_key: pk0.clone(),
            }],
        }
    };
    let bh = BlockHash("epoch-change".into());
    let precommit = sign_precommit(&mut s0, "v0", 10, 5, 0, &real_hash, &bh);
    let cert = CommitCertificate {
        height: 10,
        round: 5,
        block_hash: bh,
        precommits: vec![precommit],
        epoch: 0,
    };

    // Altered incoming: alice's key replaced with a different one.
    let mut altered_reg = make_registry();
    add_validator(&mut altered_reg, "alice", mldsa65_key(0xBB), 1.0, 1.0);
    let altered_incoming = admit_pq_native(&altered_reg, HEIGHT).unwrap();

    // verify_handoff_proof: real_hash but altered_incoming → SetHashMismatch.
    let err = verify_handoff_proof(CHAIN, &cert, &out, 6, &altered_incoming, real_hash, 0)
        .unwrap_err();
    use chain_forge_consensus::pq_hotstuff::epoch_handoff::HandoffError;
    assert!(matches!(err, HandoffError::SetHashMismatch { .. }),
        "AD-2: expected SetHashMismatch, got: {err}");
    println!("[AD-2] substituted key → SetHashMismatch PASS: {err}");
}

/// AD-7: happy path — admit → canonical_set_hash → verify_handoff_proof all pass.
/// Uses real Fips204Signer keys so the outgoing sigs actually verify.
#[test]
fn ad7_happy_path_end_to_end() {
    // Three-validator outgoing set (signers of the epoch-change block).
    let signers: Vec<(Fips204Signer, Vec<u8>)> = (0..3)
        .map(|_| { let s = Fips204Signer::generate().unwrap(); let pk = s.public_key().to_vec(); (s, pk) })
        .collect();
    let mut signers = signers;

    let out = {
        use chain_forge_core::ValidatorInfo;
        chain_forge_consensus::ValidatorSet {
            height: 10,
            validators: signers.iter().enumerate().map(|(i, (_, pk))| ValidatorInfo {
                id: CoreValidatorId(format!("v{i}")),
                voting_power: 1,
                pop_verified: true,
                public_key: pk.clone(),
            }).collect(),
        }
    };
    // Incoming set derived from registry via admit_pq_native.
    let mut reg = make_registry();
    add_validator(&mut reg, "new_alice", mldsa65_key(0x01), 1.0, 1.0);
    add_validator(&mut reg, "new_bob",   mldsa65_key(0x02), 1.0, 1.0);

    let incoming = admit_pq_native(&reg, HEIGHT + 1).unwrap();
    let set_hash = canonical_set_hash(&incoming);

    let bh = BlockHash("epoch-change-happy".into());
    let precommits: Vec<Vote> = signers.iter_mut().enumerate()
        .map(|(i, (s, _))| sign_precommit(s, &format!("v{i}"), 10, 5, 0, &set_hash, &bh))
        .collect();
    let cert = CommitCertificate { height: 10, round: 5, block_hash: bh, precommits, epoch: 0 };

    verify_handoff_proof(CHAIN, &cert, &out, 6, &incoming, set_hash, 0).unwrap();
    println!("[AD-7] end-to-end happy path PASS");
}
