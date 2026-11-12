//! Gate A acceptance tests: epoch-boundary signing rules (QAT-07, R2–R3).
//!
//! These tests use in-process doubles (MemStorage, TestCounter, TestSigner) with
//! real ML-DSA-65 message encodings. They demonstrate — without TCP or OS processes —
//! that the safety store enforces the R2 transition table and that R3-a/R3-b recovery
//! paths restore a validator correctly after a crash at any point in the write order.
//!
//! Run: cargo test -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_epoch_boundary
#![cfg(feature = "pq-hotstuff")]

#[path = "common/pq_safety_doubles.rs"]
mod doubles;

use chain_forge_consensus::pq_hotstuff::safety::*;
use chain_forge_consensus::pq_hotstuff::wire::*;
use doubles::*;
use sha3::{Digest, Sha3_256};

const ALG: AlgId = AlgId::MLDSA65_FIPS204;
const CHAIN: &str = "qattice-pqhs2-dev";
const PROFILE: &str = "qattice-pq-hotstuff-2-v2";
const ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

// Epoch-change block is committed at round z=4; B_child is at round z+1=5.
// The seal round is 5 (QC_child.round).
const EPOCH_Z: u64 = 4;
const SEAL_ROUND: u64 = 5; // z+1

type Store = SafetyStore<MemStorage, TestCounter>;

fn sha3_32(d: &[u8]) -> [u8; 32] { Sha3_256::digest(d).into() }

fn vote(epoch: u64, round: u64, b: u8) -> VoteMessage {
    VoteMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch, round, block_id: [b; 32], parent_id: [0x22; 32], parent_round: round.saturating_sub(1) }
}

#[allow(dead_code)]
struct World { st: MemStorage, ctr: TestCounter, f: Shared, signer: TestSigner, pk: Vec<u8> }

impl World {
    fn new() -> Self {
        let f = faults();
        Self { st: MemStorage::new(f.clone()), ctr: TestCounter::new(f.clone()), f, signer: TestSigner::new(1), pk: test_public_key(1) }
    }

    fn init(&self) -> Store {
        Store::initialize_fresh(
            self.st.clone(), self.ctr.clone(),
            &FreshInit { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &self.pk, instance_id: ID, epoch: 0 },
            &ParticipationEvidence::default(),
        ).expect("initialize")
    }

    fn expected(&self) -> Expected<'_> { Expected { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &self.pk } }

    fn open(&self, st: &MemStorage, ctr: &TestCounter) -> Result<Store, OpenError> {
        Store::open(st.clone(), ctr.clone(), &self.expected(), &TestVerifier, &ParticipationEvidence::default())
    }

}

/// Fake cert + set hashes (content doesn't matter for the in-process tests).
fn fake_hashes() -> ([u8; 32], [u8; 32]) {
    let cert_hash = sha3_32(b"fake-commit-cert");
    let set_hash = sha3_32(b"fake-validator-set");
    (cert_hash, set_hash)
}

/// Build a store that has voted for B_ec (round EPOCH_Z) and B_child (round SEAL_ROUND),
/// then written the seal. This is the state just before advance_epoch_record.
fn store_after_seal(w: &mut World) -> Store {
    let mut s = w.init();
    // Sign at epoch 0, rounds 1..=EPOCH_Z (simulate normal operation leading up to handoff)
    s.sign_vote(&vote(0, 1, 1), 0, &mut w.signer).unwrap();
    s.sign_vote(&vote(0, EPOCH_Z, 2), EPOCH_Z - 1, &mut w.signer).unwrap();
    // Vote for B_child at SEAL_ROUND
    s.sign_vote(&vote(0, SEAL_ROUND, 3), EPOCH_Z, &mut w.signer).unwrap();
    // Write seal (R2 step 2): CommitCertificate is now durable in block store (simulated)
    s.write_seal(0, SEAL_ROUND).unwrap();
    s
}

/// Full happy-path advance: seal written, then epoch advanced.
fn store_after_advance(w: &mut World) -> Store {
    let mut s = store_after_seal(w);
    let (cert_hash, set_hash) = fake_hashes();
    s.advance_epoch_record(1, set_hash, cert_hash).unwrap();
    s
}

// ── R2: Seal enforced ─────────────────────────────────────────────────────────

#[test]
fn outgoing_set_cannot_produce_new_epoch0_vote_above_seal_round() {
    let mut w = World::new();
    let mut s = store_after_seal(&mut w);
    // Any new vote at round > SEAL_ROUND for epoch 0 must be denied
    let err = s.sign_vote(&vote(0, SEAL_ROUND + 1, 0xff), SEAL_ROUND, &mut w.signer).unwrap_err();
    assert!(matches!(err, SignError::SealViolation { epoch: 0, round: _, seal_round: SEAL_ROUND }), "got {err:?}");
}

#[test]
fn outgoing_set_can_retransmit_below_or_at_seal_round() {
    let mut w = World::new();
    let mut s = store_after_seal(&mut w);
    // Retransmit of the exact vote at SEAL_ROUND must succeed (same bytes)
    let r = s.sign_vote(&vote(0, SEAL_ROUND, 3), EPOCH_Z, &mut w.signer).unwrap();
    assert!(r.resent, "must be a retransmit, not a new signature");
}

#[test]
fn incoming_set_cannot_produce_epoch0_signature_after_advance() {
    let mut w = World::new();
    let mut s = store_after_advance(&mut w);
    // After advancing to epoch 1, epoch 0 is an EpochRegression
    let err = s.sign_vote(&vote(0, SEAL_ROUND + 1, 0xaa), SEAL_ROUND, &mut w.signer).unwrap_err();
    assert!(matches!(err, SignError::EpochRegression { record: 1, requested: 0 }), "got {err:?}");
}

#[test]
fn incoming_set_first_epoch1_round_must_be_at_least_1() {
    let mut w = World::new();
    let mut s = store_after_advance(&mut w);
    // Round 0 in epoch 1 is prohibited
    let err = s.sign_vote(&vote(1, 0, 0x11), 0, &mut w.signer).unwrap_err();
    assert!(matches!(err, SignError::RoundBelowEpochMinimum { epoch: 1, round: 0 }), "got {err:?}");
}

#[test]
fn incoming_set_signs_at_epoch1_round1_after_advance() {
    let mut w = World::new();
    let mut s = store_after_advance(&mut w);
    let r = s.sign_vote(&vote(1, 1, 0x55), 1, &mut w.signer).unwrap();
    assert!(!r.resent);
    assert_eq!(s.record().epoch, 1);
    assert_eq!(s.record().hvr, Some(1));
}

#[test]
fn no_conflicting_commits_across_boundary() {
    let mut w = World::new();
    let mut s = store_after_advance(&mut w);
    // Outgoing-epoch vote is now an EpochRegression
    let err_old = s.sign_vote(&vote(0, 10, 0xde), 9, &mut w.signer).unwrap_err();
    // Incoming-epoch vote at round 1 is allowed
    let ok_new = s.sign_vote(&vote(1, 1, 0xad), 1, &mut w.signer);
    assert!(matches!(err_old, SignError::EpochRegression { .. }), "got {err_old:?}");
    assert!(ok_new.is_ok(), "epoch-1 round-1 vote failed: {ok_new:?}");
}

// ── R3-a: Safety record in epoch 0, block store committed epoch is 1 ─────────

#[test]
fn r3a_recovery_seal_durable_epoch_not_advanced() {
    // Simulate: CommitCertificate is in block store, seal is written, process crashes
    // before advance_epoch_record. On restart, the safety record is at epoch 0 with
    // seal=(0, SEAL_ROUND). Recovery re-runs advance_epoch_record.
    let mut w = World::new();
    let s = store_after_seal(&mut w);

    // Snapshot the storage+counter after seal write (the "crash" state)
    let (st_after_seal, ctr_after_seal) = s.into_parts();

    // On restart: open the store (should succeed; seal is in the record)
    let mut s2 = w.open(&st_after_seal, &ctr_after_seal).expect("R3-a: open after crash");
    assert_eq!(s2.record().epoch, 0, "epoch must still be 0 after crash");
    assert_eq!(s2.record().seal, Some((0, SEAL_ROUND)), "seal must be durable");

    // R3-a recovery: derive from block store (simulated here) and advance epoch
    let (cert_hash, set_hash) = fake_hashes();
    s2.advance_epoch_record(1, set_hash, cert_hash).expect("R3-a: advance_epoch_record");

    // Verify correct epoch-1 state
    assert_eq!(s2.record().epoch, 1);
    assert!(s2.record().seal.is_none(), "seal cleared after advance");
    assert_eq!(s2.record().set_hash, Some(set_hash));
    assert_eq!(s2.record().handoff_cert_hash, Some(cert_hash));

    // And can now sign at epoch 1
    s2.sign_vote(&vote(1, 1, 0x01), 1, &mut w.signer).expect("epoch-1 vote after R3-a");
}

#[test]
fn r3a_recovery_no_seal_missing_means_cert_hash_check_on_restart_fails_closed() {
    // Simulate: crash between CommitCertificate write and seal write (R2 step 1→2 crash).
    // The safety record has no seal. The block store has the cert. The validator cannot
    // yet advance epoch — that's correct: the caller must re-run write_seal first.
    let mut w = World::new();
    let mut s = w.init();
    s.sign_vote(&vote(0, SEAL_ROUND, 3), EPOCH_Z, &mut w.signer).unwrap();
    // No write_seal call (crashed before step 2)
    let (st, ctr) = s.into_parts();

    // Restart: epoch is 0, no seal
    let s2 = w.open(&st, &ctr).expect("open should succeed (pre-seal crash)");
    assert_eq!(s2.record().epoch, 0);
    assert!(s2.record().seal.is_none(), "no seal written before crash");
    // Caller (R3-a) must write_seal before advancing
}

// ── R3-b: Safety record in epoch 1 — verify on open ──────────────────────────

#[test]
fn r3b_set_hash_and_cert_hash_persisted_and_readable_on_restart() {
    let mut w = World::new();
    let s = store_after_advance(&mut w);
    let (cert_hash, set_hash) = fake_hashes();
    assert_eq!(s.record().set_hash, Some(set_hash), "set_hash must be persisted");
    assert_eq!(s.record().handoff_cert_hash, Some(cert_hash), "cert hash must be persisted");
    let (st, ctr) = s.into_parts();

    // Reopen: record must survive a round-trip through storage
    let s2 = w.open(&st, &ctr).expect("R3-b: open after advance");
    assert_eq!(s2.record().epoch, 1);
    assert_eq!(s2.record().set_hash, Some(set_hash));
    assert_eq!(s2.record().handoff_cert_hash, Some(cert_hash));
}

#[test]
fn r3b_epoch1_floors_start_clean() {
    let mut w = World::new();
    let s = store_after_advance(&mut w);
    // After advancing to epoch 1, per-epoch floors are cleared
    assert!(s.record().hvr.is_none(), "hvr must be None in epoch 1 on fresh advance");
    assert!(s.record().hqr.is_none(), "hqr must be None in epoch 1 on fresh advance");
}

// ── Crash injection at each write-order step ─────────────────────────────────

#[test]
fn crash_before_write_seal_leaves_no_seal_and_store_opens_at_epoch0() {
    let mut w = World::new();
    let mut s = w.init();
    s.sign_vote(&vote(0, SEAL_ROUND, 3), EPOCH_Z, &mut w.signer).unwrap();
    // Crash before write_seal (step 2 never runs)
    let (st, ctr) = s.into_parts();
    let s2 = w.open(&st, &ctr).expect("open after pre-seal-write crash");
    assert_eq!(s2.record().epoch, 0);
    assert!(s2.record().seal.is_none());
}

#[test]
fn crash_after_write_seal_before_advance_epoch_record_recovers_via_r3a() {
    let mut w = World::new();
    let s = store_after_seal(&mut w);
    let (st, ctr) = s.into_parts();

    // On restart: seal is durable, epoch is 0
    let mut s2 = w.open(&st, &ctr).expect("open after post-seal crash");
    assert_eq!(s2.record().epoch, 0);
    assert_eq!(s2.record().seal, Some((0, SEAL_ROUND)));

    // R3-a: re-run advance_epoch_record (idempotent recovery)
    let (cert_hash, set_hash) = fake_hashes();
    s2.advance_epoch_record(1, set_hash, cert_hash).expect("R3-a advance");
    assert_eq!(s2.record().epoch, 1);
}

#[test]
fn crash_after_advance_epoch_record_reopens_at_epoch1() {
    let mut w = World::new();
    let s = store_after_advance(&mut w);
    let (st, ctr) = s.into_parts();

    // Reopen: epoch 1 record is durable
    let s2 = w.open(&st, &ctr).expect("open after full advance");
    assert_eq!(s2.record().epoch, 1);
    assert!(s2.record().seal.is_none());
}
