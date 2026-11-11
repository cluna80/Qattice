//! PQ-HotStuff-2 engine foundation: validator sets, limits, leader selection and the section 5/6 safety rules.
//! Spec: docs/pq-hotstuff-001-spec.md (sections 3.4.1, 3.4.3, 4, 5, 6). Off by default: `--features pq-hotstuff`.
#![cfg(feature = "pq-hotstuff")]

use chain_forge_consensus::pq_hotstuff::leader::{leader, leader_index};
use chain_forge_consensus::pq_hotstuff::limits::{
    qc_max_bytes, tc_max_bytes, LimitsError, PqLimits, MAX_CERT_VALIDATORS,
};
use chain_forge_consensus::pq_hotstuff::rules::{
    commits_parent, next_round, record_timeout, record_vote, safe_to_timeout, safe_to_vote, BlockHeader, TcInfo,
    TimeoutRefusal, TimeoutRequest, VoteRefusal, VoterState,
};
use chain_forge_consensus::pq_hotstuff::types::{EpochSet, SetError, ValidatorEntry};

fn key(b: u8) -> Vec<u8> { vec![b; 1952] }
fn entry(addr: &str, b: u8, power: u64) -> ValidatorEntry {
    ValidatorEntry { address: addr.to_string(), public_key: key(b), power }
}
fn set4() -> EpochSet {
    EpochSet::new(0, vec![entry("qcb1carol", 3, 1), entry("qcb1alice", 1, 1), entry("qcb1dave", 4, 1), entry("qcb1bob", 2, 1)]).unwrap()
}

// ---- validator set: canonical order, uniqueness, quorum ------------------------------------------------------------------

#[test]
fn entries_are_in_ascending_bytewise_address_order_whatever_the_input_order() {
    let s = set4();
    let names: Vec<&str> = s.entries().iter().map(|e| e.address.as_str()).collect();
    assert_eq!(names, ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"]);
    assert_eq!(s.index_of("qcb1carol"), Some(2));
    assert_eq!(s.index_of("nobody"), None);
}

/// Bytewise, not case-insensitive or locale order: an uppercase letter sorts before a lowercase one.
#[test]
fn order_is_bytewise_not_case_folded() {
    let s = EpochSet::new(0, vec![entry("b", 1, 1), entry("B", 2, 1), entry("a", 3, 1)]).unwrap();
    let names: Vec<&str> = s.entries().iter().map(|e| e.address.as_str()).collect();
    assert_eq!(names, ["B", "a", "b"]);
}

#[test]
fn invalid_sets_are_refused() {
    let e = |v| EpochSet::new(0, v).unwrap_err();
    assert_eq!(e(vec![]), SetError::Empty);
    assert_eq!(e(vec![entry("a", 1, 1), entry("a", 2, 1)]), SetError::DuplicateAddress);
    assert_eq!(e(vec![entry("a", 1, 1), entry("b", 1, 1)]), SetError::DuplicateKey);
    assert_eq!(e(vec![entry("", 1, 1)]), SetError::BadAddress);
    assert_eq!(e(vec![entry(&"x".repeat(256), 1, 1)]), SetError::BadAddress);
    assert_eq!(e(vec![entry("a\0b", 1, 1)]), SetError::BadAddress);
    assert_eq!(e(vec![ValidatorEntry { address: "a".into(), public_key: vec![1; 32], power: 1 }]), SetError::BadKeyLength(32));
    assert_eq!(e(vec![entry("a", 1, 0), entry("b", 2, 0)]), SetError::NoPower);
}

/// Dynamic membership is disabled: only epoch 0 can be built.
#[test]
fn epoch_change_is_disabled() {
    assert_eq!(EpochSet::new(1, vec![entry("a", 1, 1)]).unwrap_err(), SetError::EpochChangeDisabled);
}

#[test]
fn quorum_is_floor_two_thirds_plus_one_in_wide_arithmetic() {
    let s = set4();
    assert_eq!(s.total_power(), 4);
    assert_eq!(s.quorum_threshold(), 3);
    assert!(!s.is_quorum(2));
    assert!(s.is_quorum(3));
    // T mod 3 in {0,1,2}
    let q = |n: u64| EpochSet::new(0, (0..n).map(|i| entry(&format!("v{i:03}"), i as u8 + 1, 1)).collect()).unwrap().quorum_threshold();
    assert_eq!((q(3), q(4), q(5), q(6), q(7)), (3, 3, 4, 5, 5));
    // powers near u64::MAX must not wrap
    let big = EpochSet::new(0, vec![entry("a", 1, u64::MAX), entry("b", 2, u64::MAX), entry("c", 3, u64::MAX)]).unwrap();
    assert_eq!(big.total_power(), 3 * u64::MAX as u128);
    assert_eq!(big.quorum_threshold(), 2 * u64::MAX as u128 + 1);
}

#[test]
fn signer_power_rejects_duplicates_out_of_range_and_zero_power_signers() {
    let s = EpochSet::new(0, vec![entry("a", 1, 1), entry("b", 2, 0), entry("c", 3, 5)]).unwrap();
    assert_eq!(s.signer_power(&[0, 2]), Ok(6));
    assert_eq!(s.signer_power(&[0, 0]), Err(SetError::DuplicateSigner));
    assert_eq!(s.signer_power(&[3]), Err(SetError::IndexOutOfRange));
    assert_eq!(s.signer_power(&[1]), Err(SetError::ZeroPowerSigner));
}

// ---- limits ---------------------------------------------------------------------------------------------------------------

/// Sizes computed from the layouts of spec 3.4.3 / 3.4.3a.
#[test]
fn certificate_maxima_match_the_layout_formulas() {
    assert_eq!(qc_max_bytes(4), Some(13_401));
    assert_eq!(tc_max_bytes(4, 4), Some(26_766));
    assert_eq!(qc_max_bytes(31), Some(102_909));
    assert_eq!(tc_max_bytes(31, 31), Some(205_998));
    assert_eq!(qc_max_bytes(100), Some(331_653));
    assert_eq!(tc_max_bytes(100, 100), Some(664_038));
    assert_eq!(qc_max_bytes(1024), Some(3_394_828));
    assert_eq!(tc_max_bytes(1024, 1024), Some(6_797_780));
    // the nested QC may come from a larger earlier set
    assert_eq!(tc_max_bytes(4, 31), Some(72 + 1 + 3323 * 4 + 102_909));
}

#[test]
fn size_arithmetic_never_wraps() {
    assert_eq!(qc_max_bytes(usize::MAX), None);
    assert_eq!(tc_max_bytes(usize::MAX, 4), None);
    assert_eq!(tc_max_bytes(4, usize::MAX), None);
}

#[test]
fn proposal_envelope_is_payload_plus_certificates_plus_signature_plus_header() {
    let l = PqLimits { max_validators: 4, max_cert_validators: MAX_CERT_VALIDATORS, max_block_payload_bytes: 1_048_576, max_message_bytes: None };
    assert_eq!(l.proposal_envelope_max(4), Some(1_048_576 + 13_401 + 26_766 + 3_315 + 512));
    assert_eq!(l.proposal_envelope_max(4), Some(1_092_570));
}

#[test]
fn limits_validation() {
    let ok = |m| PqLimits { max_validators: 4, max_cert_validators: 1024, max_block_payload_bytes: 1_048_576, max_message_bytes: m };
    assert_eq!(ok(None).validate(), Ok(()));
    assert_eq!(ok(Some(1_092_570)).validate(), Ok(()));
    // a message limit below the largest legal proposal makes valid proposals undeliverable
    assert!(matches!(ok(Some(524_288)).validate(), Err(LimitsError::MessageLimitBelowEnvelope { .. })));
    let mut l = ok(None);
    l.max_validators = 0;
    assert_eq!(l.validate(), Err(LimitsError::NoValidators));
    l.max_validators = 2000;
    assert_eq!(l.validate(), Err(LimitsError::ValidatorsAboveCertificateCeiling));
    l = ok(None);
    l.max_cert_validators = 2000;
    assert_eq!(l.validate(), Err(LimitsError::CertificateCeilingTooHigh));
    // an absent message limit must be supplied before the engine runs
    assert_eq!(ok(None).require_message_limit(), Err(LimitsError::MessageLimitUnset));
    assert_eq!(ok(Some(2_000_000)).require_message_limit(), Ok(2_000_000));
}

#[test]
fn set_size_is_checked_against_the_profile_limit() {
    let l = PqLimits { max_validators: 3, max_cert_validators: 1024, max_block_payload_bytes: 1, max_message_bytes: None };
    assert_eq!(l.check_set_size(3), Ok(()));
    assert_eq!(l.check_set_size(4), Err(LimitsError::SetTooLarge { n: 4, max: 3 }));
}

// ---- leader selection -----------------------------------------------------------------------------------------------------

#[test]
fn leader_is_round_robin_over_the_sorted_set() {
    let s = set4();
    let names: Vec<&str> = (0..8).map(|r| leader(&s, r, 0).unwrap().address.as_str()).collect();
    assert_eq!(names, ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave", "qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"]);
}

#[test]
fn leader_skips_zero_power_validators() {
    let s = EpochSet::new(0, vec![entry("a", 1, 1), entry("b", 2, 0), entry("c", 3, 1)]).unwrap();
    let idx: Vec<usize> = (0..4).map(|r| leader_index(&s, r, 0).unwrap()).collect();
    assert_eq!(idx, [0, 2, 0, 2]); // indices are positions in the full canonical order
}

#[test]
fn leader_is_deterministic_and_seed_rotates_it() {
    let s = set4();
    for r in 0..16 {
        assert_eq!(leader_index(&s, r, 0), leader_index(&s, r, 0));
    }
    assert_eq!(leader_index(&s, 0, 1).unwrap(), 1);
    assert_eq!(leader_index(&s, 3, 2).unwrap(), 1);
}

#[test]
fn leader_arithmetic_does_not_overflow() {
    let s = set4();
    assert!(leader_index(&s, u64::MAX, u64::MAX).is_ok());
    assert_eq!(leader_index(&s, u64::MAX, 1), leader_index(&s, 0, 0).map(|_| 0)); // (2^64 mod 4) = 0
}

// ---- section 5: safe to vote ----------------------------------------------------------------------------------------------

fn hdr(round: u64, qc_round: u64, tc: Option<(u64, u64)>) -> BlockHeader {
    BlockHeader { round, qc_round, tc: tc.map(|(round, max_high_qc_round)| TcInfo { round, max_high_qc_round }) }
}

#[test]
fn a_consecutive_block_is_votable_and_updates_the_floors() {
    let mut st = VoterState::default();
    let h = hdr(1, 0, None);
    assert_eq!(safe_to_vote(&st, &h), Ok(()));
    record_vote(&mut st, &h);
    assert_eq!((st.hvr, st.hqr), (1, 0));
    let h2 = hdr(2, 1, None);
    assert_eq!(safe_to_vote(&st, &h2), Ok(()));
    record_vote(&mut st, &h2);
    assert_eq!((st.hvr, st.hqr), (2, 1));
}

/// Rule 2: the round must exceed both the highest voted round and the certified parent's round.
#[test]
fn votes_never_go_back_or_repeat_a_round() {
    let st = VoterState { hvr: 5, hqr: 4 };
    assert_eq!(safe_to_vote(&st, &hdr(5, 4, None)), Err(VoteRefusal::RoundNotAboveVoted));
    assert_eq!(safe_to_vote(&st, &hdr(4, 3, None)), Err(VoteRefusal::RoundNotAboveVoted));
    assert_eq!(safe_to_vote(&VoterState::default(), &hdr(3, 3, None)), Err(VoteRefusal::RoundNotAboveQc));
}

/// Rule 3: a round gap needs a TC for exactly the previous round whose highest reported QC round does not exceed the block's QC.
#[test]
fn a_gap_without_a_timeout_certificate_is_refused() {
    let st = VoterState::default();
    assert_eq!(safe_to_vote(&st, &hdr(5, 3, None)), Err(VoteRefusal::GapWithoutTc));
}

#[test]
fn the_timeout_certificate_must_be_for_the_previous_round() {
    let st = VoterState::default();
    assert_eq!(safe_to_vote(&st, &hdr(5, 3, Some((3, 3)))), Err(VoteRefusal::TcWrongRound));
    assert_eq!(safe_to_vote(&st, &hdr(5, 3, Some((5, 3)))), Err(VoteRefusal::TcWrongRound));
    assert_eq!(safe_to_vote(&st, &hdr(5, 3, Some((4, 3)))), Ok(()));
}

/// The scripted counterexample: a leader that skips a QC higher than the one every timeout reported would fork.
#[test]
fn a_qc_below_the_timeout_certificates_highest_round_is_refused() {
    let st = VoterState::default();
    assert_eq!(safe_to_vote(&st, &hdr(5, 2, Some((4, 3)))), Err(VoteRefusal::QcBelowTcMax));
    assert_eq!(safe_to_vote(&st, &hdr(5, 3, Some((4, 3)))), Ok(()));
    assert_eq!(safe_to_vote(&st, &hdr(5, 4, Some((4, 3)))), Ok(()));
}

#[test]
fn a_consecutive_block_does_not_need_or_use_a_tc() {
    let st = VoterState::default();
    assert_eq!(safe_to_vote(&st, &hdr(4, 3, Some((3, 9)))), Ok(()));
}

#[test]
fn round_arithmetic_at_u64_max_does_not_wrap() {
    let st = VoterState::default();
    // qc_round + 1 would wrap to 0: the block is not "consecutive", it is a gap without a TC
    assert_eq!(safe_to_vote(&st, &hdr(1, u64::MAX, None)), Err(VoteRefusal::RoundNotAboveQc));
    assert_eq!(safe_to_vote(&st, &hdr(u64::MAX, u64::MAX - 1, None)), Ok(()));
    assert_eq!(safe_to_vote(&st, &hdr(u64::MAX, 5, None)), Err(VoteRefusal::GapWithoutTc));
}

#[test]
fn the_vote_floor_only_rises() {
    let mut st = VoterState { hvr: 9, hqr: 8 };
    record_vote(&mut st, &hdr(10, 3, Some((9, 3))));
    assert_eq!((st.hvr, st.hqr), (10, 8)); // hqr keeps the higher lock
}

// ---- section 5: safe to timeout ---------------------------------------------------------------------------------------------

fn to(round: u64, high_qc_round: u64, tc_round: Option<u64>) -> TimeoutRequest {
    TimeoutRequest { round, high_qc_round, tc_round }
}

#[test]
fn a_timeout_for_the_round_after_the_high_qc_is_allowed() {
    let st = VoterState { hvr: 3, hqr: 3 };
    assert_eq!(safe_to_timeout(&st, &to(4, 3, None)), Ok(()));
}

#[test]
fn the_reported_high_qc_cannot_be_below_the_lock() {
    let st = VoterState { hvr: 6, hqr: 5 };
    assert_eq!(safe_to_timeout(&st, &to(7, 4, None)), Err(TimeoutRefusal::HighQcBelowLock));
}

#[test]
fn a_timeout_round_must_exceed_the_high_qc_and_the_voted_round_minus_one() {
    let st = VoterState { hvr: 6, hqr: 5 };
    assert_eq!(safe_to_timeout(&st, &to(5, 5, None)), Err(TimeoutRefusal::RoundNotAboveHighQc));
    assert_eq!(safe_to_timeout(&st, &to(4, 5, None)), Err(TimeoutRefusal::RoundNotAboveHighQc));
    // voting in round r and then timing out in round r is allowed (r == hvr)
    assert_eq!(safe_to_timeout(&st, &to(6, 5, None)), Ok(()));
    let st2 = VoterState { hvr: 6, hqr: 2 };
    assert_eq!(safe_to_timeout(&st2, &to(5, 3, Some(4))), Err(TimeoutRefusal::RoundBelowVoted));
}

#[test]
fn a_timeout_after_a_gap_needs_the_previous_rounds_tc() {
    let st = VoterState { hvr: 2, hqr: 2 };
    assert_eq!(safe_to_timeout(&st, &to(6, 2, None)), Err(TimeoutRefusal::GapWithoutTc));
    assert_eq!(safe_to_timeout(&st, &to(6, 2, Some(4))), Err(TimeoutRefusal::GapWithoutTc)); // wrong round
    assert_eq!(safe_to_timeout(&st, &to(6, 2, Some(5))), Ok(()));
}

#[test]
fn the_timeout_floor_only_rises_and_never_lowers_the_vote_floor() {
    let mut st = VoterState { hvr: 9, hqr: 4 };
    record_timeout(&mut st, &to(6, 4, Some(5)));
    assert_eq!(st.hvr, 9);
    record_timeout(&mut st, &to(10, 4, Some(9)));
    assert_eq!((st.hvr, st.hqr), (10, 4));
}

// ---- section 6: commit rule and round advance --------------------------------------------------------------------------------

#[test]
fn a_parent_commits_only_with_a_consecutive_certified_child() {
    assert!(commits_parent(7, 8));
    assert!(!commits_parent(7, 9)); // the scripted counterexample: a non-consecutive QC must not commit
    assert!(!commits_parent(7, 7));
    assert!(!commits_parent(8, 7));
    assert!(!commits_parent(u64::MAX, 0)); // no wrap-around
}

#[test]
fn rounds_advance_on_a_certificate_for_the_current_or_a_later_round() {
    assert_eq!(next_round(5, 5), 6);
    assert_eq!(next_round(5, 9), 10);
    assert_eq!(next_round(5, 4), 5); // an older certificate never moves the round back
    assert_eq!(next_round(10, 0), 10);
    assert_eq!(next_round(5, 2), 5);
    assert_eq!(next_round(u64::MAX, u64::MAX), u64::MAX); // saturates, never wraps
}
