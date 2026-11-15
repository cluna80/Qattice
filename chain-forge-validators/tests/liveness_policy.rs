// SPDX-License-Identifier: MIT
//! Property tests for H0-11B liveness-suspension policy.
//!
//! All thresholds and windows are derived from PQ-HotStuff-2 devnet
//! measurements on BossKing (Windows/MINGW64). See ROADMAP.md H0-11B
//! and `chain-forge-validators::liveness_policy` for the derivation.
//!
//! Tests:
//!   LP-01  Healthy validator (0% miss rate) → Ok.
//!   LP-02  Tier-W alert fires at ≥10% miss in last 100 blocks.
//!   LP-03  Tier-O alert fires at ≥20% miss in last 200 blocks.
//!   LP-04  33% miss rate exceeds threshold → ThresholdBreached during grace window.
//!   LP-05  After grace window (50 blocks) with threshold still breached → SuspendEligible.
//!   LP-06  Quorum floor: 4-node committee cannot suspend anyone (would breach 3f+1=4).
//!   LP-07  5-node committee can suspend one (resulting size 4 ≥ MIN_COMMITTEE).
//!   LP-08  Byzantine-safe threshold: 1 omitting proposer (25% of 4) cannot trigger 33% threshold.
//!   LP-09  Below-threshold miss rate stays below 33% (20% miss → ThresholdBreached stays false).
//!   LP-10  Exact 33% miss in a full 500-block window → ThresholdBreached.

use chain_forge_validators::liveness_policy::{
    evaluate_liveness_policy, suspension_safe,
    LivenessAlert, ValidatorLivenessRecord,
    GRACE_WINDOW_BLOCKS, LIVENESS_WINDOW_BLOCKS,
    MIN_COMMITTEE_AFTER_SUSPENSION, SUSPENSION_THRESHOLD_PCT,
    TIER_O_THRESHOLD_PCT, TIER_O_WINDOW_BLOCKS,
    TIER_W_THRESHOLD_PCT, TIER_W_WINDOW_BLOCKS,
};

fn record(
    id: &str,
    missed_main: u64,
    total_main: u64,
    missed_tier_w: u64,
    missed_tier_o: u64,
    blocks_above: u64,
) -> ValidatorLivenessRecord {
    ValidatorLivenessRecord {
        validator_id:            id.to_string(),
        missed_in_main_window:   missed_main,
        blocks_in_main_window:   total_main,
        missed_in_tier_w_window: missed_tier_w,
        missed_in_tier_o_window: missed_tier_o,
        blocks_above_threshold:  blocks_above,
    }
}

fn healthy(id: &str) -> ValidatorLivenessRecord {
    record(id, 0, LIVENESS_WINDOW_BLOCKS as u64, 0, 0, 0)
}

// ---------------------------------------------------------------------------
// LP-01: healthy validator → Ok
// ---------------------------------------------------------------------------
#[test]
fn lp_01_healthy_validator_ok() {
    let records = vec![healthy("alice")];
    let outcome = evaluate_liveness_policy(&records, 4);
    assert_eq!(outcome.statuses[0].alert, LivenessAlert::Ok);
}

// ---------------------------------------------------------------------------
// LP-02: Tier-W alert at ≥10% in last 100 blocks
// ---------------------------------------------------------------------------
#[test]
fn lp_02_tier_w_alert() {
    // 10% of 100 = 10 missed blocks in the Tier-W window
    let threshold_missed = TIER_W_THRESHOLD_PCT as u64 * TIER_W_WINDOW_BLOCKS / 100;
    let r = record("bob", 0, LIVENESS_WINDOW_BLOCKS as u64, threshold_missed, 0, 0);
    let outcome = evaluate_liveness_policy(&[r], 4);
    assert_eq!(outcome.statuses[0].alert, LivenessAlert::TierW,
        "10% in Tier-W window must trigger TierW alert");
}

#[test]
fn lp_02b_below_tier_w_no_alert() {
    // 9% → no alert
    let r = record("bob", 0, LIVENESS_WINDOW_BLOCKS as u64, 9, 0, 0);
    let outcome = evaluate_liveness_policy(&[r], 4);
    assert_eq!(outcome.statuses[0].alert, LivenessAlert::Ok,
        "9% in Tier-W window must not alert");
}

// ---------------------------------------------------------------------------
// LP-03: Tier-O alert at ≥20% in last 200 blocks
// ---------------------------------------------------------------------------
#[test]
fn lp_03_tier_o_alert() {
    // 20% of 200 = 40 missed blocks in the Tier-O window
    let threshold_missed = TIER_O_THRESHOLD_PCT as u64 * TIER_O_WINDOW_BLOCKS / 100;
    // Also satisfy Tier-W (put ≥10% in Tier-W window)
    let r = record("carol", 0, LIVENESS_WINDOW_BLOCKS as u64, 15, threshold_missed, 0);
    let outcome = evaluate_liveness_policy(&[r], 4);
    assert_eq!(outcome.statuses[0].alert, LivenessAlert::TierO,
        "20% in Tier-O window must trigger TierO alert");
}

// ---------------------------------------------------------------------------
// LP-04: 33% miss → ThresholdBreached (within grace window)
// ---------------------------------------------------------------------------
#[test]
fn lp_04_threshold_breached_in_grace() {
    // 33% of 500 = 165 missed
    let missed = SUSPENSION_THRESHOLD_PCT as u64 * LIVENESS_WINDOW_BLOCKS as u64 / 100;
    let r = record("dave", missed, LIVENESS_WINDOW_BLOCKS as u64, 50, 100, 10); // 10 blocks above threshold
    let outcome = evaluate_liveness_policy(&[r], 4);
    // Still in grace window (10 < 50 = GRACE_WINDOW_BLOCKS) → ThresholdBreached
    assert_eq!(outcome.statuses[0].alert, LivenessAlert::ThresholdBreached,
        "33% miss within grace window → ThresholdBreached, not SuspendEligible");
}

// ---------------------------------------------------------------------------
// LP-05: past grace window → SuspendEligible (but then quorum check applies)
// ---------------------------------------------------------------------------
#[test]
fn lp_05_suspend_eligible_after_grace_on_large_committee() {
    // 5-node committee: suspending 1 leaves 4 ≥ MIN_COMMITTEE_AFTER_SUSPENSION
    let missed = SUSPENSION_THRESHOLD_PCT as u64 * LIVENESS_WINDOW_BLOCKS as u64 / 100;
    let dave = record("dave", missed, LIVENESS_WINDOW_BLOCKS as u64, 50, 100, GRACE_WINDOW_BLOCKS);
    let alice = healthy("alice");
    let bob   = healthy("bob");
    let carol = healthy("carol");
    let eve   = healthy("eve");
    let outcome = evaluate_liveness_policy(&[dave, alice, bob, carol, eve], 5);
    let dave_status = outcome.statuses.iter().find(|s| s.validator_id == "dave").unwrap();
    assert_eq!(dave_status.alert, LivenessAlert::SuspendEligible,
        "past grace window on 5-node committee → SuspendEligible");
}

// ---------------------------------------------------------------------------
// LP-06: 4-node committee cannot suspend (quorum floor)
// ---------------------------------------------------------------------------
#[test]
fn lp_06_four_node_committee_cannot_suspend() {
    // Even if dave is past the grace window and threshold, the 4-node
    // committee (f=1, minimum 4) prevents suspension.
    let missed = SUSPENSION_THRESHOLD_PCT as u64 * LIVENESS_WINDOW_BLOCKS as u64 / 100;
    let dave = record("dave", missed, LIVENESS_WINDOW_BLOCKS as u64, 50, 100, GRACE_WINDOW_BLOCKS);
    let outcome = evaluate_liveness_policy(&[
        dave,
        healthy("alice"),
        healthy("bob"),
        healthy("carol"),
    ], 4);
    let dave_status = outcome.statuses.iter().find(|s| s.validator_id == "dave").unwrap();
    assert_ne!(dave_status.alert, LivenessAlert::SuspendEligible,
        "4-node committee cannot suspend: quorum floor prevents it");
    // Status falls back to ThresholdBreached (threshold exceeded, but quorum check failed)
    assert_eq!(dave_status.alert, LivenessAlert::ThresholdBreached,
        "quorum floor demotes SuspendEligible → ThresholdBreached on 4-node committee");
}

// ---------------------------------------------------------------------------
// LP-07: 5-node committee can suspend one
// ---------------------------------------------------------------------------
#[test]
fn lp_07_five_node_committee_can_suspend_one() {
    assert!(suspension_safe(5, 1), "5-node committee, suspend 1 → 4 remaining ≥ MIN_COMMITTEE");
    assert!(!suspension_safe(4, 1), "4-node committee, suspend 1 → 3 remaining < MIN_COMMITTEE");
    assert!(suspension_safe(4, 0), "suspending nobody from 4 is safe");
    assert!(suspension_safe(5, 0), "suspending nobody is always safe");
    assert!(!suspension_safe(5, 2), "5 - 2 = 3 < 4 = MIN_COMMITTEE");
}

// ---------------------------------------------------------------------------
// LP-08: Byzantine-safe threshold (1 omitting proposer cannot trigger jail)
// ---------------------------------------------------------------------------
#[test]
fn lp_08_one_byzantine_proposer_cannot_trigger_suspension() {
    // In a 4-node devnet: f=1, so 1 proposer controls 25% of blocks.
    // If that proposer omits dave from every evidence block it proposes,
    // dave accrues at most 25% miss rate — below the 33% threshold.
    // Even over the full 500-block window, 25% < 33%.
    let byzantine_controlled_pct = 25u64; // 1 of 4 proposers = 25%
    let total = LIVENESS_WINDOW_BLOCKS as u64;
    let worst_case_missed = byzantine_controlled_pct * total / 100; // 125 blocks
    let threshold_missed  = SUSPENSION_THRESHOLD_PCT as u64 * total / 100; // 165 blocks
    assert!(worst_case_missed < threshold_missed,
        "1 Byzantine proposer (25% of blocks) cannot supply enough misses to reach 33% threshold");
    // Confirm: policy does not breach threshold at 25% miss rate
    let r = record("dave", worst_case_missed, total, 25, 50, 0);
    let outcome = evaluate_liveness_policy(&[r], 4);
    assert_ne!(outcome.statuses[0].alert, LivenessAlert::ThresholdBreached,
        "25% miss rate (Byzantine proposer worst case) must not breach 33% threshold");
}

// ---------------------------------------------------------------------------
// LP-09: 20% miss rate stays below threshold
// ---------------------------------------------------------------------------
#[test]
fn lp_09_twenty_pct_miss_stays_below_threshold() {
    // The old provisional 20% threshold would have triggered here;
    // the new 33% threshold does not.
    let total  = LIVENESS_WINDOW_BLOCKS as u64;
    let missed = 20 * total / 100; // 100 missed in 500
    let r = record("dave", missed, total, 15, 40, 60); // even past the grace window
    let outcome = evaluate_liveness_policy(&[r], 5); // 5-node so quorum is not the issue
    assert_ne!(outcome.statuses[0].alert, LivenessAlert::SuspendEligible,
        "20% miss rate must not trigger suspension at the new 33% threshold");
    assert_ne!(outcome.statuses[0].alert, LivenessAlert::ThresholdBreached,
        "20% miss rate is below the 33% suspension threshold");
}

// ---------------------------------------------------------------------------
// LP-10: exact 33% miss in full 500-block window → ThresholdBreached
// ---------------------------------------------------------------------------
#[test]
fn lp_10_exact_threshold_breaches() {
    let total  = LIVENESS_WINDOW_BLOCKS as u64;
    let missed = SUSPENSION_THRESHOLD_PCT as u64 * total / 100; // 165
    // blocks_above_threshold = 1 (just entered the threshold, still in grace)
    let r = record("dave", missed, total, 50, 100, 1);
    let outcome = evaluate_liveness_policy(&[r], 5);
    assert_eq!(outcome.statuses[0].alert, LivenessAlert::ThresholdBreached,
        "33% exact miss → ThresholdBreached (grace window not yet expired)");
}

// ---------------------------------------------------------------------------
// Constant sanity checks
// ---------------------------------------------------------------------------
#[test]
fn constants_are_internally_consistent() {
    // Grace window must be < liveness window
    assert!((GRACE_WINDOW_BLOCKS as usize) < LIVENESS_WINDOW_BLOCKS,
        "grace window must be less than the main liveness window");
    // Suspension threshold must be above Tier-O
    assert!(SUSPENSION_THRESHOLD_PCT > TIER_O_THRESHOLD_PCT,
        "suspension threshold must be above Tier-O alert threshold");
    // Tier-O threshold must be above Tier-W
    assert!(TIER_O_THRESHOLD_PCT > TIER_W_THRESHOLD_PCT,
        "Tier-O threshold must be above Tier-W alert threshold");
    // MIN_COMMITTEE_AFTER_SUSPENSION must be >= 4 (3f+1 for f=1)
    assert!(MIN_COMMITTEE_AFTER_SUSPENSION >= 4,
        "committee minimum must be at least 4 for f=1 BFT");
    // The Byzantine-safe property: f proposers (1/4 = 25%) < threshold (33%)
    let f_pct = 100 / 4; // 25%
    assert!((f_pct as u32) < SUSPENSION_THRESHOLD_PCT,
        "single Byzantine proposer (25%) must not reach suspension threshold (33%)");
}
