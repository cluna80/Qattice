// SPDX-License-Identifier: MIT

//! H0-11B liveness-suspension policy (Phase 2).
//!
//! This module specifies and enforces the automatic-suspension policy for
//! validators that fail to participate in consensus. The policy is fully
//! designed here but **automatic suspension stays disabled in production
//! genesis** pending a separate owner decision. The constants and logic
//! in this module are derived from real PQ-HotStuff-2 devnet measurements
//! on BossKing (Windows/MINGW64), recorded in ROADMAP.md H0-11B.
//!
//! # Measurement basis
//!
//! | Measurement                        | Devnet value          |
//! |------------------------------------|-----------------------|
//! | Actual block time (Windows)        | ~9 s/block            |
//! | Precommit collection (idle)        | 2.1–3 s               |
//! | Precommit collection (loaded)      | ~1 s                  |
//! | Lateness cliff (miss-recording)    | 12–15% sustained delay|
//! | 500-block window wall time         | ~75 min               |
//! | Byzantine discount (f)             | f = 1 (of 4 seats)    |
//!
//! # Policy decisions (derived)
//!
//! **Grace window (50 blocks, ~7.5 min):** A validator that restarts after a
//! crash or connectivity loss must not be jailed before it has had a reasonable
//! time to rejoin. 50 blocks clears the typical restart window (< 5 min on the
//! devnet) with margin.
//!
//! **Attestation threshold (33%):** The existing default of 20% has a known
//! cliff at 12–15% sustained lateness (a validator whose precommits arrive
//! consistently ~1.1–1.35 s late — close to the loaded collection window —
//! can be recorded as missing by an omitting proposer). Raising to 33% puts
//! ~20 percentage points of headroom between the cliff and the jail trigger.
//! At 9 s/block, a validator must miss 165 of 500 blocks (~25 min of true
//! absence) to be jailed. The Byzantine discount (f=1) means one omitting
//! proposer cannot contribute more than 25% of blocks to any validator's
//! miss count — well below the 33% trigger.
//!
//! **Tier-W alert (10% / 100 blocks, ~15 min):** Early operator warning.
//! Does not trigger jailing; triggers a log event and monitoring alert only.
//!
//! **Tier-O alert (20% / 200 blocks, ~30 min):** Operational alert requiring
//! investigation. Still does not trigger jailing; this is the signal for the
//! operator to act before the jail threshold is reached.
//!
//! **Quorum floor:** A suspension that would leave fewer than 3f+1 validators
//! in the committee is postponed. For f=1 this means the minimum committee
//! size is 4; on the 4-node devnet no suspension ever fires. The rule scales
//! correctly as the validator set grows.
//!
//! **Automatic suspension in production:** Disabled. Enable only after the
//! quorum-protection rule, `ResumeValidator`/probation, and deterministic
//! requalification are implemented and Windows-confirmed.

// ValidatorRecord, ValidatorRegistry, ValidatorStatus used by node.rs callers.

// ---------------------------------------------------------------------------
// Devnet-derived constants
// ---------------------------------------------------------------------------

/// Sliding window (blocks) over which the miss rate is computed.
/// Matches the genesis default; set here for use in alert computations.
pub const LIVENESS_WINDOW_BLOCKS: usize = 500;

/// Fraction of blocks (as percent) a validator must miss within
/// `LIVENESS_WINDOW_BLOCKS` to be suspended.
///
/// Raised from the provisional 20% to 33% based on measured data:
/// the lateness cliff at 12–15% leaves insufficient headroom at 20%.
pub const SUSPENSION_THRESHOLD_PCT: u32 = 33;

/// Blocks before the suspension trigger fires after the threshold is first
/// exceeded. Gives a restarting validator time to rejoin without being jailed.
/// At ~9 s/block (PQ-HotStuff-2 Windows devnet) this is ~7.5 minutes.
pub const GRACE_WINDOW_BLOCKS: u64 = 50;

/// Tier-W (warning) alert: miss rate ≥ this percent over `TIER_W_WINDOW_BLOCKS`.
/// Triggers a log event / monitoring alert only — no jailing.
pub const TIER_W_THRESHOLD_PCT: u32 = 10;

/// Block window for Tier-W evaluation (~15 min at 9 s/block).
pub const TIER_W_WINDOW_BLOCKS: u64 = 100;

/// Tier-O (operational) alert: miss rate ≥ this percent over `TIER_O_WINDOW_BLOCKS`.
/// Requires operator investigation — still no jailing.
pub const TIER_O_THRESHOLD_PCT: u32 = 20;

/// Block window for Tier-O evaluation (~30 min at 9 s/block).
pub const TIER_O_WINDOW_BLOCKS: u64 = 200;

/// Minimum committee size after suspension for the transition to proceed.
/// Derived from 3f+1 where f = ⌊(n-1)/3⌋. For 4 seats: f=1, minimum=4.
/// Suspension is postponed when removing the validator would breach this floor.
pub const MIN_COMMITTEE_AFTER_SUSPENSION: usize = 4;

// ---------------------------------------------------------------------------
// Policy structs
// ---------------------------------------------------------------------------

/// Alert tier for a validator's current liveness state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LivenessAlert {
    /// Below all alert thresholds — healthy.
    Ok,
    /// Tier-W: miss rate ≥ 10% in last 100 blocks. Operator warning.
    TierW,
    /// Tier-O: miss rate ≥ 20% in last 200 blocks. Operational alert.
    TierO,
    /// Suspension threshold breached (miss rate ≥ 33% in 500-block window).
    /// Not yet past the grace window.
    ThresholdBreached,
    /// Past the grace window with threshold still breached — eligible for
    /// suspension at the next epoch boundary (pending quorum check).
    SuspendEligible,
}

/// Per-validator liveness assessment.
#[derive(Debug, Clone)]
pub struct ValidatorLivenessStatus {
    pub validator_id: String,
    pub alert: LivenessAlert,
    /// Missed-block fraction in the main window (0.0 to 1.0).
    pub miss_rate: f64,
    /// Blocks since the threshold was first exceeded (0 if not exceeded).
    pub blocks_above_threshold: u64,
}

/// Result of running the liveness policy over the full active validator set.
#[derive(Debug, Clone)]
pub struct LivenessPolicyOutcome {
    pub statuses: Vec<ValidatorLivenessStatus>,
}

impl LivenessPolicyOutcome {
    /// Validators eligible for suspension at the next epoch boundary.
    pub fn suspend_eligible(&self) -> Vec<&str> {
        self.statuses.iter()
            .filter(|s| s.alert == LivenessAlert::SuspendEligible)
            .map(|s| s.validator_id.as_str())
            .collect()
    }

    /// Validators in Tier-O or higher alert state.
    pub fn tier_o_or_higher(&self) -> Vec<&str> {
        self.statuses.iter()
            .filter(|s| s.alert >= LivenessAlert::TierO)
            .map(|s| s.validator_id.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Quorum check
// ---------------------------------------------------------------------------

/// True when suspending `n_to_suspend` validators from a committee of
/// `current_committee_size` leaves a committee that meets the BFT quorum
/// floor (≥ `MIN_COMMITTEE_AFTER_SUSPENSION`, i.e. 3f+1 for the devnet f=1).
///
/// Returns `false` — suspension postponed — whenever the resulting size
/// would fall below the minimum. The caller must not remove any validator
/// unless this returns `true`.
pub fn suspension_safe(current_committee_size: usize, n_to_suspend: usize) -> bool {
    current_committee_size.saturating_sub(n_to_suspend) >= MIN_COMMITTEE_AFTER_SUSPENSION
}

// ---------------------------------------------------------------------------
// Policy evaluation
// ---------------------------------------------------------------------------

/// Liveness record for a single validator at the current block height.
/// The node assembles these from its validator registry and block evidence.
#[derive(Debug, Clone)]
pub struct ValidatorLivenessRecord {
    pub validator_id:         String,
    /// Blocks missed in the full `LIVENESS_WINDOW_BLOCKS` window.
    pub missed_in_main_window: u64,
    /// Blocks in the full `LIVENESS_WINDOW_BLOCKS` window (may be less
    /// at the start of the chain before `window_blocks` blocks have committed).
    pub blocks_in_main_window: u64,
    /// Blocks missed in the Tier-W window (`TIER_W_WINDOW_BLOCKS`).
    pub missed_in_tier_w_window: u64,
    /// Blocks missed in the Tier-O window (`TIER_O_WINDOW_BLOCKS`).
    pub missed_in_tier_o_window: u64,
    /// How many consecutive blocks this validator has been above the
    /// suspension threshold. Reset to 0 when the validator drops below.
    pub blocks_above_threshold: u64,
}

/// Evaluate the liveness policy for every active validator given per-validator
/// liveness records assembled by the node's block-evidence accounting.
///
/// `active_committee_size` is the number of validators currently in the
/// consensus committee (used for the quorum-floor check).
///
/// The function is **pure**: it does not mutate the registry or any record.
/// The caller (node.rs epoch-boundary logic) acts on the returned outcome.
pub fn evaluate_liveness_policy(
    records: &[ValidatorLivenessRecord],
    active_committee_size: usize,
) -> LivenessPolicyOutcome {
    let mut statuses: Vec<ValidatorLivenessStatus> = records.iter().map(|r| {
        let miss_rate = if r.blocks_in_main_window == 0 {
            0.0
        } else {
            r.missed_in_main_window as f64 / r.blocks_in_main_window as f64
        };

        let tier_w_miss_pct = if r.missed_in_tier_w_window * 100 >= TIER_W_THRESHOLD_PCT as u64 * TIER_W_WINDOW_BLOCKS {
            true
        } else {
            false
        };
        let tier_o_miss_pct = if r.missed_in_tier_o_window * 100 >= TIER_O_THRESHOLD_PCT as u64 * TIER_O_WINDOW_BLOCKS {
            true
        } else {
            false
        };
        let threshold_breached = r.missed_in_main_window * 100
            >= SUSPENSION_THRESHOLD_PCT as u64 * r.blocks_in_main_window;

        let alert = if threshold_breached && r.blocks_above_threshold >= GRACE_WINDOW_BLOCKS {
            LivenessAlert::SuspendEligible
        } else if threshold_breached {
            LivenessAlert::ThresholdBreached
        } else if tier_o_miss_pct {
            LivenessAlert::TierO
        } else if tier_w_miss_pct {
            LivenessAlert::TierW
        } else {
            LivenessAlert::Ok
        };

        ValidatorLivenessStatus {
            validator_id: r.validator_id.clone(),
            alert,
            miss_rate,
            blocks_above_threshold: r.blocks_above_threshold,
        }
    }).collect();

    // Sort for deterministic output.
    statuses.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));

    // Quorum floor: demote SuspendEligible → ThresholdBreached if suspending
    // all eligible validators would breach the committee minimum.
    let n_eligible = statuses.iter().filter(|s| s.alert == LivenessAlert::SuspendEligible).count();
    if !suspension_safe(active_committee_size, n_eligible) {
        for s in statuses.iter_mut() {
            if s.alert == LivenessAlert::SuspendEligible {
                s.alert = LivenessAlert::ThresholdBreached;
            }
        }
    }

    LivenessPolicyOutcome { statuses }
}
