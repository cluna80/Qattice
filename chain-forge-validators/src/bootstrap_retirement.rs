// SPDX-License-Identifier: MIT

//! Bootstrap-validator retirement (H0-11D).
//!
//! Genesis / synthetic validators have no permanent exemption from the
//! personhood and bond requirements that apply to every other operator.
//! This module enforces the transition policy decided on 2026-11-14:
//!
//! 1. **Trigger**: an on-chain governance decision records a future
//!    `activation_epoch`. Before that epoch every validator (genesis or
//!    not) participates normally.
//!
//! 2. **Credential requirement**: at the activation epoch boundary every
//!    validator — including the genesis/founder set — must hold
//!    `VerificationTier::Verified` (or `Established`) AND a bonded stake
//!    ≥ `min_bond_uqcb`. Validators below either bar are excluded from
//!    the incoming set.
//!
//! 3. **Equal treatment**: `is_genesis == true` confers no exemption.
//!    The same filter runs over every record regardless of origin.
//!
//! 4. **Liveness protection**: before the outgoing set finalises the
//!    handoff, the proposed incoming set must contain at least
//!    `min_quorum_operators` distinct eligible operators. If the count
//!    falls short, `RetirementOutcome::Postponed` is returned — the
//!    outgoing set remains active and the transition is retried at the
//!    next epoch boundary.

use chain_forge_identity::VerificationTier;

use crate::{ValidatorRecord, ValidatorRegistry, ValidatorStatus};

// ---------------------------------------------------------------------------
// Policy struct
// ---------------------------------------------------------------------------

/// Parameters that govern the bootstrap-validator retirement transition.
///
/// These are set by governance and should not change between the trigger
/// and the activation boundary — the on-chain governance record is the
/// authoritative source of these values; this struct is a pure-Rust
/// representation of that record for use in the execution layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapRetirementPolicy {
    /// The epoch at which the retirement rule takes effect.
    /// Before this epoch `compute_retirement_outcome` returns `NotYet`.
    pub activation_epoch: u64,

    /// Minimum number of distinct eligible operators that the incoming
    /// validator set must contain for the transition to proceed.
    /// If the incoming set has fewer, the result is `Postponed`.
    ///
    /// A BFT quorum needs 2f+1 participants, so this should be at least
    /// the minimum set size required for liveness under any anticipated f.
    /// The governance record fixes this at trigger time.
    pub min_quorum_operators: usize,

    /// Minimum bonded uqcb required at the activation boundary (identical
    /// to the ordinary `min_bond_uqcb` enforced by the bond module, but
    /// applied retroactively to genesis validators).
    pub min_bond_uqcb: u128,
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

/// Per-validator retirement decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorRetirementDecision {
    pub validator_id: String,
    /// True when the validator was registered via `register_genesis_validator`.
    pub is_genesis: bool,
    pub decision: RetirementDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetirementDecision {
    /// Meets both the credential and bond requirements; admitted to the
    /// incoming validator set.
    Admitted,
    /// Missing Verified/Established tier — excluded at the activation boundary.
    ExcludedCredential {
        had_tier: Option<VerificationTier>,
    },
    /// Credential tier is sufficient but bonded stake is below the minimum.
    ExcludedBond {
        bonded_uqcb: u128,
        required: u128,
    },
}

impl RetirementDecision {
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted)
    }
}

/// Result of running the retirement filter over the full active validator set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetirementOutcome {
    /// The activation epoch has not been reached yet; no action taken.
    NotYet,
    /// The transition proceeds: `decisions` contains one entry per active
    /// validator; `eligible` is the subset admitted to the incoming set.
    Transition {
        decisions: Vec<ValidatorRetirementDecision>,
    },
    /// The incoming eligible set is too small to satisfy `min_quorum_operators`.
    /// The outgoing set remains active; retry next epoch.
    Postponed {
        decisions: Vec<ValidatorRetirementDecision>,
        eligible_count: usize,
        required: usize,
    },
}

impl RetirementOutcome {
    /// Admitted validator IDs, if the transition proceeds.
    pub fn admitted_ids(&self) -> Vec<&str> {
        match self {
            Self::Transition { decisions } => decisions
                .iter()
                .filter(|d| d.decision.is_admitted())
                .map(|d| d.validator_id.as_str())
                .collect(),
            _ => vec![],
        }
    }

    /// Excluded validator IDs, if the transition proceeds.
    pub fn excluded_ids(&self) -> Vec<&str> {
        match self {
            Self::Transition { decisions } => decisions
                .iter()
                .filter(|d| !d.decision.is_admitted())
                .map(|d| d.validator_id.as_str())
                .collect(),
            _ => vec![],
        }
    }

    pub fn is_transition(&self) -> bool {
        matches!(self, Self::Transition { .. })
    }

    pub fn is_postponed(&self) -> bool {
        matches!(self, Self::Postponed { .. })
    }
}

// ---------------------------------------------------------------------------
// Core function
// ---------------------------------------------------------------------------

/// Compute the retirement outcome for every *active* validator at epoch
/// `current_epoch`.
///
/// Only `Active`-status validators are evaluated; `Candidate`, `Jailed`,
/// and `Tombstoned` validators are already excluded from consensus and
/// require no additional treatment here.
///
/// The function is pure: it reads registry state and returns a decision
/// without mutating anything. The caller (node.rs epoch-boundary logic)
/// is responsible for acting on the outcome — removing excluded validators
/// from the consensus ValidatorSet and either applying or postponing the
/// handoff.
pub fn compute_retirement_outcome(
    registry: &ValidatorRegistry,
    policy: &BootstrapRetirementPolicy,
    current_epoch: u64,
) -> RetirementOutcome {
    if current_epoch < policy.activation_epoch {
        return RetirementOutcome::NotYet;
    }

    // Evaluate every active validator — genesis and non-genesis alike.
    let mut decisions: Vec<ValidatorRetirementDecision> = registry
        .validators()
        .filter(|r| r.status == ValidatorStatus::Active)
        .map(|r| ValidatorRetirementDecision {
            validator_id: r.id.0.clone(),
            is_genesis: r.is_genesis,
            decision: eligibility_decision(r, policy),
        })
        .collect();

    // Deterministic order: sort by validator_id so test assertions are stable.
    decisions.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));

    let eligible_count = decisions.iter().filter(|d| d.decision.is_admitted()).count();

    if eligible_count < policy.min_quorum_operators {
        RetirementOutcome::Postponed {
            decisions,
            eligible_count,
            required: policy.min_quorum_operators,
        }
    } else {
        RetirementOutcome::Transition { decisions }
    }
}

/// Eligibility check for one validator record.
fn eligibility_decision(
    r: &ValidatorRecord,
    policy: &BootstrapRetirementPolicy,
) -> RetirementDecision {
    // Credential gate first.
    let tier_ok = r
        .verification_tier
        .as_ref()
        .map(|t| t.grants_consensus())
        .unwrap_or(false);

    if !tier_ok {
        return RetirementDecision::ExcludedCredential {
            had_tier: r.verification_tier.clone(),
        };
    }

    // Bond gate.
    if r.bonded_uqcb < policy.min_bond_uqcb {
        return RetirementDecision::ExcludedBond {
            bonded_uqcb: r.bonded_uqcb,
            required: policy.min_bond_uqcb,
        };
    }

    RetirementDecision::Admitted
}

// ---------------------------------------------------------------------------
// Governance quorum helper
// ---------------------------------------------------------------------------

/// Returns true when a validator-set vote to trigger the retirement
/// transition meets the standard BFT quorum requirement (strictly more
/// than 2/3 of total voting power).
///
/// `yes_power` and `total_power` are the sums of consensus voting power
/// for the yes-voting validators and all voting validators respectively,
/// as reported by the consensus engine. This mirrors the existing quorum
/// check used for `CommitCertificate` formation — the governance vote is
/// not exempt from, and does not change, the BFT threshold.
///
/// Returns `false` for `total_power == 0` (no active validators).
pub fn governance_vote_meets_quorum(yes_power: u64, total_power: u64) -> bool {
    if total_power == 0 {
        return false;
    }
    // Strictly more than 2/3: yes * 3 > total * 2
    yes_power * 3 > total_power * 2
}
