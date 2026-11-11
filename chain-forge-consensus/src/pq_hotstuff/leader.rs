//! Deterministic leader selection (spec section 4): `leader(round) = eligible[(round + seed) mod |eligible|]`, where
//! `eligible` is the validators with power > 0 in canonical order. Uses only committed state, so every node computes the same
//! leader. The reduction of the epoch seed (the epoch-change block hash) to an integer is not specified yet (finding K3);
//! the caller passes the seed, and Phase 0 uses 0.
use super::types::{EpochSet, ValidatorEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LeaderError {
    #[error("no validator with power can lead")]
    NoEligibleLeader,
}

/// Index (in the full canonical order) of the leader of `round`.
pub fn leader_index(set: &EpochSet, round: u64, seed: u64) -> Result<usize, LeaderError> {
    let eligible: Vec<usize> = set.entries().iter().enumerate().filter(|(_, e)| e.power > 0).map(|(i, _)| i).collect();
    if eligible.is_empty() {
        return Err(LeaderError::NoEligibleLeader);
    }
    let pos = ((u128::from(round) + u128::from(seed)) % eligible.len() as u128) as usize;
    Ok(eligible[pos])
}

pub fn leader(set: &EpochSet, round: u64, seed: u64) -> Result<&ValidatorEntry, LeaderError> {
    leader_index(set, round, seed).map(|i| &set.entries()[i])
}
