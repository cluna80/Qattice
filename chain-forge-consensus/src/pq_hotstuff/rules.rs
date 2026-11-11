//! The safety rules of spec sections 5 and 6 as pure functions over the persisted floors (`hvr`, `hqr`). They decide whether
//! signing is *allowed*; the crash-safe record of what was signed is the [`super::safety`] store. All round arithmetic is
//! checked: a hostile `u64::MAX` round can neither wrap into a vote nor into a commit.
use super::types::Round;

/// The persisted floors: highest voted-or-timed-out round, and highest QC round voted on (the lock).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VoterState {
    pub hvr: Round,
    pub hqr: Round,
}

/// A verified timeout certificate as the vote rule sees it: its round and the maximum of its (verified, signed) `high_qc_rounds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcInfo {
    pub round: Round,
    pub max_high_qc_round: Round,
}

/// The fields of a proposal the vote rule needs (the certificates are verified before this is built).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub round: Round,
    pub qc_round: Round,
    pub tc: Option<TcInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VoteRefusal {
    #[error("the block round is not above the highest voted round")]
    RoundNotAboveVoted,
    #[error("the block round is not above its certified parent's round")]
    RoundNotAboveQc,
    #[error("the block skips rounds without a timeout certificate")]
    GapWithoutTc,
    #[error("the timeout certificate is not for the previous round")]
    TcWrongRound,
    #[error("the block's QC is below the highest QC round the timeout certificate reported")]
    QcBelowTcMax,
}

/// Vote rules 2 and 3 (rule 1, well-formedness and certificate validity, is the caller's).
pub fn safe_to_vote(st: &VoterState, b: &BlockHeader) -> Result<(), VoteRefusal> {
    if b.round <= st.hvr {
        return Err(VoteRefusal::RoundNotAboveVoted);
    }
    if b.round <= b.qc_round {
        return Err(VoteRefusal::RoundNotAboveQc);
    }
    if b.qc_round.checked_add(1) == Some(b.round) {
        return Ok(());
    }
    let tc = b.tc.ok_or(VoteRefusal::GapWithoutTc)?;
    if b.round.checked_sub(1) != Some(tc.round) {
        return Err(VoteRefusal::TcWrongRound);
    }
    if b.qc_round < tc.max_high_qc_round {
        return Err(VoteRefusal::QcBelowTcMax);
    }
    Ok(())
}

/// Update the floors after a vote has been durably recorded and is about to be sent.
pub fn record_vote(st: &mut VoterState, b: &BlockHeader) {
    st.hvr = st.hvr.max(b.round);
    st.hqr = st.hqr.max(b.qc_round);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutRequest {
    pub round: Round,
    /// Round of the highest QC the validator holds and will report.
    pub high_qc_round: Round,
    /// Round of a held TC, if any.
    pub tc_round: Option<Round>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimeoutRefusal {
    #[error("the reported high QC is below the lock")]
    HighQcBelowLock,
    #[error("the timeout round is not above the reported high QC")]
    RoundNotAboveHighQc,
    #[error("the timeout round is below the highest voted round")]
    RoundBelowVoted,
    #[error("the timeout skips rounds without the previous round's timeout certificate")]
    GapWithoutTc,
}

/// Timeout rules 1 to 3. A vote in round `r` followed by a timeout in round `r` is allowed.
pub fn safe_to_timeout(st: &VoterState, t: &TimeoutRequest) -> Result<(), TimeoutRefusal> {
    if t.high_qc_round < st.hqr {
        return Err(TimeoutRefusal::HighQcBelowLock);
    }
    if t.round <= t.high_qc_round {
        return Err(TimeoutRefusal::RoundNotAboveHighQc);
    }
    if t.round <= st.hvr.saturating_sub(1) {
        return Err(TimeoutRefusal::RoundBelowVoted);
    }
    if t.high_qc_round.checked_add(1) == Some(t.round) {
        return Ok(());
    }
    match (t.round.checked_sub(1), t.tc_round) {
        (Some(prev), Some(tc)) if prev == tc => Ok(()),
        _ => Err(TimeoutRefusal::GapWithoutTc),
    }
}

pub fn record_timeout(st: &mut VoterState, t: &TimeoutRequest) {
    st.hvr = st.hvr.max(t.round);
}

/// Two-chain commit (spec section 6): a certified child commits its parent only if their rounds are consecutive.
pub fn commits_parent(parent_round: Round, child_round: Round) -> bool {
    parent_round.checked_add(1) == Some(child_round)
}

/// Round advance (spec section 6): on a valid certificate for round `cert_round` enter `cert_round + 1`; never move back.
pub fn next_round(current: Round, cert_round: Round) -> Round {
    if cert_round >= current { cert_round.saturating_add(1) } else { current }
}
