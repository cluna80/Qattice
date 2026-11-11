//! AN-3: anchored restart integration (docs/pq-hotstuff-2/phase11-an3-anchored-restart.md). Compiled only with the
//! `pq-anchored-evidence` feature (off by default). **Library only**: nothing in the node, driver or network calls
//! this; no anchor-start mode exists; network installation, pruning and dynamic membership remain outside this slice.
//!
//! Two public pieces:
//! 1. [`AnchorMode`]: `Off` (current behaviour, default) or `AuditFirst` (signing gated until audit + reconciliation).
//! 2. [`AnchorRestart`]: the typed restart-path state machine. `open` loads the ring, runs the cross-check, and begins
//!    a genesis-rooted re-verification from height 1 (regardless of the persisted `audited_height` watermark — in
//!    `AuditFirst` mode the security guarantee requires a full re-verify on every startup, not just when the watermark
//!    is below the anchor). If the newest record fails the cross-check the machine tries the previous generation before
//!    returning an error. `advance` feeds header windows until the audit completes or fails; the caller is expected to
//!    call `ring.set_audited` after each progress step (for display/diagnostics). After `RestartOutcome::Ready` the
//!    caller reconciles the anchor against executor state; signing stays disabled until both succeed.
//!
//! SafetyStore floors, application state, exactly-once execution and blockstore pruning are untouched.
use super::anchor_record::{AnchorBinding, AnchorError, AnchorLimits, AnchorRecord, AnchorRing};
use super::anchor_verify::{cross_check, Audit, AuditError, AuditStep, CrossCheckError};
use super::header::ChainParams;
use super::header::{PayloadFreeBlock, Start};
use super::recovery::tree::TreeFs;
use super::safety::ConsensusVerifier;

/// Whether the restart path performs anchored verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnchorMode {
    /// Existing behaviour: no ring is opened, no verification runs, signing is ungated by this layer.
    #[default]
    Off,
    /// Signing stays disabled until genesis-rooted historical verification (audit) and executor-state
    /// reconciliation both succeed.
    AuditFirst,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestartError {
    #[error("the anchor ring is empty; no record to start from")]
    NoRecord,
    #[error("the anchor record is damaged or cannot be decoded: {0}")]
    Damaged(AnchorError),
    #[error("the anchor record is bound to a different genesis, profile, chain, validator set or checkpoint parameters")]
    Foreign,
    #[error("the cross-check failed: {0}")]
    CrossCheckFailed(CrossCheckError),
    #[error("the audit failed: {0}")]
    AuditFailed(AuditError),
    #[error("the anchor is inconsistent with the executor's committed state: {0}")]
    Inconsistent(&'static str),
}

/// The result of an `advance` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartOutcome {
    /// Verification complete; the caller may enable signing after reconciliation.
    Ready { audited_height: u64 },
    /// More headers needed; call `advance` again starting at this height.
    NeedHeaders { next_height: u64 },
    /// Verification failed; signing must remain disabled.
    Failed(RestartError),
}

/// The restart-path state machine. Created by [`AnchorRestart::open`]; fed headers via [`AnchorRestart::advance`].
pub struct AnchorRestart {
    /// The record under audit (the generation that passed the cross-check).
    pub record: AnchorRecord,
    audit: Audit,
}

impl std::fmt::Debug for AnchorRestart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorRestart")
            .field("anchor_height", &self.record.anchor.height)
            .field("next_height", &self.audit.next_height())
            .finish()
    }
}

impl AnchorRestart {
    /// Load and cross-check the newest ring record. On cross-check failure, tries the previous generation before
    /// returning an error. On success, begins a genesis-rooted re-verification from height 1 regardless of the
    /// persisted `audited_height` watermark — `AuditFirst` mode requires a complete re-verify on every startup.
    ///
    /// Returns `Err(RestartError::NoRecord)` when the ring is empty, `Err(RestartError::Damaged)` when decode
    /// fails, `Err(RestartError::Foreign)` when the binding does not match `own_binding`, and
    /// `Err(RestartError::CrossCheckFailed)` when both generations fail the cross-check.
    pub fn open<F: TreeFs, V: ConsensusVerifier>(
        ring: &AnchorRing<F>,
        own_binding: &AnchorBinding,
        p: &ChainParams,
        v: &V,
        lim: &AnchorLimits,
        seg: usize,
    ) -> Result<Self, RestartError> {
        let gens = ring.generations();
        if gens.is_empty() { return Err(RestartError::NoRecord); }

        // try newest first, then fall back to previous
        let mut last_cross_err = None;
        for rec in gens.into_iter().take(2) {
            if rec.binding != *own_binding { return Err(RestartError::Foreign); }
            match cross_check(rec, p, v, lim) {
                Ok(_) => {
                    // Always use Audit::new (not new_from): AuditFirst requires genesis-rooted
                    // re-verification on every startup; the persisted watermark must not shortcut it.
                    let audit = Audit::new(rec, seg).map_err(|e| {
                        RestartError::AuditFailed(AuditError::Segments(e))
                    })?;
                    return Ok(AnchorRestart { record: rec.clone(), audit });
                }
                Err(e) => { last_cross_err = Some(e); }
            }
        }
        Err(RestartError::CrossCheckFailed(last_cross_err.unwrap()))
    }

    /// The height the next fed header window must start at.
    pub fn next_height(&self) -> u64 { self.audit.next_height() }

    /// The carried verification start state (for callers that want to persist it).
    pub fn resume(&self) -> &Start { self.audit.resume() }

    /// Feed the next header window. Returns `NeedHeaders` until the audit completes, then `Ready`. On any
    /// error returns `Failed` — the caller must keep signing disabled.
    pub fn advance<V: ConsensusVerifier>(
        &mut self,
        p: &ChainParams,
        v: &V,
        headers: &[PayloadFreeBlock],
    ) -> RestartOutcome {
        match self.audit.advance(p, v, headers) {
            Ok(AuditStep { complete: true, audited_height }) =>
                RestartOutcome::Ready { audited_height },
            Ok(AuditStep { complete: false, audited_height: _ }) =>
                RestartOutcome::NeedHeaders { next_height: self.audit.next_height() },
            Err(e) => RestartOutcome::Failed(RestartError::AuditFailed(e)),
        }
    }

    /// Check that the anchor is consistent with the executor's committed state. Called by the caller
    /// after `RestartOutcome::Ready`. Does NOT replay effects or rewind application state.
    ///
    /// `executor_committed_height`: the height the executor has committed up to.
    /// `cursor_at`: a function that returns `(block_id, state_root)` the executor committed at a given
    /// height, or `None` when that height is not in the executor's history.
    pub fn reconcile(
        &self,
        executor_committed_height: u64,
        cursor_at: impl Fn(u64) -> Option<([u8; 32], [u8; 32])>,
    ) -> Result<(), RestartError> {
        let anchor = &self.record.anchor;
        if anchor.height > executor_committed_height {
            return Err(RestartError::Inconsistent("executor has not committed up to the anchor height"));
        }
        let ref_height = self.record.reference.height;
        match cursor_at(ref_height) {
            None => return Err(RestartError::Inconsistent("executor has no committed state at the reference height")),
            Some((block_id, _)) if block_id != self.record.reference.block_id =>
                return Err(RestartError::Inconsistent("attested block id disagrees with executor's committed block")),
            Some((_, root)) if root != self.record.reference.state_root =>
                return Err(RestartError::Inconsistent("attested state root disagrees with executor's committed state")),
            Some(_) => {}
        }
        Ok(())
    }
}
