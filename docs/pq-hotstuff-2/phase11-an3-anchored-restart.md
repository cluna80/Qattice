# PQ-HotStuff-2 - AN-3: anchored restart integration (DRAFT; off by default)

Scope: stacked on AN-2 (`feat/pq-hotstuff-2-anchored-evidence-an2`, frozen code at `7f2416d`).
Feature `pq-anchored-evidence`, OFF by default. **Nothing in the node, driver or network calls any
of this; network snapshot installation, automatic recovery triggers, pruning and dynamic membership
remain outside this slice.**

---

## Short plan (reviewer brief of 2026-11-10)

### What this slice adds

A single new library component: `anchor_restart.rs` (compiled only under `pq-anchored-evidence`).
It wraps the AN-1 ring and AN-2 verifier into a typed restart-path state machine that the driver
can call at start-up. No existing driver, engine or safety-store code changes in this slice.

---

### A. Mode

```rust
pub enum AnchorMode {
    Off,        // preserves current behavior entirely; no ring is opened, no verification runs
    AuditFirst, // signing stays disabled until genesis-rooted historical verification completes
}
```

`Off` is the default. When `Off`, `Driver::start` behaves identically to today. `AuditFirst` is
the only mode that opens the ring and gates signing.

---

### B. Restart state machine (`AnchorRestart`)

```rust
pub enum RestartOutcome {
    /// Verification complete; the caller may enable signing.
    Ready { audited_height: u64 },
    /// More headers needed; call `advance` again with the next window.
    NeedHeaders { next_height: u64 },
    /// Verification failed; signing must remain disabled.
    Failed(RestartError),
}

pub enum RestartError {
    NoRecord,                   // ring is empty; no anchor to start from
    Damaged(AnchorError),       // record fails decode or binding check
    Foreign,                    // binding does not match this node's own config
    CrossCheckFailed(CrossCheckError),
    AuditFailed(AuditError),
    Inconsistent(&'static str), // reconciled anchor fields disagree with executor state
}

pub struct AnchorRestart { /* rec, audit: Audit, checked: bool */ }

impl AnchorRestart {
    /// Load and cross-check the newest ring record. Returns `Err(RestartError)` for every
    /// failure mode (missing, damaged, foreign, failed cross-check). On success, begins the
    /// resumable audit from `rec.audited_height` (not necessarily 0 — progress is durable).
    pub fn open<V: ConsensusVerifier>(
        ring: &AnchorRing<impl TreeFs>,
        p: &ChainParams,
        v: &V,
        lim: &AnchorLimits,
        seg: usize,
    ) -> Result<Self, RestartError>

    /// Feed the next window of headers. Returns `NeedHeaders` until the audit reaches the
    /// anchor height, then `Ready`. On any error returns `Failed` — the caller must keep
    /// signing disabled.
    pub fn advance<V: ConsensusVerifier>(
        &mut self,
        p: &ChainParams,
        v: &V,
        headers: &[PayloadFreeBlock],
    ) -> RestartOutcome

    /// The height the caller should request next (`Audit::next_height`).
    pub fn next_height(&self) -> u64

    /// The `Start` to pass to the verifier for the next window (wraps `Audit::resume`).
    pub fn resume(&self) -> &Start
}
```

**Older-generation fallback**: if `ring.newest()` fails cross-check, `open` tries
`ring.previous()` before returning `RestartError::CrossCheckFailed`. A single fallback attempt
only; if both fail, the outer error is from the newer record.

**Durable progress**: `ring.newest().audited_height` seeds the audit's starting point. After each
`advance` call that makes progress, the caller is expected to call `ring.set_audited(generation,
height)` to persist the new watermark.

---

### C. Executor-state reconciliation

After `RestartOutcome::Ready`, the caller reconciles:

- `rec.anchor.height ≤ executor_committed_height` — the executor has not rolled back below the anchor
- `rec.reference.state_root == executor_state_root_at(rec.reference.height)` — the state root the
  anchor attests matches what the executor actually committed

If either fails, the caller returns `RestartError::Inconsistent` and signing stays disabled.
Reconciliation does NOT replay effects or rewind application state; it only reads what the executor
already holds. This keeps AN-3 within the existing crash-recovery safety contract from the driver
(`DriverError::ExecutorBehind` / `DriverError::ExecutorMismatch`).

---

### D. What is NOT changed

- `Driver::start` signature and behavior when `AnchorMode::Off` (default).
- `SafetyStore`: no new floors, no new latch triggers.
- `Engine`: no new fields; `is_recovering` / `complete_recovery` are unchanged.
- Application state, signing floors, blockstore pruning: untouched.

The caller (future node wiring, outside this slice) is responsible for:
- Choosing `AnchorMode` from config.
- Supplying header windows to `advance` from wherever it fetches them.
- Calling `ring.set_audited` after each progress step.
- Enabling signing after `RestartOutcome::Ready` and successful reconciliation.

---

## Tests (`pq_anchor_restart_suite.rs`, real ML-DSA-65)

| # | Test name | What it tests |
|---|---|---|
| T1 | `open_with_valid_record_cross_checks_and_begins_audit_at_durable_progress_height` | Happy-path open: valid ring record, cross-check passes, audit starts at persisted `audited_height` not 0 |
| T2 | `open_with_no_record_returns_no_record_error_signing_stays_disabled` | Empty ring → `RestartError::NoRecord` |
| T3 | `open_with_damaged_record_returns_damaged_error` | Corrupt bytes → `RestartError::Damaged` |
| T4 | `open_with_foreign_binding_returns_foreign_error` | Mismatched chain_id/genesis → `RestartError::Foreign` |
| T5 | `open_falls_back_to_previous_generation_when_newest_cross_check_fails` | Newest record tampered → fallback to previous → `open` succeeds |
| T6 | `advance_drives_audit_to_completion_and_returns_ready` | Full genesis-to-anchor audit in bounded windows → `RestartOutcome::Ready` |
| T7 | `interrupted_audit_resumes_from_durable_watermark_after_simulated_restart` | Audit advances partway, `set_audited` called, `open` on fresh ring picks up from watermark |
| T8 | `failed_audit_returns_failed_and_signing_stays_disabled` | Forged ancestor field → `RestartOutcome::Failed(AuditFailed(...))` |
| T9 | `reconciliation_fails_when_executor_state_root_disagrees` | Audit completes but attested state root ≠ executor root → `RestartError::Inconsistent` |
| T10 | `feature_off_path_is_untouched_existing_engine_counts_unchanged` | Engine test count with feature OFF is unchanged from AN-2 baseline (194) |

---

## Limits

- **Not implemented**: node wiring, actual signing-gate integration, anchor-start mode, pruning,
  network distribution.
- **Not tested here**: multi-node liveness; production key custody; adversarial peers; dynamic
  membership.
- Signing remains disabled until `RestartOutcome::Ready` and reconciliation both succeed; a partial
  or failed audit provides no additional trust (trust rule from AN-2 carries forward).
- The mutation campaign for AN-3 should use a disposable worktree.

---

## Windows validation request (MINGW64, owner must run)

Scope: `anchor_restart.rs` and its 10 tests, exercised through `pq_hotstuff_engine_fips204`.

```bash
git pull origin feat/pq-hotstuff-2-anchored-evidence-an3
cargo build -p chain-forge-node
cargo test -p chain-forge-consensus --test pq_hotstuff_engine_fips204 --features pq-hotstuff-fips204,pq-anchored-evidence -- --nocapture 2>&1 | tail -3
# expect: test result: ok. 220 passed; 0 failed; 2 ignored  (210 AN-2 + 10 AN-3)
cargo test -p chain-forge-consensus --test pq_hotstuff_engine_fips204 --features pq-hotstuff-fips204 -- --nocapture 2>&1 | tail -3
# expect: test result: ok. 194 passed; 0 failed; 2 ignored  (feature-off unchanged)
```

Per CLAUDE.md, the milestone is NOT marked ✅ until these pass on Windows.
