# PQ-HotStuff-2 - AN-3: anchored restart integration ✅ COMPLETE

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

**Linux result — component tests** (commit `01699c5`, 2026-11-10, release mode, real FIPS 204 ML-DSA-65):
`test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 212 filtered out; finished in 1.07s`

**Windows result — component tests** (commit `fb60173`, 2026-11-10, MINGW64 krizz@BossKing, release mode, real FIPS 204 ML-DSA-65):
All 11 tests run individually — each reported `test result: ok. 1 passed; 0 failed`. Cargo exit 0.

**Linux result — driver wiring tests** (commit `04c98c0`, 2026-11-10, release mode, real FIPS 204 ML-DSA-65):
`test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 223 filtered out; finished in 0.59s`

**Windows result — driver wiring tests** (commit `0716a72`, 2026-11-11, MINGW64 krizz@BossKing, release mode, real FIPS 204 ML-DSA-65):
All 5 tests run individually — each reported `test result: ok. 1 passed; 0 failed`. Cargo exit 0.

**Linux sandbox result — signing gate + audit-watermark fix** (commit `54f2bc7`, 2026-11-11, debug mode, `TestVerifier`):
`test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 218 filtered out; finished in 284.01s`
(All prior T1–T16 plus new T17–T19; no regressions.)

**Windows result — signing gate + audit-watermark fix** (tested code commit `54f2bc7`, recording commit `9792fbf` is docs-only, 2026-11-11, MINGW64 krizz@BossKing, release mode, real FIPS 204 ML-DSA-65):
- T17 `audit_watermark_bypass_is_closed_full_reverification_required`: `test result: ok. 1 passed; 0 failed` (0.75s)
- T18 `tick_with_anchor_pending_produces_no_outbound`: `test result: ok. 1 passed; 0 failed` (0.57s)
- T19 `on_bytes_with_consensus_msg_while_anchor_pending_produces_no_signing_outbound`: `test result: ok. 1 passed; 0 failed` (0.62s)

**Windows result — T19 assertion fix** (commit `dcae423`, 2026-11-11, MINGW64 krizz@BossKing, release mode, real FIPS 204 ML-DSA-65):
- T19 `on_bytes_with_consensus_msg_while_anchor_pending_produces_no_signing_outbound`: `test result: ok. 1 passed; 0 failed` (0.75s)

**Windows result — T20/T20b/T21/T22 reconciliation + gate suppression + FS restart** (commit `3eb572e`, 2026-11-11, MINGW64 krizz@BossKing, debug mode, real FIPS 204 ML-DSA-65):
```
cargo test -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- advance_anchor_reaches_ready_with_matching_executor_state advance_anchor_returns_reconcile_failed_on_executor_mismatches anchor_pending_suppresses_try_complete_recovery_until_gate_clears fs_backed_restart_preserves_signing_floors_and_prevents_duplicate_execution --nocapture
```
- T20 `advance_anchor_reaches_ready_with_matching_executor_state`: ok
- T20b `advance_anchor_returns_reconcile_failed_on_executor_mismatches`: ok (ran >60 s — second Eng3 simulation with real ML-DSA-65 is slow)
- T21 `anchor_pending_suppresses_try_complete_recovery_until_gate_clears`: ok
- T22 `fs_backed_restart_preserves_signing_floors_and_prevents_duplicate_execution`: ok

`test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 231 filtered out; finished in 63.66s`

| # | Test name | What it tests |
|---|---|---|
| T1 | `off_mode_is_the_default_and_no_ring_or_verification_runs` | `AnchorMode::default() == Off`; mode enum is wired |
| T2 | `open_with_valid_record_cross_checks_and_begins_audit_at_durable_progress_height` | Happy-path open: valid ring record, cross-check passes, audit starts from genesis |
| T3 | `open_with_no_record_returns_no_record_error_signing_stays_disabled` | Empty ring → `RestartError::NoRecord` |
| T4 | `open_with_foreign_binding_returns_foreign_error` | Mismatched chain_id → `RestartError::Foreign` |
| T5 | `open_falls_back_to_previous_generation_when_newest_cross_check_fails` | Newest record tampered → fallback to previous → `open` succeeds |
| T6 | `advance_drives_audit_to_completion_and_returns_ready` | Full genesis-to-anchor audit in bounded windows → `RestartOutcome::Ready` |
| T7 | `interrupted_audit_resumes_from_durable_watermark_after_simulated_restart` | Audit advances partway, `set_audited` called, re-open picks up from watermark |
| T8 | `failed_audit_returns_failed_and_signing_stays_disabled` | Forged ancestor field → `RestartOutcome::Failed(AuditFailed(...))` |
| T9 | `reconciliation_fails_when_executor_state_root_disagrees` | Audit ready but attested state root ≠ executor root → `RestartError::Inconsistent` |
| T10 | `reconciliation_succeeds_with_consistent_executor_state` | Correct executor state → `reconcile` returns `Ok` |
| T11 | `feature_off_path_is_untouched_engine_counts_unchanged` | `AnchorMode::default() == Off` (feature-off regression guard) |
| T12 | `audit_first_start_returns_empty_first_and_blocks_retransmission` | `start` with anchor pending returns empty first-sends; `anchor_pending` is true |
| T13 | `advance_anchor_returns_pending_until_audit_is_complete` | Partial window (1 header, `audited_height=0`) → `Pending`; gate not cleared |
| T14 | `advance_anchor_drives_audit_to_completion_or_reconcile` | Full audit completes; outcome is `Ready` or `ReconcileFailed` (not `AuditFailed`) |
| T15 | `not_pending_when_no_anchor_is_installed` | No anchor in config → `anchor_pending` false; `advance_anchor` returns `NotPending` |
| T16 | `failed_audit_returns_audit_failed_and_anchor_pending_stays_true` | Tampered record → `AuditFailed`; gate not cleared |
| T17 | `audit_watermark_bypass_is_closed_full_reverification_required` | `audited_height == anchor.height` → first `advance` call returns `NeedHeaders` (bypass closed) |
| T18 | `tick_with_anchor_pending_produces_no_outbound` | `tick` while audit pending produces zero outbound messages (no propose, no timeout) |
| T19 | `on_bytes_with_consensus_msg_while_anchor_pending_produces_no_signing_outbound` | Injecting real peer consensus bytes while audit pending produces no broadcast (signing) outbound |
| T20 | `advance_anchor_reaches_ready_with_matching_executor_state` | Node0 engine from real chain (matching block IDs + state roots) → `advance_anchor` returns `Ready`; gate clears |
| T20b | `advance_anchor_returns_reconcile_failed_on_executor_mismatches` | Executor behind anchor height, wrong block_id (independent Eng3 simulation), wrong state_root → each returns `ReconcileFailed`; gate stays up |
| T21 | `anchor_pending_suppresses_try_complete_recovery_until_gate_clears` | Five ticks while gate is up produce zero consensus outbound; after `Ready`, deferred contains ≥1 consensus message |
| T22 | `fs_backed_restart_preserves_signing_floors_and_prevents_duplicate_execution` | FsStorage safety+app+blockstore: second-run executor cursor matches pre-drop cursor; `Driver::start` succeeds; no duplicate execution |

**Audit-watermark bypass (closed):** `Audit::new_from` set `checked_anchor = true` when
`audited_height == anchor.height`, which made `advance` return `Ready` after a single header window
even for a fully-persisted record — the whole genesis-to-anchor re-verification was skipped. This is
the wrong behaviour for `AuditFirst` mode. `AnchorRestart::open` now always uses `Audit::new`
(ignoring the persisted watermark), so a full genesis-rooted re-verification runs on every startup.
T17 (`audit_watermark_bypass_is_closed_full_reverification_required`) confirms the bypass is closed:
feeding one header to a fully-persisted record must return `NeedHeaders`, not `Ready`.

---

## Limits

- **Not implemented**: node wiring, actual signing-gate integration, anchor-start mode, pruning,
  network distribution.
- **Not tested here**: multi-node liveness; production key custody; adversarial peers; dynamic
  membership.
- Signing remains disabled until `RestartOutcome::Ready` and reconciliation both succeed; a partial
  or failed audit provides no additional trust (trust rule from AN-2 carries forward).
- The mutation campaign for AN-3 should use a disposable worktree.

## Driver gate mutation campaign (signing-gate tests T18–T19, worktree `/tmp/claude-0/an3-mutants`)

Three gate sites in `driver.rs` under `#[cfg(feature = "pq-anchored-evidence")]`:

| # | Gate site | Mutation | Kill signal | Time |
|---|---|---|---|---|
| M6 | Tick gate (line 586): `if self.anchor.is_some() { return Ok(out); }` | Remove the early-return block entirely | T18 `tick_with_anchor_pending_produces_no_outbound`: FAILED | 19.35 s |
| M7 | Deliver gate (lines 494–505): `if self.anchor.is_some() { return match ... route_anchor_pending ... }` + `try_complete_recovery` gate (line 275) | Remove both blocks | T19 `on_bytes_with_consensus_msg_while_anchor_pending_produces_no_signing_outbound`: FAILED | 19.73 s |
| M8 | `route_anchor_pending` Broadcast suppression | Defense-in-depth; `Output::Broadcast` through the deliver path would only appear if the anchor-pending driver collects 2f+1 votes and forms a TC — which requires the full chain history not present in a fresh-start T19 driver. Not independently testable with current DNet infrastructure. | (n/a — architectural defense-in-depth) | — |

**T19 assertion fix (commit in this session):** The original assertion `o.to.is_some()` could not detect votes because votes are unicast `Output::Send { to: Some(leader) }` (non-None) rather than `Output::Broadcast`. The assertion was replaced with `net::decode(&o.bytes, &mlim())` checked against `NetMsg::Consensus(_)`, which catches votes, proposals, and timeouts correctly. M7 is now killed by T19 in 19.73 s.

## Mutation campaign (`anchor_restart.rs`, component tests, commit `2516600`)

Five mutations, all killed. M3 was re-verified against `2516600` (with the iteration guard) on
2026-11-11, MINGW64 krizz@BossKing — confirmed fast assertion (0.74 s), not a timeout.

| # | Mutation | Kill signal | Time |
|---|---|---|---|
| M1 | Comment out `NoRecord` check in `open` | T3 assertion | fast |
| M2 | Remove `Foreign` check in `open` | T4 assertion | fast |
| M3 | Swap `Ready`/`NeedHeaders` arms in `advance` | `drive_restart` iteration-bound panic | 0.74 s (Windows, `2516600`) |
| M4 | Invert `anchor.height > executor_committed_height` guard in `reconcile` | T9 assertion | fast |
| M5 | Remove `state_root` check in `reconcile` | T9 assertion | fast |

---

## Windows validation request (MINGW64, owner must run)

Scope: `anchor_restart.rs` and its 11 tests, exercised through `pq_hotstuff_engine_fips204`.

Individual tests (fastest; each ~60–120 s with real ML-DSA-65):

```bash
git pull origin feat/pq-hotstuff-2-anchored-evidence-an3
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- off_mode_is_the_default
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- open_with_valid_record
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- open_with_no_record
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- open_with_foreign
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- open_falls_back
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- advance_drives_audit
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- interrupted_audit
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- failed_audit
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- reconciliation_fails
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- reconciliation_succeeds
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- feature_off_path
```

Each command should report `test result: ok. 1 passed; 0 failed`.

Driver wiring tests (T12–T16, commit `04c98c0`):

```bash
git pull origin feat/pq-hotstuff-2-anchored-evidence-an3
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- audit_first_start
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- advance_anchor_returns_pending
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- advance_anchor_drives_audit
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- not_pending_when_no_anchor
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- failed_audit_returns_audit_failed
```

Signing gate + audit-watermark fix (T17–T19):

```bash
git pull origin feat/pq-hotstuff-2-anchored-evidence-an3
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- audit_watermark_bypass_is_closed
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- tick_with_anchor_pending
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- on_bytes_with_consensus_msg_while_anchor_pending
```

Each command should report `test result: ok. 1 passed; 0 failed`.

**Reconciliation, gate suppression, FS restart (T20/T20b/T21/T22) — ✅ PASSED on Windows (commit `3eb572e`, 2026-11-11):**

```bash
git pull origin feat/pq-hotstuff-2-anchored-evidence-an3
cargo test -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 -- advance_anchor_reaches_ready_with_matching_executor_state advance_anchor_returns_reconcile_failed_on_executor_mismatches anchor_pending_suppresses_try_complete_recovery_until_gate_clears fs_backed_restart_preserves_signing_floors_and_prevents_duplicate_execution --nocapture
```

Expected (confirmed): `test result: ok. 4 passed; 0 failed; finished in 63.66s`

All AN-3 tests (T1–T22) have passed on Windows/MINGW64. Milestone is ✅.
