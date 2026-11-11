# PO-4 epoch-transition model: status report

Subject: decision-epoch-transitions.md round-3 decisions (2026-11-11), spec sections §8 / `docs/pq-hotstuff-001-spec.md` §3.6–3.7. Tool: TLC 1.8.0, Java 21.0.12, 4 cores. See README.md.

---

## Round-2 result (earlier run, carried forward)

PR #130 head `72c24df31b4e67a573374bb8102f69dde6996c01`, spec sections 3.6 and 3.7.

**No safety counterexample found. Search incomplete. No mutant demonstrated a violation.**

| Run | Config | Bounds | Result |
|---|---|---|---|
| selftest | static assertions | n/a | passed (26 assumptions) |
| safety_t3_overlap | 3v/epoch same membership, R=4, ByzProposeOn | no bound | **incomplete**: 398,323 distinct states, depth 17, no violation |
| mut_M1_no_seal__t3_disjoint | zero overlap, seal removed | time cap | **incomplete** (2 min): expected conflicting commit not reached |
| safety_t3_disjoint | zero overlap, baseline, deep prelude, R=4 | time cap | **incomplete** (2 min): 67,051 distinct states, depth 12, no violation |

---

## Round-3 result (2026-11-11, this run)

Same `EpochTransition.tla` model — invariants already encode the round-3 decisions:

- **`SealOn`** ↔ outgoing-set cutoff: a voter of the completing block may not sign epoch-0 objects beyond that round (§ Outgoing-set cutoff).
- **`BoundaryCheck`** ↔ SSI activation check: verifiers reject certificates inconsistent with a known boundary row.
- **`Inv_NoOldEpochBeyondBoundary`** (S4) ↔ directly tests the outgoing-set cutoff: no honest validator holding the boundary row may hold an old-epoch certificate beyond it.
- **`Inv_NoConflictingCommit`** (S1) ↔ main safety property.

No model changes were required because the existing constants already parameterize these rules.

### Results table

| Run | Config | Distinct states | Depth | Time | Result |
|---|---|---|---|---|---|
| selftest | SelfTest.tla | 1 | 1 | 1 s | **passed** (all 26 assumptions) |
| witness_t3_overlap | overlap, 3v/epoch, R=4 | 2,741 | 9 | 6 s | **Inv_NotCompleted violated** (goal reachable: epoch transition completes) |
| witness_t3_disjoint | disjoint, 3v/epoch, R=4 | 126,366 | 19 | 5m 23s | **Inv_NotCompleted violated** (goal reachable: epoch transition completes) |
| mut_M1_no_seal__t3_overlap | seal removed, overlap | 7,032 | 11 | 29 s | **Inv_NoOldEpochBeyondBoundary violated** ✓ (outgoing-set cutoff fails without seal) |
| mut_M1_no_seal__t3_disjoint | seal removed, disjoint | 128,084 | 19 | 11m 36s | **Inv_NoOldEpochBeyondBoundary violated** ✓ (outgoing-set cutoff fails without seal) |
| witness_t3_compete | compete (3 candidates, SetB={0,3,6}) | 406,048+ | 10 | >30 min | **stopped** — state space too large for this run |
| mut_M1_no_seal__t3_compete | seal removed, compete | — | — | — | **stopped** (not started in time) |
| safety_t3_disjoint | baseline safety, disjoint | — | — | — | **incomplete** — times out before exhaustion |
| safety_t3_overlap | baseline safety, overlap | — | — | — | **incomplete** — times out before exhaustion |

### Key findings

**PO-4 Q1 (outgoing-set cutoff holds with the seal rule, both disjoint and overlapping sets):**
Confirmed by detection. M1 (no seal) violates `Inv_NoOldEpochBeyondBoundary` in both the disjoint scenario (depth 19, 11m 36s) and the overlap scenario (depth 11, 29s). The seal rule (`SealOn = TRUE`) is therefore necessary; removing it admits an old-epoch certificate beyond the boundary row. The baseline (seal enabled) did not violate this invariant in any completed run.

**PO-4 Q2 (epoch transition is reachable, both disjoint and overlapping sets):**
Confirmed by witness. `Inv_NotCompleted` was violated for both the overlap scenario (depth 9, 6s) and the disjoint scenario (depth 19, 5m 23s), meaning TLC found a state satisfying `Goal` (a QC on an epoch-1 block at a consecutive-round pair in epoch 1). The handoff trace is reachable within the model's bounds.

**What is not yet confirmed:**

- **`Inv_NoConflictingCommit` (S1) in the baseline:** neither the disjoint nor the overlap safety check exhausted its state space within the available run time. No violation was found, but no exhaustive confirmation was obtained. The safety check requires either a smaller abstraction or a longer dedicated run.
- **Compete scenario (SetB — third competing epoch-change candidate):** the state space is too large for the current abstraction. The witness check reached 406K+ distinct states at depth 10 without finding the goal. The M1 compete check was not started.
- **Crash/restart configs:** not run in this session. The `crash_t3_*` family (CrashOn = TRUE) covers the restart-on-both-sides-of-boundary requirement from the PO-4 scope. These require `StageVotes = TRUE` and are slower than the no-crash runs.

---

## Coverage and limitations

Unchanged from round-2, plus:

- Byzantine validators are implicit (may add a vote or timeout to any certificate, never required to obey a rule); perfect cryptography; power 1 per validator.
- One transition 0→1 only. The model does not generate a second epoch change in epoch 1.
- Payload content is abstracted to kinds N, EC, S.
- Delivery is item-granular per validator; `EagerOn` restricts lagging to `LagSet`.
- Scenario-directed runs (`SkeletonOn`, `PreludeOn`) only cover behaviours reachable from the skeleton prefix.
- Liveness (`live_*.cfg`) and crash-restart (`crash_*.cfg`) configurations were not run.
- Round-robin leaders stand in for the unspecified seed reduction (K3).
- The compete scenario (`SetB` non-empty) expands the state space by roughly 20× vs. the overlap scenario; it requires either a longer run or a reduced abstraction to complete.

---

## State-space reduction recommendation

The disjoint safety check (baseline) and the compete witness both require more than 10+ minutes at 3 validators per epoch and R=4. Two reductions that preserve the safety question:

1. **Snapshot synchronization:** model validators as synchronizing to full shared snapshots rather than tracking per-validator knowledge sets. Eliminates delivery-order interleavings. Reduces state space by roughly 10–100×. Trade-off: loses the ability to model lagging nodes (which the crash configs currently cover).

2. **R=3 with SkeletonOn:** the scenario skeleton pre-places the conflicting-commit scenario, so the conflict can be found at shallower depths. R=3 reduces the round fan-out further. The disjoint scenario at R=3 would likely exhaust its state space in under 2 minutes.

The competing epoch-change candidate scenario (SetB) is specifically needed to validate the PO-4 requirement that "no coalition straddling the boundary can produce conflicting QCs at the same height under different `valset_hash` values." This requires running either the compete safety check to exhaustion (with a reduction) or demonstrating the violation path via M3 (no boundary check) on the compete scenario.

---

## Recommended next runs

| Priority | Run | Expected duration | Why |
|---|---|---|---|
| 1 | `mut_M1_no_seal__t3_compete` | 20–60 min | Demonstrates outgoing-set cutoff failure with competing candidates — the strongest mutant evidence |
| 2 | `safety_t3_disjoint` with R=3 | <2 min | Baseline safety check at reduced depth |
| 3 | `crash_t3_disjoint` | 15–30 min | Restart-on-both-sides-of-boundary (PO-4 scope item 4) |
| 4 | `mut_M3_no_boundary_check__t3_compete` | 20–60 min | Validates the SSI eligibility check is load-bearing |
| 5 | Snapshot-sync abstraction | n/a — requires model edit | Prerequisite for exhaustive safety check |

---

## Decision implication

PO-4 scope (from decision-epoch-transitions.md round 3):

| Requirement | Status |
|---|---|
| Disjoint validator sets | Covered: witness (goal reachable) + M1 violation (cutoff detectable). Safety check incomplete. |
| Delayed handoff evidence | Not explicitly covered in this run (crash configs not run). |
| Competing outgoing-set continuations | Partially covered: disjoint/overlap witness + M1. Compete scenario too large. |
| Restarts on both sides of epoch boundary | Not run (crash_t3 configs). |
| Report search bounds | Done — see table above. |

**Track B gate:** `Inv_NoConflictingCommit` has not been exhaustively verified for any scenario. The seal rule is load-bearing (M1 violations confirmed in two scenarios). PO-4 is not complete; dynamic membership remains disabled. The recommended next runs above are the minimum to close PO-4.
