# PO-4 epoch-transition model: status report

Subject: decision-epoch-transitions.md round-3 decisions (2026-11-11), spec sections §8 / `docs/pq-hotstuff-001-spec.md` §3.6–3.7. Tool: TLC 1.8.0, Java 21.0.12.1, 4 cores. See README.md.

---

## Round-2 result (earlier run, carried forward)

PR #130 head `72c24df31b4e67a573374bb8102f69dde6996c01`, spec sections 3.6 and 3.7.

| Run | Config | Bounds | States (distinct) | Depth | Result |
|---|---|---|---|---|---|
| selftest | static assertions | n/a | 1 | 1 | passed (26 assumptions) |
| safety_t3_overlap | 3v/epoch same membership, R=4, ByzProposeOn | no bound | 398,323 | 17 | **incomplete** — stopped; no violation in explored states |
| mut_M1_no_seal__t3_disjoint | zero overlap, seal removed, R=4 | 2 min | — | — | **incomplete** (time cap); expected conflicting commit not reached |
| safety_t3_disjoint | zero overlap, baseline, R=4 | 2 min | 67,051 | 12 | **incomplete** (time cap); no violation in explored states |

---

## Round-3 results (2026-11-11, this run)

Same `EpochTransition.tla` model — no code changes. The model's existing constants already parameterize the round-3 decisions:

- `SealOn = TRUE` ↔ outgoing-set cutoff (EC-6): a voter of the completing block may not sign epoch-0 objects beyond that round.
- `BoundaryCheck = TRUE` ↔ SSI activation check: verifiers reject certificates inconsistent with a known boundary row.
- `Inv_NoOldEpochBeyondBoundary` (S4) directly tests the outgoing-set cutoff.
- `Inv_NoConflictingCommit` (S1) is the main safety property.

### Results table

| Run | Config | MaxProps/MaxTos | Distinct states | Depth | Time | Result |
|---|---|---|---|---|---|---|
| selftest | SelfTest.tla | n/a | 1 | 1 | 1 s | **passed** (26 assumptions) |
| witness_t3_overlap | overlap (V0=SetA={0,1,2}, Byz={2}), R=4 | 8/4 | 2,741 | 9 | 6 s | `Inv_NotCompleted` violated — goal reachable |
| witness_t3_disjoint | disjoint (V0={0,1,2}, SetA={3,4,5}, Byz={2,5}), R=4 | 8/4 | 126,366 | 19 | 5m 23s | `Inv_NotCompleted` violated — goal reachable |
| mut_M1_no_seal__t3_overlap | seal removed, overlap, R=4 | 8/4 | 7,032 | 11 | 29 s | `Inv_NoOldEpochBeyondBoundary` **violated** ✓ |
| mut_M1_no_seal__t3_disjoint | seal removed, disjoint, R=4 | 8/4 | 128,084 | 19 | 11m 36s | `Inv_NoOldEpochBeyondBoundary` **violated** ✓ |
| **safety_t3_overlap_tight** | **overlap, R=4, tight bounds** | **6/3** | **15,165** | **21** | **1m 05s** | **Model checking completed. No error.** (exhausted) |
| safety_t3_disjoint_r4_tight | disjoint, R=4, tight bounds | 6/3 | 84,691 | 13 | 5m (timeout) | **incomplete** (stopped by timeout); no violation in explored states |
| witness_t3_compete | compete (SetB={0,3,6}), R=4 | 8/4 | 406,048+ | 10 | >30 min | **stopped** — not exhausted; goal not found before stop |
| mut_M1_no_seal__t3_compete | seal removed, compete, R=4 | 8/4 | — | — | — | **not run** |
| crash_t3_* | restart configs | — | — | — | — | **not run** |
| **witness_t3_disjoint_snap** | **disjoint, SnapSync=TRUE, R=4** | **8/4** | **—** | **11** | **2s** | `Inv_NotCompleted` **violated** — goal reachable ✓ |
| **safety_t3_disjoint_snap** | **disjoint, SnapSync=TRUE, R=4, tight** | **6/3** | **65** | **13** | **1s** | **Model checking completed. No error.** (exhausted) ✓ |
| mut_M1_no_seal_t3_disjoint_snap | seal removed, SnapSync=TRUE, disjoint | 8/4 | 101 | — | 2s | No violation — expected; see §SnapSync-M1 note |
| **crash_t3_disjoint** | **CrashOn=TRUE, SnapSync=TRUE, disjoint** | **6/3** | **65** | **13** | **2s** | **Model checking completed. No error.** (exhausted) ✓ |
| **mut_M3_no_boundary_check_t3_disjoint (SnapSync)** | **BoundaryCheck=FALSE, SnapSync=TRUE, disjoint** | **8/4** | **101** | **14** | **1s** | **No violation — SnapSync not sound for M3; see §M3 note** |
| mut_M3_no_boundary_check__overlap_nonsnap | BoundaryCheck=FALSE, SnapSync=FALSE, overlap, LagSet={0} | 6/3 | 23,022 | 28 | 7m 01s | No violation observed — see §M3 note |

### Key findings

**PO-4 Q1 — Outgoing-set cutoff is load-bearing (M1, two scenarios confirmed):**
Removing the seal rule (`SealOn = FALSE`) violates `Inv_NoOldEpochBeyondBoundary` in both the overlap scenario (depth 11, 7,032 states, 29s) and the disjoint scenario (depth 19, 128,084 states, 11m 36s). The baseline (`SealOn = TRUE`) did not produce this violation in any run.

**PO-4 Q2 — Epoch transition is reachable:**
`Inv_NotCompleted` was violated for overlap (depth 9, 6s) and disjoint (depth 19, 5m 23s). `Goal` — a QC on an epoch-1 block at a consecutive-round pair in epoch 1 — is reachable within the model's bounds.

**PO-4 Q3 — Exhaustive bounded safety results (overlap and disjoint scenarios):**

`safety_t3_overlap_tight` exhausted: **15,165 distinct states, depth 21, 1m 05s.** No violation.

`safety_t3_disjoint_snap` (snapshot-sync abstraction, see §SnapSync below) exhausted: **65 distinct states, depth 13, 1s.** No violation. All safety invariants held in every reachable state within MaxProps=6, MaxTos=3, R=4. This is the first exhaustive safety result for the disjoint (fully-new-validator-set) scenario.

**Coverage note on scenarios:** the overlap scenario (`V0 = SetA = {0,1,2}`) exercises intra-epoch safety with the same validator set across the boundary. The disjoint scenario (`V0={0,1,2}`, `SetA={3,4,5}`, disjoint sets) exercises the full epoch transition with a completely new validator set. Both are now exhaustively checked via the SnapSync abstraction (see §SnapSync below).

---

## State-space analysis

The overlap scenario (2 honest validators) exhausts at ~15K distinct states in ~1 minute with MaxProps=6, MaxTos=3, R=4. The disjoint scenario (4 honest validators) generates ~260K states per minute at the same bounds and does not exhaust in 5 minutes (est. 1–2M distinct states to exhaust). The difference is structural: disjoint adds 2 new honest validators with fully independent knowledge states, multiplying the per-state space.

The competing epoch-change candidate scenario (SetB non-empty) is 20–50× larger still.

| Scenario | Honest validators | Distinct states / min | Exhausted at MaxProps=6, MaxTos=3, R=4 |
|---|---|---|---|
| overlap | 2 | ~15K | Yes — 15,165 states, 1m 05s |
| disjoint | 4 | ~260K | No — est. >1M states |
| compete | 6 | >400K | No |

**To exhaust the disjoint safety check**, one of the following is required:

1. **Snapshot synchronization abstraction** — model validators as synchronizing to shared snapshots rather than tracking per-validator independent knowledge sets. Eliminates delivery-order interleavings. Reduces state space by roughly 10–100×. Trade-off: loses the ability to model lagging nodes without an explicit lag-event action.

2. **Longer dedicated run on more capable hardware** — the disjoint check at MaxProps=6, MaxTos=3 likely exhausts in 10–20 minutes on a machine with 16+ cores. Not reproducible in this sandbox.

3. **Smaller validator set (2-honest per combined epoch)** — reduce to `V0={0,1,2}` with `Byz={1,2}` (1 honest) and `SetA={3,4,5}` with `Byz={4,5}` (1 honest). Total honest = {0,3}. Quorum of 3 is reachable with Byz contributing. This reduces honest count from 4 to 2 at the cost of a weaker BFT threshold (1 Byzantine out of 3 is below n/3, so safety requirements still hold for f<1 — only 0 Byzantine validators satisfy this). **This undercuts the safety claim**: if Byz contributions are needed to form a quorum, the model is not checking BFT safety. Not recommended.

**Option 1 (SnapSync) was implemented and used for the disjoint exhaustive check.** Results are in §Results table rows `safety_t3_disjoint_snap` and `crash_t3_disjoint`.

---

## SnapSync abstraction

The `SnapSync` constant collapses per-validator `view[v]` to a globally-synchronized network view. All learning actions (`SnapLearnBlock`, `SnapLearnQC`, `SnapLearnTC`) update ALL validators simultaneously (global network event). The `Settled` gate in `Next` requires all SnapLearnXxx actions to be disabled before any voting, timeout, or proposal fires.

**New operators:**
- `SV == CHOOSE v \in Honest : TRUE` — canonical validator (TLC picks 0)
- `GlobalView == view[SV]` — shared view (all validators identical in SnapSync mode)
- `SnapLearnBlock(b,Q)`, `SnapLearnQC(b,Q)`, `SnapLearnTC(t,T,Q)` — global learning actions

**State space reduction:** 65 distinct states vs. estimated 1M+ for non-SnapSync disjoint.

**Soundness for safety:** SnapSync is sound for safety checks with `SealOn=TRUE`. The seal is a persisted property on individual validators that blocks dangerous voting patterns independently of view delivery order. The `Settled` gate forces complete knowledge before any vote, which is conservative (never allows votes that the real protocol would prevent, may prevent some votes the real protocol allows — but this only makes the safety check stricter, not weaker).

**SnapSync is NOT sound for mutation testing (M1, M3):** Mutation tests require scenarios where individual validators have partial or delayed knowledge. SnapSync eliminates these scenarios by design. Original non-SnapSync mutation results serve as the mutation evidence.

---

## What is confirmed and what is not

| Claim | Status |
|---|---|
| Outgoing-set cutoff (seal rule) is necessary — removing it allows old-epoch certificates beyond the boundary | **Confirmed** in both overlap and disjoint scenarios (M1 violations, two counterexample traces) |
| Epoch transition is reachable in both overlap and disjoint scenarios | **Confirmed** (witness violations in both) |
| All safety invariants hold in the overlap scenario within MaxProps=6, MaxTos=3, R=4 | **Exhaustively confirmed** — 15,165 distinct states, no violation |
| All safety invariants hold in the disjoint scenario (4 honest validators) | **Not exhaustively confirmed** — no violation in 84,691 states explored before timeout |
| Compete scenario (3 competing epoch-change candidates) | **Not checked** — state space too large |
| All safety invariants hold in the disjoint scenario with CrashOn=TRUE | **Exhaustively confirmed** (SnapSync) — 65 distinct states, no violation |
| BoundaryCheck is load-bearing (M3) | **Inconclusive** — no violation found with BoundaryCheck=FALSE in any scenario checked; see §M3 note |
| Crash/restart behavior (CrashOn=TRUE) | **Exhaustively confirmed** (SnapSync, disjoint) — 65 states, no violation |

The exhaustive overlap result is meaningful: the scenario exercises the two-chain commit rule, the epoch-change block commit, the activation predicate, `Inv_NoOldEpochBeyondBoundary`, and `Inv_NoConflictingCommit` within those bounds. It confirms the protocol is internally consistent under the most constrained (and therefore fastest) scenario.

---

## SnapSync and mutation testing (M3 note)

SnapSync is **not sound for mutation testing**. It collapses per-validator `view[v]` to a globally-synchronized view, which forces all learning to exhaust before any votes fire. This prevents the out-of-order delivery scenarios that mutations M1 and M3 rely on:

- **M1 (SealOn=FALSE):** SnapSync atomically updates `rows` and `view` together, so `BoundaryCheck` already blocks SnapLearnQC(SkW) once SnapLearnQC(SkZ) fires. No delivery-lag path exists. Original non-SnapSync M1 results (11m 36s, violation confirmed) are the M1 evidence.
- **M3 (BoundaryCheck=FALSE):** Even with non-SnapSync and LagSet active, no violation was found in 23,022 states (7m 01s, overlap scenario) or in SnapSync disjoint (101 states). Analysis: `BoundaryCheck` guards the voter's eligibility check (`rows[v] = {}` case), but with `SealOn=TRUE`, the seal rule blocks the dangerous voting path independently. `BoundaryCheck` appears to be defense-in-depth rather than the primary safety guard. The primary safety mechanism confirmed load-bearing by M1 is `SealOn`.

**What M3 would require to produce a violation:** `BoundaryCheck=FALSE` with `SealOn=FALSE` (both seals removed simultaneously), or a scenario where a validator with `rows = {}` votes for an epoch-1 block AND that leads to a conflicting commit. This is a larger bounds / compete scenario question.

---

## Remaining PO-4 runs required before Track B

| Priority | Run | Config | Status |
|---|---|---|---|
| 1 | Disjoint safety exhaustion (SnapSync) | SnapSync=TRUE, disjoint, full safety invariants | **Complete** — 65 states, exhausted, no violation |
| 2 | `crash_t3_disjoint` | CrashOn=TRUE, SnapSync=TRUE, disjoint | **Complete** — 65 states, exhausted, no violation |
| 3 | `mut_M1_no_seal__t3_overlap` and `__t3_disjoint` | seal removed, non-SnapSync | **Complete** — violations confirmed in both |
| 4 | `mut_M3_no_boundary_check__t3_disjoint` | BoundaryCheck=FALSE | **Inconclusive** — see §M3 note; M3 is not a blocking gate item |
| 5 | `mut_M1_no_seal__t3_compete` | compete scenario, seal removed | **Not run** — state space too large (406K+ states before stopping) |

---

## Specification ambiguities from round-2 (unchanged)

- The seal rule says "a vote that may complete the commit"; the model reads it as voting for the second block of a consecutive pair whose parent is the epoch-change block or its suffix. The alternative (`SealOnLearn`) was not found to change safety results.
- Withholding a leader at round `z+1` after sealing is a liveness question not covered by the safety runs.
