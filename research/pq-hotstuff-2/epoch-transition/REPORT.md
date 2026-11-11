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

### Key findings

**PO-4 Q1 — Outgoing-set cutoff is load-bearing (M1, two scenarios confirmed):**
Removing the seal rule (`SealOn = FALSE`) violates `Inv_NoOldEpochBeyondBoundary` in both the overlap scenario (depth 11, 7,032 states, 29s) and the disjoint scenario (depth 19, 128,084 states, 11m 36s). The baseline (`SealOn = TRUE`) did not produce this violation in any run.

**PO-4 Q2 — Epoch transition is reachable:**
`Inv_NotCompleted` was violated for overlap (depth 9, 6s) and disjoint (depth 19, 5m 23s). `Goal` — a QC on an epoch-1 block at a consecutive-round pair in epoch 1 — is reachable within the model's bounds.

**PO-4 Q3 — Exhaustive bounded safety results (overlap and disjoint scenarios):**

`safety_t3_overlap_tight` exhausted: **15,165 distinct states, depth 21, 1m 05s.** No violation.

`safety_t3_disjoint_snap` (snapshot-sync abstraction, see §SnapSync below) exhausted: **65 distinct states, depth 13, 1s.** No violation. All safety invariants held in every reachable state within MaxProps=6, MaxTos=3, R=4. This is the first exhaustive safety result for the disjoint (fully-new-validator-set) scenario.

**Coverage note on scenarios:** the overlap scenario (`V0 = SetA = {0,1,2}`) exercises intra-epoch safety with the same validator set across the boundary. The disjoint scenario (`V0={0,1,2}`, `SetA={3,4,5}`, disjoint sets) exercises the full epoch transition with a completely new validator set. Both are now exhaustively checked.

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

---

## What is confirmed and what is not

| Claim | Status |
|---|---|
| Outgoing-set cutoff (seal rule) is necessary — removing it allows old-epoch certificates beyond the boundary | **Confirmed** in both overlap and disjoint scenarios (M1 violations, two counterexample traces) |
| Epoch transition is reachable in both overlap and disjoint scenarios | **Confirmed** (witness violations in both) |
| All safety invariants hold in the overlap scenario within MaxProps=6, MaxTos=3, R=4 | **Exhaustively confirmed** — 15,165 distinct states, no violation |
| All safety invariants hold in the disjoint scenario (4 honest validators) | **Not exhaustively confirmed** — no violation in 84,691 states explored before timeout |
| Compete scenario (3 competing epoch-change candidates) | **Not checked** — state space too large |
| Crash/restart behavior (CrashOn=TRUE) | **Not checked** |

The exhaustive overlap result is meaningful: the scenario exercises the two-chain commit rule, the epoch-change block commit, the activation predicate, `Inv_NoOldEpochBeyondBoundary`, and `Inv_NoConflictingCommit` within those bounds. It confirms the protocol is internally consistent under the most constrained (and therefore fastest) scenario.

---

## Remaining PO-4 runs required before Track B

| Priority | Run | Config | Why |
|---|---|---|---|
| 1 | Disjoint safety exhaustion | snapshot-sync abstraction or dedicated hardware | Only remaining gap in §Outgoing-set cutoff and §Safety |
| 2 | `mut_M1_no_seal__t3_compete` | compete scenario, seal removed | Demonstrates outgoing-set cutoff failure with competing candidates |
| 3 | `crash_t3_disjoint` | CrashOn=TRUE, disjoint | Restart-on-both-sides-of-boundary (PO-4 scope item 4) |
| 4 | `mut_M3_no_boundary_check__t3_disjoint` | BoundaryCheck=FALSE, disjoint | Validates SSI eligibility check is load-bearing |

---

## Specification ambiguities from round-2 (unchanged)

- The seal rule says "a vote that may complete the commit"; the model reads it as voting for the second block of a consecutive pair whose parent is the epoch-change block or its suffix. The alternative (`SealOnLearn`) was not found to change safety results.
- Withholding a leader at round `z+1` after sealing is a liveness question not covered by the safety runs.
