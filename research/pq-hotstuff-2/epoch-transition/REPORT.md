# PO-4 epoch-transition model: status report (first result)

Subject: PR #130 head `72c24df31b4e67a573374bb8102f69dde6996c01`, spec sections 3.6 and 3.7. Tool: TLC 2.19, Java 21, 4 cores. See README.md.

## Result

**No safety counterexample was found. The baseline was not exhaustively verified. No mutant has yet been shown to produce a violation.** Nothing here supports a claim that the proposed epoch-transition rules are safe; the model's search is incomplete.

| Run | Config | Bounds | Result |
|---|---|---|---|
| selftest | static assertions on helper operators | n/a | passed (26 assumptions) |
| safety_t3_overlap (partial log kept in `out/safety_t3_overlap.partial.log`) | 3 validators/epoch, same membership, R=4, Byzantine proposals on | no exploration bound | **incomplete**: stopped at 398,323 distinct states, depth 17, no violation reached so far |
| mut_M1_no_seal__t3_disjoint | zero overlap, seal removed, scenario skeleton + prelude, R=4 | see cfg | **incomplete** (time cap); the expected conflicting commit was **not** reached, so the checker's ability to detect the missing-seal failure is **not yet demonstrated** |
| safety_t3_disjoint | zero overlap, baseline, deep prelude | see cfg | **incomplete** (time cap, 2 min): 67,051 distinct states, depth 12, no violation so far |

The other mutants (no boundary check, floor reset, non-empty suffix, send-before-persist, seal on learn) were generated (`cfg/`) but **not run**.

## Why it is incomplete

The model keeps each honest validator's knowledge as an arbitrary set of learned items, so independent delivery orders multiply the state space. Even three validators per epoch and four rounds exceed what TLC explores in the time I allowed. Reductions tried: memoised chain information, per-state certificate sets, leader-filtered proposal candidates, a pre-proposed scenario skeleton, a reachable prelude (validators 0 and 1 have voted for `P` and `Z`), eager learning for non-lagging validators, small proposal/timeout bounds. Random simulation also found nothing in its time cap.

## Coverage and limitations (explicit)

* Byzantine validators are implicit (they may add a vote or timeout to any certificate, never need to obey a rule); perfect cryptography; power 1 per validator.
* One transition 0 to 1 only; a second epoch change in epoch 1 is not generated.
* Payload content is abstracted to kinds N, EC, S.
* Delivery is item-granular per validator, but runs with `EagerOn` restrict lagging to `LagSet`.
* Scenario-directed runs (`SkeletonOn`, `PreludeOn`) cover only behaviours reachable from that prefix, and only the pre-placed block shapes.
* Liveness (deadlock, stalled suffix) configurations exist (`cfg/live_*.cfg`) but were not run.
* Round-robin leaders with seed 0 stand in for the unspecified seed reduction (K3).

## Specification ambiguities the modelling exposed (no change made)

* The seal rule says "a vote that may complete the commit"; the model reads it as voting for the second block of a consecutive pair whose parent is the epoch-change block or its suffix. The alternative of sealing when the completing certificate is learned is a configuration (`SealOnLearn`).
* Votes go "to the next leader" (spec section 5); the model lets any validator learn any existing certificate (the safe-side reading for safety). A withholding leader at round `z+1` is a liveness question: sealed validators cannot time out in epoch 0 above `z`, so if `QC(Z)` is never published the transition could stall. This is a hypothesis for the liveness runs, not a result.

## Recommended use of this model

Treat it as a harness, not evidence. Before engine code relies on dynamic membership, the model needs either a smaller knowledge abstraction (validators synchronise to snapshots) or a distributed/longer run, then the five mutants as detection checks. The 4-node devnet with a fixed validator set does not depend on it.
