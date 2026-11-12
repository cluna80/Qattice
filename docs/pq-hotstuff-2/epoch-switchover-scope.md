# Epoch switch-over scope — QAT-07 phase 2

**Status:** specification only. Dynamic membership is disabled in code.
Implementing behind a disabled gate requires owner approval of this document.
Enabling the gate requires separate owner approval after the acceptance tests
listed in R5 pass on Windows.

**Tied to:** PO-4 model `EpochTransition.tla` commit `e818fda` (SnapSync
abstraction). See §Model citations for the exact configurations.

---

## Handoff trace

Every rule below is a step in or a constraint on this exact trace. No rule
applies outside it.

```
Round z     B_ec proposed — carries the encoded incoming validator set V_new.
            Outgoing set (V_old) votes for B_ec.
            QC_ec forms: 2f+1 precommits from V_old over B_ec at round z.
            locked_qc := QC_ec  (round z)

Round z+1   B_child proposed — parent = B_ec, carries QC_ec as pol_qc.
            V_old votes for B_child.
            QC_child forms: 2f+1 precommits from V_old over B_child at round z+1.
            high_qc := QC_child  (round z+1)

Commit      locked_qc.round + 1 == high_qc.round  →  B_ec is committed.
            CommitCertificate(B_ec, QC_ec, QC_child) written to durable block store.
            Outgoing seal becomes durable (see R2).

Handoff     Incoming set V_new extracted from finalized B_ec.
            Epoch counter advances: epoch 0 → epoch 1.
            signing_ctx.advance_epoch(1) fires.

Round 1,    V_new begins signing at epoch=1, round=1.
epoch 1     V_old cannot sign any epoch=0 or epoch=1 object (see R2, R3).
```

The trace has a single epoch-change block candidate. Byzantine epoch-change
proposals are covered by R1-b below.

---

## R1 — Handoff proof: two-chain finality over the epoch-change block

**What must be proven before the incoming set signs:**

a. A valid `CommitCertificate` for `B_ec` exists in durable block storage.
   The certificate contains:
   - `B_ec`'s block hash and height.
   - `QC_ec`: a quorum (≥ 2f+1) of precommit signatures from V_old over
     `B_ec` at round `z`.
   - `QC_child`: a quorum (≥ 2f+1) of precommit signatures from V_old over
     `B_child` at round `z+1`, where `B_child.parent_hash == B_ec.block_hash`.
   - The consecutive-round check: `QC_child.round == QC_ec.round + 1`.

   This establishes two-chain finality, not merely a quorum over `B_ec` alone.

b. The incoming validator set `V_new` is extracted from the committed `B_ec`
   body, not from a proposal or pending QC. If `B_ec`'s encoded validator set
   does not parse or is empty, the handoff fails closed.

c. Byzantine epoch-change proposals: a validator at round `z` refuses any
   epoch-change proposal whose `V_new` encoding does not match the one
   committed in the two-chain certificate it has seen. Once `B_ec` is
   committed, the safety store's epoch floor prevents the outgoing set from
   signing an alternative epoch-change block at or below `z+1` in epoch 0.

d. The certificate must be verifiable by any party holding V_old's public
   keys. It is an independent deliverable: a node that was offline during
   the handoff can verify it without replaying all earlier rounds.

**PO-4 basis:** `Inv_NoConflictingCommit` (S1). The two-chain commit rule
(`locked_qc.round + 1 == high_qc.round`) is verified exhaustively in
`safety_t3_overlap_tight` (15,165 states, no violation) and
`safety_t3_disjoint_snap` (65 states, no violation). The parent-link and
consecutive-round check on `QC_child` are the structural conditions that
make two independent QCs unforgeable under BFT assumptions (f < n/3).

---

## R2 — Outgoing-set signing cutoff: `B_child` at round `z+1`

**Permitted boundary:** The outgoing set (V_old) may sign epoch-0 objects up
to and including `B_child` at round `z+1`. This is the last epoch-0 action
in the trace. After the seal becomes durable (see below), V_old must not sign
any epoch-0 or epoch-1 object.

**Seal durability:** The seal becomes durable when the `CommitCertificate`
(containing `QC_child`) is written and synced to the block store. The signing
context persists the seal separately from `hvr`:

- A new field `seal_epoch_round: Option<(epoch, round)>` is written to the
  safety record at the same time the certificate is written to block store,
  before `advance_epoch` fires.
- On subsequent sign attempts, the store checks: if `seal_epoch_round` is
  `Some((0, z+1))` and the requested message is `epoch=0, round > z+1`,
  return `Err(SealViolation)` before calling the signer.
- `hvr` (the lower signing floor) is not sufficient for this upper cutoff.
  `hvr` prevents signing *below* a known round; it does not cap signing
  *above* a committed boundary. The seal field is the enforcement mechanism.
- The epoch-regression check (`epoch < rec.epoch → EpochRegression`) protects
  a signer that has already advanced to epoch 1. It does not protect V_old
  members that have not yet advanced — they need the seal field.

**Write order (crash-safe):**
1. Write `CommitCertificate` to block store. Sync.
2. Write `seal_epoch_round = Some((0, z+1))` to safety record. Sync.
3. Advance epoch counter.
4. Call `signing_ctx.advance_epoch(1)`.

A crash between steps 1 and 2 leaves no seal; on restart the node re-derives
the seal from the certificate (see R3-a). A crash between steps 2 and 3
leaves a durable seal; on restart the node resumes from step 3.

**PO-4 basis:** `Inv_NoOldEpochBeyondBoundary` (S4). Mutation M1
(`SealOn=FALSE`) violated S4 in both overlap (depth 11, 7,032 states, 29 s)
and disjoint (depth 19, 128,084 states, 11 m 36 s). The seal rule is
confirmed load-bearing. The model's `SealOn` predicate maps to the
`seal_epoch_round` field: a validator with `seal_epoch_round = Some((e, z))`
cannot vote for epoch-`e` objects beyond round `z`.

---

## R3 — Restart: two crash scenarios

### R3-a: Node restarts with safety record in epoch 0 (pre-handoff crash)

The node's safety record shows `epoch = 0`. The block store may be ahead.

1. Load the block store's committed tip. If it is epoch 1 or later:
   a. Load the `CommitCertificate` for `B_ec` from durable block store.
   b. Verify it: 2f+1 precommits from V_old, consecutive rounds, parent
      link `B_child.parent == B_ec`. Fail closed if any check fails.
   c. Extract `V_new` from committed `B_ec`. Fail closed if parsing fails.
   d. Set `seal_epoch_round = Some((0, QC_child.round))` in the safety record.
      Sync before proceeding.
   e. Advance epoch counter. Call `signing_ctx.advance_epoch(1)`.
   f. Call `restore_floors()` for epoch 1 (floors are `hvr=None, hqr=None`
      since no epoch-1 messages have been signed yet).
2. Only then allow signing in epoch 1.

If the certificate cannot be loaded or verified, the node must not sign and
must halt with a recoverable error. The signing context must not be attached
until step f completes.

### R3-b: Node restarts with safety record in epoch 1 (post-handoff crash)

The node's safety record shows `epoch = 1`.

1. The handoff has already been recorded. No re-verification of the
   certificate is required (the epoch advance is itself the attestation that
   verification passed at the time it was persisted).
2. Call `restore_floors()` for epoch 1: load `hvr` and `hqr` from the epoch-1
   safety record and raise `locked_qc.round` and `high_qc.round` accordingly.
3. Floors are restored within epoch 1; epoch-0 floors are not carried forward.

### R3-c: Minimum round for the incoming set

After advancing to epoch 1, the safety store must refuse signing at
`epoch=1, round < 1`. This is enforced by an explicit check in `sign_core`:

```
if epoch == rec.epoch && round < 1 {
    return Err(SignError::RoundBelowEpochMinimum { epoch, round });
}
```

`EpochRegression` (`epoch < rec.epoch`) covers old-epoch messages after the
advance. It does not cover `epoch=1, round=0`: that check is new.

**PO-4 basis:** `crash_t3_disjoint` — `CrashOn=TRUE`, `SnapSync=TRUE`,
disjoint validator sets, `MaxProps=6, MaxTos=3, R=4`. 65 distinct states,
depth 13, 2 s, exhausted, no violation. The crash action in this configuration
models a validator halting and restarting within the two-chain commit window.
The `Crashed` and `Restart` actions were reachable: the depth-13 exhaustion
includes paths that enter and exit the crashed state. See REPORT.md §Results
table row `crash_t3_disjoint`.

---

## R4 — Single-candidate enforcement

The scope assumes at most one epoch-change block is finalized per epoch.

**Enforceable protocol rule:** A validator receiving a competing epoch-change
proposal for epoch 0 at the same height as a `B_ec` it has already voted for
at round `z` will not vote for the competing proposal: the safety store's
`RoundBelowSigned` check prevents it from voting for the same round twice
with a different message, and the voting rule (`round >= locked_qc.round`)
prevents it from voting for a lower round. Under BFT assumptions (f < n/3),
no competing epoch-change block can gather 2f+1 precommits from honest V_old
validators simultaneously with `B_ec`.

**Open obligation:** The PO-4 compete scenario (SetB non-empty) was not
exhaustively checked (406K+ states, stopped before completion). The
single-candidate assumption is sound under the standard BFT safety argument
but is not exhaustively model-checked. Any protocol change that allows
multiple valid epoch-change proposals per epoch must trigger a new model run
before this scope can be re-approved.

---

## R5 — Activation gates (two separate approvals)

**Gate A — Implement behind disabled flag (requires owner approval of this
document):**
- `on_commit(cert, Some(new_vs))` verifies the certificate against `V_old`
  per R1 before advancing the epoch.
- The write order in R2 is implemented and crash-tested.
- R3-a and R3-b recovery paths are implemented.
- `RoundBelowEpochMinimum` check added to `sign_core`.
- An in-process epoch-boundary test passes on Windows: 4 validators, real
  ML-DSA-65 keys (not doubles), one epoch-change block, outgoing set cannot
  sign epoch-0 or epoch-1 objects after seal, incoming set cannot sign
  epoch-0 objects, no conflicting commits. Per CLAUDE.md: developer-run,
  MINGW64, result pasted.

**Gate B — Enable the flag (requires separate owner approval after Gate A):**
- TCP variant of the Gate A test passes on Windows: same scenario over OS
  processes with real ML-DSA-65 keys and a real `MonotonicCounter`. Per
  CLAUDE.md: developer-run, MINGW64, result pasted.
- The `seal_epoch_round` persistence and recovery paths are covered by
  crash-injection tests (kill between each of the four write-order steps in
  R2; verify no epoch-0 message beyond `z+1` can be signed on restart).

The word "doubles" in any acceptance test for this scope means the test
does not qualify as evidence for Gate A or Gate B.

---

## Model citations

| Configuration | Config file | States | Depth | Time | Result |
|---|---|---|---|---|---|
| `safety_t3_overlap_tight` | tight bounds, overlap, R=4 | 15,165 | 21 | 1m 05s | No violation (exhausted) |
| `safety_t3_disjoint_snap` | SnapSync=TRUE, disjoint, R=4, tight | 65 | 13 | 1s | No violation (exhausted) |
| `crash_t3_disjoint` | CrashOn=TRUE, SnapSync=TRUE, disjoint, tight | 65 | 13 | 2s | No violation (exhausted); crash+restart reachable |
| `mut_M1_no_seal__t3_overlap` | SealOn=FALSE, overlap | 7,032 | 11 | 29s | S4 **violated** — seal load-bearing |
| `mut_M1_no_seal__t3_disjoint` | SealOn=FALSE, disjoint | 128,084 | 19 | 11m 36s | S4 **violated** — seal load-bearing |

SnapSync is sound for safety checks with `SealOn=TRUE`. It is not sound for
mutation testing (M1, M3). The non-SnapSync M1 results serve as M1 evidence.
The compete scenario (SetB non-empty) is not exhaustively checked and is out
of scope for this phase.

`safety_t3_disjoint_snap` and `crash_t3_disjoint` both ran with `SnapSync=TRUE`,
disjoint validator sets, tight bounds (`MaxProps=6, MaxTos=3, R=4`), and
exhausted at 65 states / depth 13. They use different `.cfg` files:
`safety_t3_disjoint_snap.cfg` has `CrashOn=FALSE`; `crash_t3_disjoint.cfg`
has `CrashOn=TRUE`. Both are in
`research/pq-hotstuff-2/epoch-transition/cfg/`. The 65-state count is
identical because the SnapSync abstraction collapses delivery-order
interleavings; the crash configuration adds crash/restart actions that are
reachable but do not expand the state space under tight bounds.
