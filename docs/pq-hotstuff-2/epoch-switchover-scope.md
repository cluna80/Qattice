# Epoch switch-over scope — QAT-07 phase 2

**Status:** specification only. Dynamic membership is disabled in code.
Gate A (implement behind a disabled flag) requires owner approval of this
document. Gate B (enable the flag) requires separate owner approval after
the acceptance tests in R5 pass on Windows.

**Tied to:** PO-4 model `EpochTransition.tla` commit `e818fda`.
See §Model citations for exact configurations and what each result does
and does not establish.

---

## Handoff trace

Every rule is a step in or a constraint on this exact trace.

```
Round z     B_ec proposed — carries the encoded incoming validator set V_new.
            V_old votes for B_ec.
            QC_ec forms: 2f+1 precommits from V_old over B_ec at round z.
            locked_qc := QC_ec (round z).

Round z+1   B_child proposed — parent = B_ec, pol_qc = QC_ec.
            V_old votes for B_child.
            QC_child forms: 2f+1 precommits from V_old over B_child at round z+1.
            high_qc := QC_child (round z+1).

Commit      locked_qc.round + 1 == high_qc.round → B_ec committed.
            CommitCertificate{B_ec, QC_ec, QC_child} written to durable block store.
            Signing eligibility rule evaluated for each validator (see R2 table).

Handoff     V_new extracted from committed B_ec body.
            Epoch counter advances: 0 → 1.
            signing_ctx.advance_epoch(1) fires.

Epoch 1     V_new begins signing at epoch=1, round=1.
            V_old signing eligibility: see R2 table.
```

---

## R1 — Handoff proof: two-chain finality

**What must exist in durable block store before the incoming set signs:**

A `CommitCertificate` containing:
- `B_ec`'s block hash and height.
- `QC_ec`: ≥ 2f+1 precommit signatures from V_old over `B_ec` at round `z`.
- `QC_child`: ≥ 2f+1 precommit signatures from V_old over `B_child` at
  round `z+1`, where:
  - `B_child.parent_hash == B_ec.block_hash`
  - `QC_child.round == QC_ec.round + 1`

This establishes two-chain finality. A quorum over `B_ec` alone is not
sufficient. The parent-link and consecutive-round check bind the incoming set
to the specific block that was finalized, not to a proposal or pending QC.

**Independent deliverability:** The certificate is verifiable by any party
holding V_old's public keys, without replaying earlier rounds. A node that
was offline during the handoff can receive the certificate, verify it, and
join the incoming set.

**Byzantine epoch-change proposals:** A validator at round `z` that has
already voted for `B_ec` cannot vote for a competing epoch-change proposal at
the same height in round `z` (the safety store's `RoundBelowSigned` check
prevents signing a different message in the same round). It may receive a
competing proposal at a later round `z'`. Whether it votes at round `z'`
depends on the cross-round locking rule — see R4.

**V_new binding:** `V_new` is extracted from the committed `B_ec` body after
the certificate is verified. If the encoded validator set does not parse or is
empty, the handoff fails closed. `V_new` is NOT taken from a proposal or QC.

---

## R2 — Signing eligibility rule

### Transition table

The table below is the normative definition of R2. All other text in this
section is derived from it. Each row applies when all conditions in that row
match; rows are evaluated top to bottom, first match wins.

| `req.epoch` vs `rec.epoch` | `req.round` | Proof durable | Seal set | Membership | Prior record for `(epoch, round)` | Decision |
|---|---|---|---|---|---|---|
| `req.epoch < rec.epoch` | any | any | any | any | any | **DENY** `EpochRegression` |
| `req.epoch == rec.epoch` | `< rec.hvr` | any | any | any | any | **DENY** `FloorViolation` |
| `req.epoch == rec.epoch` | `== rec.last_signed_round` | any | any | any | same message bytes | **RETRANSMIT** stored bytes |
| `req.epoch == rec.epoch` | `== rec.last_signed_round` | any | any | any | different message bytes | **DENY** `ConflictingMessage` |
| `req.epoch == rec.epoch` | `> rec.last_signed_round` | any | `(e_s, z_s)` with `req.epoch == e_s AND req.round > z_s` | any | — | **DENY** `SealViolation` |
| `req.epoch == rec.epoch` | `> rec.last_signed_round` | any | none or `e_s != req.epoch` | any | — | **CREATE** new signature |
| `req.epoch == rec.epoch + 1` | `< 1` | any | any | any | any | **DENY** `RoundBelowEpochMinimum` |
| `req.epoch == rec.epoch + 1` | `>= 1` | FALSE | any | any | any | **DENY** `ProofNotDurable` |
| `req.epoch == rec.epoch + 1` | `>= 1` | TRUE | any | not in V_new | any | **DENY** `NotMember` |
| `req.epoch == rec.epoch + 1` | `>= 1` | TRUE | any | in V_new | any | **CREATE** new signature; advance `rec.epoch` |
| `req.epoch > rec.epoch + 1` | any | any | any | any | any | **DENY** `EpochSkip` |

**Column definitions:**

- `rec.epoch`: the epoch stored in the validator's durable safety record.
- `rec.hvr`: highest vote round stored; `None` treated as 0.
- `rec.last_signed_round`: the round of the last committed signing record for
  `req.epoch`. `None` treated as 0 for comparison; retransmit path applies
  only when a record exists.
- `Proof durable`: `CommitCertificate{B_ec, QC_ec, QC_child}` has been
  written and fsynced to block store before this signing call.
- `Seal set`: the safety record's `seal` field contains a tuple `(e_s, z_s)`.
- Membership: whether the signer's public key appears in the V_new encoded in
  the committed `B_ec`.

### Seal timing: voting vs. proof delivery

**Voting for `B_child` and learning `QC_child` are separate events.**

A validator `v` can vote for `B_child` at round `z+1` (contributing its share
of `QC_child`) but not yet have received the full `QC_child` back. Until `v`
learns that `QC_child` has formed and the `CommitCertificate` is durably
written, the proof-durable condition is false. During this window `v` remains
eligible to sign epoch-0 objects at rounds `> z+1` (the `SealViolation` row
does not trigger while `seal` is unset).

**What prevents prohibited epoch-0 certificates in this window:**

The safety argument is that under BFT assumptions (at most `f` Byzantine
validators, `f < n/3`), no quorum of `2f+1` outgoing validators can form a
certificate for a conflicting object. At the moment `QC_child` forms, `2f+1`
honest validators have precommitted for `B_child`. Those validators have their
`locked_qc` set to `QC_ec` (round `z`). By the cross-round locking rule (R4),
they will not vote for any object whose `pol_qc.round < z`. A competing
certificate at any conflicting chain tip would require `2f+1` precommits that
include at least `f+1` honest validators, each of which is locked and will not
grant them.

**This is a BFT-assumption argument, not a model-verified result.** The
crash+SnapSync TLC run with a saved output log and a witness trace is required
to verify that the delayed-proof window does not create a reachable path to a
boundary violation. See §Open model obligations.

### Durable write order

1. Write `CommitCertificate` to block store. fsync.
2. Write `seal = (0, z+1)` to safety record. fsync.
3. Advance epoch counter.
4. Call `signing_ctx.advance_epoch(1)`.

A crash between steps 1 and 2 leaves no seal. Recovery: re-derive from the
certificate (R3-a). A crash between steps 2 and 3: seal is durable; resume
from step 3. A crash between steps 3 and 4: epoch counter is ahead of the
signing context; resume from step 4. Steps 1–4 are idempotent individually;
the safety record's compare-and-advance counter ensures step 2 is not applied
twice.

**Retransmission:** A validator may retransmit a message it signed before the
seal was written (the safety store returns the stored signature byte-for-byte
on a re-request for the same round). It may not produce a new signature for
epoch 0 at any round above `z+1` after the seal is durable.

**PO-4 basis:** `Inv_NoOldEpochBeyondBoundary` (S4). M1 mutation (`SealOn=FALSE`)
violated S4 in both overlap and disjoint. The model's `SealOn` predicate maps
to the seal field: a validator with `seal = (e_s, z_s)` refuses new signatures
for epoch `e_s` at round `> z_s`. The delayed-proof window is modelled by the
non-SnapSync delivery-lag paths; no S4 violation was observed in those runs.

---

## R3 — Restart authentication

**The durable signer record must bind to the handoff**, not just to an epoch
number. Each validator's safety record stores:
- `epoch`: the current epoch.
- `set_hash`: SHA3-256 of the canonical encoding of the accepted validator
  set for `epoch`. Written at the same time as the epoch counter advance.
- `handoff_cert_hash`: SHA3-256 of the `CommitCertificate` that authorized
  the transition. Written at the same time as `set_hash`.

On open, the safety store verifies:
- `set_hash` matches the validator set loaded from the block store for
  `epoch`. Fail closed if not.
- `handoff_cert_hash` matches the certificate in the block store. Fail
  closed if not.

### R3-a: Safety record in epoch 0, block store committed epoch is 1

**Trigger condition:** `safety_record.epoch < block_store.committed_epoch`.

The handoff happened — the block store has an epoch-1 committed tip — but
the signer did not fully advance. The handoff proof may already be durable in
the block store while the tip still identifies epoch 0; R3-a applies as soon
as the committed epoch in the block store is ahead of the safety record,
regardless of which block is at the tip.

Recovery:

1. Load `CommitCertificate` for `B_ec` from block store. Fail closed if
   missing or unverifiable against V_old public keys.
2. Extract `V_new` from committed `B_ec`. Fail closed if parsing fails.
3. Write `seal = (0, QC_child.round)` to safety record if not already set.
   fsync.
4. Advance epoch counter.
5. Write `set_hash` and `handoff_cert_hash` to safety record. fsync.
6. Call `signing_ctx.advance_epoch(1)`.
7. Call `restore_floors()` for epoch 1 (hvr=None, hqr=None — no epoch-1
   messages have been signed yet).

The signing context is not attached until step 7 completes.

### R3-b: Safety record in epoch 1

1. Verify `handoff_cert_hash` against the certificate in the block store.
   Fail closed if mismatch.
2. Verify `set_hash` against the validator set for epoch 1 in the block store.
   Fail closed if mismatch.
3. Call `restore_floors()` for epoch 1: load `hvr` and `hqr` from the
   epoch-1 safety record. Raise `locked_qc.round` and `high_qc.round`
   to at least these values. Floors are epoch-scoped; epoch-0 floors are
   not carried into epoch 1.
4. Only then attach the signing context.

### R3-c: Round-1 minimum for the incoming set

The first signature in epoch 1 must have `round >= 1`. This is enforced by
an explicit check in `sign_core`, applied when `req.epoch > rec.epoch` (the
incoming-epoch row in the R2 table):

```
if requested_epoch > rec.epoch && requested_round < 1 {
    return Err(SignError::RoundBelowEpochMinimum {
        epoch: requested_epoch,
        round: requested_round,
    });
}
```

The guard fires when the safety record is still at epoch 0 and the first
incoming request names epoch 1. Using `epoch == rec.epoch` in this check is
wrong: when the record has not yet advanced (`rec.epoch == 0`) and the
request is for epoch 1, `epoch == rec.epoch` is false and the check would be
skipped entirely for the first incoming request. The condition must be
`requested_epoch > rec.epoch`.

`EpochRegression` (`req.epoch < rec.epoch`) covers old-epoch messages after
the advance and does not overlap with this check.

---

## R4 — Competing candidates: cross-round locking rule

**Open obligation.**

A validator that voted for `B_ec` at round `z` will not vote for a competing
epoch-change block `B_ec'` at the same round (the safety store's
`RoundBelowSigned` check prevents it). It may receive a competing proposal at
a later round `z'`.

The cross-round locking rule (spec §3.4) constrains this: a validator votes
for a proposal at round `z'` only if the proposal's `pol_qc.round >= locked_qc.round`.
If the validator's `locked_qc` certifies `B_ec` at round `z`, it will not vote
for `B_ec'` at `z'` unless `B_ec'`'s `pol_qc.round >= z`. Producing such a
`pol_qc` would require `2f+1` outgoing validators to have precommitted for a
competing block at some round `>= z`, which under BFT assumptions is
impossible once `2f+1` honest validators have locked on `B_ec`.

**This argument has not been exhaustively model-checked in the compete
scenario.** The PO-4 compete run (`witness_t3_compete`, SetB non-empty) was
stopped before exhaustion (406K+ states). The cross-round locking rule is a
BFT-assumption-dependent claim that holds in the same-round case but has not
been verified for all reachable later-round configurations. This scope document
cannot close the competing-candidates obligation. Any protocol change that
introduces multiple valid epoch-change candidates per epoch, or that relaxes
the BFT assumption, requires an exhaustive compete-scenario model run before
Gate A can be re-approved.

---

## R5 — Activation gates

**Gate A — Implement behind disabled flag:**
Requires owner approval of this document (R1–R4 above).

Acceptance:
- `on_commit(cert, Some(new_vs))` verifies the certificate per R1 before
  advancing the epoch. Fails closed if verification fails.
- Durable write order in R2 implemented and tested with crash injection at
  each of the four steps. Each crash scenario re-opens correctly.
- `set_hash` and `handoff_cert_hash` written to safety record on advance.
  Mismatch on restart fails closed.
- R3-a and R3-b recovery paths implemented and tested. R3-a trigger is
  `safety_record.epoch < block_store.committed_epoch`, not tip identity.
- `RoundBelowEpochMinimum` check implemented in `sign_core` using
  `requested_epoch > rec.epoch && requested_round < 1`.
- An in-process epoch-boundary test passes on Windows (BossKing MINGW64,
  developer-run, result pasted): 4 validators, real ML-DSA-65 keys, one
  epoch-change block. Test must demonstrate:
  - Outgoing set cannot produce a new epoch-0 signature at round > `z+1`
    after the seal is durable.
  - Incoming set cannot produce an epoch-0 signature.
  - No conflicting commits across the boundary.
  - A node restarting at R3-a and R3-b recovers correctly and resumes signing.

The word "doubles" means the test does not qualify as evidence for Gate A.

**Gate B — Enable the flag:**
Requires separate owner approval after Gate A passes.

Acceptance (additional, beyond Gate A):
- TCP variant of the Gate A test: same scenario over OS processes with real
  ML-DSA-65 keys and a real `MonotonicCounter`. Developer-run, MINGW64,
  result pasted.
- Crash injection between each of the four write-order steps in R2, over
  OS processes with real keys, verifying that no epoch-0 message beyond
  round `z+1` can be signed on restart.

---

## Model citations

### What is confirmed by exhaustive runs

| Config | CrashOn | SnapSync | MaxProps | MaxTos | States | Depth | Result |
|---|---|---|---|---|---|---|---|
| `safety_t3_overlap_tight` | FALSE | FALSE | 6 | 3 | 15,165 | 21 | No violation (exhausted) |
| `safety_t3_disjoint_snap` | FALSE | TRUE | 6 | 3 | 65 | 13 | No violation (exhausted) |

### What the crash run does and does not establish

`crash_t3_disjoint.cfg` at commit `e818fda` (the revision this document is
tied to):
- `CrashOn=TRUE`, `StageVotes=TRUE`, `MaxProps=8`, `MaxTos=4`, `LagSet={0,1}`
- **No `SnapSync` assignment** — the SnapSync abstraction was not enabled at
  this revision.

The file was subsequently modified in commit `dc3f273` to add `SnapSync=TRUE`,
set `StageVotes=FALSE`, and reduce `MaxProps` to 6 and `MaxTos` to 3. That
modified configuration produced a 65-state exhaustive run recorded in
REPORT.md, but **no output log was saved** to `out/`. The run cannot be
independently verified from saved artifacts.

**What this means for R3:** The crash recovery rules in R3 are derived from
the protocol structure and the safety store's existing crash tests (76 tests
in `pq_hotstuff_safety.rs`, Windows-confirmed at `c77c567`). They are not
supported by a verified TLC crash-restart witness for the epoch-transition
model. A re-run of `crash_t3_disjoint.cfg` with a saved log and a witness
trace is required before R3 can cite PO-4 as evidence.

### Mutation evidence (non-SnapSync, output logs saved)

| Config | States | Depth | Time | Result |
|---|---|---|---|---|
| `mut_M1_no_seal__t3_overlap` | 7,032 | 11 | 29 s | S4 violated — seal load-bearing |
| `mut_M1_no_seal__t3_disjoint` | 128,084 | 19 | 11 m 36 s | S4 violated — seal load-bearing |

Output logs: `out/mut_M1_no_seal__t3_disjoint.log`, `.json`. The overlap
run log was not saved but the REPORT.md records the result.

### Open model obligations

| Obligation | Status |
|---|---|
| `crash_t3_disjoint` with saved log and restart witness | **Not yet run with saved output** |
| Compete scenario (SetB non-empty) exhaustive safety | **Not exhausted** (406K+ states stopped) |
| Cross-round locking rule under competing candidates | **BFT-assumption argument only; not model-checked** |
| Delayed-proof window safety (SnapSync crash witness) | **BFT-assumption argument only; not model-checked** |
