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
            Signing eligibility rule evaluated for each validator (see R2).

Handoff     V_new extracted from committed B_ec body.
            Epoch counter advances: 0 → 1.
            signing_ctx.advance_epoch(1) fires.

Epoch 1     V_new begins signing at epoch=1, round=1.
            V_old signing eligibility: see R2.
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

This single rule covers the boundary child, delayed proof delivery,
overlapping membership, and the moment the cutoff becomes binding.

**Definition:** A validator `v` is *eligible* to sign an object `m` if and
only if all of the following hold:

1. `m.epoch == v.safety_record.epoch` (no cross-epoch signing).
2. `m.round >= v.safety_record.hvr` (no signing below the voting floor).
3. If `v.seal` is set to `(e_s, z_s)`:
   - `m.epoch != e_s` OR `m.round <= z_s`.
   That is: once sealed, `v` may only retransmit messages it already signed
   in epoch `e_s` at round `<= z_s`. It may not produce new signatures for
   epoch `e_s` at any round above `z_s`.
4. `v` holds a valid authenticated membership credential for `m.epoch`.
   An overlap validator (member of both V_old and V_new) must present its
   epoch-1 credential to sign epoch-1 objects; it cannot reuse its epoch-0
   credential. The two epochs are authenticated separately.

**When the seal becomes binding:**

The seal `(0, z+1)` is set on `v` when ALL of the following are true:
- `v` has signed `QC_child` (i.e., `v` voted for `B_child` at round `z+1`).
- The `CommitCertificate` for `B_ec` has been written and synced to durable
  block store.
- The seal field `(0, z+1)` has been written and synced to `v`'s safety
  record, in that order.

A validator that has not yet learned `QC_child` has not signed it and is not
yet sealed. It remains eligible to sign epoch-0 objects at rounds `> z+1`
until it learns the certificate and the seal is durably written. This is the
delayed-proof window. It is not a safety gap: `Inv_NoOldEpochBeyondBoundary`
(S4) is an upper-bound invariant on committed certificates, not on individual
validator actions. A late-learning validator may sign objects beyond `z+1`,
but those objects cannot form a quorum that conflicts with a committed
certificate, because the outgoing set has already committed `B_ec` with a
2f+1 majority.

**Durable write order:**
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

### R3-a: Safety record in epoch 0, block store tip in epoch 1

The handoff happened but the signer did not advance. Recovery:

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
an explicit check in `sign_core`, applied when `epoch > rec.epoch` at the
moment of the first sign (i.e., the advance just happened) or when
`epoch == rec.epoch == 1` and `rec.hvr` is `None`:

```
if epoch == rec.epoch && round < 1 {
    return Err(SignError::RoundBelowEpochMinimum { epoch, round });
}
```

`EpochRegression` (`epoch < rec.epoch`) covers old-epoch messages after the
advance. It does not cover `epoch=1, round=0`: the above check fills that gap.
The check applies on the first incoming signature even when the safety record
still names the outgoing epoch at the moment of evaluation (R3-a step 6).

---

## R4 — Competing candidates: cross-round locking rule

Same-round vote restriction (R1 / `RoundBelowSigned`) prevents two different
messages at the same round. It does not prevent a competing epoch-change
proposal at a later round `z'`.

**Cross-round locking rule (derived from spec §3.4):** A validator votes for
a proposal at round `z'` only if the proposal's `pol_qc.round >= locked_qc.round`.
If the validator's `locked_qc` certifies `B_ec` at round `z`, it will not
vote for a competing epoch-change block `B_ec'` at round `z'` unless
`B_ec'`'s `pol_qc.round >= z`. Producing such a `pol_qc` requires 2f+1
outgoing validators to have precommitted for `B_ec'` at some round `>= z`.
Under BFT assumptions (f < n/3), this is impossible if 2f+1 validators have
already precommitted for `B_ec` at round `z`, because honest validators lock
on `B_ec` and will not vote for a conflicting block at the same or lower
round.

**Open obligation:** This argument holds under BFT assumptions but has not
been exhaustively model-checked in the compete scenario. The PO-4 compete
run (`witness_t3_compete`, SetB non-empty) was stopped before exhaustion
(406K+ states). Until the compete scenario is exhaustively checked, the
single-candidate assumption is a BFT-assumption-dependent claim, not a
model-verified result. Any protocol change that relaxes the BFT assumption or
introduces multiple valid epoch-change candidates per epoch requires a new
model run before this scope can be re-approved.

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
- R3-a and R3-b recovery paths implemented and tested.
- `RoundBelowEpochMinimum` check implemented in `sign_core`.
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

`crash_t3_disjoint.cfg` exists at commit `e818fda`:
- `CrashOn=TRUE`, `SnapSync=TRUE`, `MaxProps=6`, `MaxTos=3`, `LagSet={0,1}`

The TLC result (65 states, exhausted, no violation) was recorded in the
session context during PO-4 work on 2026-11-11 but **no output log was
saved** to `out/`. The run cannot be independently verified from saved
artifacts. No witness trace establishes that crash and restart actions were
reachable in the explored states; exhaustion depth alone does not.

**What this means for R3:** The crash recovery rules in R3 are derived from
the protocol structure and the safety store's existing crash tests (76 tests
in `pq_hotstuff_safety.rs`, Windows-confirmed). They are not supported by a
verified TLC crash-restart witness for the epoch-transition model. A re-run
of `crash_t3_disjoint.cfg` with a saved log and a witness trace is required
before R3 can cite PO-4 as evidence.

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
