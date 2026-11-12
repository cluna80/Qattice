# Epoch switch-over scope — QAT-07 phase 2

**Status:** specification only. Dynamic membership remains disabled in code
(`update_validator_set` accepts the new set but no SSI switch-over fires).
No implementation is authorized until this document is reviewed and approved.

**Tied to:** PO-4 model `EpochTransition.tla` at commit `e818fda` (SnapSync
abstraction). Exhaustive results:

| Run | States | Result |
|---|---|---|
| `safety_t3_overlap_tight` | 15,165 | No violation (exhausted, 1m 05s) |
| `safety_t3_disjoint_snap` (SnapSync) | 65 | No violation (exhausted, 1s) |
| `mut_M1_no_seal__t3_overlap` | 7,032 | `Inv_NoOldEpochBeyondBoundary` **violated** — seal is load-bearing |
| `mut_M1_no_seal__t3_disjoint` | 128,084 | `Inv_NoOldEpochBeyondBoundary` **violated** — seal is load-bearing |

The SnapSync exhaustive result is sound for safety with `SealOn=TRUE` (see
`docs/pq-hotstuff-2/decision-epoch-transitions.md §SnapSync`). It is not
sound for mutation testing; the non-SnapSync M1 results serve as M1 evidence.

---

## Rules

### R1 — Commit evidence required before switch

The incoming validator set does not begin signing until a valid
`CommitCertificate` for the epoch-change block is present in durable storage
and verifiable by the incoming set against the **outgoing** set's public keys.

Specifically, before `on_commit(cert, Some(new_vs))` advances the epoch:

1. `cert` must satisfy `verify_commit(&cert, &outgoing_vs)` — 2f+1 precommits
   from the outgoing set over the epoch-change block hash.
2. `cert` must be written to durable block store before the epoch counter
   advances. The write order is: block store sync → epoch counter advance →
   `signing_ctx.advance_epoch(new_epoch)`.
3. A restarting node must re-verify this certificate from durable storage
   before allowing the incoming set to sign at any round.

**PO-4 basis:** `Inv_NoConflictingCommit` (S1) requires that two honest
validators cannot commit conflicting blocks. The two-chain commit rule
(`locked_qc.round + 1 == high_qc.round`) is the primary mechanism; the
certificate is the witness that 2f+1 outgoing validators agreed.

### R2 — Outgoing set signing cutoff (EC-6, `seal_round`)

When an epoch-change block at round `z` is committed:

- `seal_round` is set to `z` on the engine.
- The signing context records `seal_round` as the per-epoch `hvr` floor in
  the safety store (`sign_vote` with `round > z` is refused for epoch 0
  messages after the epoch advances).
- Outgoing validators MUST NOT sign any epoch-0 object (vote, timeout,
  proposal) with `round > z`. The safety store enforces this automatically
  through the epoch floor: once `signing_ctx.advance_epoch(1)` fires, the
  store rejects `epoch=0` messages.

**PO-4 basis:** `Inv_NoOldEpochBeyondBoundary` (S4). M1 mutation (seal
removed) violated S4 in both overlap (depth 11, 7,032 states) and disjoint
(depth 19, 128,084 states). The seal rule is confirmed load-bearing.

### R3 — Restarting node verification before incoming set signs

A node that restarts across an epoch boundary (last safety record is epoch 0,
chain tip is epoch 1) must, before signing anything as an epoch-1 validator:

1. Load the epoch-change `CommitCertificate` from durable block store.
2. Verify it against the outgoing (epoch-0) validator set public keys.
3. Call `restore_floors()` to reload hvr/hqr from the durable safety record.
4. Only then call `attach_signing_context` and proceed.

If step 1 or 2 fails (certificate missing, insufficient signatures, wrong
block hash), the node MUST NOT sign and MUST halt with a recoverable error.

**PO-4 basis:** `CrashOn=TRUE` exhaustive check (`crash_t3_disjoint`,
SnapSync, 65 states, no violation). The SnapSync model verifies that crash
and restart within the two-chain commit window does not break safety when the
seal is active.

### R4 — Incoming set may not backdate rounds

The incoming validator set begins signing at `round = 1` of epoch 1. No
incoming validator may sign an epoch-1 message at a round below 1, nor may
it sign an epoch-0 message at any round (the safety store epoch field
enforces this: `epoch < rec.epoch` → `EpochRegression` error).

### R5 — Dynamic membership gate (unchanged)

Dynamic membership remains disabled. `update_validator_set` stores the new
set but no SSI switch-over fires until this document is approved and an
acceptance test passes on Windows per CLAUDE.md policy. The gate is:

- This document approved by owner.
- An in-process four-validator test with real ML-DSA-65 keys that spans one
  epoch boundary (epoch-change block committed, outgoing set stops signing,
  incoming set starts, no conflicting commits) passes on Windows.
- TCP variant of the same test passes on Windows (separate item).

---

## What is NOT specified here

- **Competing epoch-change candidates** (SetB non-empty in PO-4 model): the
  compete scenario was not exhaustively checked (406K+ states, stopped). This
  scope assumes at most one epoch-change block proposal per epoch. If
  competing proposals are added to the protocol, a new model run is required.
- **Key rotation within an epoch**: a validator replacing its ML-DSA key
  mid-epoch is out of scope. Key rotation is a separate QAT-08 item.
- **Next-block revocation**: a validator revoked at block `b` stops signing
  at `b+1`. This interacts with the validator set and is scoped separately.
- **ML-DSA-only admission**: incoming validators must hold a valid ML-DSA-65
  PoP. Enforcement is scoped to QAT-08.

---

## Implementation checklist (phase 2, not yet authorized)

- [ ] `on_commit(cert, Some(new_vs))`: verify `cert` against `outgoing_vs`
      before advancing epoch; fail closed if verification fails.
- [ ] Write epoch-change `CommitCertificate` to block store durably before
      calling `signing_ctx.advance_epoch(new_epoch)`.
- [ ] `restore_floors` extended: on epoch mismatch (stored epoch < chain epoch),
      require re-verification of the epoch-change certificate before allowing
      any signing.
- [ ] In-process epoch-boundary test: 4 validators, real ML-DSA-65 doubles,
      one epoch-change block, verify outgoing set cannot sign epoch-1 objects,
      incoming set cannot sign epoch-0 objects.
- [ ] Windows confirmation of the above test per CLAUDE.md.
- [ ] TCP variant: same test over OS processes (separate PR).

---

## PO-4 model revision and bounds reference

| Item | Value |
|---|---|
| Model file | `research/pq-hotstuff-2/epoch-transition/EpochTransition.tla` |
| Commit | `e818fda` (SnapSync abstraction added) |
| TLC version | 1.8.0, Java 21.0.12.1, 4 cores |
| Overlap bounds | MaxProps=6, MaxTos=3, R=4 |
| Disjoint bounds (SnapSync) | MaxProps=6, MaxTos=3, R=4 |
| M1 bounds (non-SnapSync) | MaxProps=8, MaxTos=4, R=4 |
| Compete scenario | Not exhausted — out of scope for this phase |
| SnapSync soundness | Sound for safety (`SealOn=TRUE`); not sound for M1/M3 mutation testing |
