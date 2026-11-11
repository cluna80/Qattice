# Decision Request: Epoch Transitions (G8-E, G8-R, G8-K)

**Date:** 2026-11-11  
**Gate:** QAT-07 / PQHS-P1  
**Status:** Pending owner decision — no implementation authorized.  
**Tracks:** Track B (§8 reconfiguration)  
**Spec refs:** §8, R8-2 through R8-5  

---

## Current state

Dynamic membership is disabled. `EpochSet::new()` refuses any epoch other than 0 with
`SetError::EpochChangeDisabled` (`types.rs:53-54`). PO-4 (the safety proof for epoch
transitions under the two-chain lock rule) is listed as an open obligation in the spec.

The engine holds one `EpochSet` for the lifetime of a session. `QC` and `TC` verification
always uses that single set. No epoch-change block type exists. No revocation or key-rotation
path is implemented.

---

## Proposed rules

### R8-2 — Epoch-change committed block

An epoch change is triggered only by a **committed** epoch-change block: a block whose
payload carries a valid, signed next-epoch validator set. The new set takes effect from
**round 1 of epoch `e+1`**, not from the round the block was proposed. Uncommitted
epoch-change proposals are ignored.

**When it takes effect:** at the round of execution following the commit of the epoch-change
block. The engine must hold both the outgoing set (epoch `e`) and the incoming set (epoch
`e+1`) simultaneously until all messages from epoch `e` have been processed.

**Implementation gate:** PO-4 must be accepted (or scoped out for this phase) before
implementation begins.

---

### R8-3 — Historical set verification

Every `QC` and `TC` is verified against the validator set of its own epoch, not the current
epoch. A certificate from epoch `e` verified against the epoch-`e` set is still valid after
an epoch transition.

**When it takes effect:** alongside R8-2; the engine needs epoch-indexed set storage.

---

### R8-4 — Revocation (mini-epoch rule)

A revocation committed in block `B` takes effect in the **first block after `B`** (the
block at height `B.height + 1`). Power drops to 0; it never takes effect mid-round (a
validator whose revocation is committed retains its signing weight for the current round).

**When it takes effect:** whenever the block at `B.height + 1` becomes the current leader
block. The engine must remove the entry — or set `power = 0` — before computing the quorum
threshold for the new round.

---

### R8-5 — Key rotation (one-block power gap)

A key rotation committed in block `B` takes effect in the **block at `B.height + 1`**. The
validator is absent (power = 0) for exactly that one block; the new key is active from
`B.height + 2`.

**When it takes effect:** same as R8-4. The gap prevents double-signing by ensuring no
valid certificate can span the old and new key within the same validator-set window.

---

## Tests that would demonstrate each rule

All tests are integration tests in `chain-forge-consensus/tests/`.

### R8-2 epoch transitions

| Test name (proposed) | What it asserts |
|----------------------|-----------------|
| `epoch_change_block_committed_activates_new_set_at_round_one_of_next_epoch` | After a valid epoch-change block is committed, messages in epoch `e+1` are verified against the new set; the engine round resets to 1. |
| `epoch_change_block_uncommitted_does_not_activate_new_set` | An epoch-change proposal that does not reach commit is ignored; the engine continues on the old set. |
| `qc_from_previous_epoch_is_verified_against_its_own_set` | A `QC` from epoch `e` remains valid after the transition to epoch `e+1`; it is not re-verified against the new set. |

### R8-4 revocation

| Test name (proposed) | What it asserts |
|----------------------|-----------------|
| `revocation_removes_power_from_the_next_block` | A revoked validator's weight is 0 from the first block after the commit; the validator's vote in that round is rejected as zero-power. |
| `revocation_does_not_remove_power_mid_round` | A revocation committed in round `r` does not affect the quorum count for round `r`; the validator's vote in round `r` is still counted. |

### R8-5 key rotation

| Test name (proposed) | What it asserts |
|----------------------|-----------------|
| `mid_epoch_key_rotation_has_a_one_block_power_gap` | Between the commit block and the block two positions later, the validator's power is 0; it cannot sign a vote that counts toward quorum. |
| `key_rotation_new_key_is_active_from_the_second_block_after_commit` | A vote signed with the new key in the block after the gap is accepted; the same vote with the old key is rejected. |

---

## Decision needed

1. **Accept PO-4 for Phase 1** (proceed with implementation under the existing two-chain
   lock rule, deferring a formal proof) or **defer R8-2/R8-3 to Phase 2**.
2. **Approve R8-4 and R8-5** as Phase 1 requirements, or designate them as Phase 2.
3. If approved: authorize removal of the `EpochChangeDisabled` guard and the implementation
   of epoch-indexed set storage, epoch-change block parsing, and the revocation/rotation
   paths in `engine.rs`.

No implementation begins until this decision is recorded here.
