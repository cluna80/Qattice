# Decision Request: Epoch Transitions (G8-E, G8-R, G8-K)

**Date:** 2026-11-11 (revised 2026-11-11 — owner review round 2)  
**Gate:** QAT-07 / PQHS-P1  
**Status:** Pending owner decision — no implementation authorized.  
**Tracks:** Track B (§8 reconfiguration)  
**Spec refs:** §8, R8-2 through R8-5  

---

## Current state

Dynamic membership is disabled. `EpochSet::new()` refuses any epoch other than 0 with
`SetError::EpochChangeDisabled` (`types.rs:53-54`). PO-4 is an open proof obligation.

Every `Qc` and `Tc` already carries `valset_hash: [u8; 32]` (`certs.rs:110,121,133`).
`verify_qc`/`verify_tc` reject any certificate whose `valset_hash` does not match the
engine's current commitment (`certs.rs:308`). This is the existing hook.

---

## Exact acceptance condition: epoch-change commit

The engine commits `B_ec` when `observe_cert` processes a QC `Q` satisfying all of:

1. `Q.block_id` is in `engine.blocks` as block `B_child` with
   `B_child.parent_id == B_ec.block_id`
2. `engine.round_of(B_child.block_id) == B_ec.round + 1`  
   (the **stored** round is consecutive — the QC's `round` field alone is not used for
   the commit check; `engine.rs:391,397` derives `cr` from `self.round_of(&q.block_id)`)
3. `engine.round_of(B_ec.block_id) == B_ec.round` and `B_ec.block_id != genesis_id`
4. `Q.valset_hash == S_e.validator_set_hash()` and signatures form a supermajority of `S_e`

When all four hold, `commit_through(B_ec.block_id)` fires (`engine.rs:397`), committing
`B_ec` and all its uncommitted ancestors.

**What is not the commit evidence:** the QC field `Q.round` is used only for `high_qc`
tracking, not for the consecutive-round check. The commit cannot be triggered by crafting a
QC with a fake `round` field; it depends on the stored block rounds.

---

## Exact acceptance condition: epoch-change handoff

After `B_ec` is committed:

1. The engine holds `S_{e+1}` bytes, recovered from `B_ec.payload` and verified:
   `sha3(S_{e+1}_bytes) == expected_set_hash` where `expected_set_hash` is in the
   epoch-change block's payload header or derived from the checkpoint.
2. The first block of epoch `e+1` satisfies:
   - `B1.parent_id == B_ec.block_id`
   - `B1.epoch == e + 1`
   - `B1.round == 1`
   - `B1.height == B_ec.height + 1`
   - `B1.qc` certifies `B_ec` and carries `valset_hash == S_e.validator_set_hash()`
     (the commit QC `Q` from the condition above, or a QC with the same content)
3. All QCs and TCs in epoch `e+1` carry `valset_hash == S_{e+1}.validator_set_hash()` and
   are verified against `S_{e+1}`.

**Open sub-question (Q1):** Specifying the payload header format for `expected_set_hash`
and the exact checkpoint record extension (adding `valset_hash` to the existing
`Checkpoint` type) are design tasks, not decisions. This document treats them as
implementation details once R8-2 is approved.

**On restart:** a restarting node at epoch `e+1` locates `B_ec` via the checkpoint's
`valset_hash`, loads `S_{e+1}` bytes from `B_ec.payload`, verifies the set hash, then
processes blocks using `S_{e+1}`. The commit evidence for `B_ec` (the QC `Q` above) must
also be durable — it is stored as part of the high-QC record and in the block store.

---

## Exact acceptance condition: SSI activation boundary

A set-state identifier (SSI) is the `valset_hash` of an active validator set. Each
revocation or rotation that takes effect at height `h_act` produces a new SSI.

**Activation table:**

```
SSI[0]  = S_genesis.validator_set_hash()         activation_height[0]  = 1
SSI[k]  = updated_set_hash after change k        activation_height[k]  = h_k + 1
                                                 where h_k = height of the committed
                                                 block that introduced change k
```

**Eligibility rule:** a certificate `C` is eligible to certify a block at height `h_block`
if and only if:

```
C.valset_hash == SSI[k]  where  k = max { j : activation_height[j] ≤ h_block }
```

In words: the certificate must carry the SSI that was active at the block's height — the
most recent set change at or before that height.

**When later blocks are already in flight:** because the activation boundary is determined
by **committed** state (`activation_height[k] = h_k + 1` where `h_k` is a committed
height), no block at height ≥ `h_k + 1` can have been certified under `SSI[k-1]` before
the change was committed. The two-chain rule ensures `B_ec` (or the revocation block) is
committed only after a consecutive-round QC exists for a child — that child is at height
`h_k + 1` and must carry a QC under `SSI[k-1]` certifying `B_ec`. After that, all further
proposals extend the new tip and use `SSI[k]`.

**Edge case:** a QC certifying `B_ec` itself (at height `h_k`) uses `SSI[k-1]` (the set
before the change). That QC is permanently valid under `SSI[k-1]`; the eligibility check
accepts it because `activation_height[k-1] ≤ h_k < activation_height[k]`.

**What must be tracked in the engine:** a map `valset_hash → (EpochSet, height_range)` where
`height_range = [activation_height[k], activation_height[k+1] - 1]`. On certificate
verification, the engine checks both that the set is known and that the certified height is
within the set's range. Retention: an SSI entry may be evicted once no QC or TC from its
height range is pending finality (bounded by the two-chain window: at most two rounds of
certificates can be pending at any time, so at most two SSIs back must be retained).

---

## Proposed tests (reviewed against acceptance conditions)

### R8-2 epoch commit

| Test | Acceptance condition verified |
|------|-------------------------------|
| `epoch_change_requires_consecutive_rounds_to_commit` | `B_child.round != B_ec.round + 1` → no commit; `B_child.round == B_ec.round + 1` → commit fires. Directly exercises condition 2. (**New** — not in prior draft.) |
| `epoch_change_block_committed_activates_new_set_at_round_one_of_next_epoch` | Presents `B_child` at `B_ec.round + 1` and QC `Q`; asserts `committed_height == B_ec.height` after `Q` is processed; then asserts `valset_hash` for epoch `e+1` certificates uses `S_{e+1}`. |
| `epoch_change_block_uncommitted_does_not_activate_new_set` | QC with non-consecutive rounds does not trigger commit; set remains `S_e`. |

### R8-3 historical set verification

| Test | Acceptance condition verified |
|------|-------------------------------|
| `qc_from_epoch_e_is_verified_against_S_e_after_transition_to_epoch_e_plus_1` | A QC with `valset_hash = S_e.validator_set_hash()` for a block at height ≤ `B_ec.height` is accepted post-transition. |
| `qc_with_epoch_e_valset_hash_for_a_post_transition_height_is_rejected` | A QC with `valset_hash = SSI[k-1]` for a block at height > `activation_height[k]` is rejected. (**New** — directly tests the eligibility rule.) |
| `restart_after_epoch_transition_reconstructs_the_set_from_committed_block` | Cold-start node loads `S_{e+1}` from `B_ec.payload`, verifies `sha3(bytes) == expected_set_hash`, accepts a QC in epoch `e+1`. |

### R8-4 revocation (pending SSI design acceptance)

| Test | Acceptance condition verified |
|------|-------------------------------|
| `revocation_removes_power_from_the_next_block` | `SSI[k+1]` becomes active at `activation_height[k+1] = h_rev + 1`; revoked validator's vote is zero-power from that height. |
| `revocation_does_not_remove_power_mid_round` | QC formed in round `r_rev` uses `SSI[k]`; revocation committed at `h_rev` does not affect quorum in round `r_rev`. |
| `a_qc_formed_before_revocation_is_still_valid_after_revocation_takes_effect` | QC with `valset_hash = SSI[k]` for block at height < `activation_height[k+1]` is accepted even after `SSI[k+1]` is active. Exercises the eligibility rule at the boundary. |

### R8-5 key rotation (pending SSI design acceptance)

| Test | Acceptance condition verified |
|------|-------------------------------|
| `mid_epoch_key_rotation_has_a_one_block_power_gap` | `SSI[k+1]` active at height `h_rot + 1`: validator power is 0 for that one block. |
| `key_rotation_new_key_active_from_the_second_block_after_commit` | `SSI[k+2]` (new key active) at height `h_rot + 2`; vote under old key rejected; vote under new key accepted. |

---

## Decisions needed

1. **Accept the exact two-chain commit evidence stated above** as the normative definition
   of "commits `B_ec`," or revise.
2. **Accept the SSI activation-boundary eligibility rule** (`C.valset_hash == SSI[k]` for
   the most recent active set at `h_block`), or revise.
3. **Accept the retention bound** (at most two SSIs back; eviction after two-chain window
   closes), or specify a different bound.
4. **Accept R8-4 and R8-5 as Phase 1** once the SSI design is accepted, or defer.
5. **Keep PO-4 open** (no implementation begins until this decision changes).

No implementation begins until decisions 1–4 are recorded here and PO-4 is resolved.
