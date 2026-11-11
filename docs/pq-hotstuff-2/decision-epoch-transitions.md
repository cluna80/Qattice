# Decision Request: Epoch Transitions (G8-E, G8-R, G8-K)

**Date:** 2026-11-11 (revised 2026-11-11 — owner review round 1)  
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

**Existing mechanism:** every `Qc` and `Tc` already carries a `valset_hash: [u8; 32]`
field (`certs.rs:110, 121, 133`). `verify_qc` and `verify_tc` reject any certificate whose
`valset_hash` does not match the engine's current commitment (`certs.rs:308`). This is the
hook for set-authenticated certificate verification.

---

## Open design questions (raised by owner review 2026-11-11)

The following must be resolved before R8-2/R8-3 and R8-4/R8-5 can be approved for
implementation.

### Q1 — Epoch-change handoff: what does the first new-epoch block extend?

**Proposed answer:** The epoch-change block `B_ec` is a normal block in epoch `e`. Its
payload carries the signed next-epoch validator set `S_{e+1}`. `B_ec` is committed by a
`QC` from epoch `e` (signed by epoch-`e` validators against their `valset_hash`). The
first block of epoch `e+1` has:

```
B1_new.parent_id  = B_ec.block_id
B1_new.epoch      = e + 1
B1_new.round      = 1
B1_new.height     = B_ec.height + 1
B1_new.qc         = QC(B_ec)   // the same QC that committed B_ec, signed by epoch-e validators
```

The QC that commits `B_ec` is the last epoch-`e` certificate. All subsequent QCs and TCs
carry `valset_hash = S_{e+1}.validator_set_hash()`.

**What still needs resolution:**
- Must a restarting node have access to `S_{e+1}` bytes, or is `S_{e+1}.validator_set_hash()`
  sufficient to verify `B1_new`? If only the hash is kept, the node cannot re-derive the
  set after a restart. **The full set bytes must be persisted with `B_ec`.**
- Who authenticates `S_{e+1}`? Options: (a) `S_{e+1}` bytes are in `B_ec.payload` and
  committed by the epoch-`e` QC that commits `B_ec`; (b) `S_{e+1}` is a separate signed
  document anchored to `B_ec.block_id`. Option (a) is simpler: the commitment is
  `sha3(B_ec.block_id || S_{e+1})`, verified by any node that has the committed block.

### Q2 — Restart: how does a restarting node verify the transition?

A restarting node at epoch `e+1` must be able to verify that `S_{e+1}` is the correct
set without re-executing every prior block. It needs:

1. The committed `B_ec` block (block store already persists committed blocks).
2. The `S_{e+1}` bytes (from `B_ec.payload` if option (a) above is chosen).
3. Verification: `sha3(B_ec.payload) == expected_set_hash` where `expected_set_hash` is
   anchored in a checkpoint or derived from the genesis cert of the new epoch.

**What still needs resolution:** define the checkpoint record for an epoch transition. The
current `Checkpoint` type records a `block_id`, `height`, and `params`. It needs a
`valset_hash` field (or the full `EpochSet`) to allow a cold-start node to verify
`S_{e+1}` without walking the full chain.

### Q3 — Historical QC/TC verification: authenticated record of each applicable set

A `QC` from epoch `e` must remain verifiable after a transition to epoch `e+1`. The
`valset_hash` in the certificate is the commitment. The engine needs:

- A map from `(epoch, valset_hash)` to the full `EpochSet` bytes, stored durably.
- On restart, this map must be reconstructible from committed blocks (committed epoch-change
  blocks contain `S_e` bytes) or from a checkpoint.

**What still needs resolution:** specify the storage format and eviction policy for
historical sets. A node pruned past the epoch-change block cannot reconstruct the old set
from the block store. It must either retain the set bytes separately or refuse to process
any QC from pruned epochs (acceptable if the two-chain rule guarantees no QC from an
evicted epoch is ever needed post-commit).

---

## Revocation and rotation: the intra-epoch set identity problem

### The problem

R8-4 and R8-5 introduce mid-epoch validator-set changes. After a revocation or rotation in
block `B` at height `h`, the set that governs blocks at height `h+1` and later differs from
the set that governed blocks at height `< h+1` — but the epoch number is the same for all
of them.

**Consequence:** epoch number alone cannot identify the applicable set. A `QC` from height
`h+2` and a `QC` from height `h-1` both carry `epoch = e`, but they were signed under
different sets.

The `valset_hash` field in `Qc` and `Tc` is the natural discriminator. But it is currently
verified as an equality check against the engine's single current `self.valset_hash`. That
check must be extended:

- The engine must track the **set state sequence** within an epoch: each revocation or
  rotation that takes effect at height `h` increments a set-state counter, producing a
  new `valset_hash`.
- Certificates are verified against the `valset_hash` current at the round they were
  formed, not the round they are processed.
- When finality arrives for block `B` at height `h` after blocks at height `h+1` or later
  have already been proposed or certified:
  - The QC that commits `B` was formed under the pre-transition set.
  - Any QC or TC formed under the post-transition set (height `h+1`+) is verified against
    that set.
  - The engine must not reject a valid QC formed under a set state it has since superseded.

### Proposed set-state model

Introduce a **set-state identifier** (SSI) that is the `valset_hash` of the set currently
in force. It changes only when a revocation or rotation is committed:

```
SSI[0] = genesis validator_set_hash
SSI[k] = validator_set_hash(apply_change(SSI[k-1], change_k))
```

Each certificate carries the SSI at the time it was formed (already encoded in
`valset_hash`). Verification uses the SSI matching the certificate's `valset_hash` from an
engine-maintained map `SSI → EpochSet`.

**What still needs resolution:**
- How long must historical SSIs be retained? A certificate from SSI[k] is needed as long
  as there is a QC or TC from that round still pending finality. After the two-chain commit
  rule guarantees finality, certificates from the superseded SSI can no longer affect
  safety. Determine the retention window.
- Specify the data type for the SSI map in the engine. Maximum size: bounded by the number
  of revocations and rotations in a single epoch — in practice O(n) for n validators.

### Approval gate for R8-4 and R8-5

R8-4 and R8-5 cannot be approved for implementation until:

1. The set-state model (SSI map, retention window) is accepted.
2. The engine change to verify certificates against their `valset_hash` using the SSI map
   (rather than the single `self.valset_hash`) is designed.
3. PO-4 scope is defined: does it need to cover intra-epoch transitions, or only
   epoch-boundary transitions?

---

## Proposed rules (unchanged from first draft)

### R8-2 — Epoch-change committed block

An epoch change is triggered only by a **committed** epoch-change block carrying a valid
signed next-epoch validator set. The new set takes effect from round 1 of epoch `e+1`.
Uncommitted proposals are ignored.

### R8-3 — Historical set verification

Every QC and TC is verified against the set whose `valset_hash` matches the certificate's
own `valset_hash` field. The engine maintains a durable map from `valset_hash` to
`EpochSet` bytes for every set state ever applicable.

### R8-4 — Revocation (mini-epoch rule)

A revocation committed in block `B` takes effect in the first block after `B`. Power drops
to 0; it never takes effect mid-round.

### R8-5 — Key rotation (one-block power gap)

A rotation committed in block `B` takes effect in the block at `B.height + 1`; the
validator is absent for one block, the new key is active from `B.height + 2`.

---

## Tests that would demonstrate each rule

### R8-2/R8-3 — epoch transitions

| Test name (proposed) | What it asserts |
|----------------------|-----------------|
| `epoch_change_block_committed_activates_new_set_at_round_one_of_next_epoch` | First block of epoch `e+1` extends committed `B_ec`; its QC uses the new `valset_hash`. |
| `epoch_change_block_uncommitted_does_not_activate_new_set` | An uncommitted epoch-change proposal does not change the active set. |
| `qc_from_previous_epoch_is_verified_against_its_own_valset_hash` | A `QC` with the outgoing set's `valset_hash` remains valid after a transition; a QC with the wrong `valset_hash` is rejected. |
| `restart_after_epoch_transition_reconstructs_the_set_from_committed_block` | A cold-start node at epoch `e+1` loads `S_{e+1}` from the committed epoch-change block and accepts a QC formed in epoch `e+1`. |

### R8-4/R8-5 — revocation and rotation (pending SSI design)

| Test name (proposed) | What it asserts |
|----------------------|-----------------|
| `revocation_removes_power_from_the_next_block` | Revoked validator's vote is zero-power from height `B.height + 1`. |
| `revocation_does_not_remove_power_mid_round` | Revocation committed in round `r` does not affect quorum count in round `r`. |
| `a_qc_formed_before_revocation_is_still_valid_after_revocation_takes_effect` | A QC carrying the pre-revocation `valset_hash` is accepted by the engine even after the revocation SSI is active. |
| `mid_epoch_key_rotation_has_a_one_block_power_gap` | Validator power is 0 for the one gap block; its vote does not count toward quorum. |
| `key_rotation_new_key_is_active_from_the_second_block_after_commit` | A vote signed with the new key in the block after the gap is accepted; the old key is rejected. |

---

## Decision needed

1. **Accept proposed epoch-change handoff (Q1):** first new-epoch block extends committed
   `B_ec`; `S_{e+1}` bytes in `B_ec.payload`; committed by the last epoch-`e` QC.
2. **Accept or revise restart checkpoint design (Q2):** `Checkpoint` record carries
   `valset_hash`; set bytes recoverable from committed epoch-change block.
3. **Accept or revise historical-set storage (Q3):** durable `valset_hash → EpochSet` map;
   define eviction policy.
4. **Accept or revise the SSI model** for intra-epoch set changes (prerequisite for
   R8-4/R8-5 approval).
5. **Define PO-4 scope** for this phase before authorizing implementation.

No implementation begins until decisions 1–5 are recorded here.
