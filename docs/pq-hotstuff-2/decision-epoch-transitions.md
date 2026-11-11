# Decision Request: Epoch Transitions (G8-E, G8-R, G8-K)

**Date:** 2026-11-11 (revised 2026-11-11 — owner review round 3)  
**Gate:** QAT-07 / PQHS-P1  
**Status:** Direction approved; implementation blocked on PO-4 model check.  
**Tracks:** Track B (§8 reconfiguration)  
**Spec refs:** §8, R8-2 through R8-5  

### Owner decisions recorded 2026-11-11 (round 3)

| Item | Decision |
|------|----------|
| Two-chain commit evidence and SSI eligibility | **Direction approved.** Exact activation predicate, outgoing-set cutoff and restart handling must be specified (see §Activation predicate and §Outgoing-set cutoff below) before Track B begins. |
| Q3 — pruned-node set recovery | **Option (a) selected** (checkpoint carries `S_{e+1}` bytes). Checkpoint bytes alone are insufficient; the checkpoint must bind those bytes to the committed block hash of `B_ec` so a cold-start node can verify the set against the authenticated handoff. |
| Explicit epoch-boundary block type | **Approved.** `B_child` carries an explicit `EpochBoundary` type tag. This simplifies sync verification and the activation rule. |
| SSI retention bound (two SSIs back) | **Deferred.** The two-chain commit window does not bound what lagging nodes, pruned restarts, or historical-evidence verification may need. Retention policy is specified as part of the SSI store design when Track B implements it. |
| PO-4 scope | Run with disjoint validator sets, delayed handoff evidence, competing outgoing-set continuations, and restarts on both sides of the epoch boundary. Report search bounds. Dynamic membership remains disabled until PO-4 returns. |

No Track B implementation begins until PO-4 completes.

---

## Current state

Dynamic membership is disabled. `EpochSet::new()` refuses any epoch other than 0 with
`SetError::EpochChangeDisabled` (`types.rs:53-54`). PO-4 is an open proof obligation.

Every `Qc` and `Tc` already carries `valset_hash: [u8; 32]` (`certs.rs:110,121,133`).
`verify_qc`/`verify_tc` reject any certificate whose `valset_hash` does not match the
engine's current commitment (`certs.rs:308`). This is the existing hook.

---

## Circular-dependency resolution (owner decision round 3)

**The apparent circularity:** the handoff trace shows `B_ec` becomes final when the node
processes `QC_B_child` carried inside `B_{e+1,1}`. It also says `S_{e+1}` can sign only
after `B_ec` is final. If `S_{e+1}` must sign `B_{e+1,1}` and `B_{e+1,1}` must arrive
to deliver `QC_B_child` — who signs `B_{e+1,1}`?

**Resolution: `QC_B_child` is independently deliverable.** `QC_B_child` is an outgoing-set
(`S_e`) certificate. It can be received, verified against `S_e`, and stored before any
`S_{e+1}` member signs anything. No `S_{e+1}` signature is required to verify it.

The correct activation sequence is:

1. Any node receives `QC_B_child` (a supermajority certificate from `S_e` over `B_child`).
2. The node verifies `QC_B_child` against `S_e` (the currently active set): checks
   `valset_hash`, signature count, and ML-DSA-65 signatures.
3. The node observes that `B_child` is at round `r_ec+1` and `B_ec` is at round `r_ec`
   (consecutive stored rounds). Two-chain rule: `commit_through(B_ec)` fires.
4. The node loads `S_{e+1}` from `B_ec.payload`, verifies `sha3(bytes) == expected_set_hash`,
   and replaces `self.valset_hash` with `S_{e+1}.validator_set_hash()`.
5. `S_{e+1}` members may now sign. The first `S_{e+1}` proposer constructs `B_{e+1,1}`
   with `B_{e+1,1}.qc = QC_B_child` — embedding the already-verified outgoing-set QC as
   the cross-epoch handoff evidence.
6. Any node receiving `B_{e+1,1}` can verify the embedded `QC_B_child` independently
   (against `S_e` via the SSI map) without requiring a second `S_{e+1}` signature on it.

**Key property:** when `B_{e+1,1}` arrives, the handoff can already be verified on its
own. The first new-epoch proposal carries evidence of a transition that any honest node
holding `QC_B_child` and the block ancestry has already committed independently.

This is the design PO-4 must validate, specifically:

- That no competing `S_e` continuation can be certified once a supermajority of `S_e` has
  signed `QC_B_child` (covered by intra-epoch safety of S_e extended to the boundary).
- That a node restarted between steps 3 and 5 (after `B_ec` is committed, before
  `B_{e+1,1}` arrives) holds `QC_B_child` in its high-QC store, resumes at round 1 of
  epoch e+1, and accepts `B_{e+1,1}` without re-verifying `QC_B_child` against S_e's
  signatures a second time (they are stored with the QC record).

---

## Activation predicate (exact)

A node activates `S_{e+1}` when **all** of the following hold:

1. The node has committed `B_ec` via `commit_through(B_ec.block_id)`.
2. `B_ec.payload` contains a serialized `EpochSet` whose hash matches the
   `expected_set_hash` field in `B_ec.payload_header`.
3. `sha3(S_{e+1}_bytes) == expected_set_hash`.
4. `S_{e+1}` passes `EpochSet::new()` validation (all keys 1952 bytes, ML-DSA-65).

After these four checks pass, `self.valset_hash` ← `S_{e+1}.validator_set_hash()`. All
subsequent QCs and TCs must carry this hash. The activation is **not deferred** — it
takes effect before any block at height `B_ec.height + 2` is proposed or accepted.

**Q1 (payload header format):** `expected_set_hash` placement in the epoch-change block's
payload is an implementation detail for Track B. It must be part of the **authenticated**
block content (i.e., included in the signed header), not a separate un-signed field.

---

## Outgoing-set cutoff

`S_e` may certify blocks at rounds ≤ `r_ec + 1` within epoch e. Its cutoff is:

- `S_e` cannot certify any block at round > `r_ec + 1` in epoch e. Any such certificate
  would require a competing extension of `B_child` and would violate intra-epoch safety
  (two distinct QCs at consecutive rounds is impossible for honest supermajorities).
- After `B_ec` is committed, no honest `S_e` member will form a QC extending `B_ec`'s
  parent chain in a direction that conflicts with `B_ec` — the safety proof for the
  intra-epoch two-chain rule applies up to and including `r_ec + 1`.
- **PO-4 must verify** that this cutoff holds even when some `S_{e+1}` members overlap
  with `S_e` (non-disjoint sets) and that no coalition straddling the boundary can
  construct two valid QCs at the same height under different `valset_hash` values.

---

## Restarted-node handling of late QCs and TCs

A node restarted in epoch e+1 with committed tip `B_ec` (height h) and
`high_qc = QC_B_child` (epoch e, round r_ec+1):

- **Resume round:** round 1 of epoch e+1 (not r_ec+2). The pacemaker must detect that
  `high_qc.epoch < current_epoch` and reset the round to 1.
- **Late epoch-e TCs:** a TC with `valset_hash = S_e.validator_set_hash()` and
  `epoch = e` at round ≤ r_ec+1 is verified against S_e via the SSI map. It must not
  advance the pacemaker past round 1 of epoch e+1 — a late TC cannot "fast-forward" into
  the new epoch.
- **SSI map on restart:** the node loads the SSI map from durable storage. If the SSI
  entry for `S_e` is present, late epoch-e TCs are verifiable. If it has been evicted,
  late TCs from epoch e are discarded (safe — the transition has already committed).

**Test needed (G8-E new):** `restart_at_epoch_boundary_resumes_at_round_1_of_new_epoch`
— a node restarted between steps 3 and 5 (after B_ec committed, before B_{e+1,1}) must
resume at round 1 of epoch e+1 and accept B_{e+1,1} when it arrives.

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

## Handoff trace: block-by-block disposition

The following trace resolves the height conflict in the previous draft (which put
`B_child` and the first new-epoch block at the same height).

```
Height | Round    | Epoch | Block      | Certifying set | Disposition
-------|----------|-------|------------|----------------|------------------------------------
h      | r_ec     | e     | B_ec       | S_e            | Epoch-change block; payload = S_{e+1}
       |          |       |            |                | Not yet committed when first proposed
h+1    | r_ec+1   | e     | B_child    | S_e            | Extends B_ec; commits B_ec when
       |          |       |            |                |   QC(B_child) is processed
       |          |       |            |                | Still epoch e; S_{e+1} known but not
       |          |       |            |                |   yet active
h+2    | 1        | e+1   | B_{e+1,1}  | S_{e+1}        | First block of new epoch; parent =
       |          |       |            |                |   B_child.block_id; round resets to 1
```

**What commits `B_ec`:** a QC on `B_child` satisfying the acceptance condition (stored
round consecutive, `parent_id = B_ec.block_id`, supermajority of `S_e`). When that QC is
processed, `commit_through(B_ec.block_id)` fires.

**When `S_{e+1}` becomes active:** after `B_ec` is committed, before any block at height
`h+2` is accepted. The engine loads `S_{e+1}` from `B_ec.payload`, verifies the set hash,
and replaces `self.valset_hash` with `S_{e+1}.validator_set_hash()`. All subsequent
certificates must carry that hash.

**`B_child`'s disposition:** `B_child` is an ordinary epoch-`e` block at height `h+1`. It
carries no special type flag in the current design. Its only role is to provide the
consecutive-round QC that triggers the commit of `B_ec`. It may carry empty payload.

**Open question for owner decision:** should `B_child` have an explicit "epoch boundary"
block type, or is an ordinary epoch-`e` block at round `r_ec+1` sufficient? An explicit
type would make it unambiguous to external observers and simplify the activation rule (the
engine transitions on commit of an epoch-change block, not on commit of any block at that
height). Without an explicit type, the activation is triggered solely by the payload
content of the committed block (`B_ec.payload` contains `S_{e+1}`), which is equivalent
but requires the engine to inspect payload on every commit.

**Timeout certificates in epoch `e` during the transition window:** a TC formed at round
`r_ec` or `r_ec+1` in epoch `e` carries `valset_hash = S_e.validator_set_hash()` and no
block height. Its activation rule follows the SSI eligibility condition using the round,
not the block height: a TC is eligible if `S_e` was the active set for the rounds at which
it was formed. Because the epoch transition takes effect after `B_ec` is committed (between
height `h+1` and `h+2`), any TC at rounds ≤ `r_ec+1` in epoch `e` is verified against
`S_e`. TCs at round 1 of epoch `e+1` are verified against `S_{e+1}`.

**Retention for cold-start authentication after pruning (Q3 — decision recorded):**
Option (a) selected: the checkpoint record carries `S_{e+1}` bytes directly. However,
checkpoint bytes alone do not authenticate the set — the checkpoint must also carry the
committed block hash of `B_ec` so a cold-start node can verify:

```
sha3(checkpoint.epoch_set_bytes) == checkpoint.expected_set_hash
                                 == B_ec.payload_header.expected_set_hash
checkpoint.B_ec_block_hash       == committed B_ec hash (from the durable commit log)
```

Without binding the set bytes to the authenticated `B_ec` hash, a corrupted checkpoint
could substitute a different set without detection. This is a Track B implementation
requirement, not an open decision.

---

## Extended handoff trace: finalization, incoming-block evidence, restart tip, TCs

### Block-by-block trace

`B.qc` certifies `B.parent_id` (`engine.rs:395`). The two-chain rule commits the
**parent of the block being certified**, not the certified block itself.

```
Step | Block       | h    | Round    | Epoch | .qc certifies       | certifying set | Chain action on accept           | Committed tip
-----|-------------|------|----------|-------|---------------------|----------------|----------------------------------|---------------
1    | B_ec        | h    | r_ec     | e     | B_ec's parent (S_e) | S_e            | Stored; prior ancestors may      | ≤ h-1
     |             |      |          |       |                     |                | commit via standard two-chain    |
2    | B_child     | h+1  | r_ec+1   | e     | B_ec (S_e)          | S_e            | Stored; observe_cert(QC_B_ec):   | h-1 or less
     |             |      |          |       |                     |                | cr=r_ec, pr=r_ec-1 → may commit  |
     |             |      |          |       |                     |                | B_ec's parent if consecutive     |
3    | B_{e+1,1}   | h+2  | 1        | e+1   | B_child (S_e) [★]   | S_e via SSI    | observe_cert(QC_B_child):        | h ← B_ec
     |             |      |          |       |                     |                | cr=r_ec+1, pr=r_ec,              | committed
     |             |      |          |       |                     |                | commits_parent(r_ec, r_ec+1)=T   |
     |             |      |          |       |                     |                | → commit_through(B_ec);          |
     |             |      |          |       |                     |                | engine loads S_{e+1} from        |
     |             |      |          |       |                     |                | B_ec.payload; self.valset_hash   |
     |             |      |          |       |                     |                | ← S_{e+1}                        |
4    | B_{e+1,2}   | h+3  | 2        | e+1   | B_{e+1,1} (S_{e+1}) | S_{e+1}        | observe_cert(QC_B_{e+1,1}):      | h (no change)
     |             |      |          |       |                     |                | cr=1, pr=r_ec+1,                 |
     |             |      |          |       |                     |                | commits_parent(r_ec+1, 1)=FALSE  |
     |             |      |          |       |                     |                | (round gap — no commit)          |
5    | B_{e+1,3}   | h+4  | 3        | e+1   | B_{e+1,2} (S_{e+1}) | S_{e+1}        | observe_cert(QC_B_{e+1,2}):      | h+2 ← B_{e+1,1}
     |             |      |          |       |                     |                | cr=2, pr=1,                      | B_child (h+1)
     |             |      |          |       |                     |                | commits_parent(1, 2)=TRUE        | committed as
     |             |      |          |       |                     |                | → commit_through(B_{e+1,1}):     | ancestor
     |             |      |          |       |                     |                | commits B_child (h+1) first,     |
     |             |      |          |       |                     |                | then B_{e+1,1} (h+2)             |
```

**[★] Cross-epoch QC:** `B_{e+1,1}.qc` certifies B_child and was signed by S_e validators
(`valset_hash = S_e`). At step 3, the engine has transitioned to epoch e+1
(`self.valset_hash = S_{e+1}`). The existing single-hash check
(`Q.valset_hash != self.valset_hash`) would reject this QC. **The SSI map is required:**
the engine must look up `Q.valset_hash` in the map to find S_e and verify against it.
This is the first mandatory use of the SSI map in the transition sequence.

### What finalizes B_child

B_child (height h+1) is **never directly committed** by its own two-chain evidence. It is
committed as an **uncommitted ancestor** in step 5 when `commit_through(B_{e+1,1})` walks
backwards from B_{e+1,1} (height h+2) and finds B_child at h+1 above the current
committed tip (B_ec at h).

B_child has no special commit rule. Its finalization is a consequence of the first normal
two-chain commit in epoch e+1 (rounds 1 and 2 consecutive, triggering commit at round 3).

**Implication for `B_child`'s type:** because B_child is committed transitively rather
than directly, it needs no special commit rule. An explicit "epoch-boundary" block type
is still useful for execution and sync verification (nodes can identify B_child as the
boundary marker without inspecting B_ec.payload), but it does not change the commit path.
Owner recommendation accepted: use an explicit epoch-boundary type. See decision needed §4.

### What evidence B_{e+1,1} carries

```
B_{e+1,1} = Block {
    epoch:     e+1,
    round:     1,
    height:    h+2,
    parent_id: B_child.block_id,
    qc:        QC { block_id: B_child.block_id,
                    round: r_ec+1,          // B_child's round
                    parent_id: B_ec.block_id,
                    parent_round: r_ec,
                    epoch: e,               // the epoch of the QC, not of this block
                    valset_hash: S_e.validator_set_hash() },  // ← cross-epoch
    ...
}
```

The QC inside B_{e+1,1} is an epoch-e certificate carrying `epoch = e` and
`valset_hash = S_e`. The block itself is epoch e+1. The engine must accept a block in
epoch e+1 that carries a QC from epoch e — this is the cross-epoch evidence that proves
the outgoing set authorized the transition.

### Restarting node's committed tip

A node that restarts between step 3 and step 5 (after B_ec is committed but before
B_child and B_{e+1,1} are committed) has:
- `committed_tip = B_ec.block_id`, `committed_height = h`
- `high_qc = QC_B_child` (round r_ec+1, epoch e, valset_hash = S_e) or higher if
  B_{e+1,2} has arrived before the restart
- Epoch is e+1 (the transition completed at step 3)
- Resume round = `max(high_qc.round, high_tc.round) + 1` within epoch e+1

**Round resumption at the boundary:** if `high_qc` is the epoch-e QC_B_child at round
r_ec+1, the engine must not resume at round r_ec+2 — it must resume at round 2 of epoch
e+1 (since round 1 is already in the block store). The round-resumption rule must handle
the epoch boundary: after the epoch transitions, rounds in the new epoch are independent
of the old epoch's round numbers. `next_round` after B_child's QC (from epoch e) must
return round 1 of epoch e+1 if the transition has occurred, not r_ec+2.

---

### TC activation: `(epoch, round) → eligible set`

The eligible set for a TC is determined by its `valset_hash` via the SSI map, combined
with an epoch+round consistency check to prevent a delayed epoch-e TC from being
processed as an epoch-e+1 TC.

**Rule:** a TC is eligible if and only if:
1. `TC.valset_hash` is in the SSI map (the set is known and was active at some point)
2. `TC.epoch` is consistent with the activation range of the matching SSI entry

```
TC event                       | Epoch | Round    | valset_hash    | SSI lookup     | Eligible set
-------------------------------|-------|----------|----------------|----------------|---------------
Last outgoing TC at r_ec+1     | e     | r_ec+1   | S_e            | SSI[k] = S_e   | S_e (valid; activation range includes rounds in epoch e)
First incoming TC at round 1   | e+1   | 1        | S_{e+1}        | SSI[k+1]=S_{e+1}| S_{e+1}
Delayed outgoing TC at r_ec    | e     | r_ec     | S_e            | SSI[k] = S_e   | S_e (valid until SSI[k] evicted)
Delayed outgoing TC after      | e     | r_ec+1   | S_e            | SSI[k] = S_e   | S_e; accepted by node in epoch e+1
restart in epoch e+1           |       |          |                |                | if SSI[k] is retained; must not
                               |       |          |                |                | advance the engine past round 1 of e+1
```

**Derivability requirement:** the `(epoch, round) → eligible set` mapping must produce
identical results on every node given the same authenticated transition history. The SSI
map is built from committed blocks (the epoch-change block commits the new S_{e+1}; each
revocation/rotation block commits an SSI update). Every correct node that has processed
the same committed blocks holds the same SSI map. A cold-start node reconstructs the map
from the epoch-set store (see retention rule, Q3).

**Retention rule for epoch-e SSI:** SSI[k] (S_e) may be evicted when no pending certificate
from epoch e can affect safety. Under the two-chain rule, all epoch-e certificates are
finalized when B_child (the last epoch-e block) is committed in step 5. After step 5,
SSI[k] = S_e may be evicted. Until then, it must be retained to verify cross-epoch
evidence (the [★] QC in step 3 and any delayed TCs).

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
within the set's range.

**Retention policy (deferred — owner round 3):** the two-chain commit window bounds
in-flight certificates for a caught-up node, but does not bound what lagging nodes,
pruned restarts, or historical-evidence verification may need. The retention policy
is a Track B design task. It must specify:

- Minimum retention for a node that has not yet processed `B_child`'s commit
- Retention for sync/recovery across a pruning boundary
- Eviction policy once all evidence from an SSI's height range is finalized

The earlier bound of "two SSIs back" is **not approved** and must not be used as a basis
for implementation or the PO-4 search scope.

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

## Decision status (updated 2026-11-11, round 3)

| # | Decision | Status |
|---|----------|--------|
| 1 | Two-chain commit evidence as the normative definition of "commits B_ec" | **Direction approved** — exact activation predicate specified above; PO-4 must validate |
| 2 | SSI activation-boundary eligibility rule (`C.valset_hash == SSI[k]` for most recent active set at `h_block`) | **Direction approved** — PO-4 must validate with disjoint sets and competing continuations |
| 3 | SSI retention bound | **Deferred** — two-chain window argument insufficient for lagging/pruned nodes; retention policy is a Track B design task |
| 4 | R8-4 (revocation) and R8-5 (key rotation) as Phase 1 | **Deferred** — pending SSI store design and PO-4 return |
| 5 | Q3: pruned-node set recovery | **Option (a) selected** — checkpoint carries S_{e+1} bytes bound to B_ec committed block hash |
| 6 | Explicit epoch-boundary block type for B_child | **Approved** |
| 7 | PO-4 scope | Disjoint sets, delayed handoff evidence, competing outgoing-set continuations, restarts on both sides of boundary; report search bounds |

**Remaining blockers for Track B:**
- PO-4 model check: partially complete (see PO-4 partial results below)
- SSI retention policy design (deferred above)
- R8-4/R8-5 approval after SSI store design

Dynamic membership remains disabled until PO-4 returns.

---

## PO-4 partial results (2026-11-11, TLC 1.8.0, 4 cores)

Branch `research/pq-hotstuff-2-epoch-transition-model` commit `9bafb8e`. Full table in `REPORT.md`.

### Key findings

**Outgoing-set cutoff is load-bearing (M1, two scenarios confirmed):**
Removing the seal rule (`SealOn = FALSE`) violates `Inv_NoOldEpochBeyondBoundary` in both the overlap scenario (depth 11, 7,032 distinct states, 29s) and the disjoint scenario (depth 19, 128,084 distinct states, 11m 36s).

**Epoch transition is reachable (witness, two scenarios confirmed):**
`Inv_NotCompleted` was violated for the overlap scenario (depth 9, 2,741 distinct states, 6s) and the disjoint scenario (depth 19, 126,366 distinct states, 5m 23s).

**Exhaustive bounded safety result (overlap scenario, MaxProps=6, MaxTos=3, R=4):**
`safety_t3_overlap_tight` exhausted its state space — **15,165 distinct states, depth 21, 1m 05s** — with no violation of `Inv_NoConflictingCommit`, `Inv_NoOldEpochBeyondBoundary`, or any other safety invariant. First fully exhausted safety check.

**On baseline runs that did not complete:** where a run was stopped by timeout or manually, the correct statement is that **no violation was observed in the explored states before the run stopped.** This applies to: the disjoint tight safety run (84,691 distinct states in 5 min, stopped by timeout), and all round-2 baseline runs.

### State-space: why disjoint exhaustion is out of reach here

Overlap (2 honest validators) exhausts at ~15K distinct states in 1 minute. Disjoint (4 honest validators — 2 per epoch, completely separate) generates ~260K states per minute at the same bounds and does not exhaust in 5 minutes. Exhaustion requires a snapshot-synchronization abstraction or dedicated hardware with 16+ cores.

### What is not yet confirmed

- **`Inv_NoConflictingCommit` exhaustively verified for disjoint sets:** 84,691 states explored, no violation observed in explored states before timeout.
- **Compete scenario (SetB — third competing epoch-change candidate):** witness reached 406K+ states at depth 10 in 30 min without finding the goal; stopped. The M1 compete check was not run.
- **Crash/restart configs (CrashOn=TRUE):** not run.

### Remaining PO-4 runs required before Track B

| Priority | Run | Why |
|---|---|---|
| 1 | Disjoint safety exhaustion | Snapshot-sync abstraction or dedicated hardware |
| 2 | `mut_M1_no_seal__t3_compete` | Outgoing-set cutoff failure with competing candidates |
| 3 | `crash_t3_disjoint` | Restart-on-both-sides-of-boundary |
| 4 | `mut_M3_no_boundary_check__t3_disjoint` | SSI eligibility check load-bearing evidence |
