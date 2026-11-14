# PQ-HotStuff-2 — Epoch-Change Handoff Trace and Design Review

**Status:** Design review — open  
**Branch:** `feat/vote-format-v2` unchanged pending resolution  
**Dated:** 2026-11-14  
**Prerequisite reading:** `pq-hotstuff-001-spec.md` §5, §6, §8

---

## 1. Purpose

This document records the normative handoff trace from the first outgoing
quorum certificate through the first incoming vote for a PQ-HotStuff-2
epoch change, identifies three distinct safety claims that the handoff
proof must establish, notes a gap between the implemented commit rule and
the spec §6 commit rule, and specifies what a late or restarting node
must verify independently.

It is a **design review document**, not an implementation task. The branch
stays unchanged until these questions are resolved and an owner decision is
recorded.

---

## 2. Confirmed trace (same-validator-set devnet, 2026-11-14)

The following trace is confirmed by four Windows BossKing runs at commit
`e80214e`. It uses the implemented commit rule (§4 below).

**Setup:** 4-node ML-DSA-65 devnet, epoch-change at height H=2 (same 4
validators, epoch 0 → 1). All nodes run `genesis-4node-pqhs2-epoch.json`.

```
Epoch 0 — outgoing validator set V0 = {alice, bob, carol, dave}

Round 1 at H=2:
  Leader proposes block B2 (epoch-change payload: encodes V1)
  alice, bob, carol, dave sign precommit(H=2, r=1, hash(B2), epoch=0)
    using vote_signing_bytes_v2(epoch=0, set_hash=hash(V0), ...)
  QC1 = QC(H=2, r=1) forms: {precommit_alice, precommit_bob, precommit_carol}
    QC1.epoch = 0 (from votes)

Round 2 at H=2:
  Next round trigger (QC1 is known; no cross-height advance yet)
  alice, bob, carol, dave sign precommit(H=2, r=2, hash(B2), epoch=0)
  QC2 = QC(H=2, r=2) forms: {precommit_alice, precommit_bob, precommit_carol}
    QC2.epoch = 0 (from votes)
  QC2.round == QC1.round + 1 → try_two_chain_commit(QC1) fires
  → commit_block(cert=QC1, proposal=B2)
  → on_commit(B2): decode V1 from payload, verify_handoff_proof, epoch 0 → 1

After on_commit(B2):
  validator_set = V1 = {alice, bob, carol, dave}  [same 4 in this test]
  epoch = 1
  seal_round set (further epoch-0 votes rejected)

Round 1 at H=3:
  alice, bob, carol, dave sign precommit(H=3, r=1, hash(B3), epoch=1)
    using vote_signing_bytes_v2(epoch=1, set_hash=hash(V1), ...)
  QC3 = QC(H=3, r=1) forms, QC3.epoch=1

Round 2 at H=3:
  QC4 = QC(H=3, r=2) forms, QC4.epoch=1
  QC4.round == QC3.round + 1 → commit_block(cert=QC3, proposal=B3)
```

**Observed cert epochs across all 4 nodes:**

| Block | cert.height | cert.epoch | vote_epochs     |
|-------|-------------|------------|-----------------|
| H=2   | 2           | 0          | [0, 0, 0]       |
| H=3   | 3           | 1          | [1, 1, 1]       |
| H=4   | 4           | 1          | [1, 1, 1]       |

The epoch flip in `cert.epoch` is between H=2 and H=3.

Note: `last_commit` for block H stores `cert=QC1` (the FIRST QC at height H,
returned by `try_two_chain_commit` as `prev_locked`). `QC2` (the TRIGGER QC)
is NOT stored in the block summary.

---

## 3. Three distinct safety claims

A valid epoch handoff must establish all three:

### Claim A — Quorum signature

> An authenticated quorum of the outgoing validator set V0 signed a
> precommit over the epoch-change block B2 that commits the incoming
> set V1.

**Evidence:** `cert = QC1` from `last_commit` for block H=2.
`verify_handoff_proof(chain_id, QC1, V0, V1)` checks that at least 2f+1
signers from V0 signed `vote_signing_bytes_v2(epoch=0, set_hash=hash(V1), ...)`.

**Current implementation:** Establishes Claim A. ✓

### Claim B — Finality of the epoch-change block

> Block B2 is irreversibly committed (cannot be replaced by a competing
> block at H=2 under any prefix of honest validator behavior).

**Required evidence:** Two consecutive-round QCs at the same height:
  - QC1 = QC(H=2, r=1) (the committed cert — stored in `last_commit`)
  - QC2 = QC(H=2, r=2) (the trigger cert — **not stored**)
  - QC2.round == QC1.round + 1

A node that sees only QC1 knows that 2f+1 validators certified H=2 in
round 1, but cannot independently verify that the two-chain commit rule
fired. QC1 alone is a lock, not a commit signal.

**Current implementation:** Does not establish Claim B independently of
the live consensus path. `last_commit` stores QC1; QC2 is discarded after
`on_commit` returns. A late or syncing node has no stored proof of the
consecutive-round trigger.

**Gap:** The trigger QC2 must either be stored alongside QC1 in the block
summary, or finality must be established by an alternative mechanism (e.g.,
storing both QCs in a `HandoffCertificate` struct, or verifying finality
from the next epoch's first committed block which implicitly confirms the
transition).

### Claim C — Outgoing validator cutoff

> After the epoch-change block commits, no validator may cast or relay
> epoch-0 precommits for any height H′ > H=2.

**Evidence required:** The epoch transition is irreversible and no honest
replica can be induced to extend an epoch-0 chain past H=2.

**Current implementation:**
- `seal_round` is set on `on_commit(B2)`: any subsequent epoch-0 vote
  is rejected by the engine.
- `vote_signing_bytes_v2` binds the vote to an epoch; a validator cannot
  sign `epoch=0` bytes after its SafetyStore records epoch=1 (`hvr` and
  `hqr` advance in the new epoch).
- An outgoing validator **removed** in the transition (future different-set
  case) is not in V1; its epoch-1 votes would be ignored. Its epoch-0 votes
  are blocked by `seal_round`.

**Current implementation:** Partially establishes Claim C for live nodes.
Does not establish it for a restarting node unless the safety-state file
records the epoch-advance before the restart (§7 of pq-hotstuff-001-spec).

---

## 4. Commit rule discrepancy: implementation vs. spec §6

**Spec §6 (pq-hotstuff-001-spec.md, cross-height rule):**

> "when a node holds a valid QC for block B, and B.qc certifies B's
> parent P with `B.round == P.round + 1`, then P commits"

This describes: QC for block B at height H+1, B's embedded high_qc
certifying parent P at height H, with consecutive rounds.

**Implementation (`try_two_chain_commit`, engine.rs:253):**

```rust
if to_commit.height == self.height && self.locked_qc.round == to_commit.round + 1
```

This describes: two consecutive-round QCs, both at the SAME height H.
`to_commit` = QC(H=2, r=1); `locked_qc` = QC(H=2, r=2). Both at H=2.

**These are different rules.** The spec rule commits a PARENT across a
height boundary; the implementation rule commits a block using two rounds
of voting within the SAME height.

**Consequence for the handoff trace:**

Under the spec rule:
- Block at H=2 commits when block at H=3 is proposed with high_qc(H=2)
  and QC(H=3) forms with QC(H=3).round = QC(H=2).round + 1.
- Votes for H=3 would be cast while the engine is still at epoch 0
  (before on_commit(H=2) fires).
- H=3's cert would carry epoch=0 (outgoing set certified H=3).

Under the implemented rule:
- Block at H=2 commits when two consecutive-round QCs form within H=2.
- After commit, epoch advances to 1 before any H=3 voting begins.
- H=3's cert carries epoch=1 (incoming set certified H=3).
- **Confirmed by devnet: cert.epoch=1, vote_epochs=[1,1,1] for H=3.** ✓

**The implementation rule is consistent with DiemBFT v4 as described in
Jolteon (Gelashvili et al., FC 2022).** The spec §6 description conflates
the block B with the block B.parent. In DiemBFT v4, the parent (P) is the
block containing the high_qc; block B carries a QC FOR P as its high_qc.
When QC(B) forms with consecutive round, P commits. If B and P are at
consecutive heights (H+1 and H), the cross-height interpretation holds.
But if the engine advances height only after a commit, and multiple rounds
can occur at the same height, then B and P can share the same height H.

The spec §6 must be rewritten to accurately describe which blocks are at
which heights under the same-height-multiple-rounds model, and whether
the commit fires within a height or across heights.

**This is a spec defect, not an implementation defect.** The implementation
matches the BossKing-confirmed trace and passes all property tests.

---

## 5. What a late or restarting node must verify

A node that is behind (crashed, partitioned, or joining late) must
independently verify the epoch-change transition by replaying committed
blocks. Currently it can only do what the block summary provides.

For block H=2, the block summary contains:
- `last_commit = QC1` = QC(H=2, r=1, epoch=0, precommits=[…])
- Block payload: epoch-change payload encoding V1

A restarting node that runs `verify_handoff_proof(chain_id, QC1, V0, V1)`:
- Establishes Claim A (quorum signed B2 binding V1). ✓
- Does NOT establish Claim B (finality) independently. The node must
  trust that the block was committed by an honest majority, inferred from
  the existence of subsequent committed blocks in the chain.

**Minimum additional evidence for independent finality verification:**

Option 1: Store `trigger_qc = QC2` in the block summary alongside `last_commit`.
A syncing node checks `trigger_qc.round == last_commit.round + 1` and
`trigger_qc.height == last_commit.height` and verifies `trigger_qc`'s
precommit signatures against V0.

Option 2: Accept chain-of-custody finality: a block at H=3 committed under
epoch 1 (with V1 as the validator set) implicitly certifies that the transition
at H=2 was final. A restarting node that syncs H=3 and verifies it under V1
derives finality of H=2 transitively.

Option 1 is stronger (self-contained per block) but costs an extra ~3×3.3KB
of signature data per epoch-change block. Option 2 reuses existing chain
integrity without schema changes.

---

## 6. PO-4 safety properties to re-examine for different-set handoff

**PO-4 (from pq-hotstuff-001-spec.md §12):** A validator cannot equivocate
in the same epoch. The two-chain commit rule guarantees that at most one
block can commit per height under honest ≥ 2f+1 behavior.

For a different-set handoff (V0 ≠ V1), the following PO-4-adjacent questions
must be answered before the design is approved:

**PO-4a — Fork between QC1 and QC2 at H=2:**
Can a Byzantine leader cause two different block hashes to be certified at
H=2 at round 1 (QC1) and at round 2? In DiemBFT v4, the round-2 leader
must propose an extension of the highest QC it knows. If QC1(H=2, hash=A)
exists and the round-2 leader sees it, what can it propose at round 2?
If rounds advance HEIGHT (not just round number within a height), then round
2 at H=2 would propose a block at H=3, not a competing block at H=2.
This requires clarifying the height-round relationship in the implementation.

**PO-4b — Outgoing validator equivocation window:**
Between QC1(H=2, r=1) forming and the commit of H=2 triggering
(QC2(H=2, r=2)), outgoing validators have signed epoch-0 precommits for
H=2 (round 1). Can they also sign epoch-0 precommits for a competing
block at H=2 (round 2, different hash)? The SafetyStore's `locked_qc`
prevents voting for a block conflicting with QC1 (rule 3 of §5), so an
honest validator cannot equivocate here. Byzantine validators who do
equivocate produce slashable evidence.

**PO-4c — Incoming validator pre-signing:**
Can an incoming validator E (not in V0) cast epoch-0 votes to influence
which block commits at H=2? No: epoch-0 votes are verified against V0;
E's key is not in V0 and its vote is rejected.

**PO-4d — Outgoing validator post-transition vote:**
After on_commit(H=2) fires for an honest node, can a removed validator D
(in V0 but not V1) cast epoch-0 votes for H=3 and beyond? D's epoch-0
votes at H=3 are rejected by seal_round. D cannot cast epoch-1 votes
(its key is not in V1; they would be rejected by the new validator set).
D is effectively silenced immediately on any node that has committed H=2.
For a node that has NOT yet committed H=2 (behind by one block), D can
still contribute epoch-0 votes toward QC1 or QC2 at H=2 — which is
correct, since those are the votes needed to commit H=2.

**PO-4e — Incoming set adoption timing:**
When exactly does V1 take effect for a given node? For a live node: on
`on_commit(B2)`. For a syncing node: when it replays and commits H=2.
The gap between these two timings cannot allow a split where some nodes
treat a quorum as V0-valid and others treat the same quorum as V1-invalid
(or vice versa).

---

## 7. Required specification work before different-set handoff is approved

The following items must be resolved and recorded as owner decisions in
ROADMAP.md before dynamic membership (V0 ≠ V1) may be implemented:

1. **Commit rule spec correction.** Rewrite pq-hotstuff-001-spec.md §6 to
   describe the same-height consecutive-round rule as implemented, and
   re-verify that the DiemBFT v4 safety argument applies to this variant.

2. **Trigger QC storage.** Decide between Option 1 (store QC2 as
   `trigger_qc` in block summary) or Option 2 (chain-of-custody finality)
   for Claim B, and add the chosen mechanism to the spec and implementation.

3. **Handoff proof scope.** Update `verify_handoff_proof` to establish
   Claim B using the chosen mechanism. Currently it only establishes Claim A.

4. **Late-node verification spec.** Specify step-by-step what a node
   syncing from genesis (or from a snapshot) must verify for each
   epoch-change block, including which certificates are required and
   which authority certifies the incoming set.

5. **PO-4a height-round clarification.** Confirm whether two distinct block
   hashes can appear at the same height in different rounds, or whether the
   engine always advances height after a commit (making same-height
   multi-round mean: multiple rounds voting on the SAME block hash). If
   the latter, document the invariant explicitly and add a property test.

6. **Different-set acceptance test.** Write the analog of
   `pqhs2_4node_epoch_live.rs` with V0 ≠ V1 (at least one validator
   removed and one added). The same cert-epoch and vote-epoch assertions
   must hold, plus an assertion that the removed validator's epoch-0 votes
   are rejected after the transition and the new validator's epoch-1 votes
   are accepted.

---

*This document records the design state as of 2026-11-14 and may be revised
as decisions are made. Each resolved item above should be updated here and
in ROADMAP.md.*
