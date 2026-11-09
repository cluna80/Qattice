# Checkpoint commitment (protocol profile v3): implementation and validation record — Linux, sandbox; NOT closed; Windows confirmation pending (CLAUDE.md)

Base: `4783df523eadfba57130a84ec845531359b85425` (the recovery components, #141). **DRAFT. Profile v3 is not accepted by the core genesis validation and no node, devnet or network is configured with it: nothing is activated.**
Existing-profile (v2) block ids, wire bytes and behavior are unchanged (golden values and an independent reconstruction with the original preimage type; every pre-existing test passes unchanged). Network snapshot installation and pruning remain disabled and unwired.
Snapshot-based ENGINE SEEDING is NOT in this PR; it is the subsequent integration PR (see the end).

## What was implemented
* **Profile and identity.** `qattice-pq-hotstuff-2-v3` (exact string). A separate, domain-separated id preimage (`CFH1|blockid3|`: the v2 body then `0x00` or `0x01 || SHA3-256("CFH1|ckpt|" || ref)`); v2 keeps its preimage. A v2 chain refuses any block that carries a reference.
* **Canonical encoding.** `CheckpointRef = height u64 || block_id [32] || state_root [32]` (72 bytes, big-endian). On a block or header it is a 73-byte trailing extension (`0x01 || ref`); absence adds nothing, so a reference-free block has exactly its v2 bytes. Decoding accepts nothing else (bad flag, truncation, extra bytes are malformed).
* **Configuration.** Genesis-bound validity parameters `CheckpointParams { interval K, max_age }` with checked bounds (`1 <= K <= 2^40`, `K <= max_age <= 2^50`); the v3 genesis hash is `SHA3-256("CFH1|v3-genesis|" || genesis_hash || params)`, so any difference is a different genesis block id and certificate. Local policy `RefPolicy { propose_refs, margin, omit_rotations, alarm_age_intervals }` (validated, NOT bound: it changes what a node proposes or reports, never what is valid). A v3 profile without parameters, and parameters on any other profile, are refused at engine construction and in header verification.
* **Validity rules R1 (shape), R2 (final), R3 (identity), R4 (monotonic; a repeat is legal at any age), R6 (freshness of a NEW reference)** in one function (`check_reference`) used by BOTH the engine (`accept`, so also block sync and recovery) and header-chain verification, with checked arithmetic. `F(B)` and the chain's last reference are tracked per block.
* **Voting rule R5** (not validity): `Match` votes; `NotYet` defers the vote until the executor reaches the height (`on_executed` releases it); `Unknown` and `Mismatch` withhold it and record evidence. A `Match` is also granted when a block final in the validator's chain carries the identical reference (authenticated by finality).
* **Alarms.** A root contradicted by a block that carries a QC raises `LocalDivergence`; two QC'd blocks with different references for one height raise `ConflictingCertifiedRoots`. Both are generic (no attribution, not a claim of equivocation), halt signing (propose, timeout and vote all refuse) and leave the SafetyStore untouched. The driver treats the halt as fatal; the `Recovering` state that would reinstall is not implemented.
* **Proposer policy.** The newest final multiple of `K` at least `margin` behind the node's own executor, with a recorded root, newer than the chain's last reference, passing every rule. After a failed reference-bearing proposal of its own the node omits references for a number of rotations that DOUBLES per consecutive failure (cap 2^9), reset when one is certified. (A fixed single rotation was implemented first and rejected by the lag test: with two of four validators lagging, about half the rounds timed out and only 5 blocks were committed in 60 rounds; with the backoff the chain commits steadily.)
* **Durable root log** in the block store (`root-<height>` records, idempotent, conflicts refused, interval-checked, damage and gaps REPORTED not guessed); written after the executor makes a checkpoint durable and reconciled from the executor's cursor at start (so a crash in between loses nothing); a record that contradicts the executor's own cursor stops the node.
* **Driver.** Feeds roots and executor progress to the engine, loads the root log before recovery, and has an execution budget (`exec_per_tick`) to model lag.
* **Header verification** of R1 to R4 and R6 (differentially identical to the engine), genesis binding of the parameters, and anchors that carry their exact state (height, round, parent round, `F`, last reference and the ids of the blocks a new reference can name; anything else fails closed).

## Results (release mode; `PQHS_SEEDS=10` unless noted)
| Suite | Result | Time |
|---|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204` | 139 passed (31 new), 3 ignored | 34 s |
| same, `PQHS_SEEDS=60` | 139 passed, 3 ignored | 167 s |
| doubles `pq_hotstuff_engine` | 139 passed (31 new), 3 ignored | 76 s |
| foundation / safety / safety_fips204 / wire | 30 / 76 / 11 / 24 passed | <1 s |
| consensus lib / core lib / p2p lib | 98 / 74 / 21 passed | — |
| node default check, `--features pq-devnet` check, `pq_devnet` unit tests, LIVE four-node test | ok, ok, 4 passed, 1 passed | 39 s live |

## Checkpoint progress and consensus progress, separately (group L; n = 4 equal power, quorum 3, `T - Q = 1`, `K = 4`, freshness bound 8, margin 2)
| Test | Assumption | Consensus progress | Checkpoint progress |
|---|---|---|---|
| L1 | every executor keeps up, every leader follows the policy | 60+ blocks in 80 rounds, 0 timeouts | `checkpoint_age` never above `K + margin + n + 4` |
| L2 | leaders 0 and 1 never propose references | 0 timeouts | still advances through leaders 2 and 3; only they propose references; age bound plus the omitting run |
| L3 | every leader omits forever | 40+ blocks in 50 rounds, 0 timeouts | none; `checkpoint_age` equals the committed height and the staleness alarm fires; the chain still verifies from headers (Option A) |
| L4 | validators 2 and 3 (power 2 > `T - Q`) stop executing | timeouts occur (reference-bearing proposals cannot gather a quorum) yet at least 20 more blocks commit | none beyond the height the lagging executors had reached; resumes after they catch up |
| L5 | validator 3 only stops executing (power 1 = `T - Q`) | 0 timeouts | continues without it; it defers its votes |
Not claimed: any lower bound on checkpoint frequency from power assumptions alone (leader slots are by COUNT, not power), and nothing about networks other than the reliable-delivery model of the harness. The driver-level test pauses two real executors, shows the deferred votes and the backlog, and drains them in order exactly once.

## Mutation check (`mut_ckpt.py`: 66 mutants across the rules, genesis binding, engine, headers, root log, driver, identity and codecs; build errors not counted)
First run 63 of 66 caught. Survivors: the backoff reset on certification (no observable), non-multiple heights in the root log, and the v3 tag (the test compared the type with itself). Fixed with a read-only backoff accessor and tests, plus an independent byte-level reconstruction of the v3 preimage. Second run on those and their neighbours: 5 of 5. **66 of 66 caught.**

## Specification corrections made alongside (`phase5-snapshot-spec.md`, Revision 4)
The root log ordering is apply-then-log with reconciliation from the cursor (the log-first ordering was withdrawn); the omission backoff is exponential; anchors need their exact state and ancestor ids; the v3 identity and genesis binding are stated precisely; halting is fatal in the driver and the `Recovering` state is not implemented.

## Not in this PR (the subsequent integration PR, which needs its own review)
Snapshot-based engine seeding. It must preserve the SafetyStore floors and reconstruct consensus state from the verified checkpoint, the retained dependencies (headers and certificates down to the freshness bound, the root log) and QC/TC evidence, NOT from an install record alone. Also not here: the `Recovering` signing gate, node and devnet configuration for profile v3, acceptance of profile v3 by the core genesis validation, a canonical state root for the real application (U5), and pruning.

## Windows (owner to run; record separately)
```
git fetch origin feat/pq-hotstuff-2-checkpoint-commitment && git checkout feat/pq-hotstuff-2-checkpoint-commitment && git rev-parse HEAD
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204 2>&1 | grep -E "test result|FAILED"
cargo test --release -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine 2>&1 | grep -E "test result|FAILED"
```

## Windows results (supplied by the owner; MINGW64, `C:\Dev\qattice-main-wt`, branch `feat/pq-hotstuff-2-checkpoint-commitment`) — recorded separately
`git rev-parse HEAD` printed **`73e4a69240da92cf46d6ed6ec634d26da8faaab1`** in the paste, so the revision is confirmed by the output. Release mode:
| Run | Result | Time |
|---|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204`, default seeds | 139 passed, 0 failed, 2 ignored | 199.77 s |
| doubles `pq_hotstuff_engine`, default seeds | 139 passed, 0 failed, 2 ignored | 500.51 s |
The ignored count is 2 here against the 3 in the Linux table above: the Linux figures were taken before the temporary golden-value diagnostic test was deleted from the final commit; the pass count is identical. Not run on Windows for this revision: the 60-seed soak and the live four-node test (the latter does not use profile v3). This closes no milestone: profile v3 is off and unwired, snapshot-based engine seeding is not implemented, and the change still needs the owner's consensus review.

## Focused consensus review of this PR (2026-11-09), requested before snapshot-based engine seeding
Scope: reference binding, R6 and repeats, root-log recovery and execution lag, profile separation. Method: reading the rule code against the engine and header-verifier call sites, then a mutation check of each fix. The Windows results above validate the tests at `73e4a69`; they are not part of this review and the revision below needs its own Windows run.

**Confirmed as specified (no change).**
- *Binding.* A reference is bound three ways: R3 pins `(height, block_id)` to the block's OWN ancestor chain (engine: walk from the parent; verifier: the verified headers plus the anchor's `ancestors`); `state_root` is covered by the block id through `ref_hash`, so it is signed with the block; R5 compares the root with the validator's own execution (or an identical reference in a final ancestor). Two finalized blocks at one height cannot differ under the stated fault assumptions, so "the ancestor at height h on a chain whose F(B) >= h" is unique.
- *One implementation of R1-R4 and R6.* The engine, the proposer policy and the header verifier all call `check_reference`; they differ only in how they build `F(B)` and the ancestor lookup, and both are covered by the differential test (same reason strings for the same input).
- *Repeats.* A repeated reference skips R3 and R6 only (it was checked when first included) and still obeys R2 and R4; a different block or root at the same height is `Conflicting`. At an anchor the repeat baseline is the anchor's `last_ref`, which the caller supplies.
- *Root log.* Apply-then-log with reconciliation from the executor cursor: a crash between the two loses nothing, a conflicting stored root fails the start, a damaged or missing record costs a deferral or an abstention and never a guessed root. A missing root heals once the first block carrying that reference is final (`final_refs`).
- *Profile separation.* v2 identities are unchanged (golden vectors), v3 uses its own id tag and genesis binding, a v2 block refuses a reference, and replay across profile or chain is rejected by the id and signing-message identity checks.

**Findings and fixes (both in this PR).**
1. *R3 ran before R6.* A reference that was too old still caused the ancestor walk, which is as long as the chain, before the O(1) age check refused it; a Byzantine leader could spend that on every proposal it signed. R6 now runs first, so a too-old reference is refused with no lookup and any lookup is bounded by `max_age` plus the finality lag. Test: lookup-count assertions in the boundary test; the mutant that restores the old order is caught. The same pass removed an always-true assertion (`.is_ok() || true`) in that test.
2. *Deferred-vote eviction was arbitrary.* At the cap (64) the engine dropped the first deferred id in hash order, so a stale deferral could displace a recent one. It now drops the lowest round. Test: a validator that never executes keeps a full set covering the most recent two thirds of the lag period with a current newest member; the "evict newest" and "evict arbitrary" mutants are both caught. (A first version of this assertion lived in the L4 test and did not discriminate, because that scenario never reaches the cap; it was replaced, not kept.)

**Limits the review found that the seeding PR must address (not defects here).**
- `child_state` treats an unknown parent-of-parent as the genesis case (F(B) computed from `None`). Today every block above the genesis is retained, so this is sound; after seeding from a checkpoint, blocks below it are NOT in the tree, so the seeded engine must start from the anchor's `ChainRefState` and `(round, height)` of the anchor and its parent, exactly as the header verifier's `Start::Anchor` does. Anything else makes the engine and the verifier disagree about F(B).
- `ancestor_at` must be able to answer from the anchor's `ancestors` list for heights below the checkpoint.
- The root log has integrity checksums, not authentication, and sits in the same trust domain as the safety store. A seeded node has no roots below its checkpoint: it must record the verified checkpoint root and rely on `final_refs` for older repeats, and the `Recovering` gate (not implemented here) must hold signing until that state exists.
- The deferred set is in memory only; a restart drops it, which costs a vote, not safety.
- Leaders are chosen by count, not power, so there is still no lower bound on checkpoint frequency.
