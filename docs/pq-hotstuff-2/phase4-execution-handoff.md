# PQ-HotStuff-2 execution handoff (PR 4)

Implemented in `chain-forge-consensus/src/pq_hotstuff/exec.rs` and used by `driver.rs`. **The application in this PR is a DEVNET-INTERIM hash chain.
Nothing here is transaction-execution validation.**

## The boundary
| Element | Definition |
|---|---|
| Finalized block identity | `Committed { id, round, height, payload }`: `id` is the `block_id` that commits to the payload hash, the parent QC and any TC. Finalized under the implemented two-chain commit predicate and the protocol's stated fault and cryptographic assumptions. |
| Durable execution cursor | `ExecCursor { height, block_id, state_digest }`: the last block whose effects are durable. Height 0 means nothing executed. |
| Atomicity | The executor makes the block's effects AND the new cursor durable as ONE record (write, sync, rename, sync directory). There is no state in which effects exist without the cursor, or the reverse. |
| Acknowledgement | `Executor::apply` returning `Ok` is the acknowledgement. A test asserts an acknowledged apply is durable in every post-crash state. |
| Ordering | `apply` accepts only `cursor.height + 1` (`OutOfOrder` otherwise, state unchanged): duplicates and skipped heights are impossible, not just unlikely. |
| Replay | On every start the driver recovers committed history from the block store, then applies `committed_after(cursor.height)` in order. The executor's own cursor decides what is replayed, so a crash before the effects, between effects and the driver noticing, or after, all converge to exactly-once. |
| Fail closed | A cursor above the recovered committed tip (`ExecutorAhead`), or whose block id differs from the recovered block at that height (`Diverged`), or a damaged/foreign state file (`Corrupt`/`ForeignChain`), stops startup. Damaged executor state is never treated as fresh. Nothing resets signing safety. |

Order of durable effects for one block, as the driver applies engine outputs: block stored, then commit marker stored, then executor applies, then
anything that follows is sent. A lost commit marker is re-derived from the recovered certificates and rewritten at start.

## Reuse of existing Qattice execution components
Checked, not integrated. `chain-forge-execution::Executor::execute_block(height, Vec<Transaction>, &mut StateStore, timestamp_ms)` consumes decoded
`Transaction`s against a `StateStore` (which has its own Merkle state roots and snapshots). A block payload is currently opaque bytes, and the
canonical payload codec is open item **U5**. Until U5 is decided there is nothing to decode a payload into `Transaction`s, so the real adapter cannot
be written without inventing a codec, which this work does not do. The `Executor` trait here is the slot: a future adapter implements `apply` by
decoding the payload, calling `execute_block`, and making the resulting `StateStore` commit and the cursor durable atomically (that atomicity
requirement is the part the existing node's persistence layer would have to meet; not assessed here).

`StateStore`'s own state root is NOT used as a consensus state root. This work introduces no consensus state root and no checkpoint certification.

## What this does NOT establish
Transaction execution, fees, nonces, gas, state roots, snapshot recovery, or any pruning. Pruning stays disabled and unimplemented; finalized
payloads are retained (the driver keeps every block and `committed_after(0)` returns them all; a test asserts it).

## Tests (shared body, run on doubles and on real ML-DSA-65)
`the_interim_app_applies_in_order_and_refuses_anything_else`, `a_crash_at_any_point_of_applying_a_block_leaves_the_old_or_the_new_state_never_a_torn_one`,
`damaged_or_foreign_executor_state_is_never_treated_as_fresh`, `a_driver_restart_replays_only_what_the_executor_missed_and_resends_its_vote_byte_for_byte`,
`a_driver_refuses_to_start_when_the_executor_is_ahead_of_or_diverged_from_the_recovered_history`,
`a_block_store_failure_is_fatal_stops_the_node_and_recovery_never_signs_a_second_vote`.
