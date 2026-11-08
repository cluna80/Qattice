# Snapshot-recovery components: validation record (Linux, sandbox) — NOT closed; Windows confirmation pending (CLAUDE.md)

Base: `d67255040fe6364df05a973181568fddef700e92` (the hardened specification, #140). Scope: independent codecs, bounded request handling, shadow-state staging and generation-bound installation with crash-recovery
tests. **Disabled and isolated**: `netmsg::decode` still rejects kinds 7 to 14 as unknown; the driver, the engine, the node binary and `MessageLimits` do not reference the new module (checked with a search: only the module and its
tests do); no network path installs a snapshot; pruning does not exist. Existing profile ids, block identity, certificate validity and consensus behavior are unchanged (the only edits to existing files are two module lines and the test include lines).
Checkpoint references and rule R6 are a separate consensus change and are NOT implemented. The interim application's state is a hash chain, so these tests exercise codecs, bounds and storage ordering, not transaction state.

## What exists (`chain-forge-consensus/src/pq_hotstuff/recovery/`)
* `codec`: kinds 7 to 12, `CodecLimits`, manifests with all structural constraints, content-addressed snapshot ids, bounded decoding (nothing allocated from a reported length), typed statuses.
* `requests`: correlation table (peer, kind, request id AND echoed selector), per-(peer, selector) cool-downs, temporary suppression for locally verified invalidity only, non-terminal stall detection, and the serving gate with a reserve-then-refund token bucket, concurrency, spacing and per-peer limits, plus configuration invariants.
* `records` and `install`: generation-bound local records (integrity tags only), the staged installer with the flush barrier, forward-only installs, the start-time recovery table, garbage collection restricted to the installer's own names, and an adapter that installs the interim application's state.
* `tree`: a directory-tree filesystem trait (directories, `fsync` of files and directories, directory rename) with a real-filesystem implementation.

## Results (release mode; `PQHS_SEEDS=10` unless noted)
| Suite | Result | Time |
|---|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204` | 108 passed (31 new), 2 ignored | 22 s |
| same, `PQHS_SEEDS=60` | 108 passed, 2 ignored | 108 s |
| doubles `pq_hotstuff_engine` | 108 passed (31 new), 2 ignored | 45 s |
| foundation / safety / safety_fips204 / wire | 30 / 76 / 11 / 24 passed | <1 s |
| consensus lib / core lib / p2p lib | 98 / 74 / 21 passed | — |
| node default check, `--features pq-devnet` check, `pq_devnet` unit tests, LIVE four-node test | ok, ok, 4 passed, 1 passed | 28 s live |

Crash matrices (sampled crash model, see the spec): first interim install, 54 crash points, 117 outcomes examined; second interim install on top of a completed first, 56 points, 131 outcomes; nested multi-file tree, second install, 82 points, 887 outcomes; nested tree, first
install, 80 points, 873 outcomes. Every outcome of a correct install recovered (no refusal), to the previous generation intact, to a published generation awaiting the engine with a complete tree, or to a completed install; re-running the install from every "previous generation"
outcome succeeded; the node's own files were byte-identical in every outcome.
Two successive installs are tested on the in-memory model (generation 1 then 2, with the first removed only after the second is seeded, a stale record under the second's name refused) and on a real directory, where the installed directory is then opened by the real interim executor, which
executes the next block.

## Mutation check (`mut_recovery.py`: 76 mutants of `codec`, `requests`, `install`, `records`; build errors not counted as catches)
First run 65 of 76 caught. The 11 survivors: three were not real gaps (two redundant lines in the installer, which were removed: the flush barrier's own syncs of the staging directories, which the post-rename syncs of both parents already cover, and a second garbage collection in the discard branch that the common tail of
`start` repeats; and one invalid mutant that only changed a comment) and eight were real test gaps, fixed with new tests: the per-header length bound reported as such, the encoder refusing an empty `OK`, the refund of a reservation (masked by the burst cap in the first test), re-measuring a published tree after a crash window, the recorded Staging phase and
a restart in it, and record version, trailing-byte and type checks. Second run on the eight plus the neighbours of the removed code (15 mutants): 15 of 15 caught. Total: all 73 meaningful mutants caught; the barrier, durability-ordering and record-ordering mutants are caught by the crash matrices, so those tests have teeth.

## Specification corrections made alongside (Revision 3 of `phase5-snapshot-spec.md`)
Garbage collection could have deleted the operational application directory (now a dedicated `generations/` directory and exact-name matching); install records were not generation-bound (now per-generation files, the pointer names the record's digest, the directory is derived from the generation); installs were not forward-only (now required); the crash window after the pointer swap is an explicit start-time table;
status combinations per kind were underspecified; the barrier's redundant staging syncs were removed from the text.

## Not done / limits
Not implemented: checkpoint references and R6, the root log, header and snapshot serving or consumption over the network, engine seeding from an install record, the post-install continuity check, the `Recovering` signing gate, liveness tests of group L, any node wiring. The crash model is a sampled model of ordering guarantees, not exhaustive and not NTFS power-loss behavior. `same_device` is only checked on Unix (other platforms assume true).

## Windows (owner to run; record separately)
```
git fetch origin feat/pq-hotstuff-2-recovery-components && git checkout feat/pq-hotstuff-2-recovery-components && git rev-parse HEAD
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204 2>&1 | grep -E "test result|FAILED"
cargo test --release -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine 2>&1 | grep -E "test result|FAILED"
```
The real-directory test (`two_successive_installs_on_a_real_directory...`) also exercises directory rename and `fsync` of files and directories on NTFS; it can show that they succeed, not that they are power-loss durable.
