# PR 3 validation (Linux, sandbox) — NOT closed; Windows confirmation pending (CLAUDE.md)

Base: `98d2822c69234b610b5f7c28ff75820b835b8a00` (#135). Scope: p2p topics, validated sync, persistent block store + recovery, pacemaker
backoff, message envelope + limits. Pruning is NOT implemented (see `phase3-pruning-prerequisites.md`); finalized payloads are retained.

## Linux results (release, `PQHS_SEEDS=10` unless noted)
| Suite | Result | Time |
|---|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204` (feature `pq-hotstuff-fips204`) | 55 passed, 1 ignored | 19 s |
| same, `PQHS_SEEDS=60` | 54 passed (before the last test was added) | 105 s |
| doubles `pq_hotstuff_engine` | 55 passed, 1 ignored | 40 s |
| `pq_hotstuff_foundation` | 30 passed | <1 s |
| consensus lib (pq-hotstuff) / core lib / p2p lib | 98 / 74 / 21 passed | — |
| `cargo check -p chain-forge-node` | ok | — |

Mutation check (`mut_sync.py`, 29 mutants, real-crypto suite, 10 seeds, build errors not counted as catches): 28 caught on the first valid run.
R02 survived: with a missing block `commit_through` still fails closed, so only the height-mismatch case depended on the check. Test
`...forged_or_damaged_stored_block...` now covers a marker whose height disagrees with its block; R02 is then caught (29 of 29). An earlier run
reported 29/29 but was invalid (sim coverage tests failed at 3 seeds regardless; a build error counted as a catch); it is not evidence.

## Windows (owner to run; record results separately)
```
git fetch origin feat/pq-hotstuff-2-sync-storage && git checkout feat/pq-hotstuff-2-sync-storage
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204 -- --nocapture
export PQHS_SEEDS=60   # then repeat the line above
cargo test --release -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine
cargo test --release -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_foundation
```

## Windows confirmation (supplied by the owner; MINGW64, `C:\Dev\qattice-main-wt`) — recorded separately from the Linux results
Commit `6ab56accf221cb01a88915d069efcc33176d6269` (`git rev-parse HEAD` printed by the owner), release mode:
| Run | Result | Time |
|---|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204`, default seeds | 55 passed, 0 failed, 1 ignored | 175.37 s |
| same, `PQHS_SEEDS=60` | 55 passed, 0 failed, 1 ignored | 199.26 s |
| doubles `pq_hotstuff_engine`, `PQHS_SEEDS=60` still exported | 55 passed, 0 failed, 1 ignored | 481.24 s |
| `pq_hotstuff_foundation` (earlier paste, same branch) | 30 passed | 0.03 s |

This confirms the PR 3 engine, sync, store, pacemaker and envelope tests on Windows at the pinned commit. It does not close any milestone: pruning is
unimplemented, and the owner decisions listed in the PR remain open. The earlier first paste on this branch lacked result lines and is superseded by this one.
