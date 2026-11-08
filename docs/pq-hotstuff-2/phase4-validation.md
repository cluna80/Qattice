# PR 4 validation (Linux, sandbox) — NOT closed; Windows confirmation pending (CLAUDE.md)

Base: `e3d9209a4c8302dbc06a51cd3fe2c549deb449c5` (PR 3 head, docs-only on top of the Windows-confirmed `6ab56ac`). Scope: execution handoff, node driver,
four-node fixed-validator-set devnet. Pruning is NOT implemented; finalized payloads are retained. See `phase4-execution-handoff.md`, `phase4-devnet.md`.

## Linux results (release mode; `PQHS_SEEDS=10` unless noted)
| Suite | Result | Time |
|---|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204` | 68 passed, 1 ignored | 20 s |
| same, `PQHS_SEEDS=60` | 68 passed, 1 ignored | 109 s |
| doubles `pq_hotstuff_engine` | 68 passed, 1 ignored | 41 s |
| `pq_hotstuff_foundation` | 30 passed | <1 s |
| `pq_hotstuff_safety` / `_safety_fips204` / `_wire` | 76 / 11 / 24 passed | <1 s |
| consensus lib (pq-hotstuff) / core lib / p2p lib | 98 / 74 / 21 passed | — |
| `cargo check -p chain-forge-node` (default features) and `--features pq-devnet` | ok | — |
| node `pq_devnet` unit tests (key loader, counter, transport) | 4 passed | 1 s |
| **LIVE** `pq_devnet_live` (four processes, real ML-DSA-65) | 1 passed | 38 s |

The live test: all four nodes execute height 6 (about 2 s); one node is killed, the other three finalize 4 more blocks, the node restarts from disk and
catches up; node 3 is partitioned from the others (files `partition.txt`), the majority finalizes 5 more blocks while node 3 stays frozen, the partition heals
and node 3 catches up by block sync (`sync_requests > 0`); all four processes are killed and restarted and the chain continues past its old height. After each
phase every pair of nodes agrees on block id AND application state digest at every height both report (12 to 53 cross-node comparisons per phase), and no node
reports a fatal error. Runs are timing-dependent; the figures above are from one run.

## What the live run is, and is not
It exercises proposal, certification, finalization, the execution handoff with a durable cursor, crash recovery, partition/rejoin, and the safety store
(real, with the NON-PRODUCTION file counter). The application is the DEVNET-INTERIM hash chain over opaque payloads: it is NOT transaction-execution validation.

## Mutation check (`mut_driver.py`: 17 mutants of `exec.rs`/`driver.rs`, doubles suite, build errors not counted as catches)
First run: 12 of 17 caught. Survivors and what each showed: D04 (stored vote not re-sent: the restart test passed vacuously when nothing was sent), D07
(conflicting commit swallowed: the classification had no direct test), D08 (lost commit markers not rewritten), D10 (sync response not validated by the driver),
D11 (start does not validate the configuration). Tests were added for each (the classification was extracted as `classify_engine_error`), and the strengthened
crash test now also requires an acknowledged apply to be durable in every post-crash state. Second run: **17 of 17 caught**. The real-crypto run of the same
tests passes; the mutation run used the doubles suite for speed.

## Changes outside the new files (review these)
* `chain-forge-consensus/Cargo.toml`: the renamed `fips204-crypto` dependency is removed; `pq-hotstuff-fips204` now enables `chain-forge-crypto/fips204-backend`.
  Needed because Cargo rejects one crate depending on the same package twice under different names once the node enables both `real-crypto` and the FIPS 204
  adapter. The three Rust paths that named `fips204_crypto` now name `chain_forge_crypto`. No behavior change (the same backend crate is used).
* `Engine::config()`, `SyncClient::is_pending()`: read-only accessors. `.gitignore`: `*.seed`. `chain-forge-node`: feature `pq-devnet`, one bin, one test, one module.

## Windows (owner to run; record separately)
```
git fetch origin feat/pq-hotstuff-2-node-driver && git checkout feat/pq-hotstuff-2-node-driver && git rev-parse HEAD
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204 2>&1 | grep -E "test result|FAILED"
cargo test --release -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine 2>&1 | grep -E "test result|FAILED"
cargo test --release -p chain-forge-node --features pq-devnet --test pq_devnet_live -- --nocapture
```
The live test spawns four processes and uses free local ports; allow the Windows firewall prompt for `pq_devnet_live`/`pq-devnet-node` on loopback if asked. Set
`PQDEV_KEEP=1` to keep the temporary node directories (each holds a devnet seed; they are in the OS temp directory, never in the repository).

## Still open (unchanged by this PR)
U5 payload codec; owner approval of the draft QC/TC layouts; PO-4; D2 certificate sizing for 1,000 validators (this PR adds no committee); production key
storage (#109) and a real monotonic counter; authenticated snapshot recovery and defensive pruning (next, against this execution boundary).

## Windows results (supplied by the owner; MINGW64, `C:\Dev\qattice-main-wt`, branch `feat/pq-hotstuff-2-node-driver`) — recorded separately
The paste did not include `git rev-parse HEAD`, so the commit is **not confirmed by the paste**. The test counts (68, including the tests added last) and the
presence of `pq_devnet_live` match the pushed head `c7b2ffb2e4c5d03f344dce63ae3668491c6a5af6`; the owner is asked to confirm the hash. Release mode:
| Run | Result | Time |
|---|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204`, default seeds | 68 passed, 0 failed, 1 ignored | 182.34 s |
| doubles `pq_hotstuff_engine`, default seeds | 68 passed, 0 failed, 1 ignored | 420.88 s |
| **LIVE** `pq_devnet_live` (four processes, real ML-DSA-65) | 1 passed | 35.08 s |
The live run on Windows: all four executed height 6 in 1.8 s; a killed node recovered and caught up; the partitioned node rejoined (heights [22, 21, 20, 21]
right after healing); after a full restart the chain continued from 25 to 26; every phase reported agreement on block id and state digest (18, 26, 55 and 14
cross-node comparisons) and no fatal error. The 60-seed real-crypto run was not requested for this commit and has not been run on Windows.
