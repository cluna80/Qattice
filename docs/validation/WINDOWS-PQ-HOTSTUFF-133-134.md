# Windows validation record: PQ-HotStuff-2 PRs #133 and #134

Recorded 2026-11-08 from the output the owner pasted (developer machine "BossKing", Git Bash / MINGW64, worktree `C:\Dev\qattice-main-wt`, detached HEAD at each pinned commit). The claude sandbox did not run these; this file only records what the owner reported. Nothing here is a roadmap change.

## #133 engine foundation, commit `cb68259f289b681ebf12b268664d2abf00ad7b66` (`git rev-parse HEAD` confirmed)

| Command | Result |
|---|---|
| `cargo test -p chain-forge-core --lib` | 74 passed, 0 failed |
| `cargo test -p chain-forge-consensus --lib` | 98 passed, 0 failed (includes the Tendermint engine and simulations) |
| `cargo test -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_foundation --test pq_hotstuff_safety --test pq_hotstuff_wire` | foundation 30, safety 76, wire 24: all passed (safety 52.70 s in debug) |
| `cargo check -p chain-forge-node` | finished without errors (only pre-existing warnings in code the PR does not touch) |

## #134 engine core, commit `164e44daa1bc18d46511c6869d71ebac738081eb` (`git rev-parse HEAD` confirmed; includes #133)

| Command | Result |
|---|---|
| `cargo test --release -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine --test pq_hotstuff_foundation --test pq_hotstuff_safety --test pq_hotstuff_wire` | engine 32 passed, 1 ignored (diagnostic), 68.89 s; foundation 30; safety 76 (1.00 s); wire 24: all passed |

The five simulation campaigns (all honest, one silent, one equivocator, crash/restart, restart plus equivocator; 10 seeds each) passed on Windows.

## What this does and does not show
* Shows: the foundation and the fixed-validator-set engine behave on Windows as on Linux at these commits.
* Does not show: behaviour with real FIPS 204 signatures in the engine (these simulations use the non-cryptographic test doubles); the PO-4 epoch-transition question; anything about networking, sync or persistence beyond the safety store.
* This validates the two draft PRs; neither is merged.

---

## #135 real FIPS 204 ML-DSA-65 engine validation, commit `0b48f27d20efa57c9e3df06f34979f0089d3bc01` (`git rev-parse HEAD` confirmed)

Recorded 2026-11-08 from output the owner pasted (same machine and worktree as above). Command:
`cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204 --test pq_hotstuff_engine --test pq_hotstuff_safety_fips204 --test pq_hotstuff_foundation --test pq_hotstuff_safety --test pq_hotstuff_wire`

| Suite | Result |
|---|---|
| `pq_hotstuff_engine` (fast doubles, 10 seeds per scenario) | 36 passed, 1 ignored (diagnostic), 70.65 s |
| `pq_hotstuff_engine_fips204` (REAL ML-DSA-65, 10 seeds per scenario) | 36 passed, 1 ignored (diagnostic), 27.26 s |
| `pq_hotstuff_safety_fips204` | 11 passed |
| `pq_hotstuff_foundation` | 30 passed |
| `pq_hotstuff_safety` | 76 passed |
| `pq_hotstuff_wire` | 24 passed |

Shows: the engine, certificate verifier and safety store behave on Windows with real FIPS 204 signatures as on Linux, in all five scenarios (honest, silent, equivocating, crash/restart, restart plus equivocator), including the wrong-key, wrong-context and cross-chain rejection tests. Does not show: the 60-seed soak (Linux only), networking, sync, persistence beyond the safety store, node wiring, or anything about epoch transitions. Nothing is merged.

### #135 soak on Windows: 60 seeds per scenario, commit `0b48f27d20efa57c9e3df06f34979f0089d3bc01`

Recorded 2026-11-08 from output the owner pasted. `export PQHS_SEEDS=60` then
`cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204`
(`git rev-parse HEAD` confirmed). Result: 36 passed, 0 failed, 1 ignored (diagnostic), finished in 163.80 s. All five scenarios (honest, silent, equivocating,
crash/restart, restart plus equivocator) ran 60 seeds each with real ML-DSA-65 signatures, with no agreement, double-signing or commit-conflict violation and
progress after the network stabilized. Linux ran the same soak in 68.4 s. A first attempt that set the variable only on the `cd` command ran the default 10
seeds and is not counted as a soak.
