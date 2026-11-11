# QAT-06 — Adversarial Simulation Campaign

**Status: sandbox compile-verified. Windows confirmation required before ✅.**

Branch: `feat/pq-hotstuff-2-qat06-adversarial-sim` (stacked on `feat/pq-hotstuff-2-real-crypto` / PR #135)

---

## Spec requirement (§12 Phase 0 gate)

> **Model-based simulation:** port `tendermint/engine/sim.rs` (staggered start, slow links, crash/restart,
> Random / SplitBrain / Withhold adversaries within f, fork detection beyond f) to drive PQ-HotStuff.
> **Gate:** thousands of seeded runs with agreement, no unsafe signing, and termination after GST.

---

## Coverage mapping

### Already covered by PR #134 / #135 (10 seeds each, Windows-confirmed 2026-11-08)

| ID | Test name | What it covers |
|----|-----------|----------------|
| E1 | `sim_all_honest_agree_and_make_progress_after_gst` | 4 honest, baseline agreement + liveness |
| E2 | `sim_one_silent_validator_within_the_fault_bound` | f=1 silent; quorum still forms |
| E3 | `sim_one_equivocating_validator_cannot_split_the_chain` | f=1 equivocator (twin proposals) |
| E4 | `sim_honest_nodes_crash_and_restart_without_double_signing` | crash/restart; safety store survives |
| E5 | `sim_restarts_together_with_an_equivocator` | crash/restart + equivocator combined |

### Added by this PR (QAT-06, 10 seeds default; soak with PQHS_SEEDS=1000)

| ID | Test name | What it covers | Spec reference |
|----|-----------|----------------|----------------|
| S1 | `sim_qat06_s1_staggered_start_agrees_and_makes_progress` | nodes join at random times in [0,80) | §12 "staggered start" |
| S2 | `sim_qat06_s2_slow_links_agree_and_make_progress` | 25% msgs + 15 extra ticks | §12 "slow links" |
| S3 | `sim_qat06_s3_partition_heals_and_converges` | 2+2 partition t=30..230, heals, converges | §12 partition |
| S4 | `sim_qat06_s4_isolated_node_rejoins_and_catches_up` | 1 isolated node rejoins, catch-up sync | §12 partition |
| S5 | `sim_qat06_s5_withhold_adversary_within_fault_bound_cannot_violate_safety` | Withhold (f=1), split-lock pattern | §12 "Withhold within f" |
| S6 | `sim_qat06_s6_splitbrain_adversary_within_fault_bound_cannot_violate_safety` | SplitBrain (f=1), two proposals to disjoint halves | §12 "SplitBrain within f" |
| S7 | `sim_qat06_s7_crash_restart_with_slow_links_never_double_signs` | crash/restart + 20% slow links | §12 "crash/restart" extended |
| S8 | `sim_qat06_s8_fork_is_detected_beyond_the_fault_bound` | 2 Byzantine (f+1), ConflictingCommit raised | §12 "fork detection beyond f" |
| S9 | `sim_qat06_s9_withhold_plus_restarts_cannot_violate_safety` | Withhold (f=1) + crash/restart | §12 combined |
| S10 | `sim_qat06_s10_combined_adversity_within_fault_bound_cannot_violate_safety` | SplitBrain + stagger + slow links | §12 "thousands of seeded runs" |

---

## Adversary models

**Withhold** (`Role::Withhold`): the Byzantine validator's votes and timeouts are forwarded to only a randomly-chosen half of the network. Different subsets see different round messages — the split-lock scenario the two-chain lock rule (§5 rule 3: `hqr ≥ parent_round`) is designed to defeat. Matches `Adversary::Withhold` in `tendermint/engine/sim.rs`.

**SplitBrain** (`Role::SplitBrain`): the Byzantine leader sends two different signed proposals — one to even-indexed nodes, one to odd-indexed. Matches `Adversary::SplitBrain` in `tendermint/engine/sim.rs`. Within f=1 (n=4), honest nodes must not commit conflicting blocks.

**Fork detection** (S8): with 2 Byzantine validators (f+1 = 2), the engine raises `EngineError::ConflictingCommit` when it detects a would-be fork. The test asserts this is raised at least once across the campaign; it does **not** assert agreement (which is explicitly not guaranteed beyond the fault bound).

---

## Gaps remaining after this PR

| Gap | Why open | Gate |
|-----|----------|------|
| Named counterexamples in-sim | §5 "voting without rule 3 forks" / "non-consecutive QC forks" are unit-tested in `pq_hotstuff_safety` but not wired into the sim | QAT-06 / Phase 0 |
| 1000-seed soak on Windows | Gate requires "thousands of seeded runs"; 10 seeds are the default; needs `PQHS_SEEDS=1000` | QAT-06 gate closure |
| Phase 1 persistence tests | §7 safety-state persistence, §8 reconfiguration | QAT-07 / Phase 1 |
| PQ-HotStuff-2 live devnet | 4-node `genesis-4node-pq-hotstuff.json` with real OS-RNG keys | QAT-08 / Phase 2 |

---

## How to run

```bash
# Fast (non-cryptographic doubles), 10 seeds:
cargo test -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine -- sim_qat06 --nocapture

# Real ML-DSA-65, 10 seeds:
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204 -- sim_qat06 --nocapture

# 1000-seed soak (required for gate closure):
PQHS_SEEDS=1000 cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204 -- sim_qat06 --nocapture
```

---

## Sandbox evidence

### Fast doubles (non-cryptographic, 10 seeds each)

```
cargo test --release -p chain-forge-consensus --features pq-hotstuff \
  --test pq_hotstuff_engine -- sim_qat06 --nocapture

running 10 tests
test sim_qat06_s1_staggered_start_agrees_and_makes_progress ... ok
test sim_qat06_s2_slow_links_agree_and_make_progress ... ok
test sim_qat06_s3_partition_heals_and_converges ... ok
test sim_qat06_s4_isolated_node_rejoins_and_catches_up ... ok
test sim_qat06_s5_withhold_adversary_within_fault_bound_cannot_violate_safety ... ok
test sim_qat06_s6_splitbrain_adversary_within_fault_bound_cannot_violate_safety ... ok
test sim_qat06_s7_crash_restart_with_slow_links_never_double_signs ... ok
test sim_qat06_s8_conflicting_commit_is_detected_not_silently_accepted ... ok
test sim_qat06_s9_withhold_plus_restarts_cannot_violate_safety ... ok
test sim_qat06_s10_combined_adversity_within_fault_bound_cannot_violate_safety ... ok
test result: ok. 10 passed; 0 failed; 0 ignored; finished in 121.79s
```

### Real ML-DSA-65 / FIPS 204 (10 seeds each)

```
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 \
  --test pq_hotstuff_engine_fips204 -- sim_qat06 --nocapture

running 10 tests
test sim_qat06_s1_staggered_start_agrees_and_makes_progress ... ok
test sim_qat06_s2_slow_links_agree_and_make_progress ... ok
test sim_qat06_s3_partition_heals_and_converges ... ok
test sim_qat06_s4_isolated_node_rejoins_and_catches_up ... ok
test sim_qat06_s5_withhold_adversary_within_fault_bound_cannot_violate_safety ... ok
test sim_qat06_s6_splitbrain_adversary_within_fault_bound_cannot_violate_safety ... ok
test sim_qat06_s7_crash_restart_with_slow_links_never_double_signs ... ok
test sim_qat06_s8_conflicting_commit_is_detected_not_silently_accepted ... ok
test sim_qat06_s9_withhold_plus_restarts_cannot_violate_safety ... ok
test sim_qat06_s10_combined_adversity_within_fault_bound_cannot_violate_safety ... ok
test result: ok. 10 passed; 0 failed; 0 ignored; finished in 49.82s
```

Sandbox: 2026-11-11, Linux container, commit pending.

<!-- Windows BossKing MINGW64 confirmation paste goes here (required for ✅ per CLAUDE.md policy) -->
