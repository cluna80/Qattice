# Phase 0 / Phase 0.5 Closeout

**Updated:** 2026-11-15  
**Branch:** `feat/pqhs2-fips204-signing`  
**Merge candidate:** commit `eebbcdb`  
**Compile baseline:** `eebbcdb` — 39 live-test binaries, 0 errors (standard build); `pqhs2_*` require `--features pq-hotstuff`  
**Chain:** Qattice (`qcb-devnet-4node-mldsa` / per-test variants)  
**Engine version:** 0.1.0

---

## 1. Scope

This document records the Phase 0 and Phase 0.5 acceptance evidence for the
Qattice protocol. It covers:

- **Phase 0 milestones P0-1..P0-9** (original closeout 2026-10-31; reproduced here for
  completeness)
- **Phase 0.5 protocol hardening H0-1..H0-12** (cumulative through 2026-11-15)
- **BIZ-PRE gates 1–5** (current status 2026-11-15)
- **Full live-test sweep** (39 test binaries; Windows evidence per test)
- **Known limitations and open owner decisions**

The original P0-1 closeout (two-machine ML-DSA devnet, state-root match, controlled
restart) was written 2026-10-31 and is preserved in full at the end of this document
(§ P0-1 Original Evidence). The table in §3 supersedes it for milestone tracking.

---

## 2. Cryptographic Baseline

All production paths and new test fixtures use **ML-DSA-65** (`pqc-native`,
`ml-dsa-65`, `keys/mldsa/`). Ed25519 is retired from new Qattice tests
(owner decision 2026-10-30, recorded in `CLAUDE.md`). Classical-compatibility fixtures
(`genesis-val-jail.json`, root-level `keys/*.key.json`) survive for regression tests
only and must not be copied into new test genesis files.

---

## 3. Phase 0 Milestones (P0-1..P0-9)

| Milestone | Description | Windows Evidence | Status |
|-----------|-------------|-----------------|--------|
| **P0-1** | Two-machine ML-DSA consensus devnet | BossKing ↔ bossking-node Ethernet; state_root `a92a28fed791…` on both machines; controlled restart; `95b9e51` baseline | ✅ 2026-10-31 |
| **P0-2** | DIS live-test sweep (all suites) | `dis_auth_live`, `dis_003a..003e`, `dis_002a`, `dis_002b_migration`, `dis_002b_recovery` — all Windows-confirmed 2026-10-31 (#40) | ✅ 2026-10-31 |
| **P0-3** | ML-DSA transaction: `mldsa_tx_live` P0-3..P0-6 | `mldsa_tx_live` Windows-confirmed (#24, 2026-10-28) | ✅ 2026-10-28 |
| **P0-4** | ML-DSA transaction state root stable | Same test run as P0-3 | ✅ 2026-10-28 |
| **P0-5** | ML-DSA transaction: reject Ed25519 tx | Same test run as P0-3 | ✅ 2026-10-28 |
| **P0-6** | ML-DSA transaction: reject wrong-chain tx | Same test run as P0-3 | ✅ 2026-10-28 |
| **P0-7** | State root stability (deterministic across restarts) | Covered by devnet and crash-recovery tests | ✅ |
| **P0-8** | Consensus safety and finality | `consensus_safety_live` 3/3; adversarial gossip 3/3×3; equivocation detection; `adversarial_equivocation_over_gossip` on Ed25519 and ML-DSA; partition recovery sandbox-only (no iptables on Windows) | ✅ |
| **P0-9** | PoCD reward (application layer) | `pocd_reward_live` Windows-confirmed (#30, 2026-10-30); classified as application layer | ✅ 2026-10-30 |

---

## 4. Phase 0.5 Protocol Hardening (H0 Milestones)

| Milestone | Description | Windows Evidence | Status |
|-----------|-------------|-----------------|--------|
| **H0-1 / H0-2** | Deterministic participation, state-root binding, liveness jails without burning, Byzantine-robust miss counting, genesis liveness policy | Integration candidate #31, 2026-10-30; node 257/257 | ✅ 2026-10-30 |
| **H0-3** | Crash-safe persistence (P-02a) | `h0_3_crash_recovery_live` C-01..C-11 (12/12); C-01 5/5 repeated; BossKing `b38bc0c` 2026-11-04 | ✅ 2026-11-04 |
| **H0-3b** | PERSIST-001 — crash-safe persistence beyond H0-3 | `storage_v2_live` 8/8; proposal-signing guard; PERSIST-HALT-1/1b/PERSIST-APPEND-1/PERSIST-DIR-1 unit tests; BossKing `b38bc0c` 2026-11-04; owner acceptance 2026-11-04 | ✅ 2026-11-04 |
| **H0-4** | Nonce replay prevention | `h0_4_nonce_replay_live` — 24/24 integration candidate sweep 2026-10-30 | ✅ 2026-10-30 |
| **H0-5** | Execution atomicity | `h0_5_atomicity_live` H5-1..H5-5 (66.83 s); BossKing 2026-10-30; re-confirmed 2026-11-02 | ✅ 2026-10-30 |
| **H0-6** | Keybind race | `h0_6_keybind_race_live` — integration candidate sweep 2026-10-30 | ✅ 2026-10-30 |
| **H0-7** | Supply conservation | `h0_7_supply_conservation_live` S-01..S-06 (83.69 s); BossKing 2026-10-30; re-confirmed S-01..S-06 51.93 s 2026-11-02 | ✅ 2026-10-30 |
| **H0-8** | Genesis peer verification | `h0_8_genesis_peer_verification_live` — 24/24 integration candidate sweep 2026-10-30 | ✅ 2026-10-30 |
| **H0-9** | Validator fixtures / harness | Validator fixtures and harness; H0-9 merged (#42); Windows integration sweep 2026-11-02 | ✅ 2026-11-02 |
| **H0-10** | DIS-003E — timelock expiry enforcement | `dis_003e_timelock_live`; BossKing 2026-11-01 (D 38.77 s, E 55.78 s) | ✅ 2026-11-01 |
| **H0-11A** | Epoch-boundary eviction | `validator_eviction_live` EV-01..03 (88.83–89.70 s); state root `48d58b5f…`; BossKing 2026-11-02; re-confirmed 2026-11-03 on `main` `b9f1e7e` | ✅ 2026-11-02 |
| **H0-11B jail** | Jail enforcement, epoch accounting, restart committee | `validator_jail_live` JL-01..JL-09 (670.20–686.27 s); roots `51136494…` / `eebbee53…` / `33362db6…`; BossKing 2026-11-02 | ✅ 2026-11-02 |
| **H0-11B resume** | Re-entry after unjail | `h0_11b_resume_validator_live` RV-01..RV-09 (637 s); commit `2db43df`; BossKing 2026-11-15 | ✅ 2026-11-15 |
| **H0-11B auto-suspend** | Automatic suspension gate (`automatic_suspension_enabled`) | `h0_11b_auto_suspend_live` AS-01..AS-06 (842 s); Dave auto-jailed epoch 22 after liveness+grace window; 3-node state-root agreement; Carol restart with persistence; commit `e687643`; BossKing 2026-11-15. **Private-fixture only (`genesis-auto-suspend.json`). Production-genesis enablement is a separate owner decision.** | ✅ 2026-11-15 |
| **H0-11C** | Equivocation detection + penalty | `h0_11c_equivocation_live` EQ-01..EQ-04 (67.00 s); commit `66ff2dd`; `--features pq-hotstuff`; BossKing 2026-11-15. **H0-11C penalty amount and re-entry policy set at launch-set time.** | ✅ 2026-11-15 |
| **H0-11D** | Bootstrap-validator retirement | `validator_eviction_live` (H0-11D suite) BR-01..BR-09 (9/9); commit `58c8bfb`; BossKing 2026-11-15. **Activation epoch number and grace period length set at launch-set time.** | ✅ 2026-11-15 |
| **H0-12** | (Merged; regression-confirmed in H0-11 sweep 2026-11-02) | Node 336/0 on merged `main` after integration 2026-11-02 | ✅ 2026-11-02 |

---

## 5. BIZ-PRE Gates

| Gate | Description | Status |
|------|-------------|--------|
| BIZ-PRE-1 | Protocol hardening (H0-5, H0-7) | ✅ Windows-confirmed 2026-10-30; re-confirmed 2026-10-31 and 2026-11-02 |
| BIZ-PRE-2 | DIS account security and recovery (DIS-003D, DIS-003E) | ✅ DIS-003D 2026-10-30, DIS-003E 2026-11-01 |
| BIZ-PRE-3 | DIS standalone product (independent crypto review) | 🔲 Crypto review gates DIS-CORE-001, DIS-PQ-001, DIS-PRIV-001 not yet passed |
| BIZ-PRE-4 | FeeSponsor (FS-03 live authorization) | 🔲 Not started |
| BIZ-PRE-5 | Validator onboarding (H0-11 policy + implementation) | ✅ **Private-fixture validation Windows-confirmed 2026-11-15** (commit `e687643`). Scope: H0-11A epoch eviction ✅, H0-11B jail/resume/auto-suspend ✅, H0-11C equivocation ✅, H0-11D bootstrap retirement ✅. Production-genesis enablement of automatic suspension is a separate owner decision. |

---

## 6. Live-Test Sweep — 39 Tests, Merge Candidate `eebbcdb`

### 6.1 Code-change impact analysis

The following production source files changed on this branch vs `main`:

| File | Change | Behavioral impact on existing tests |
|------|--------|-------------------------------------|
| `chain-forge-core/src/lib.rs` | Added `GenesisLiveness.automatic_suspension_enabled` (serde default=false) and `LivenessParams.automatic_suspension_enabled` | None — defaults to false for all existing genesis files |
| `chain-forge-execution/src/lib.rs` | Added `TxBody::ResumeValidator`, fee multiplier for it | None — existing tests do not submit `ResumeValidator` |
| `chain-forge-node/src/node.rs` | Pass 5 liveness evaluation in `commit_block`; `ResumeValidator` unjail wiring | Pass 5 adds warn logs only; produces no state mutations unless `automatic_suspension_enabled=true`. Existing genesis files do not set this flag. `suspension_tracker` changes are in-memory only and do not affect state root. |
| `chain-forge-slashing/src/lib.rs` | Added `EquivocationEvidence.epoch` field (serde default=0) | Fully backward-compatible; evidence records without epoch field deserialize to epoch=0 |
| `chain-forge-validators/src/bootstrap_retirement.rs` | New module: `compute_retirement_outcome` | **Not wired into `node.rs`**. Library-only. No node execution path change. |
| `chain-forge-validators/src/liveness_policy.rs` | New module: `evaluate_liveness_policy`, alert tiers | Called only from Pass 5 in `commit_block`; produces only advisory warn logs for genesis files without auto-suspend |
| `chain-forge-validators/src/lib.rs` | Added `suspend_eligible()`, `tier_o_or_higher()`, `validators()` helpers; `is_admitted()`/`admitted_ids()`/etc. for retirement | Used only by H0-11B/C/D test paths |

**Conclusion:** no production code change on this branch alters the state-root or
consensus behavior for genesis files that do not set `automatic_suspension_enabled=true`.
All existing tests use genesis files without that flag. Their carry-forward evidence
remains valid at the code level.

**H0-4 and H0-6 are already Windows-confirmed on this branch:** commits `d585e42`
(H0-4 NR-05 overflow guard), `1fa8b75` (H0-6 KB-01), and `5174e28` (H0-6 KB-02)
are all on `feat/pqhs2-fips204-signing` and were confirmed on BossKing 2026-11-14.

### 6.2 Per-test evidence table

| Test | Scenarios | Last Windows run | Commit | Branch status |
|------|-----------|-----------------|--------|---------------|
| `attestation_live` | guard, coordinator gate | PR #40, 2026-10-31 | pre-branch | ⚠ pending re-run |
| `bootstrap_order_live` | 4-node start order × 3 | 24/24 sweep, 2026-10-30 | pre-branch | ⚠ pending re-run |
| `consensus_safety_live` | prevote/precommit/lock/restart | #18–24, Windows-confirmed | pre-branch | carry-forward valid |
| `dis_002a_key_rotation_live` | key rotation | DIS-002A, 2026-10-31 | pre-branch | ⚠ pending re-run |
| `dis_002b_migration_live` | B-01..B-08 | 5/5 BossKing, 2026-11-03 | pre-branch | ⚠ pending re-run |
| `dis_002b_recovery_live` | B-09..B-13 | DIS-002B, 2026-11-01 | pre-branch | ⚠ pending re-run |
| `dis_003a_policy_lifecycle_live` | policy lifecycle | #28/32, 2026-10-30 | pre-branch | ⚠ pending re-run |
| `dis_003b_guardian_update_live` | D-01..D-09 | #40, 2026-10-31 | pre-branch | ⚠ pending re-run |
| `dis_003c_replay_attack_live` | replay rejection | #28, 2026-10-30 | pre-branch | ⚠ pending re-run |
| `dis_003d_expiry_live` | F-00..F-08 | #32, 2026-10-30 | pre-branch | ⚠ pending re-run |
| `dis_003e_timelock_live` | pending-recovery sweep | DIS-003E, 2026-11-01 | pre-branch | ⚠ pending re-run |
| `dis_auth_live` | auth challenge flow | #40, 2026-10-31 | pre-branch | ⚠ pending re-run |
| `fee_settle_live` | fee settlement | 24/24 sweep, 2026-10-30 | pre-branch | ⚠ pending re-run |
| `governance_quorum_live` | governance quorum | 24/24 sweep, 2026-10-30 | pre-branch | ⚠ pending re-run |
| `h0_11b_auto_suspend_live` | AS-01..AS-06 | BossKing `e687643`, 2026-11-15, 842 s | on-branch | ✅ |
| `h0_11b_resume_validator_live` | RV-01..RV-09 | BossKing `2db43df`, 2026-11-15, 637 s | on-branch | ✅ |
| `h0_11c_equivocation_live` | EQ-01..EQ-04 | BossKing `66ff2dd`, 2026-11-15, 67 s | on-branch (`--features pq-hotstuff`) | ✅ |
| `h0_3_crash_recovery_live` | C-01..C-11 | BossKing `b38bc0c`, 2026-11-04, 12/12 | pre-branch | carry-forward valid |
| `h0_4_nonce_replay_live` | NR-01..NR-05 | BossKing `d585e42`, 2026-11-14 | on-branch | ✅ |
| `h0_5_atomicity_live` | H5-1..H5-5 | BossKing 2026-10-30, 66.83 s | pre-branch | carry-forward valid |
| `h0_6_keybind_race_live` | KB-01, KB-02 | BossKing `5174e28`, 2026-11-14 | on-branch | ✅ |
| `h0_7_supply_conservation_live` | S-01..S-06 | BossKing 2026-11-02, 51.93 s | pre-branch | carry-forward valid |
| `h0_8_genesis_peer_verification_live` | genesis peer check | 24/24 sweep, 2026-10-30 | pre-branch | ⚠ pending re-run |
| `liveness_under_crash_live` | L-01..L-03 | BossKing #43, 2026-11-01 | pre-branch | carry-forward valid |
| `max_block_live` | M-01..M-05 | BossKing #34, 2026-10-30 | pre-branch | carry-forward valid |
| `mldsa_only_accounts_live` | ML-DSA-only accounts | BossKing #35, Windows-confirmed | pre-branch | carry-forward valid |
| `mldsa_tx_live` | P0-3..P0-6 | BossKing #24, 2026-10-28 | pre-branch | carry-forward valid |
| `mn8_reward_exclusion_live` | MN-8 exclusion | BossKing #20, 6/6 | pre-branch | carry-forward valid |
| `personhood_live` | personhood tier | 24/24 sweep, 2026-10-30 | pre-branch | ⚠ pending re-run |
| `pocd_reward_live` | PoCD reward | BossKing #30, 2026-10-30 | pre-branch | carry-forward valid |
| `pqhs2_4node_crash_live` | Gate B crash (CJ-1..CJ-3) | BossKing `72b5a88`, 2026-11-14 | on-branch | ✅ |
| `pqhs2_4node_dis_tx_live` | PQ-HS2 DIS tx + pruning | BossKing `e83643c` (noted in ROADMAP) | on-branch | ✅ |
| `pqhs2_4node_epoch_live` | Gate B epoch handoff | BossKing `72b5a88`, 2026-11-14 | on-branch | ✅ |
| `pqhs2_4node_live` | Base 4-node PQ-HotStuff | BossKing 3 runs `888979b`, 2026-11-14 | on-branch | ✅ |
| `pqhs2_4node_pruning_live` | Gate B pruning | BossKing `72b5a88`, 2026-11-14 | on-branch | ✅ |
| `storage_v2_live` | 8 storage v2 scenarios | BossKing `b38bc0c`, 2026-11-04, 8/8 | pre-branch | carry-forward valid |
| `timestamp_monotonic_live` | timestamp monotonicity | 24/24 sweep, 2026-10-30 | pre-branch | ⚠ pending re-run |
| `validator_eviction_live` | EV-01..03 | BossKing `b9f1e7e`, 2026-11-03, 89.70 s | pre-branch | ⚠ pending re-run (uses `validator_registry`) |
| `validator_jail_live` | JL-01..JL-09 | BossKing `main` 2026-11-03, 670.20 s | pre-branch | ⚠ pending re-run (uses `validator_registry`) |
| `validator_key_live` | key registration (CF-VAL-KEY-002) | BossKing 2026-10-31, 5/5, 124 s | pre-branch | carry-forward valid |
| `validator_liveness_integrity_live` | FP-01/FP-06 | BossKing 2026-11-02, 652.47 s | pre-branch | ⚠ pending re-run (reads liveness data) |
| `validator_precommit_delay_live` | idle 436 s + loaded 302 s | BossKing 2026-11-02 | pre-branch | ⚠ pending re-run |
| `vca_pq_live` | VCA quorum floor | BossKing #22, Windows-confirmed | pre-branch | carry-forward valid |

**Summary:** 20 tests ✅ (on-branch or carry-forward valid); 13 tests ⚠ pending
re-run. The 13 pending are grouped by risk in §6.3 below.

### 6.3 BossKing sweep — commands and result slots

Pull and build:

```bash
git pull origin feat/pqhs2-fips204-signing
git log --oneline -1
```
Expected: `eebbcdb` (or a newer commit if the branch advanced).

```bash
cargo build -p chain-forge-node
```

#### Group A — Validator-registry / liveness suites (re-run because validator_registry now handles ResumeValidator and Pass 5 fires on every block)

Estimated: ~2000 s total.

```bash
cargo test -p chain-forge-node --test validator_eviction_live          -- --nocapture 2>&1 | tee sweep-eviction.log
cargo test -p chain-forge-node --test validator_jail_live               -- --nocapture 2>&1 | tee sweep-jail.log
cargo test -p chain-forge-node --test validator_liveness_integrity_live -- --nocapture 2>&1 | tee sweep-liveness.log
cargo test -p chain-forge-node --test validator_precommit_delay_live    -- --nocapture 2>&1 | tee sweep-precommit.log
```

Expected results (carry-forward):

| Test | Expected scenarios | Expected time | Root / result |
|------|--------------------|---------------|---------------|
| `validator_eviction_live` | EV-01..03 ok | ~90 s | root `48d58b5f…` |
| `validator_jail_live` | JL-01..09 ok | ~670 s | roots `51136494…` / `eebbee53…` / `33362db6…` |
| `validator_liveness_integrity_live` | FP-01/FP-06 ok | ~650 s | — |
| `validator_precommit_delay_live` | idle + loaded ok | ~740 s | — |

Actual results (fill in after BossKing run):

| Test | Result | Time | Notes |
|------|--------|------|-------|
| `validator_eviction_live` | | | |
| `validator_jail_live` | | | |
| `validator_liveness_integrity_live` | | | |
| `validator_precommit_delay_live` | | | |

#### Group B — DIS suites

Estimated: ~400 s total.

```bash
cargo test -p chain-forge-node --test dis_002a_key_rotation_live    -- --nocapture 2>&1 | tee sweep-dis002a.log
cargo test -p chain-forge-node --test dis_002b_migration_live        -- --nocapture 2>&1 | tee sweep-dis002b-mig.log
cargo test -p chain-forge-node --test dis_002b_recovery_live         -- --nocapture 2>&1 | tee sweep-dis002b-rec.log
cargo test -p chain-forge-node --test dis_003a_policy_lifecycle_live -- --nocapture 2>&1 | tee sweep-dis003a.log
cargo test -p chain-forge-node --test dis_003b_guardian_update_live  -- --nocapture 2>&1 | tee sweep-dis003b.log
cargo test -p chain-forge-node --test dis_003c_replay_attack_live    -- --nocapture 2>&1 | tee sweep-dis003c.log
cargo test -p chain-forge-node --test dis_003d_expiry_live           -- --nocapture 2>&1 | tee sweep-dis003d.log
cargo test -p chain-forge-node --test dis_003e_timelock_live         -- --nocapture 2>&1 | tee sweep-dis003e.log
cargo test -p chain-forge-node --test dis_auth_live                  -- --nocapture 2>&1 | tee sweep-disauth.log
```

Actual results:

| Test | Result | Time | Notes |
|------|--------|------|-------|
| `dis_002a_key_rotation_live` | | | |
| `dis_002b_migration_live` | | | |
| `dis_002b_recovery_live` | | | |
| `dis_003a_policy_lifecycle_live` | | | |
| `dis_003b_guardian_update_live` | | | |
| `dis_003c_replay_attack_live` | | | |
| `dis_003d_expiry_live` | | | |
| `dis_003e_timelock_live` | | | |
| `dis_auth_live` | | | |

#### Group C — Infrastructure and remaining suites

Estimated: ~200 s total.

```bash
cargo test -p chain-forge-node --test attestation_live               -- --nocapture 2>&1 | tee sweep-attestation.log
cargo test -p chain-forge-node --test bootstrap_order_live           -- --nocapture 2>&1 | tee sweep-bootstrap.log
cargo test -p chain-forge-node --test fee_settle_live                -- --nocapture 2>&1 | tee sweep-fee.log
cargo test -p chain-forge-node --test governance_quorum_live         -- --nocapture 2>&1 | tee sweep-governance.log
cargo test -p chain-forge-node --test h0_8_genesis_peer_verification_live -- --nocapture 2>&1 | tee sweep-h0_8.log
cargo test -p chain-forge-node --test personhood_live                -- --nocapture 2>&1 | tee sweep-personhood.log
cargo test -p chain-forge-node --test timestamp_monotonic_live       -- --nocapture 2>&1 | tee sweep-timestamp.log
```

Actual results:

| Test | Result | Time | Notes |
|------|--------|------|-------|
| `attestation_live` | | | |
| `bootstrap_order_live` | | | |
| `fee_settle_live` | | | |
| `governance_quorum_live` | | | |
| `h0_8_genesis_peer_verification_live` | | | |
| `personhood_live` | | | |
| `timestamp_monotonic_live` | | | |

### 6.4 Sweep completion status

| Group | Tests | Status |
|-------|-------|--------|
| On-branch confirmed (H0-11B/C/D + H0-4/6 + pqhs2) | 20 | ✅ |
| Group A — validator-registry / liveness | 4 | ⏳ pending BossKing |
| Group B — DIS suites | 9 | ⏳ pending BossKing |
| Group C — infrastructure | 7 | ⏳ pending BossKing |
| **Total** | **40** | **20 ✅ · 20 pending** |

> Note: 40 rows because `pqhs2_4node_dis_tx_live` now has an on-branch ✅,
> promoting the previously-listed 39 → 40 tracked entries.

Once all three groups return 0 failures on BossKing, fill in the result rows above
and change each group's status to ✅. The branch is then ready for owner review
and merge.

---

## 7. What This Document Authorizes / Does Not Authorize

**Authorized by this document:**

- Phase 0 and Phase 0.5 acceptance evidence is recorded.
- BIZ-PRE-5 is closed for private-fixture validation.
- The `feat/pqhs2-fips204-signing` branch is a candidate for review and merge
  once the 12 ⚠ tests above are re-run on BossKing.

**Not authorized by this document:**

- Enabling `automatic_suspension_enabled = true` in a production genesis file.
  That requires a separate owner decision after the grace-window and alert-
  calibration parameters are set from real measurements.
- Setting the H0-11C equivocation penalty amount or re-entry policy. Those are
  set at launch-set time (owner decision 2026-11-14).
- Setting the H0-11D activation epoch number or grace-period length. Those are
  set at launch-set time (owner decision 2026-11-14).
- Flipping the storage format default from v1 to v2.
- Activating PQ-HotStuff on the production devnet (Tendermint stays the baseline
  until PQ-HotStuff passes its Phase 2 gate on Windows).
- Any deployment, mainnet launch, or SBIR filing based solely on this document.

---

## 8. Known Limitations (reproduced from ROADMAP)

| ID | Description |
|----|-------------|
| EVICT-ROOT-1 | `validator_eviction_live` state root is timing-dependent; equal roots across runs proves determinism only at the same final height. Within-run 4-node agreement is the real assertion. |
| P02A-W1 | One unexplained `h0_3_crash_recovery_live` C-01 failure on Windows (MINGW64) has not recurred after the fixture fix; root cause unresolved. |
| ACCT-LEAF-1 | Account Merkle leaf does not commit `key_version` or `pending_recovery`; two accounts differing only in those fields have the same leaf. Whether those fields are committed elsewhere is unverified. Any change alters state roots; outside Phase 0.5 scope. |
| Windows power-loss | Write-barrier durability under a hard power cut is untested on Windows. Documented limitation; not a Phase 0.5 gate. |
| `adversarial_gossip` compile | The `adversarial_gossip` test file has a compile error (H0-8 added `NetworkConfig.genesis_hash` after the test was written; fixed by PR #115 `695cc82`); it is not in the standard 39-test sweep. |
| CI coverage | CI covers only the `dis-core` crate. Node, state, and core crates are validated by Linux sandbox and BossKing runs only. |

---

## 9. Open Owner Decisions (as of 2026-11-15)

- Storage format v2 default activation (not authorised).
- `panic = "abort"` adoption (NODE-TOKIO-1 follow-up).
- API bind-failure exit behaviour.
- §13 / history-dependent roots after deletions.
- GOV-Q1 governance quorum hardening.
- H0-11B numeric choices: grace-window length, attestation threshold, alert
  calibration — to be set from real measurements before production-genesis
  enablement.
- H0-11C equivocation penalty amount and re-entry policy (set at launch-set time).
- H0-11D activation epoch number and grace-period length (set at launch-set time).
- Automatic suspension enablement in production genesis (separate from this ✅).
- ACCT-LEAF-1 leaf-encoding change (requires design + compatibility review).

---

## Appendix: P0-1 Original Evidence (2026-10-31)

**Network topology:**

| Machine | Host | IP | Validators | API ports | P2P ports |
|---------|------|----|------------|-----------|-----------|
| Machine 1 | BossKing (Windows 11 / MINGW64) | 192.168.137.1 | Alice, Bob | 19080, 19081 | 28000, 28001 |
| Machine 2 | bossking-node (Ubuntu Server) | 192.168.137.3 | Carol, Dave | 19080, 19081 | 28000, 28001 |

Link: direct Ethernet (ICS bridge). Genesis: `tests/devnet/genesis-4node-mldsa.json`,
`chain_id` `qcb-devnet-4node-mldsa`, 4 validators × 1,000,000 uqcb, ML-DSA-65 keys.

**Cross-machine API responses at height 53/57:**

```
Alice (BossKing) state_root: a92a28fed791f2c03bb88f7899807e131fc9e38729164c2abd86d4c11013e08e
Carol (Ubuntu)   state_root: a92a28fed791f2c03bb88f7899807e131fc9e38729164c2abd86d4c11013e08e
```

**Controlled restart (Machine 1 Alice + Bob stopped ~10 s, then restarted):**

```
Alice (BossKing) height=11  state_root: a92a28fed791…  peer_count=2
Carol (Ubuntu)   height=22  state_root: a92a28fed791…  peer_count=2
```

State root matched after restart. `95b9e51` is the Phase 0 baseline.
Build scripts: `tests/devnet/run_machine1.sh`, `tests/devnet/run_machine2.sh`.

**P0-1 acceptance criteria:** 4-node ML-DSA genesis loads ✓ · all 4 validators
connect cross-machine ✓ · `precommit_count=3` quorum ✓ · identical state root via
API on both machines ✓ · Machine 1 catches up with matching state root after
controlled restart ✓.
