# QAT-07 — Phase 1 Gap Review

**Date:** 2026-11-11  
**Gate:** QAT-07 / PQHS-P1 (§7 persistence and §8 reconfiguration)  
**Status:** Open — gap review only. No implementation or merge authorized.  
**Base:** `feat/pq-hotstuff-2-qat06-merge-an3` @ `9f10735` (QAT-06 closed).

---

## Spec requirements (§7 and §8)

### §7 Persistence and restart

| Req ID | Requirement (verbatim or paraphrased) |
|--------|---------------------------------------|
| R7-1 | Safety state `{epoch, profile, hvr, hqr, last_signed}` written atomically **before** any vote or timeout leaves the node |
| R7-2 | Exact canonical message bytes **and** complete signature envelope stored; byte-for-byte re-send on restart, never re-sign |
| R7-3 | On load: integrity check, message re-encode identity, envelope `alg_id`/length/sig verification; any failure → fail closed, never repair by re-signing |
| R7-4 | Fault injection at every step (before, during, after each write/fsync/rename): never two different signed messages per (type, round), never re-sign, never send before write |
| R7-5 | Missing safety-state file never resets signing history; explicit `fresh` initialization only for a new key |
| R7-6 | Explicit `fresh → active` transition in the same atomic write as the first signature |
| R7-7 | Missing/damaged file with existing marker → refuse to sign, refuse to create new state |
| R7-8 | Stale file (chain evidence shows signing above `hvr`) → abstain, never sign below it |
| R7-9 | Fresh initialization refused when chain evidence shows prior participation |
| R7-10 | Loss of safety state: fail closed; authorized recovery is key rotation only |
| R7-11 | Block store: uncommitted blocks from committed tip to highest QC + TC; on restart resume from `max(hqr, tc.round) + 1` |
| R7.1-1 | Trusted monotonic counter: `advance(expected_previous, session)` compare-and-advance; fail closed on mismatch |
| R7.1-2 | Counter read before file comparison on open; rollback (`f < t`) and counter reset (`f > t+1`) both fail closed |
| R7.1-3 | Recovery advance (`f == t+1`): gates open, nothing returned until advance succeeds; fail closed on race |
| R7.1-4 | Session (fencing token): acquired on open, presented on every advance; stale session latches store |
| R7.1-5 | Counter bound to one (key, instance_id); value 0 at initialization, never re-initialized for the same key |
| R7.1.1-1 | (Proposed, not yet approved) Digest-bound counter commits: `(value, digest)` state; `prev_digest` in record; fork detection on `d_f != d_t` |

### §8 Personhood weighting and reconfiguration

| Req ID | Requirement |
|--------|-------------|
| R8-1 | Power update order: `apply_personhood_cap` → `gate_voting_power` → gate-3 quorum floor; not bypassable |
| R8-2 | Epoch changes only through committed epoch-change block; new set takes effect from round 1 of epoch e+1 |
| R8-3 | QC and TC always verified against the set of their own epoch |
| R8-4 | Revocation takes effect in the first block after the one that commits it (never mid-round) |
| R8-5 | Key rotation: takes effect at the next block; one-block power gap |
| R8-6 | Genesis validators: fresh FIPS 204 ML-DSA-65 keys only; no converted or imported keys |
| R8-7 | Every genesis PoP verified before any consensus state is built; wrong length/alg/duplicate → refuse to start |
| R8-8 | ML-DSA-65 admission: engine refuses to start unless every key in V_e is 1952 bytes and registered with the profile's alg_id; no fallback |

---

## Existing evidence map

### Covered by existing tests (Windows-confirmed unless noted)

| Req | Test / evidence | Location | Windows? |
|-----|-----------------|----------|----------|
| R7-1 | `the_commit_order_is_write_sync_rename_sync_dir_then_counter` | `pq_hotstuff_safety.rs:410` | Linux only (sandbox) |
| R7-2 | `the_exact_canonical_message_and_envelope_are_persisted_for_every_kind` | `pq_hotstuff_safety.rs:197` | Linux only |
| R7-2 | `a_restart_re_sends_the_stored_signature_byte_for_byte_and_never_re_signs` | `pq_hotstuff_safety.rs:214` | Linux only |
| R7-2 | `a_store_reopened_with_the_real_verifier_accepts_real_signatures_and_re_sends_them_byte_for_byte` | `pq_hotstuff_safety_fips204.rs:116` | Linux only |
| R7-3 | `a_stored_signature_that_does_not_verify_is_refused_even_with_a_valid_checksum` | `pq_hotstuff_safety.rs:559` | Linux only |
| R7-3 | `a_tampered_stored_signature_is_refused_on_open_by_the_real_verifier` | `pq_hotstuff_safety_fips204.rs:143` | Linux only |
| R7-4 | `a_storage_or_counter_failure_at_any_step_latches_the_store` | `pq_hotstuff_safety.rs:393` | Linux only |
| R7-5 | `a_missing_state_file_with_a_marker_fails_closed_and_creates_nothing` | `pq_hotstuff_safety.rs:431` | Linux only |
| R7-5 | `both_files_gone_is_no_state_and_a_fresh_start_is_still_refused_by_the_counter` | `pq_hotstuff_safety.rs:448` | Linux only |
| R7-5 | `open_never_creates_state` | `pq_hotstuff_safety.rs:133` | Linux only |
| R7-6 | `initialization_is_explicit_and_the_fresh_state_is_distinguishable` | `pq_hotstuff_safety.rs:109` | Linux only |
| R7-6 | `the_first_signature_moves_fresh_to_active_in_the_same_commit` | `pq_hotstuff_safety.rs:123` | Linux only |
| R7-7 | `a_state_file_without_the_marker_fails_closed` | `pq_hotstuff_safety.rs:440` | Linux only |
| R7-7 | `a_record_that_belongs_to_another_profile_chain_key_or_instance_is_refused` | `pq_hotstuff_safety.rs:527` | Linux only |
| R7-8 | `a_key_that_already_participated_cannot_be_initialized_fresh` (chain evidence staleness) | `pq_hotstuff_safety.rs:176` | Linux only |
| R7-9 | `initialization_is_refused_when_state_or_a_marker_already_exists` | `pq_hotstuff_safety.rs:142` | Linux only |
| R7-9 | `initialization_is_refused_when_the_separate_counter_shows_the_identity_was_used` | `pq_hotstuff_safety.rs:154` | Linux only |
| R7-11 | Crash/restart in sim E4/E5, S7, S9 (block store survives restart) | `pq_engine_suite.rs` sim | ✅ Windows (via QAT-06 BossKing run) |
| R7-11 | `fs_sign_reopen_and_re_send_are_byte_identical_on_a_real_directory` | `pq_hotstuff_safety.rs:1408` | Linux only |
| R7.1-1 | `a_counter_bound_to_another_identity_is_refused_at_initialization_and_at_open` | `pq_hotstuff_safety.rs:915` | Linux only |
| R7.1-2 | `a_copy_whose_file_is_behind_the_shared_counter_cannot_open` | `pq_hotstuff_safety.rs:884` | Linux only |
| R7.1-3 | `a_recovery_advance_gates_the_open_and_a_counter_failure_leaves_no_store` | `pq_hotstuff_safety.rs:937` | Linux only |
| R7.1-3 | `a_recovery_advance_that_loses_a_race_fails_closed` | `pq_hotstuff_safety.rs:951` | Linux only |
| R7.1-3 | `a_crash_during_the_recovery_advance_reopens_correctly_in_both_outcomes` | `pq_hotstuff_safety.rs:961` | Linux only |
| R7.1-4 | `a_failed_open_does_not_supersede_the_running_store` | `pq_hotstuff_safety.rs:897` | Linux only |
| R7.1.1-1 | `two_disks_a_fenced_out_writers_restart_is_refused_so_it_can_never_send_a_vote_that_conflicts_with_the_committed_one` | `pq_hotstuff_safety.rs:992` | Linux only |
| R7.1.1-1 | `two_files_one_ahead_the_first_restart_commits_and_the_second_is_refused` | `pq_hotstuff_safety.rs:1019` | Linux only |
| R7.1.1-1 | `a_file_at_the_committed_counter_that_is_not_the_committed_record_is_a_fork` | `pq_hotstuff_safety.rs:1179` | Linux only |
| AN-3 | Anchored restart gate: T1–T22 (AnchorMode gating, driver gate wiring, deferred output) | `feat/.../an3` branch | ✅ Windows (63.66 s, 2026-11-11) |
| Pruning | P1–P9 + live devnet crash/restart with pruning | `feat/.../an3` branch | ✅ Windows (27.13 s, 2026-11-11) |

### Not covered — gaps

| Gap ID | Req | Description | Priority |
|--------|-----|-------------|----------|
| G7-W | R7-1 through R7.1.1 | **Safety store Windows confirmation** — ✅ **Closed 2026-11-11**: `pq_hotstuff_safety` 76/76 (53.81 s) + `pq_hotstuff_safety_fips204` 11/11 (2.26 s), krizz@BossKing MINGW64. | **Closed** |
| G7-F | R7-4 | Fault injection at every write/fsync/rename step: `a_storage_or_counter_failure_at_any_step_latches_the_store` exists but only on Linux; Windows fsync/rename semantics differ (NTFS directory flush) | High |
| G7-S | R7-8 | Stale file test (`stale_file_is_refused_or_forces_abstain`) — partial coverage via `a_key_that_already_participated_cannot_be_initialized_fresh`; dedicated stale-file open test needed | Medium |
| G8-P | R8-1 | Personhood power cap: `apply_personhood_cap` / `gate_voting_power` pipeline — no PQ-HotStuff tests; Tendermint has tests but the PQ-HotStuff engine takes power as input from above | Medium — required for Phase 1 gate |
| G8-E | R8-2, R8-3 | Epoch transitions: committed epoch-change block, new set at round 1 of e+1, historical set verification for old QCs/TCs — not implemented or tested in PQ-HotStuff engine | High — required for Phase 1 gate |
| G8-R | R8-4 | Revocation: power→0 in first block after commit; mini-epoch rule; not mid-round — not implemented or tested | High — required for Phase 1 gate |
| G8-K | R8-5 | Key rotation: power gap during rotation, next-block effect — not implemented or tested | Medium |
| G8-A | R8-8 | ML-DSA-only admission: ✅ **Closed 2026-11-11.** `EpochSet::new()` enforces the 1952-byte key-length invariant at the type boundary (`types.rs:63`); a wrong-length key returns `SetError::BadKeyLength` before reaching `Engine::new()`. Test `g8a_epoch_set_refuses_a_non_ml_dsa_key_length_and_accepts_1952_byte_keys` — **1/1 pass in 0.01s, krizz@BossKing MINGW64**, commit `0bd37ce`. No separate `alg_id` field in `ValidatorEntry`: ML-DSA-65 identity is implied by the 1952-byte length gate. | Medium |
| G8-G | R8-6, R8-7 | Fresh ML-DSA genesis key generation and PoP verification — Phase 2 deliverable, not Phase 1; blocked on PR #109 key-handling review | Low (Phase 2) |
| G7.1-C | R7.1-4 | Session/fencing token: stale-session test `a_failed_open_does_not_supersede_the_running_store` exists but `two_stores_sharing_one_simulated_counter_a_stale_store_cannot_commit` and related session-supersession tests from §7 change item 3 — check if fully implemented | Medium |
| G7.1-P | §7.1 overall | §7.1 is marked "PROPOSED, owner review pending" — no approval yet for the production counter backend (TPM/HSM/remote); `TestCounter` is explicitly not production-ready; the backend interface is not approved for any real deployment | Blocked on owner decision |
| G7.1.1-P | §7.1.1 | Digest-bound counter commits — two dedicated tests (`equal_counter_with_wrong_digest_is_a_fork_and_fails_closed`, `one_step_ahead_with_wrong_prev_digest_is_a_different_records_successor_and_fails_closed`) **pass 2/2 on krizz@BossKing MINGW64 (0.17 s, 2026-11-11, `339f262`)**. Ready for owner approval; PO-4 (production counter validation) remains open. | Blocked on owner approval |

---

## What the AN-3 and pruning evidence covers (and doesn't)

**Covered by AN-3 (Windows-confirmed):**
- Restart after pruning with the anchored-evidence gate: T22 (FsStorage safety + app + blockstore second-run cursor matches pre-drop cursor, no duplicate execution)
- Block store durability through the driver: the driver gate remains up during recovery; deferred output delivered after `Ready`
- Pruning watermark durability and idempotency (P1–P5, FsStorage)

**NOT covered by AN-3:**
- Safety-store (signing) persistence: T22 restarts the driver and executor but the signing safety record is in a separate store tested in `pq_hotstuff_safety`; AN-3 does not exercise the sign/re-send byte-for-byte path under Windows
- Counter rollback detection (§7.1): AN-3 uses `TestCounter`; no production counter backend
- Epoch transitions, revocation, rotation (§8): AN-3 is static membership only

---

## QAT-07 proposed scope

Based on the gap table, QAT-07 work splits into three tracks:

### Track A — Safety store Windows confirmation ✅ closed

**Windows-confirmed 2026-11-11 (krizz@BossKing MINGW64), branch `feat/pq-hotstuff-2-qat06-merge-an3` @ `5f1d289`:**
- `pq_hotstuff_safety`: **76/76 pass in 53.81 s** (non-crypto doubles, debug)
- `pq_hotstuff_safety_fips204`: **11/11 pass in 2.26 s** (real FIPS 204 ML-DSA-65, debug)

**G7-W closed.** All §7 safety-store requirements now have Windows evidence.

### Track B — §8 epoch transitions and admission (new implementation)
Requires owner approval before implementation begins. Scope:
- Epoch-change block type and committed set transition in the engine
- `apply_personhood_cap` / `gate_voting_power` wiring for PQ-HotStuff
- Revocation (power→0 at next block, mini-epoch)
- Key rotation (next-block power gap)
- ML-DSA admission check at engine startup (negative test: non-1952-byte key → refuse to start)
- Tests per §12 Phase 1 gates: "a revocation removes power from the next block", "mid-epoch rotation works", "the node refuses non-ML-DSA keys"

### Track C — §7.1 counter approval (blocked)
Blocked on owner approval of §7.1 as a required interface.  
PR #127 exists with draft implementation.  
No Track C work until the owner approves §7.1.

---

## Recommendation

**Track A complete** (G7-W closed 2026-11-11): 76/76 + 11/11 on BossKing. No further action needed on Track A.

**Before Track B implementation begins:** owner approval of §8 scope and the Phase 1 gate definition (the spec lists "a restarted validator never signs a conflicting vote or timeout" and "the node refuses non-ML-DSA keys" as Phase 1 gates; epoch transitions and revocation are listed but marked as requiring separate review).

**Track C:** hold. §7.1 (compare-and-advance counter with session/fencing) is proposed and has draft tests in `pq_hotstuff_safety`; §7.1.1 (digest-bound commits) is proposed but not approved for implementation. Neither track starts until the owner decides.
