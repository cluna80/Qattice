# PQ-HotStuff-2 — Defensive Pruning Watermark (gated prototype)

**Status: Windows-confirmed `d9c9f93` (P1–P9). Feature `pq-anchored-evidence`, OFF by default.
No network wiring. No real-application acceptance. QAT-06 open. PR unmerged.**

Branch: `feat/pq-hotstuff-2-anchored-evidence-an3`

### Windows evidence (P1–P8, commit `f49aa06`)

```
krizz@BossKing MINGW64 /c/Dev/an3-m3-recheck (feat/pq-hotstuff-2-anchored-evidence-an3)
$ git pull origin feat/pq-hotstuff-2-anchored-evidence-an3 && cargo test -p chain-forge-consensus \
  --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 \
  -- watermark_advances stale_watermark prune_payloads_removes re_running load_succeeds \
     damaged_watermark driver_prune --nocapture

running 8 tests
test stale_watermark_is_refused ... ok
test damaged_watermark_round_trip_clean ... ok
test watermark_advances_monotonically_and_is_durable ... ok
test load_succeeds_with_absent_payloads_below_watermark ... ok
test prune_payloads_removes_blk_files_below_watermark ... ok
test re_running_prune_finishes_partial_deletion ... ok
test driver_prune_below_refused_while_anchor_pending ... ok
test driver_prune_below_succeeds_after_gate_clears ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 235 filtered out; finished in 34.93s
```

2026-11-11, krizz@BossKing MINGW64. 8 passed / 34.93s.

### Windows evidence (P9, commit `d9c9f93`)

```
krizz@BossKing MINGW64 /c/Dev/an3-m3-recheck (feat/pq-hotstuff-2-anchored-evidence-an3)
$ git pull origin feat/pq-hotstuff-2-anchored-evidence-an3 && cargo test -p chain-forge-consensus \
  --features pq-hotstuff-fips204,pq-anchored-evidence --test pq_hotstuff_engine_fips204 \
  -- fs_backed_damaged_watermark_is_refused_not_silently_reset --nocapture

running 1 test
test fs_backed_damaged_watermark_is_refused_not_silently_reset ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 243 filtered out; finished in 0.01s
```

2026-11-11, krizz@BossKing MINGW64. 1 passed / 0.01s.

### Mutation campaign (Linux sandbox, all killed)

| ID | Mutation | Killed by |
|---|---|---|
| M-P1 | Idempotency guard removed (`prune_payloads`) | P1 FAILED |
| M-P2 | Stale watermark check removed | P3 FAILED |
| M-P3 | Watermark write skipped entirely | P1/P2/P3/P4/P5 FAILED |
| M-P4 | Anchor gate removed from `prune_below` | P7 FAILED |

No surviving mutations.

---

## Scope

A **durable pruning watermark** and the corresponding payload-deletion path in
`BlockStore`. Finality makes a block a *candidate* for pruning; the watermark
records the highest height whose `blk-*` files have been safely deleted. The
prototype is test-only (exercised against `InterimApp` / `MemStorage` or
`FsStorage`; not wired into the node or any network path). QAT-06, real-application
acceptance and production activation remain gated.

---

## Minimum remaining prerequisites (all satisfied by AN-3)

| Prerequisite | Status |
|---|---|
| Finality predicate: two-chain commit, `PersistCommit` durable before downstream | ✅ implemented; commit marker written before `Commit` output is routed |
| Durable root log: `put_root` / `load_roots`, gap and damage detection | ✅ `blockstore.rs` |
| Seed evidence: `put_seed_evidence` / `load_seed_evidence`; `load()` skips history below `seeded_height` | ✅ `blockstore.rs` |
| Anchor gate: signing blocked until genesis-rooted audit + executor reconciliation | ✅ AN-3 (T1–T22 Windows-confirmed `3eb572e`) |
| Executor cursor durability: `InterimApp<FsStorage>` cursor survives restart | ✅ T22 (`fs_backed_restart_preserves_signing_floors_and_prevents_duplicate_execution`) |

What is **not yet implemented** (this slice):

1. **Durable pruning watermark** — a `prune-<height:020>` file in the blockstore.
2. **Payload deletion** — `BlockStore::delete_payload(below: u64)` that removes all
   `blk-*` files for committed blocks strictly below `below`, then writes the
   watermark. Watermark write is BEFORE deletion: crash after watermark but before
   full deletion is safe (re-run deletes the remaining files). Crash before watermark
   = nothing deleted (retry on next start if the driver calls it again).
3. **`load()` update** — treat absent `blk-*` files at or below the watermark as
   expected (not damage). The committed markers for those heights are still required
   (chain continuity); only the payload bytes are gone.
4. **Anchor gate guard** — `delete_payload` refuses if called while the anchor audit
   is pending (guarded by the driver, not the blockstore; the driver exposes a
   `prune_below(height)` method gated on `!self.anchor_pending()`).

---

## Atomicity model

```
write prune-<H> (watermark)  ← crash here: nothing deleted; redo on next call
  for each h < H:
    for each blk-<id> at h:
      remove blk-<id>         ← crash here: watermark covers H; partial deletion is safe
  sync dir
```

The watermark is monotonically increasing. A lower watermark file is refused
(`StaleWatermark`). A second call with the same height is a no-op (idempotent).
The blockstore never lowers the watermark: a damaged watermark file is an error,
not a silent reset.

The commit markers (`cmt-<height>`) and root log (`root-<height>`) are NEVER pruned:
they are required for header-chain verification (AN-3 audit) and checkpoint
reconciliation.

---

## `BlockStore` API additions

```rust
/// Write the pruning watermark and delete all `blk-*` files for committed heights
/// strictly below `below`. Idempotent: a second call with the same height is a no-op;
/// a lower height is refused. The watermark is written BEFORE any deletion so a crash
/// mid-deletion is safe on restart. Returns the number of block files deleted.
pub fn prune_payloads(&mut self, below: u64) -> Result<usize, StoreError>

/// The highest height whose payloads have been pruned (0 = none).
pub fn pruned_watermark(&self) -> Result<u64, StoreError>
```

New error variants:

```rust
StaleWatermark { have: u64, requested: u64 }   // requested < stored watermark
WatermarkDamaged(u64)                           // watermark file cannot be parsed
```

`load()` change: `blk-*` files at heights ≤ `pruned_watermark()` are silently
skipped (not counted as `damaged_blocks`). The committed marker for those heights is
still required.

---

## Driver API addition (gated)

```rust
#[cfg(feature = "pq-anchored-evidence")]
/// Delete payloads for committed blocks below `below`. Refused while the anchor
/// audit is pending. Returns the number of block files deleted.
pub fn prune_below(&mut self, below: u64) -> Result<usize, DriverError>
```

Error: `DriverError::AnchorPending` if `self.anchor.is_some()`.

---

## Tests (acceptance criteria)

| # | Name | What it covers |
|---|---|---|
| P1 | `watermark_advances_monotonically_and_is_durable` | Write watermark at h=10; `pruned_watermark()` returns 10; re-open and verify 10 |
| P2 | `prune_payloads_removes_blk_files_below_watermark` | Populate blocks 1–20; prune below 10; `load()` succeeds; `loaded.blocks` has only heights 10–20 |
| P3 | `stale_watermark_is_refused` | Write watermark at 10; request prune below 5 → `StaleWatermark` |
| P4 | `load_accepts_absent_payloads_below_watermark` | Write watermark at 10; remove some `blk-*` files below 10 manually; `load()` succeeds (no damage) |
| P5 | `crash_after_watermark_before_full_deletion_is_safe` | Write watermark at 10; delete two of five `blk-*` files; re-open; call `prune_payloads(10)` → succeeds; `load()` clean |
| P6 | `damaged_watermark_is_refused_not_reset` | Corrupt the `prune-*` file; `load()` returns `WatermarkDamaged` |
| P7 | `driver_prune_below_refused_while_anchor_pending` | Start driver with anchor gate up; `prune_below(5)` → `AnchorError::AnchorPending` |
| P8 | `driver_prune_below_succeeds_after_gate_clears` | Advance anchor → Ready; `prune_below(anchor.height)` → ok; block files gone |

All tests use `MemStorage` or `FsStorage`; real FIPS 204 ML-DSA-65 via
`pq_hotstuff_engine_fips204`. Windows validation required before any milestone close.

---

## Out of scope (this slice)

- Network distribution of pruning decisions
- Catch-up (snapshot serving to nodes that missed pruned history)
- Dynamic watermark advancement (automatic vs. operator-driven)
- Pruning of commit markers or root-log files
- Production activation or node wiring
- QAT-06 gate

---

## Open owner decisions (from phase3-pruning-prerequisites.md, unchanged)

- Execution / handoff interface for the real Qattice application
- Snapshot format and authentication (beyond the devnet interim prototype)
- Checkpoint semantics (which height is "safe to prune below")
- Ordering of watermark persistence relative to the safety store counter
