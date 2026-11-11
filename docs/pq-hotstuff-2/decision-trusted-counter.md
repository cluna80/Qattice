# Decision Request: §7.1 Trusted Monotonic Counter (G7.1-P, G7.1.1-P)

**Date:** 2026-11-11  
**Gate:** QAT-07 / PQHS-P1  
**Status:** Pending owner decision — no implementation authorized.  
**Track:** Track C (§7.1 counter backend)  
**Spec refs:** §7.1, R7.1-1 through R7.1-5; §7.1.1, R7.1.1-1  

---

## Current state

The `MonotonicCounter` trait (`safety/mod.rs:210`) and the `SafetyStore` are fully
implemented. `TestCounter` (an in-memory counter used in all existing tests) satisfies the
trait for testing but is **explicitly not production-ready**: it provides no durability
guarantee and no hardware fencing.

The store's open/init logic depends on counter reads and advances to prevent rollback. All
§7.1 unit tests (76/76 + 11/11, BossKing-confirmed 2026-11-11) pass against `TestCounter`.

The `TestCounter` backend is acceptable for the PQ-HotStuff simulator and unit tests. It
is not acceptable for a validator running against a live chain, because a process restart
returns the counter to its initial value, defeating the rollback protection.

§7.1.1 (digest-bound counter commits) is also draft only: PR #127 has the design and
tests; it is not merged.

---

## The interface

```rust
pub trait MonotonicCounter {
    fn binding(&self) -> &CounterBinding;           // (public_key, instance_id)
    fn read(&mut self) -> Result<CounterState, CounterError>;   // current (value, digest)
    fn advance(
        &mut self,
        expected: &CounterState,                    // compare-and-advance
        new_digest: [u8; 32],
        session: &Session,                          // fencing token
    ) -> Result<(), CounterError>;
}
```

`CounterBinding` ties the counter to one `(public_key, instance_id)` pair. A counter bound
to a different identity is refused at both init and open. The `Session` token is acquired
once during `open` and must be presented on every subsequent `advance`; a stale session
causes the advance to fail, latching the store.

---

## Proposed rules (spec §7.1)

### R7.1-1 — Compare-and-advance, fail closed on mismatch

`advance(expected, new_digest, session)` succeeds only if the counter's current
`(value, digest)` equals `expected`. On mismatch — counter was advanced by another writer
or rolled back — the call fails and the store latches. No retry; no repair.

**When it takes effect:** at every signature commit. The store already enforces this
through `TestCounter`; the production backend must provide the same atomic compare-and-swap.

### R7.1-2 — Rollback and reset detection on open

On `open`, the counter is read **before** the file is inspected:
- `file_counter < trusted_counter`: rollback detected → fail closed, latch.
- `file_counter > trusted_counter + 1`: counter was reset or is from a different instance
  → fail closed, latch.
- `file_counter == trusted_counter + 1`: recovery window (advance did not complete) → gate
  stays up until the advance is confirmed (R7.1-3).
- `file_counter == trusted_counter`: normal open.

### R7.1-3 — Recovery advance gates the open

When `file_counter == trusted_counter + 1` the counter advance did not complete (crash
between file write and counter advance). The store must complete the advance before
returning any record. If the advance fails (race: another writer moved the counter), the
store fails closed and returns nothing.

### R7.1-4 — Session fencing

The `Session` token is acquired once at `open`. Every `advance` presents it. A second
concurrent `open` acquires a different session; when that second store tries to advance, the
first store's session is stale and all further advances from it fail, latching it.

### R7.1-5 — Bound to one (key, instance_id); value 0 at init; never re-initialized

The counter is bound to exactly one `(public_key, instance_id)` pair for its lifetime.
Value starts at 0 (initialization). `initialize_fresh` is refused if any counter value
other than 0 exists for that binding. Re-initialization for a key that has participated
(counter > 0) is refused.

---

## §7.1.1 — Digest-bound counter commits (R7.1.1-1)

This extension, described in PR #127, stores `(value, digest)` as the counter state and
requires `prev_digest` in every record. On open, a mismatch between the file's
`prev_digest` and the counter's stored `digest` is a fork indicator (another record
committed at the same counter value with a different digest) → fail closed.

**Status:** draft design; tests exist in `pq_hotstuff_safety.rs` lines 992–1179 (3 tests,
BossKing-confirmed). No production backend. Requires a separate approval before merging.

---

## Production backend options

The spec lists three candidate backends. The owner must choose one (or designate a priority
order) before Track C work can begin:

| Backend | Property | Complexity | Portability |
|---------|----------|------------|-------------|
| **TPM 2.0 NV counter** | Hardware-enforced monotonic; survives power loss | Medium (TPM 2.0 API) | Linux/Windows TPM stack required; not available in all cloud VMs |
| **HSM counter** | Hardware-enforced; supports high-throughput signing | High (HSM vendor API) | Requires HSM presence; not suitable for a software-only devnet |
| **Remote counter service** | Software-enforced via CRDT or single-writer log; fencing via session lease | High (network dependency) | Cloud-portable; adds a liveness dependency |

A **software fallback** using an atomic file-based counter (kernel-level write ordering +
fsync + rename) can approximate the guarantee on Linux and NTFS, but does not survive
hardware failure. It is suitable for a devnet-only "durable counter" that improves on
`TestCounter` without requiring a TPM.

---

## Tests that would demonstrate each rule

All tests target the `MonotonicCounter` trait plus `SafetyStore`; they are backend-agnostic
once the production backend implements the trait.

| Test name (proposed) | What it asserts |
|----------------------|-----------------|
| `production_counter_advance_is_atomic_compare_and_swap` | A concurrent advance with a stale `expected` value is rejected; the counter value does not change. |
| `production_counter_advance_with_stale_session_latches_the_store` | After a second `open` acquires a new session, the first store's advance fails and the first store is latched. |
| `production_counter_rollback_is_detected_on_open_and_fails_closed` | A counter whose file-level value is behind the stored value causes `open` to return `Err(Rollback)` and creates no store. |
| `production_counter_recovery_advance_gates_the_open` | A counter at `f == t+1` (crash window) completes the advance on `open` before returning any record. |
| `production_counter_bound_to_another_identity_is_refused` | A counter initialized for `(key_A, id_A)` refuses `open` with `(key_B, id_A)`. |
| `production_counter_cannot_be_reinitialized_once_used` | `initialize_fresh` on a binding with `counter > 0` returns an error. |

The existing `pq_hotstuff_safety` tests (R7.1-1 through R7.1.5, BossKing-confirmed)
already pass against `TestCounter` and serve as the acceptance suite: a production backend
passes G7.1-P when these same tests pass with the production backend substituted.

---

## Decision needed

1. **Approve §7.1 as a Phase 1 required interface** (Track C begins) or **designate §7.1
   as Phase 2 / devnet-optional** (Track C remains blocked).
2. If approved for Phase 1: **choose the production counter backend** (TPM, HSM, remote
   service, or software-fallback for devnet only).
3. **Approve §7.1.1 (digest-bound commits)** as an additional Phase 1 requirement, or
   hold at draft.
4. If backend is approved: authorize implementation of the backend adapter, the
   `MonotonicCounter` impl, and the integration tests listed above.

No implementation begins until this decision is recorded here.
