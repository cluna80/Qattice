# Decision Request: §7.1 Trusted Monotonic Counter (G7.1-P, G7.1.1-P)

**Date:** 2026-11-11 (revised 2026-11-11 — owner review round 2)  
**Gate:** QAT-07 / PQHS-P1  
**Status:** Pending owner decision — no implementation authorized.  
**Track:** Track C (§7.1 counter backend)  
**Spec refs:** §7.1, R7.1-1 through R7.1-5; §7.1.1, R7.1.1-1  

---

## Current state

The `MonotonicCounter` trait is fully specified. The `advance` signature is:

```rust
fn advance(
    &mut self,
    expected:   &CounterState,   // compare on (value AND digest) together
    new_digest: [u8; 32],
    session:    &Session,        // fencing token; stale session → fail closed
) -> Result<(), CounterError>;
```

`CounterState = { value: u64, digest: [u8; 32] }`. The advance succeeds only if the
counter's current state equals `expected` on **both** fields and `session` is the latest
session (`safety/mod.rs:216-219`). Failure changes nothing.

All 87 safety-store tests (76 + 11, BossKing-confirmed) pass against `TestCounter`.
`TestCounter` is in-memory and does not survive process exit. It establishes the protocol
baseline, not the backend contract.

---

## Exact acceptance condition: equal-counter open

**Precondition:** `rec.counter == trusted.value` (where `trusted = counter.read()`).

```
file_digest := sha3(canonical_body(rec))          // computed by the store
if file_digest != trusted.digest:
    return Err(OpenError::Fork { counter })        // fail closed
// else: file is the record the counter committed; proceed
```

`trusted.digest` is authoritative. The file is valid only if its digest matches what the
counter committed. A mismatch means another record was committed at this counter value
under the same binding — a fork. The store fails closed and creates nothing.

---

## Exact acceptance condition: one-step-ahead open

**Precondition:** `rec.counter == trusted.value + 1` (where `trusted = counter.read()`).

```
// 1. The file is a candidate recovery record.
//    Verify it extends the committed counter state.
if rec.prev_digest != trusted.digest:
    return Err(OpenError::SuccessorOfAnotherRecord { counter })  // fail closed
// 2. Run all content and staleness checks (verify_content, staleness).
// 3. Acquire a session (this latches out any other concurrent opener).
session := counter.acquire_session()
// 4. Fenced compare-and-advance. Uses the same 'trusted' read from step 1.
//    If another writer moved the counter between the read and this advance,
//    the advance fails and the store does not open.
result := counter.advance(&trusted, file_digest, &session)
if result is Err:
    return Err(OpenError::Counter(...))             // fail closed
// 5. Signing unblocked only after the advance succeeds.
```

**Why the file is a "candidate"** (not "authoritative"): the file's durability (`fsync +
rename` before the advance) is assumed but not yet proven — the advance is the proof. Only
after `advance` returns `Ok` is the file confirmed as the successor of the committed
record. Until then, signing is blocked.

**What `rec.prev_digest == trusted.digest` checks:** the file was produced by advancing
from the state the counter currently holds. It does not check that the file is the most
recent record ever produced — there might be a competing record from a different session.
The fenced `advance` resolves that race: only one session can win the compare-and-advance.

**Distinction from the equal-counter case:**
- Equal-counter: `trusted.digest` is compared against the file's own digest. The counter
  says "this digest was committed at value `v`"; the file must match.
- One-step-ahead: `trusted.digest` is compared against the file's `prev_digest`. The
  counter says "the predecessor of whatever is at value `v+1` had digest `d`"; the file
  must claim `d` as its predecessor.

---

## Backend evaluation criteria (from owner review 2026-11-11)

Each backend is evaluated against three criteria. All three must be satisfied; partial
satisfaction does not close G7.1-P.

| Criterion | Requirement |
|-----------|-------------|
| **Atomic CAS of (value, digest)** | The transition from `(v, d)` to `(v+1, d')` is indivisible. A concurrent reader sees either `(v, d)` or `(v+1, d')`, never `(v+1, d_old)` or `(v, d_new)`. A backend that increments a hardware counter and writes the digest in a separate step does not satisfy this criterion. |
| **Session fencing** | Only the holder of the current session can advance. A second concurrent `open` acquires a new session, and the first store's advance is then rejected — even if its `(value, digest)` check would have passed. |
| **Rollback resistance** | After a process restart or power loss, `counter.read()` returns a value ≥ the last successfully advanced value. A backend whose counter resets to 0 on restart does not satisfy this criterion. |

---

## Candidate backends

### A — TPM 2.0 NV counter

**Atomic CAS of (value, digest):** `TPM2_NV_Increment` advances the integer only. To bind
the digest atomically, a TPM policy session must sequence `TPM2_NV_Increment` and
`TPM2_NV_Write` (for a second NV index holding the digest) as a single authorized
transaction. Without a combined policy, the digest write is a separate step and the
atomicity criterion is **not satisfied** by a hardware increment alone.

**Session fencing:** yes — TPM authorization policy (PolicySigned, PolicyPCR) scopes each
session.

**Rollback resistance:** yes — TPM NV is durable across power loss.

**Gap:** define and verify the combined increment+digest write as one TPM policy session;
measure latency per advance (TPM NV write is 10–100 ms on most hardware).

**Portability:** physical or firmware TPM 2.0 required; not available in all cloud VMs.

### B — HSM counter

**Atomic CAS of (value, digest):** vendor-dependent; must confirm the HSM API exposes a
CAS over `(integer, 32-byte blob)` as a single transaction.

**Session fencing:** yes — HSM key-usage or session handle.

**Rollback resistance:** yes — HSM non-volatile storage.

**Gap:** vendor API review needed before this column can be marked satisfied.

**Portability:** HSM presence required; high setup cost.

### C — Remote counter service

**Atomic CAS of (value, digest):** yes, if the service provides a CAS over arbitrary state
(e.g. a linearizable key-value store with compare-and-swap, or a Raft-replicated log entry
where `(v, d)` is one atomic entry).

**Session fencing:** yes — session lease token per `open`.

**Rollback resistance:** conditional — depends on service durability (leader lease + fsync).
A service with weak durability guarantees (e.g. in-memory only) does not satisfy this
criterion.

**Gap:** liveness analysis needed (counter service unavailability → validator cannot sign).
Specify SLA and what happens when the service is partitioned from the validator.

**Portability:** cloud-portable.

### D — Software file counter (devnet only)

**Atomic CAS of (value, digest):** yes — write `(v+1, d')` to a temp file, `fsync`, rename
over the counter file, `fsync` directory. Rename is atomic on POSIX and NTFS; rename makes
the new state visible in one operation.

**Session fencing:** yes — file advisory lock scoped to `open`.

**Rollback resistance:** conditional — survives process restart and OS crash; does **not**
survive hardware failure (disk loss) or VM snapshot rollback.

**Classification:** devnet only. This is an improvement over `TestCounter` but does not
meet the full contract for production. A node using this backend must be explicitly
configured `devnet = true` and must refuse production keys.

---

## Production evidence required (beyond the 87 baseline tests)

A production backend must present evidence for three scenarios `TestCounter` cannot
simulate. These are structured as acceptance tests that also run against `TestCounter` as
regressions.

### Scenario 1 — Crash recovery

**Setup:** simulate a crash after the file write completes but before `counter.advance`
returns (by killing the process or injecting a fault after `fsync + rename` but before the
CAS). On restart, `counter.read()` returns `trusted`.

**Expected:** `open` enters the one-step-ahead path (`rec.counter == trusted.value + 1`),
verifies `rec.prev_digest == trusted.digest`, acquires the session, advances the counter
successfully, and returns the store. Signing is unblocked.

**Test name:** `production_counter_crash_between_file_write_and_advance_recovers_correctly`

### Scenario 2 — Concurrent writers

**Setup:** two concurrent `open` calls on the same binding. Both read the same `trusted`
state.

**Expected:** the first to call `acquire_session` + `advance` succeeds. The second's
`advance` is rejected with a stale session, and the second `open` returns an error. Neither
writer sees a partial state; the counter value is `trusted.value + 1` exactly once.

**Test name:** `production_counter_concurrent_open_only_one_writer_advances`

### Scenario 3 — Reset handling

**Setup:** destroy the counter's backing storage (simulate disk loss or TPM NV reset), then
restart. The safety store file is present and has `rec.counter > 0`.

**Expected:** `counter.read()` returns either an error or value 0. If value 0: the
equal-counter check fails (`file_digest != 0_digest`), returning `Err(Fork)`. If error:
`open` returns `Err(Counter(...))`. In both cases the validator does not sign anything.
Human key rotation is required before the node can participate.

**Test name:** `production_counter_reset_with_existing_state_file_fails_closed`

---

## §7.1.1 — Digest-bound counter commits: open question

PR #127 adds `(value, digest)` as the counter state and `prev_digest` to every record.
Three tests exist and pass on BossKing (lines 992–1179 in `pq_hotstuff_safety`).

**§7.1.1 remains pending** because the three tests exercise combined crash scenarios that
conflate the two open cases. Before approval, each case needs a dedicated test that sets up
the state precisely:

**Case A dedicated test** (`equal_counter_with_wrong_digest_fails_closed`):
- Set up: counter at `(v, d_other)` where `d_other != sha3(file_body)`.
- `rec.counter == v` (equal-counter).
- Expected: `Err(OpenError::Fork { counter: v })`. No session acquired, nothing written.

**Case B dedicated test** (`one_step_ahead_with_wrong_prev_digest_fails_closed`):
- Set up: counter at `(v, d_committed)` where `d_committed` is the digest of a previous
  record `R0`. File has `rec.counter = v+1` but `rec.prev_digest = d_other != d_committed`.
- Expected: `Err(OpenError::SuccessorOfAnotherRecord { counter: v+1 })`. No advance
  attempted, nothing written.

These two tests confirm that `trusted.digest` is the anchor in both cases and that the
failure modes are distinct. Once they exist and pass, the distinction documented above is
machine-verified and §7.1.1 can be approved for production use.

---

## Decisions needed

1. **Approve one or more backends for concrete evaluation** — choose from A (TPM), B
   (HSM), C (remote service), D (devnet file counter), or propose another.
2. **For each chosen backend:** confirm whether the atomic CAS of `(value, digest)` can be
   satisfied, and authorize gap work to demonstrate it.
3. **Approve §7.1 as Phase 1 required interface** (Track C begins) or designate it as
   Phase 2 / devnet-optional.
4. If approved: authorize the three production-evidence tests (Scenarios 1–3) and the
   backend adapter implementation.
5. **§7.1.1:** once the two dedicated tests (Case A, Case B) are written and pass, approve
   §7.1.1 for Phase 1 — or defer independently of §7.1.

No implementation begins until this decision is recorded here.
