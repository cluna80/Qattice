# Decision Request: §7.1 Trusted Monotonic Counter (G7.1-P, G7.1.1-P)

**Date:** 2026-11-11 (revised 2026-11-11 — owner review round 1)  
**Gate:** QAT-07 / PQHS-P1  
**Status:** Pending owner decision — no implementation authorized.  
**Track:** Track C (§7.1 counter backend)  
**Spec refs:** §7.1, R7.1-1 through R7.1-5; §7.1.1, R7.1.1-1  

---

## Current state

The `MonotonicCounter` trait (`safety/mod.rs:210`) is fully specified. All 87 safety-store
tests (76 + 11, BossKing-confirmed 2026-11-11) pass against `TestCounter`. `TestCounter` is
an in-memory counter: it provides no durability guarantee and no hardware fencing. It
establishes the correctness baseline for the store's protocol logic, not for any backend.

A production backend must implement the full contract before it can replace `TestCounter` in
any evidence that closes G7.1-P.

---

## The full counter contract

The existing trait already specifies more than a hardware increment. `advance` is a
**compare-and-advance on `(value, digest)` together**:

```rust
pub struct CounterState {
    pub value:  u64,
    pub digest: [u8; 32],
}

pub trait MonotonicCounter {
    fn binding(&self) -> &CounterBinding;   // bound to (public_key, instance_id)
    fn read(&self)    -> Result<CounterState, CounterError>;
    fn advance(
        &mut self,
        expected:   &CounterState,   // succeeds only if current == (expected.value, expected.digest)
        new_digest: [u8; 32],
        session:    &Session,        // fencing token; stale session → fail closed
    ) -> Result<(), CounterError>;   // on failure: nothing changes, store latches
}
```

A backend that provides only a hardware increment (TPM NV counter `TPM2_NV_Increment`) does
**not** satisfy this contract: it advances the integer but cannot atomically bind the new
digest. That leaves the digest half of the compare unproven and creates a window where the
counter value advances but the record's digest is never committed.

**Consequence:** any backend evaluation must demonstrate atomicity over both `value` and
`digest` together, not `value` alone.

---

## Backend evaluation criteria

Owner review (2026-11-11) requires each candidate to be evaluated against three axes:

| Criterion | What it requires |
|-----------|-----------------|
| **Atomic compare-and-advance of (value, digest)** | The transition from `(v, d)` to `(v+1, d')` is indivisible: a concurrent reader sees either the old state or the new state, never a half-written `(v+1, d_old)` or `(v, d_new)`. |
| **Session fencing** | Only the holder of the current session can advance; a concurrent `open` acquires a new session and invalidates all prior sessions' advances. |
| **Rollback resistance** | The counter value never decreases across process restarts, power loss, or hardware failure. A `read` after restart returns a value ≥ the last successfully advanced value. |

---

## Candidate backends

### A — TPM 2.0 NV counter

A TPM 2.0 NV index of type `TPM_NT_COUNTER` supports a hardware increment that survives
power loss. Rollback resistance: **yes** (TPM internal NV). Session fencing: **yes** (NV
authorization policy, PolicyPCR or PolicySigned). Atomic `(value, digest)`:
**no** — `TPM2_NV_Increment` advances the integer only. To bind the digest, a combined
sequence (`TPM2_NV_Increment` + `TPM2_NV_Write` in one TPM policy session) is required, or
a separate NV index holds the digest.

**Gap:** define and verify the combined increment+digest write as a single TPM policy
transaction. Without that, the digest half of the contract is not covered by hardware
atomicity.

**Portability:** requires a physical or firmware TPM 2.0. Not available in all cloud VMs.
Suitable for validator hardware; not suitable for a software-only devnet node.

### B — HSM counter

A hardware security module with a monotonic counter API can provide hardware-enforced
atomic state. Rollback resistance: **yes**. Session fencing: **yes** (HSM session handle or
key-usage policy). Atomic `(value, digest)`: **depends on HSM vendor API** — must confirm
the HSM supports a CAS write of `(integer, 32-byte blob)` as a single transaction.

**Gap:** vendor-specific; needs a concrete API review before this column can be marked
satisfied.

**Portability:** HSM presence required; high setup cost; not suitable for devnet.

### C — Remote counter service (single-writer log / CRDT)

A remote service (e.g. a linearizable key-value store with compare-and-swap, or a
Raft-replicated log) can provide software-enforced CAS over arbitrary state including
`(value, digest)`. Rollback resistance: **conditional** — depends on the service's
durability guarantees (leader lease + fsync). Session fencing: **yes** (session lease token
per open). Atomic `(value, digest)`: **yes** if the service provides a CAS primitive over
the full state.

**Gap:** introduces a network liveness dependency. If the service is unavailable, the
validator cannot sign — this is fail-closed by design, but it ties validator liveness to
the counter service. Needs a liveness analysis before approval.

**Portability:** cloud-portable; suitable for devnet and mainnet with appropriate SLA.

### D — Software file counter (devnet only)

An atomic file-based counter using kernel-level write ordering + fsync + rename approximates
the guarantee on POSIX and NTFS. Rollback resistance: **conditional** — survives process
restart and OS crash, but not hardware failure (disk loss). Session fencing: **yes** (file
lock or advisory lock). Atomic `(value, digest)`: **yes** via rename: write `(v+1, d')` to
a new file, fsync, rename over the old file, fsync directory.

**Classification:** devnet only. This is an improvement over `TestCounter` (which is
in-memory and loses state on process exit) but does not meet the full contract for
production. A node using this backend must be explicitly configured as devnet-only and must
refuse to initialize without that flag.

**Portability:** Linux, macOS, NTFS (Windows). No hardware dependency. Fast to implement.

---

## Evidence required for a production backend (not `TestCounter`)

The 87 BossKing passes establish the **store protocol** with `TestCounter`. A production
backend must present its own evidence for three scenarios that `TestCounter` cannot simulate:

| Scenario | Required test |
|----------|--------------|
| **Crash recovery** | Kill the process after `fsync` but before `advance` returns (or simulate power loss after the counter's underlying write but before the acknowledge). On restart, `open` must either find the counter at `v+1` (recovery path: advance completes) or at `v` (no-op: re-advance succeeds). It must never open a store whose `digest` does not match the counter's stored digest. |
| **Concurrent writers** | Two concurrent `open` calls acquire different sessions. The first to call `advance` succeeds; the second's advance is rejected with a stale session, latching the second store. Neither writer sees a partial state. |
| **Reset handling** | If the counter's backing storage is destroyed (simulate by wiping the counter state), `read` on restart returns either an error or value 0. If value 0 is returned and the safety store file is present and has `counter > 0`, `open` returns `Rollback` and fails closed. The node does not sign anything until a human operator performs key rotation. |

These three scenarios must be demonstrated with the production backend before G7.1-P closes.
The existing 87 tests are the protocol baseline and continue to run against the production
backend as a regression suite; they are not sufficient alone.

---

## §7.1.1 — Digest-bound counter commits: open question

PR #127 adds digest-bound commits. Three tests exist in `pq_hotstuff_safety` (lines
992–1179, BossKing-confirmed) that exercise fork detection via digest mismatch.

**Owner review (2026-11-11):** §7.1.1 remains pending until the document distinguishes two
cases that the current draft conflates:

**Case A — equal-counter open (`file_counter == trusted_counter`):**
The file's `prev_digest` is compared to the counter's stored `digest`. A mismatch means a
different record was committed at the same counter value under a different session (a fork).
The store fails closed.

**Case B — one-step-ahead recovery (`file_counter == trusted_counter + 1`):**
The advance did not complete (crash between file write and counter advance). The file is
valid; the counter just needs to catch up. The comparison here is: does the file's
`prev_digest` match the digest that was current before the advance? If yes, complete the
advance; if no, a different record was committed before the crash (a fork in the recovery
window). Fail closed on the second case only.

**What the current draft does not make explicit:** the digest check in Case B is not the
same check as in Case A. In Case A, the counter is authoritative and the file is suspect.
In Case B, the file is authoritative (write + fsync completed) and the counter's missing
advance is the gap to close. The document must state which side is trusted in each case
before the design can be approved.

**§7.1.1 remains pending** until this distinction is documented and both cases have
dedicated tests that set up the state precisely (not via a combined crash scenario).

---

## Decision needed

1. **Approve one or more backends for a concrete evaluation:** choose from A (TPM), B
   (HSM), C (remote service), or D (software file counter, devnet only), or add a backend
   not listed here.
2. **For the chosen backend(s):** confirm that the atomic `(value, digest)` CAS can be
   satisfied (or identify the gap and authorize gap work to close it).
3. **Approve §7.1 as a Phase 1 required interface** (Track C begins with the chosen
   backend) or **designate §7.1 as Phase 2 / devnet-optional**.
4. If approved for Phase 1: authorize the backend adapter implementation and the three
   crash-recovery / concurrent-writer / reset-handling tests listed above.
5. **§7.1.1:** once the Case A / Case B distinction is documented (can be a revision to
   this document or a separate PR), approve or defer §7.1.1 for Phase 1.

No implementation begins until this decision is recorded here.
