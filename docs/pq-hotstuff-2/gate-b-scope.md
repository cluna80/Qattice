# Gate B scope — QAT-07 epoch-boundary TCP + crash injection

**Status:** specification only. Gate B is locked until Gate A is Windows-confirmed.
Gate A confirmed on Windows (BossKing MINGW64) at `7ca0aa7`, 2026-11-12.

Gate B requires owner approval of this document before implementation begins.
Gate B implementation requires separate owner approval before the epoch-transition
flag is enabled in any devnet or node configuration.

**Builds on:** `docs/pq-hotstuff-2/epoch-switchover-scope.md` (Gate A scope, approved
2026-11-12). All rules in that document (R1–R5) remain in force. This document adds
only the additional acceptance criteria required to lift the flag from disabled to enabled.

---

## Gate A evidence record

Gate A used `MemStorage`, `TestCounter`, and `TestSigner` — in-process test doubles.
`TestSigner` is a hedged test scheme that produces ML-DSA-65-sized signatures (3,309
bytes) but does **not** call the real FIPS 204 signing primitive. The 13 acceptance
tests confirm the write-order logic and signing-rule enforcement; they do not confirm
real ML-DSA-65 signing behavior or OS-level write durability.

What Gate A demonstrated:
- Seal enforced: `SealViolation` on new epoch-0 signature above seal round after
  `write_seal`.
- `EpochRegression` on epoch-0 signature after `advance_epoch_record`.
- `RoundBelowEpochMinimum`: epoch-1 round-0 is denied.
- R3-a recovery: seal durable, epoch not yet advanced — `advance_epoch_record` completes
  correctly on restart with in-memory doubles.
- R3-b: `set_hash` and `handoff_cert_hash` survive a storage round-trip and are readable
  on `open` with in-memory doubles.
- Crash injection at steps 1, 2, and 3–4 of the R2 write order using `MemStorage` fault
  injection (not OS-level process kills).

What Gate A did NOT demonstrate:
- Real FIPS 204 ML-DSA-65 signing (TestSigner is a size-conformant stub).
- A `MonotonicCounter` backed by an actual OS primitive.
- Two OS processes where one is killed mid-commit and the other detects the crash window
  via counter mismatch on `open`.
- Write-order step boundaries visible at the OS level (counter advance is a separate OS
  write from the state file write).
- A live TCP connection where a vote is transmitted only after `write_seal` returns.

Gate B closes all five gaps.

---

## B1 — TCP epoch-boundary test (write-before-broadcast, isolated seal checks)

**What it tests:** the seal and epoch-advance checks are distinct. The seal fires before
the epoch advances; the epoch-regression check fires after. An incoming vote before the
durable advance must produce no wire frame.

**Setup:**

- Two OS processes on Windows (BossKing MINGW64): a sender process and a receiver process.
- Sender: `SafetyStore` backed by real file storage (`fs::FsStorage`) + real file-based
  `MonotonicCounter` (see B3). Real FIPS 204 ML-DSA-65 keys generated for the test.
- Sender and receiver communicate over a loopback TCP socket.
- Receiver logs every frame it receives, tagged by epoch and round.

**Scenario and required assertions:**

```
Step 1  Sender votes epoch=0 round=5 (B_child). Receiver logs frame (0,5). [OK]

Step 2  Sender calls write_seal(0, 5). Seal is now durable. Epoch record still at 0.

Step 3  Sender attempts to sign epoch=0 round=6 vote.
        ASSERT: sign returns SealViolation { epoch:0, round:6, seal_round:5 }.
        ASSERT: no (0,6) frame appears on the receiver socket.

Step 4  Sender attempts to sign epoch=1 round=1 vote.
        ASSERT: sign returns ProofNotDurable (advance_epoch_record not yet called).
        ASSERT: no (1,1) frame appears on the receiver socket.

Step 5  Sender calls advance_epoch_record(1, set_hash, cert_hash).
        Epoch record now at 1.

Step 6  Sender attempts to sign epoch=0 round=7 vote.
        ASSERT: sign returns EpochRegression { record:1, requested:0 }.
        ASSERT: no (0,7) frame appears on the receiver socket.

Step 7  Sender signs epoch=1 round=1 vote. Sends frame.
        ASSERT: sign succeeds with real ML-DSA-65 signature.
        ASSERT: receiver logs frame (1,1) with valid signature bytes.
        ASSERT: receiver has logged exactly one frame total at epoch=0 (step 1)
                and exactly one frame at epoch=1 (step 7). No other frames.
```

**Note on Step 4:** `ProofNotDurable` is the R2 table row for `req.epoch == rec.epoch+1,
proof durable = FALSE`. If the signing context gates on proof delivery rather than the
safety store, the error name may differ; the invariant is that no epoch-1 frame reaches
the wire until `advance_epoch_record` returns `Ok`.

**Acceptance:** owner pastes the test output on Windows showing all 7 steps completed
with the stated assertions.

---

## B2 — Crash injection at exact OS-level kill points

**What it tests:** a `TerminateProcess` kill at each step boundary leaves the store in
a state that (a) `open` accepts, (b) the counter mismatch is correctly classified, and
(c) the correct recovery path resumes signing without producing a conflicting signature.
Clean shutdown after a full advance is kept as a control, not a replacement for the kill cases.

The R2 write order has four boundaries and therefore four kill points:

| Kill point | Label | State file after kill | Counter after kill | Expected `open` outcome |
|---|---|---|---|---|
| K0 | After CommitCertificate written (block store); before `write_seal` | Record at epoch 0, no seal | Matches state file | Opens at epoch 0, no seal; R3-a: caller writes seal then advances |
| K1 | After `write_seal` state file written; before counter advance | Record at epoch 0 with seal; counter one behind file | Crash window (counter+1 == file.counter) | Opens at epoch 0 with seal; R3-a: `advance_epoch_record` |
| K2 | After `advance_epoch_record` state file written; before counter advance | Record at epoch 1 with set_hash/cert_hash; counter one behind | Crash window | Opens at epoch 1; R3-b: verify hashes, restore floors |
| K3 (control) | After full advance, clean `into_parts()` | Record at epoch 1 | Matches state file | Opens at epoch 1 normally |

**For K1 and K2 (crash window):** `open` adopts the durable file and completes the
counter advance. This is the standard crash-window recovery path in `store::open`. The
key additional assertion for Gate B is:

- After adopting a K1 state: the signer cannot produce a new epoch-0 signature at any
  round above the seal round (SealViolation fires before any new signing attempt).
- After adopting a K2 state: the signer cannot produce an epoch-0 signature
  (EpochRegression fires). It can produce an epoch-1 signature at round ≥ 1.

**Signing blocked until handoff proof reconciles (R3-a):**

After a K0 or K1 crash, the caller must run R3-a before attaching the signing context.
Specifically:
- Load `CommitCertificate` from block store. Fail closed if missing.
- Verify cert against V_old public keys. Fail closed if invalid.
- If seal not in record: `write_seal`. If seal already in record: skip.
- `advance_epoch_record(1, set_hash, cert_hash)`.
- Only then attach signing context.

The test verifies that any attempt to produce a signature between `open` and R3-a
completion returns an error (signing context not attached), not a stale epoch-0 signature.

**Crash mechanism:** `TerminateProcess(GetCurrentProcess(), 1)` called from the sender
process at a controlled point, exercised in a child process launched by the test harness.
The test harness opens the resulting files in a second process and runs the assertions.

**Acceptance:** owner pastes output from each of the four kill points showing:
- The restarted process opens successfully (or fails closed if appropriate).
- No conflicting signature is produced.
- The correct recovery step runs idempotently.
- Signing is blocked until R3-a or R3-b completes.

---

## B3 — File-based `MonotonicCounter` for devnet testing

Gate A used `TestCounter` (in-memory, not a trusted mechanism). Gate B requires an
OS-backed counter that survives process crashes.

**Specification:**

The counter file holds a fixed-width record: `value: u64` (big-endian) `|| digest: [u8; 32]`.
Writes use `FILE_FLAG_WRITE_THROUGH` and call `FlushFileBuffers` before returning.

**Writer fencing across processes:** the counter file is opened with `GENERIC_WRITE |
FILE_SHARE_READ` and no write-share flag. A second process attempting to advance the
counter will receive `ERROR_SHARING_VIOLATION` and fail closed. This is the fencing
mechanism: only the holder of the open file handle can advance the counter.

The `acquire_session()` call opens the counter file. `into_parts()` closes it, releasing
the fence. A process killed without calling `into_parts()` releases the fence when the
OS closes the handle on process exit.

**Recovery of `(value, digest)` after crash:** `read()` decodes the file. Because writes
are `FILE_FLAG_WRITE_THROUGH`, a killed process leaves either the previous record or the
new record, never a partial write (assuming the OS honours the write-through guarantee,
which is the standard Windows contract for `FILE_FLAG_WRITE_THROUGH` with sector-aligned
writes or on NTFS). The `open` logic in `SafetyStore` already handles both outcomes via
the crash-window classification.

**What this does NOT cover:**

- **Power-loss durability:** `FILE_FLAG_WRITE_THROUGH` reaches the OS page cache and the
  disk controller's write-back buffer. Reaching the platter or flash on a power loss
  requires `FILE_FLAG_NO_BUFFERING` with sector-aligned writes, or a hardware-level
  `FlushFileBuffers` on a device that honours it. This is not required for Gate B devnet
  testing but must be addressed before production deployment. Record this as an open
  obligation.
- **Rollback resistance:** a user with filesystem access can overwrite the counter file
  with an older value. A hardware-backed counter (TPM NV index, secure enclave) prevents
  this. Record this as an open obligation. For devnet, the file counter provides
  process-crash resistance; physical-access resistance is out of scope.

**Counter crate:** ships as `chain-forge-consensus/src/pq_hotstuff/safety/fs_counter.rs`
(or a new crate `chain-forge-counter`), feature-gated behind `monotonic-counter-fs`.
Not enabled in the default build or existing tests.

---

## B4 — Acceptance criteria

Both B1 and B2 must be run by the owner on BossKing MINGW64 and the output pasted.
Sandbox runs do not count (per CLAUDE.md test validation policy).

| Test | Transport | Signer | Counter | Required |
|---|---|---|---|---|
| Gate A epoch-boundary (13 tests) | In-process doubles | `TestSigner` (size-conformant stub, not real FIPS 204) | `TestCounter` (in-memory) | ✅ Windows-confirmed `7ca0aa7` |
| B1 TCP epoch-boundary | Loopback TCP, two OS processes | Real FIPS 204 ML-DSA-65 | File counter (`FILE_FLAG_WRITE_THROUGH`) | Required |
| B2 crash injection × 4 (K0–K3) | `TerminateProcess`, file storage | Real FIPS 204 ML-DSA-65 | File counter | Required |

After B1 and B2 pass on Windows with pasted output, the epoch-transition flag may be
enabled in a devnet configuration with separate owner approval.

---

## Open obligations (not Gate B blockers)

These must be resolved before the following claims can be cited as model-verified:

| Obligation | Blocks |
|---|---|
| `crash_t3_disjoint` re-run with saved log and restart witness | R3 citing PO-4 |
| Compete scenario (SetB non-empty) exhaustive safety | R4 BFT argument for competing candidates |
| Delayed-proof window safety (SnapSync crash witness) | R2 seal-timing BFT argument |
| Power-loss durability for `MonotonicCounter` | Production deployment of file counter |
| Rollback resistance for `MonotonicCounter` | Production deployment without hardware backing |
