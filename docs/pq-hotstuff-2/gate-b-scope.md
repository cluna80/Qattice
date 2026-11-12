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

## What Gate A demonstrated (in-process doubles)

Gate A proved the signing rules using `MemStorage` and `TestCounter` — in-process test
doubles with no TCP, no OS processes, and no hardware-backed monotonic counter. The 13
acceptance tests confirm:

- Seal enforced: no new epoch-0 signature above seal round after `write_seal`.
- Incoming set blocked from epoch-0 signing after `advance_epoch_record`.
- `RoundBelowEpochMinimum`: epoch-1 round-0 is denied.
- R3-a recovery: seal durable, epoch not yet advanced — `advance_epoch_record` completes
  correctly on restart.
- R3-b: `set_hash` and `handoff_cert_hash` survive a storage round-trip and are readable
  on `open`.
- Crash injection at steps 1, 2, and 3–4 of the R2 write order: each crash leaves the
  store in a state that opens correctly and resumes from the right step.

What Gate A did NOT demonstrate:

- A `MonotonicCounter` backed by an actual OS primitive (file, TPM, etc.).
- Two OS processes where one crashes mid-commit and the other (or the restarted process)
  detects the crash window via the counter mismatch on `open`.
- Write-order step boundaries visible at the OS level (e.g., the counter advance
  happening in a separate OS write from the state file write).
- A live TCP connection where a vote is transmitted only after `write_seal` returns.

Gate B closes all four gaps.

---

## B1 — TCP epoch-boundary test (write-before-broadcast over a real socket)

**What it tests:** a validator cannot transmit a signed epoch-0 vote after the seal is
written, and cannot transmit an epoch-1 vote before `advance_epoch_record` completes.

**Setup:**

- Two OS processes on Windows (BossKing MINGW64): a sender process and a receiver process.
- Sender holds a `SafetyStore` backed by real file storage (`fs::FsStorage`) and a
  `MonotonicCounter` backed by a real OS counter (see B3).
- Real ML-DSA-65 keys (generated for the test, not stored permanently).
- The sender and receiver communicate over a loopback TCP socket.

**Scenario:**

```
1. Sender votes at epoch=0, round=5 (B_child). Receiver logs the vote.
2. Sender calls write_seal(0, 5). Receiver must NOT receive any new epoch-0 vote
   at round > 5 after this point.
3. Sender calls advance_epoch_record(1, set_hash, cert_hash).
4. Sender attempts to sign epoch-0 round-6 vote — must get SealViolation.
5. Sender signs epoch-1 round-1 vote — must succeed.
6. Receiver receives the epoch-1 round-1 vote.
7. No epoch-0 message at round > 5 ever appears on the socket.
```

**Acceptance:** owner pastes the test output showing all 7 steps completed on Windows,
no epoch-0 round-6 message received, epoch-1 round-1 message received.

---

## B2 — Crash injection over OS processes

**What it tests:** a process crash at each step of the R2 write order leaves the store
in a state that (a) `open` accepts, (b) the counter mismatch is correctly classified, and
(c) the correct recovery path (R3-a or R3-b) resumes signing without producing a
conflicting signature.

The four crash points from R2:

| Crash point | State after crash | Expected `open` outcome |
|---|---|---|
| After CommitCertificate written, before `write_seal` | No seal in record | Opens at epoch 0; R3-a caller writes seal then advances |
| After `write_seal`, before `advance_epoch_record` | Seal in record, epoch 0 | Opens at epoch 0 with seal; R3-a advances |
| After `advance_epoch_record`, before `signing_ctx.advance_epoch` | Epoch 1 in record | Opens at epoch 1; signing context re-attached |
| After full advance, clean shutdown | Epoch 1, set_hash, cert_hash present | Opens at epoch 1 normally |

**Crash mechanism:** the test process is killed with `TerminateProcess` (Windows) at a
controlled point between OS writes, then a second process opens the same files. The
second process must not be able to produce a conflicting epoch-0 message at any round
above the seal round.

**Acceptance:** owner pastes output from each of the four crash scenarios showing:
- The restarted process opens successfully (or fails closed for the one scenario where it
  should fail).
- No conflicting signature is produced.
- The correct recovery step (`write_seal` or `advance_epoch_record`) runs idempotently.

---

## B3 — Real `MonotonicCounter` on Windows

Gate A used `TestCounter` (in-memory, not a trusted mechanism). Gate B requires a real
OS-backed counter. Two options; owner chooses before implementation begins:

**Option A — File-based counter (simplest, no hardware dependency):**
A counter file holding `(value: u64, digest: [u8; 32])` written with `FILE_FLAG_WRITE_THROUGH`
and `FlushFileBuffers` on Windows. The fencing token is a named mutex or file lock.
Not TPM-backed, but durable across process crashes. Sufficient for Gate B.

**Option B — Windows DPAPI-sealed counter:**
Counter value sealed with `CryptProtectData` to the machine identity. Provides
machine-binding but requires Windows CNG. Higher implementation cost; not required for
Gate B unless owner decides it is.

**Default for Gate B:** Option A (file-based, `FILE_FLAG_WRITE_THROUGH`).

The counter implementation ships as a new crate (`chain-forge-counter`) or as a
`fs` module inside `chain-forge-consensus`'s safety directory, feature-gated behind
`monotonic-counter-fs`.

---

## B4 — Acceptance criteria summary

Both B1 and B2 must be run by the owner on BossKing MINGW64 and the output pasted.
Sandbox runs do not count (per CLAUDE.md test validation policy).

| Test | Transport | Counter | Required |
|---|---|---|---|
| Gate A epoch-boundary (13 tests) | In-process doubles | `TestCounter` | ✅ Windows-confirmed at `7ca0aa7` |
| B1 TCP epoch-boundary | Loopback TCP, OS processes | Real file counter | Required for Gate B |
| B2 crash injection × 4 | OS `TerminateProcess`, file storage | Real file counter | Required for Gate B |

After B1 and B2 pass on Windows, the epoch-transition flag may be enabled in a devnet
configuration with separate owner approval.

---

## Open obligations carried forward from Gate A

These are not Gate B blockers but must be resolved before the competing-candidates
argument and the delayed-proof window can be cited as model-verified results:

| Obligation | Required for |
|---|---|
| `crash_t3_disjoint` re-run with saved log and restart witness | R3 citing PO-4 |
| Compete scenario (SetB non-empty) exhaustive safety | R4 BFT argument |
| Delayed-proof window safety (SnapSync crash witness) | R2 seal-timing argument |
