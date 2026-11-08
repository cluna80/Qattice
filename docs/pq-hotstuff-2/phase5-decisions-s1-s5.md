# Snapshot recovery decisions S1–S5 (PROPOSALS for owner approval; nothing here is implemented, activated or approved)

Revises `phase5-snapshot-recovery-design.md` (which this file supersedes where they differ). Pruning stays disabled. No snapshot is installed. Block identity is unchanged by
Step 1; anything below that changes identity is marked **IDENTITY CHANGE** and needs its own owner approval, a new profile id and regenerated test vectors.

## Corrections to the earlier design note
1. **"f+1 attestations" is not automatically sufficient.** The fault model is by VOTING POWER, not by head count. With total power `T` and Byzantine power below `T/3`, the largest
   Byzantine power is `f_p = floor((T-1)/3)`, and a set of signers contains an honest one only if its power is at least `f_p + 1`. Equal power, n = 4: 2 signers; n = 1000: 334
   signers (not 334 "humans" in general: with unequal weights any number of signers can be enough or not enough). Further conditions: the signers are distinct, eligible
   (power above zero, in the fixed set), and counted once; honest validators sign an attestation only for a height they executed themselves, only for the digest they computed, and at
   most one digest per height (a second is equivocation evidence); the attestation is domain-separated (chain, genesis hash, height, block id, digest) and bound to a block that a
   verified header chain proves final; and a validator whose execution is nondeterministic is a faulty validator for this purpose and counts against `f_p`.
2. **Header costs use the actual encodings and signer counts.** See `phase5-header-chain.md` section 4: at 1,000 equal-power validators a minimal QC (667 signers) is 2,211,370 bytes
   (not 3.3 MB, which assumed all 1,000 signers), a minimal TC 4,428,008 bytes, a plain header 2,214,780 bytes and a header with a TC 6,642,792 bytes. A legal certificate may carry
   more signers than the quorum, so protocol bounds must assume `k = n` unless the specification caps the signer count.

## S1 — Authentication: A now; C as the long-term target
**A (now):** no snapshot is trusted; history is replayed from verified headers and payloads. **C (target, IDENTITY CHANGE):** the signed block commits to execution state.

*What state the block commits to.* Header field `exec_state_digest`: the application's canonical state digest after executing the block at height `h - D` (genesis digest for
`h <= D`), where `D = exec_delay` is fixed in genesis. It enters `BlockIdInput` (new field, new profile id, new wire version); chains on the current profile are unaffected.
For the interim app the digest is `ExecCursor.state_digest`. For the real application it must be a canonical, platform-independent state root; whether the existing `StateStore`
Merkle root qualifies is unverified and belongs to S3/U5.

*Why `D >= 2`.* Only final blocks are executed. A proposal at height `h` carries the QC for its parent, which can make block `h-2` final, so `h-2` is the newest block a validator
can be required to have executed when it sees the proposal. `D = 1` would require executing a non-final block. Larger `D` lets execution overlap consensus rounds. Choose `D` from measured
execution time against round time (average execution per block must stay below the average round time, or validators fall behind and cannot vote). Devnet proposal: `D = 4`.

*How a validator verifies before voting.* On a proposal for height `h` a validator (a) validates it as today; (b) requires its durable executor cursor to be at least `h - D`, otherwise
it does not vote yet (the round timeout bounds the wait); (c) compares the proposal's `exec_state_digest` with its own digest after block `h - D` (the executor keeps the last `D + 1`
digests); (d) votes only on equality. On inequality it does not vote and keeps evidence; if the proposer is honest the validator's own state is wrong, so it stops signing (fail closed).
The leader is held to the same rule when proposing. Consequences: a QC for a block implies a quorum, hence at least one honest validator, computed that digest itself; a header chain then
authenticates state digests, and a snapshot at height `H` is verified by recomputing its digest after install and comparing it with the digest in any final header at height `H + D` or above.
No attestation message and no `f_p + 1` argument is needed. Residual assumption: deterministic execution.

*Option B* (signed attestations, corrected threshold above) is a new protocol and is not recommended unless pruning is wanted before the block layout can change.

## S2 — Retention and checkpoints: configurable, safety dependencies override
Parameters: `retain_blocks` (finalized payloads kept above the lowest safety bound), `checkpoint_interval`, `pruning_enabled` (false; hard-wired off in this work).
`prune_below = min(executor durable cursor, latest VERIFIED local checkpoint height, committed height) - retain_blocks`, clamped at zero. Safety dependencies always win: nothing at or above the
executor cursor, the committed tip, a pinned sync-serving session, or anything not final is ever eligible, whatever the targets say. Headers and certificates are not pruned by this rule.

Measured on this machine (four Linux processes, release build, a parallel build competing for CPU, minimum propose gap 150 ms, interim payload about 20 bytes):
* block rate about 5.5 blocks/s (maximum possible with the gap: 6.7/s);
* on disk about 13.7 KB per block per node (3,364,110 bytes for 246 blocks), of which about 13.5 KB is the header and its QC: **certificates are over 99% of storage; pruning interim payloads saves almost nothing**;
* about 270 MB per node per hour at that rate; the safety record is about 11 KB and does not grow;
* with the maximum 64 KiB payload the payload would dominate: up to about 1.5 GB per node per hour at 6.7 blocks/s.
Proposed initial devnet values (to be revisited with the real executor's replay cost): `retain_blocks = 25,000` (about one hour of maximum-rate blocks, the expected offline duration), `checkpoint_interval = 1,000`
(replaying at most 1,000 blocks after a checkpoint; the replay-cost measurement is in `phase5-header-chain.md` section 5). Pruning certificates (the dominant cost) is not covered by any of this and needs a
separate trust-anchor decision (a joiner must trust some recent final block instead of verifying from genesis); it is NOT proposed here.

## S3 — Snapshot interfaces now; the real format deferred
The application supplies and consumes opaque, bounded bytes; consensus never interprets them.
```
Manifest { format_version u16, genesis_hash [32], height u64, block_id [32], state_digest [32],
           total_bytes u64, chunk_size u32, chunk_count u32, chunk_hashes [chunk_count][32] }   // chunk_hash = SHA3-256("CFH1|chunk|" || index u32 || data)
trait SnapshotSource { fn manifest(&self, height: u64) -> Option<Manifest>; fn chunk(&self, height: u64, index: u32) -> Option<Vec<u8>>; }
trait SnapshotSink   { fn begin(&mut self, m: &Manifest) -> Result<(), E>;            // stages in a separate area; live state untouched
                       fn put_chunk(&mut self, index: u32, data: &[u8]) -> Result<(), E>;
                       fn finish(&mut self) -> Result<ExecCursor, E>; }                // recomputes the state digest; installs state AND cursor atomically only if it equals manifest.state_digest
```
Bounds checked with checked arithmetic: `chunk_count * chunk_size >= total_bytes > (chunk_count - 1) * chunk_size`; `total_bytes <= max_snapshot_bytes`; `chunk_count <= 65,536`; every chunk but the last is exactly
`chunk_size`. Authentication is the digest recomputed at `finish` against the digest proven by headers (S1 option C); the chunk hashes only detect and attribute bad chunks early. The real application's format
(and whether `StateStore` can produce a canonical digest and an atomic install) waits for U5 and the real executor.

## S4 — Messages and bounds (exact encodings; none implemented, none added to `netmsg` decode)
Envelope as today: `CFH1|net|` (9) + version u16 + kind u8 = 12 bytes; every length is checked against the remaining input before use; the kind's limit is checked before parsing.
| Kind | Name | Body | Size |
|---|---|---|---|
| 7 | HEADER_REQ | `after [32] || max_headers u32` | 12 + 36 = 48 |
| 8 | HEADER_RESP | `after [32] || count u32 || count x (u32 len || header) || final_qc_flag u8 [|| u32 len || qc]` | 12 + 36 + count x (4 + HDR_MAX) + 1 [+ 4 + QC_MAX] |
| 9 | MANIFEST_REQ | `height u64` (0 = latest checkpoint) | 12 + 8 |
| 10 | MANIFEST_RESP | `present u8 [|| manifest]` | 12 + 1 + (2+32+8+32+32+8+4+4+32 = 154) + 32 x chunk_count |
| 11 | CHUNK_REQ | `height u64 || index u32` | 12 + 12 |
| 12 | CHUNK_RESP | `height u64 || index u32 || u32 len || data` | 12 + 12 + 4 + chunk_size |
`HDR_MAX(n) = 3410 + QC(n,n) + 4 + TC(n,n,n)` (all signers, nested QC): 43,581 bytes at n = 4. At n = 1000 it is 9,957,141 bytes, above 8 MiB, so a single worst-case header does not fit; with a signer cap at the quorum it is 6,642,792 and fits.
`count <= max_headers_per_response = min(configured, floor((limit - 53 - QC_MAX) / (4 + HDR_MAX)))`: n = 4, 8 MiB limit: 192; devnet configured 64. `chunk_size <= 1 MiB` and `28 + chunk_size <= limit`; devnet `chunk_size = 256 KiB`,
`max_snapshot_bytes = 256 MiB` (so `chunk_count <= 1,024`, manifest at most 32 KiB + 154).
Per peer: one outstanding HEADER_REQ and one MANIFEST_REQ; at most 4 outstanding CHUNK_REQ; a served-bytes token bucket of 8 MiB burst refilling at 4 MiB/s; at least 100 ms between requests served; three invalid responses ban the peer for the session.
Aggregate: at most 8 concurrent serves and 32 MiB/s served in total; as a requester at most 3 peers at once, in-flight bytes at most `3 x 4 x chunk_size` in memory (chunks are staged on disk, not held), and deadlines of 30 s per request and 1 h per recovery.
All sizes use checked arithmetic and no allocation is made from a length a peer reported.

## S5 — Unavailable snapshot: wait without signing; genesis replay when verified history exists; fail closed
A node that needs history it does not have enters `Recovering`: it signs nothing (no vote, timeout, proposal or attestation) and proposes nothing, but still serves what it holds. It leaves `Recovering` only when its executor
cursor equals the committed tip proven by a verified header chain and the engine is seeded from it. Two paths, both fail closed: (1) genesis replay, allowed whenever peers can supply verified headers and payloads
(each payload checked against its header with `check_payload`, then executed through the normal handoff); (2) snapshot install (S3) once S1 option C exists. Invalid data from either path (bad header, bad chunk, digest mismatch,
payload hash or size) is discarded, the peer is penalized, and nothing is trusted instead. If no peer can supply either path the node stays in `Recovering` and reports it; it never falls back to unverified state and never touches the
safety store, which resumes at `max(its own record, the recovered tip)`.

## Decisions still needed
S1 approval of option C (IDENTITY CHANGE, `exec_delay`, canonical state root); whether to cap the certificate signer count (specification change that decides whether a 1,000-validator network fits 8 MiB); S2 numbers after the replay-cost
measurement; S3 real format (U5); S4 approval of the kinds and bounds; plus the unchanged items: U5, draft QC/TC approval, PO-4, D2, production keys and counter.
