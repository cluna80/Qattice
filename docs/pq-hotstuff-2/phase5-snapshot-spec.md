# Snapshot recovery specification (one recommended design; DRAFT for owner approval)

**Nothing here is implemented, activated or approved.** Option A stays operational. Block identity is unchanged. Network snapshot installation and pruning stay disabled. This document supersedes the S1, S4 and
S5 sections of `phase5-decisions-s1-s5.md` and the earlier `phase5-snapshot-recovery-design.md` wherever they differ; their corrections (voting-power thresholds, actual certificate encodings) stand.
Certificate validity rules (`check_header`, `verify_qc`, `verify_tc`) are NOT changed anywhere in this design.

## 0. Defects resolved
| Concern | Resolution |
|---|---|
| Fixed delay `D` | Removed. A block may carry an explicit `CheckpointRef { height, block_id, state_root }` (section 2). Validators prove it final, check the root against their own execution, and a snapshot is authenticated against that exact reference. |
| "A conflicting digest proves local corruption" | It does not. Mismatch with an uncertified proposal only withholds the vote. Halting happens only on a certified contradiction or a local execution failure (2.5). |
| Exactly-quorum signer cap | Not adopted. Validity unchanged; transport limits use the maximum certificate permitted (`k = n`). Power-aware selection is a separate, non-consensus proposal (`phase5-certificate-selection.md`). |
| S4 gaps | Section 3: TC-bearing header plus an extra QC, zero-fitting-header responses (typed `TOO_LARGE`), immutable snapshot ids, request/response correlation, bounded allocation and concurrency, the oversize-object rule. |
| Atomic install | Section 4: stage, validate against the independently authenticated root BEFORE publishing, publish state and cursor in one pointer swap, crash matrix, SafetyStore untouched. |
| Recovery rounds | Section 5, from the real rules in `rules.rs` (floors `hvr`, `hqr`; QC/TC round advance). |

## 1. Operational baseline (Option A) and gating
Today: no snapshot is trusted. A node that falls behind uses validated block sync, or Step 1 header verification plus payload fetch (`check_payload`), and replays through the execution handoff. All finalized
payloads are retained. This design adds nothing to that. Gates, all default off and absent from the node binary until each acceptance group in section 7 passes on Linux and Windows:
`snapshot_install_enabled = false`, `pruning_enabled = false`, message kinds 7 to 14 are not decoded (`netmsg::decode` rejects them as unknown kinds), no `checkpoint_ref` in `BlockIdInput`.

## 2. Checkpoint references (S1; target architecture C, not implemented)
### 2.1 Encoding
`CheckpointRef = height u64 || block_id [32] || state_root [32]` = 72 bytes, big-endian. `ref_hash = SHA3-256("CFH1|ckpt|" || CheckpointRef)`. `state_root` is the application's canonical commitment to its state after
executing the block at `height`, and it equals `ExecCursor.state_digest` at that height (interim app: the hash chain value; the real application's canonical root is unverified and belongs to U5).
Genesis parameter `checkpoint_interval K >= 1`; devnet proposal `K = 1,000`.

### 2.2 Where it lives (IDENTITY CHANGE, requires owner approval and a new profile id; not implemented)
A new optional block field `checkpoint_ref` (flag byte + 72 bytes, 73 bytes per block when present) enters `BlockIdInput` as `ref_hash` (absent = a fixed zero marker). Chains on profile v2 are unchanged and keep
today's ids. The header form (Step 1) gains the same field, so headers prove it.

### 2.3 Rules for a block that carries a reference (checked by every validator before voting)
* **R1 shape:** `height >= 1`, `height % K == 0`.
* **R2 finality:** `height <= F(B)`, where `F(B)` is the highest height final in the chain ending at `B.parent` once `B.qc` is counted: if `B.qc` certifies `C` and `C`'s parent `P` satisfies `commits_parent(P.round, C.round)` and is not genesis, `F = P.height`, otherwise `F` is what `C`'s own chain had. Deterministic from the proposal and the validator's chain; independent of local execution progress.
* **R3 identity:** the block at `height` on `B`'s own chain has id `block_id`.
* **R4 monotonic:** if an ancestor carries a reference, `height >= ` that height, and at equal height the reference is identical.
* **R5 execution root** (the only rule that depends on local state), three outcomes: `Match` (own root at `height` equals `state_root`): proceed to vote. `NotYet` (own executor has not reached `height`): do not vote now and re-evaluate when it does; this is
  deferral, not evidence, and the round timeout applies as usual (timeouts never depend on references). `Mismatch`: do not vote; keep `{block_id, ref, own root}` as evidence.
The executor keeps its roots at multiples of `K` for the last 4 checkpoints. **Proposer policy (not a validity rule):** reference the newest multiple of `K` that is `<= min(F(B), own executor height - ref_margin)`, `ref_margin = 100` on the devnet,
and omit the field when none qualifies. References are optional, so a lagging validator can never block block production; it can only defer its own vote on a block that carries one.

### 2.4 How a joiner proves a checkpoint final
From a trusted start (genesis or a final anchor) the joiner runs `verify_header_chain` over the header chain until a header `X` that carries reference `R` is in `finalized` (needs `X`'s child and grandchild, or a final QC). It accepts `R` iff:
(a) `X` is final; (b) the verified chain has a block at `R.height` with id `R.block_id` (it is an ancestor of `X`, so final); (c) rules R1 to R4 hold along the verified chain. Why `R.state_root` is trustworthy: `X` is final, so a QC exists for `X`; its quorum voters each applied R5 and voted only on `Match`;
a quorum contains at least one honest validator when Byzantine power is below one third; that validator's own root equals `R.state_root`; execution is assumed deterministic. Nothing is trusted from the snapshot server.

### 2.5 Divergence
* Mismatch against an uncertified proposal: withhold the vote, keep evidence, no halt (the proposer or a minority may be wrong; one validator cannot tell which).
* **Certified contradiction:** the validator's own root at `R.height` differs from the reference in a block that is FINAL in its verified view (or has a QC). Then a quorum accepted `R`, so the validator is in the minority: it stops signing, enters `Recovering` (section 5) and reinstalls through the section 4 path.
* Two final blocks carrying different roots for the same height means more than one third of voting power equivocated: raise a SAFETY alarm and stop; nothing is repaired automatically.
* A local execution error, executor checksum failure or crash-recovery inconsistency halts signing independently of any reference.

### 2.6 Snapshot authentication
A manifest request names the exact `CheckpointRef` the joiner authenticated (message 9). The installer recomputes the state root from the staged data and requires it to equal `R.state_root`, and the staged cursor to be `(R.height, R.block_id, R.state_root)`. A root or cursor taken from the snapshot, the manifest or the peer is never used for the comparison.

## 3. Messages (S4): exact encodings, big-endian; new kinds 7 to 14 in the `CFH1|net|` envelope (12 bytes: tag 9, version u16, kind u8)
**Common rules.** Every request carries `request_id u64`. Every response echoes `request_id u64` then `status u8`, then the echoed selector fields. Status: `0 OK`, `1 NOT_FOUND`, `2 TOO_LARGE`, `3 BUSY`, `4 UNAVAILABLE` (not retained, or the feature is disabled), `5 AT_TIP` (header requests only). A non-OK response carries only the fields stated for it. `OK` with a zero count is invalid and rejected.
The length of the whole message is checked against the kind's limit before parsing; each inner length and count is checked against the remaining input and its own maximum before anything is allocated; vectors grow by push, never `with_capacity(untrusted)`.

| Kind | Name | Body | Fixed size |
|---|---|---|---|
| 7 | HEADER_REQ | `request_id u64 \|\| after [32] \|\| max_headers u32` (1 to `max_headers_per_response`) | 12 + 44 = 56 |
| 8 | HEADER_RESP | `request_id u64 \|\| status u8 \|\| after [32]`; OK: `count u32 (>=1) \|\| count x (u32 len \|\| header) \|\| final_qc_flag u8 [\|\| u32 len \|\| qc] \|\| tip_height u64`; AT_TIP: `tip_height u64`; TOO_LARGE: `needed_bytes u64 \|\| next_height u64` | OK: 12 + 8 + 1 + 32 + 4 + count x (4 + header) + 1 [+ 4 + qc] + 8 |
| 9 | MANIFEST_REQ | `request_id u64 \|\| ref (72)` | 12 + 80 = 92 |
| 10 | MANIFEST_RESP | `request_id u64 \|\| status u8 \|\| ref (72)`; OK: `manifest`; TOO_LARGE: `needed_bytes u64` | OK: 12 + 8 + 1 + 72 + manifest |
| 11 | CHUNK_REQ | `request_id u64 \|\| snapshot_id [32] \|\| index u32` | 12 + 44 = 56 |
| 12 | CHUNK_RESP | `request_id u64 \|\| status u8 \|\| snapshot_id [32] \|\| index u32`; OK: `u32 len \|\| data` | OK: 12 + 8 + 1 + 32 + 4 + 4 + len |
`manifest = format_version u16 || snapshot_id [32] || total_bytes u64 || chunk_size u32 || chunk_count u32 || chunk_hashes [chunk_count][32]` (50 + 32 x chunk_count bytes).
`chunk_hash(i) = SHA3-256("CFH1|chunk|" || i u32 || data)`. **`snapshot_id = SHA3-256("CFH1|snapshot|" || genesis_hash || ref (72) || format_version || total_bytes || chunk_size || chunk_count || SHA3-256(chunk_hashes concatenated))`.** The id is content-addressed, so a snapshot is immutable by construction: the same id can only mean the same bytes. Two servers may chunk the same state differently and so produce different ids; that does not matter, because authentication is the state root of section 2.6, not the id.
Constraints (checked arithmetic): `chunk_count in 1..=65,536`; `chunk_size in 1..=1 MiB` and `61 + chunk_size <= transport limit` (the CHUNK_RESP overhead: `12 + 8 + 1 + 32 + 4 + 4`); `(chunk_count - 1) x chunk_size < total_bytes <= chunk_count x chunk_size`; `total_bytes <= max_snapshot_bytes` (devnet 256 MiB); every chunk but the last has exactly `chunk_size` bytes; the last has `total_bytes - (chunk_count - 1) x chunk_size`. Devnet `chunk_size = 256 KiB`.
Kinds 13 and 14 are reserved (`PAYLOAD_REQ` / `PAYLOAD_RESP` for fetching a payload by header hash) and not specified here.

### 3.1 Header responses: contents and worst case
Headers are returned oldest first, contiguous after `after` along the responder's final chain, and the response stops before the first header that would exceed the limit or `max_headers_per_response`. `final_qc` is a QC for the last header and is included only if it fits. `HDR_MAX(n) = 3,410 + QC_MAX(n) + 4 + TC_MAX(n)` is a TC-bearing header at the maximum certificate size (`QC_MAX(n) = 140 + ceil(n/8) + 3,315 n`; `TC_MAX(n) = 72 + ceil(n/8) + 3,323 n + QC_MAX(n)`). The smallest response a responder must be able to send, one TC-bearing header plus an additional QC, is
`HDR_RESP_MIN(n) = 12 + 8 + 1 + 32 + 4 + (4 + HDR_MAX) + 1 + (4 + QC_MAX) + 8 = HDR_MAX + QC_MAX + 74`.
Selection rule (exact): the fixed part of an OK response is `66` bytes (`12 + 8 + 1 + 32 + 4 + 1 + 8`); add headers, each costing `4 + len`, while `66 + sum <= limit` and the count is at most `max_headers_per_response` (devnet 64); then append the optional final QC (`4 + len`) only if it still fits. The result always contains at least one header or is a typed non-OK response.

### 3.2 Required transport limit (maximum permitted certificates, `k = n`, payload 64 KiB, 1,024 chunks of 256 KiB)
| n | `QC_MAX` | `TC_MAX` | `HDR_MAX` | `HDR_RESP_MIN` | proposal | binding requirement |
|---|---|---|---|---|---|---|
| 4 | 13,401 | 26,766 | 43,581 | 57,056 | 109,101 | 262,205 (chunk) |
| 31 | 102,909 | 205,998 | 312,321 | 415,304 | 377,841 | 415,304 |
| 100 | 331,653 | 664,038 | 999,105 | 1,330,832 | 1,064,625 | 1,330,832 |
| 1000 | 3,315,265 | 6,638,462 | 9,957,141 | 13,272,480 | 10,022,661 | 13,272,480 (12.66 MiB) |
Under the owner-locked 8 MiB limit the maximum permitted certificates support **at most 631 validators**; under 16 MiB (the libp2p receive cap, with zero margin and its framing overhead unverified) at most 1,264. A 1,000-validator network therefore needs a limit of about 13.3 MB, or a smaller maximum permitted certificate (a specification change this document does not make).

### 3.3 A valid object that exceeds the envelope
* **Startup (the rule that normally prevents it):** every validator computes the required limit for every enabled kind from its `n`, payload limit, `K`-block sync size and `chunk_size`, and refuses to enable the feature if its transport limit is lower. Consensus startup already does this for proposals; the recovery kinds add `HDR_RESP_MIN`, the manifest and the chunk response.
* **Responder holds a valid object that does not fit its own limit:** it answers `TOO_LARGE` with `needed_bytes` (the exact size of the smallest response containing the object) and, for headers, `next_height`. It never truncates, splits or downgrades. This is also the zero-fitting-header case: a count of zero is never sent as OK.
* **Requester:** `needed_bytes <=` its own limit: record the peer as unable and ask another peer. `needed_bytes >` its own limit: terminal state `ObjectExceedsEnvelope { kind, height, needed }`; the node stays in `Recovering`, reports it, and does not fall back to unverified state; the operator must restart with a validated larger limit.
* **An inbound frame larger than the limit** is closed by the transport before parsing and counted; it is not interpreted as `TOO_LARGE`.

### 3.4 Correlation
The requester keeps a table of at most `outstanding_cap` entries `(peer, kind, request_id, selector, deadline)`; `selector` is `after` (7), `ref` (9) or `(snapshot_id, index)` (11). A response is accepted only if it matches an entry on peer, kind, `request_id` AND the echoed selector, within its deadline; the entry is removed on acceptance. Anything else (unknown id, wrong peer or kind, selector mismatch, duplicate, late) is dropped and counted as unsolicited. `request_id` comes from a 64-bit counter started at a random value for each process and never reused within a process.

### 3.5 Bounds on allocation and concurrency
* Requester, per peer: at most 1 outstanding HEADER_REQ, 1 MANIFEST_REQ, 4 CHUNK_REQ; globally `outstanding_cap = min(16, floor(max_recovery_memory / transport_limit))` (devnet `max_recovery_memory = 64 MiB`, so 8 at 8 MiB), and the feature refuses to enable if this is 0. Worst-case buffered bytes `<= outstanding_cap x transport_limit <= max_recovery_memory`. At most 3 peers in use. Deadlines: 30 s per request, 1 h per recovery. Chunks are written to the staging area, not held in memory. Three invalid responses ban a peer for the session.
* Responder: at most 8 concurrent serves (served bytes in flight `<= 8 x limit`, 64 MiB at 8 MiB), at most 4 outstanding requests per peer, a per-peer token bucket (8 MiB burst, 4 MiB/s), at least 100 ms between requests served per peer; excess requests get `BUSY`, never silence. Total served rate `<= 32 MiB/s`.

## 4. Atomic installation (disabled; protocol and recovery matrix)
Durable files in the node's private data directory, each replaced with write, `fsync`, rename, directory sync, each with a trailing SHA3-256 checksum and a tag:
* `recovery.state` = `"CFH1|recovery|" || version u16 || phase u8 (0 Idle, 1 Staging, 2 Verified, 3 Published) || generation u64 || ref (72) || snapshot_id [32] || checksum`.
* `install-record` (local trust record, written only after the joiner's own verification succeeded) = `"CFH1|install|" || version u16 || ref (72) || carrier (id, height, round) || tip final point (id, height, round, payload_hash) || high_qc (u32 len || qc) || checksum`; at most `QC_MAX + 300` bytes.
* `app-current` pointer = `"CFH1|app-ptr|" || version u16 || generation u64 || state_dir (u8 len, at most 64 bytes) || cursor (height u64, block_id [32], state_root [32]) || checksum`. **Application state and cursor are published together by the single rename of this pointer.**
Procedure: (1) write `recovery.state = Staging{ref, snapshot_id}`; (2) stage each chunk under `staging/<snapshot_id>/`, verifying it against its `chunk_hash` on arrival; (3) when complete, load the staged data into a SHADOW state, recompute its root, and compare with the independently authenticated `R.state_root`, and the staged cursor with `(R.height, R.block_id)`; any mismatch deletes the staging area, sets `Idle`, penalizes the peer and publishes nothing; (4) write `install-record`; (5) `recovery.state = Verified`; (6) **publish** by swapping `app-current` to the new generation; (7) `recovery.state = Published`, seed the engine from `install-record` (section 5), then `Idle`, then delete the old state directory and the staging area.
| Crash point | Next start |
|---|---|
| steps 1 to 5 | old application state and cursor intact; staging area discarded; `Idle`; nothing published |
| between 5 and 6 | same (`Verified` without a swapped pointer): discard, `Idle` |
| after 6, before 7 completes | pointer names the new generation: application is at `R`; engine behind. A valid `install-record` matching the cursor allows the engine to be seeded; without a valid record the node refuses to start |
| after 7 | normal |
A damaged `recovery.state`, `install-record` or `app-current`, a pointer naming a missing directory, or a cursor that disagrees with the record: refuse to start and report; nothing is reset or guessed. The driver's `ExecutorAhead` refusal stays in force except for the one case where a valid `install-record` for exactly the executor's cursor exists. Execution after install replays heights `R.height + 1` to the committed tip once each, through the normal handoff.
**SafetyStore is never read, written, reset or advanced by any step.** Its floors (`hvr`, `hqr`, last vote, last timeout) are byte-identical before and after every outcome in this table.

## 5. Recovery rounds and signing floors (QC/TC semantics, from `rules.rs`)
Floors: `hvr` = highest round voted or timed out in; `hqr` = highest QC round voted on (the lock). Rules that bind a recovering node: a vote at round `r` needs `r > hvr`, and `r == qc.round + 1` or a TC for `r - 1` with `qc.round >= tc.max_high_qc_round`; a timeout at round `r` needs reported `high_qc.round >= hqr`, `r > high_qc.round`, `r >= hvr` (a vote and a timeout in the same round are allowed), and `r == high_qc.round + 1` or a held TC for `r - 1`. Round advance: a QC or TC for round `c` moves the node to `max(current, c + 1)`; wall-clock time never moves a round.
A node in `Recovering` signs nothing (no vote, timeout or proposal) and proposes nothing, but serves what it holds. It becomes `Active` only when ALL hold: (1) the executor cursor equals the committed tip proven by the verified header chain; (2) the engine is seeded from `install-record` plus the QCs obtained since, and `engine.high_qc.round >= hqr` (a node whose lock is above the QCs it has must first obtain a QC of at least that round from peers; without it every timeout it could sign would be refused); (3) `round = max(max(high_qc.round, high_tc.round) + 1, hvr)`, computed, never chosen; (4) the first signature it makes obeys the unchanged rules above. The install changes none of the floors and signs nothing to "catch them up".
If no peer can supply (2) or the history, the node stays `Recovering` and reports it.

## 6. Certificates
Validity is unchanged. Transport limits assume the maximum permitted certificate (`k = n`), section 3.2. Power-aware selection is proposed separately in `phase5-certificate-selection.md` and changes nothing in this document.

## 7. Acceptance tests (each must also fail under a mutation that removes the rule it covers; mutation check required, as for Steps 0 to 1)
**E encodings.** E1 every kind round-trips and re-encodes byte-identically for each status. E2 every truncation and a trailing byte are rejected. E3 `OK` with count 0, unknown status, a chunk length not equal to the manifest rule, `chunk_count 0 / > 65,536`, `chunk_size 0 / > 1 MiB`, `total_bytes` outside the chunk bounds are rejected. E4 huge counts and lengths in tiny inputs are rejected without allocating (counting allocator). E5 sizes equal the formulas for the largest message of each kind at n = 4 and, with synthetic structures, at n = 31, 100, 1000, including a TC-bearing header plus an extra QC.
**C correlation.** C1 wrong `request_id`, C2 wrong peer, C3 wrong selector (`after`, `ref`, `snapshot_id`, `index`), C4 duplicate, C5 late, C6 table bounded, C7 ids never reused: all dropped and counted, none changes state.
**B bounds.** B1 per-peer and global outstanding caps, B2 `BUSY` when over capacity (never silence), B3 token bucket and spacing, B4 feature refuses to enable when `outstanding_cap = 0`, B5 three invalid responses ban the peer.
**O oversize.** O1 a responder whose limit is below the next header sends `TOO_LARGE` with `needed_bytes` equal to the real minimal response size; O2 never `OK` with count 0; O3 `needed > own limit` ends in `ObjectExceedsEnvelope`, no fallback, node stays `Recovering`; O4 `needed <= own limit` retries another peer; O5 startup refuses n = 1000 at 8 MiB and accepts it at a limit of at least 13,272,480; O6 an oversize inbound frame is closed before parsing.
**K references (vectors for the future identity change).** K1 profile v2 ids unchanged; v3 id changes with the reference. K2 each of R1 to R4 rejects alone. K3 R5 `Match` / `NotYet` / `Mismatch`. K4 mismatch against an uncertified proposal withholds the vote and does not halt. K5 mismatch against a final reference halts signing and enters `Recovering`. K6 two final conflicting references raise the safety alarm. K7 a lagging minority does not stop block production when proposers follow the margin policy.
**P authentication.** P1 a joiner accepts `R` only when the carrying header is final; P2 rejects a reference whose block is not on the verified chain or has another height; P3 altering `state_root` in a header breaks its id and signature; P4 a manifest for another ref or snapshot id is rejected before any chunk is fetched; P5 a snapshot whose recomputed root differs from `R.state_root` is rejected with nothing published.
**I install.** I1 staged data is validated against the authenticated root before the pointer swap; I2 the crash matrix of section 4 at every durable operation using the `MemStorage` crash outcomes: always the old state or the new state plus a seedable record, never a mixture; I3 damaged or missing `recovery.state`, `install-record`, `app-current` or directory: refuse to start; I4 cursor and state are one pointer; I5 `ExecutorAhead` exception only with a valid matching record; I6 SafetyStore files byte-identical after every scenario including crashes; I7 after install the executor runs `R.height + 1` to the tip exactly once each.
**R rounds.** R1 zero signatures while `Recovering` (counting signer); R2 a node with `hqr = 50` and best QC round 40 cannot time out and stays `Recovering` until it obtains a QC of round >= 50; R3 the first vote has `r > hvr`; R4 the derived round equals `max(max(hqc, htc) + 1, hvr)`; R5 a vote and a timeout in the same round are both permitted, a lower round is refused; R6 a gap needs the previous round's TC and `qc.round >= tc.max_high_qc_round`.
**G gating.** G1 the config cannot enable pruning or snapshot installation; G2 kinds 7 to 14 are rejected as unknown by `netmsg::decode`; G3 no install code path is reachable in the node binary without the feature; G4 all existing suites pass unchanged on Linux and Windows.

## 8. Still open
Owner approval of the identity change (2.2) and `K`, `ref_margin`; the real application's canonical state root and snapshot format (U5); payload fetch kinds 13 and 14; whether to change the maximum permitted certificate (a specification change); the draft QC/TC layouts, PO-4, D2, production keys and counter.
