# Snapshot authentication and recovery: concrete design (PROPOSAL; nothing here is implemented or approved)

**Pruning stays disabled and unimplemented.** This document decides what must exist before it can be enabled, and which choices are the owner's. It introduces
no consensus state root and no checkpoint-certification protocol; where an option needs one, it is marked as requiring a separate owner-approved spec.

## 1. What a snapshot is, and what can authenticate it
A snapshot is the application state at a finalized height `H` plus its cursor `(H, block_id, state_digest)` (`ExecCursor`). Consensus today authenticates only
block ids: `block_id` commits to the payload hash, the parent QC and any TC, and each block carries a QC for its parent. **No block commits to a state digest.**
So a state snapshot cannot be verified from consensus data alone. Three options:

| | How a joining node trusts `state_digest` at `H` | Cost | Needs |
|---|---|---|---|
| **A. No snapshots (default now)** | It does not: it replays every retained payload from genesis and recomputes the state. | Full history kept everywhere; no pruning. | Nothing new. |
| **B. Signed state attestations** | It accepts `(H, block_id, state_digest)` only if `f+1` distinct validators (by voting power, with the same fixed set and `floor(2n/3)+1` arithmetic as QCs) each signed that exact tuple over a domain-separated context, AND `block_id` at `H` is proven committed by a verified header chain. At least one signer is honest, and an honest validator signs only a digest it computed itself by deterministic replay. | One new message kind and one signature per validator per checkpoint. | **A new signed message type = a checkpoint attestation protocol. Needs its own spec and owner approval; it is NOT introduced here.** Also needs a deterministic application (true of the interim hash chain; unverified for the real executor). |
| **C. State digest committed in the block** | The digest is part of `block_id`, so the header chain proves it. Strongest; no extra messages. | Block layout change and an execution rule (blocks carry the digest of the state after the parent). | Open items U5 and U18 (payload codec, block wire layout) and approval of the draft QC/TC layouts. |

**Recommendation:** stay on A until the owner decides; if pruning is wanted before U5/U18, specify B as a separate document (its signing context, quorum rule,
replay of attestations, equivocation handling); treat C as the long-term target. Choosing among them is decision **S1**.

## 2. The catch-up path for a node whose needed history was pruned
1. **Header chain (trustless).** Ask peers for headers from the node's committed tip toward a peer's committed tip. A *header* is a block without payload bytes but
   with its payload hash. Today `Block` carries the payload, and `block_id` hashes it, so a header-only form needs: a `BlockHeader` encoding, an id function proven equal to
   `block_id_of`, and engine support to accept a header chain (QC and proposer-signature checks do not need payload bytes, since the signature covers `block_id`).
   Verification is exactly the existing block validation, so the node needs only the genesis hash and the fixed validator set. **Cost note:** every header carries a
   parent QC; at 1,000 validators a signature-list QC is about 3.3 MB, so a header chain is expensive there. That is another reason the D2 certificate-sizing decision comes first.
2. **Manifest.** `{ format_version, genesis_hash, height H, block_id, state_digest, total_bytes, chunk_size, chunk_count, chunk_root }`. `chunk_root` is a hash
   tree over chunk hashes. Authenticated per section 1 (B or C); with A there is no manifest.
3. **Chunks.** Fetched from any peer, each verified against `chunk_root` on arrival (hash and index), bounded: `chunk_size` fits the derived transport envelope
   (new message kinds go through `MessageLimits`, checked arithmetic, no preallocation from a reported length), `total_bytes` and `chunk_count` have a configured
   ceiling, an overall deadline, and a per-peer failure budget. Chunks are staged in a separate directory and never touch live state.
4. **Install.** After all chunks verify and the recomputed state digest equals the manifest's, the executor installs state and cursor `(H, ...)` in ONE atomic record
   (the same write-sync-rename-sync pattern as `InterimApp`). The executor never exposes a half-installed state.
5. **Engine seeding.** The engine must start from a committed tip it did not derive from payloads. It needs a checkpoint-start entry (committed tip id/height from the verified
   header chain) so that proposal validation and commit rules continue from `H`. This is an engine change with its own tests; it must not touch the safety store.
6. **Replay.** Blocks above `H` are fetched with the existing validated sync and handed to the executor by the existing handoff. Payloads above the watermark are retained, so this
   is the current path.

**Signing safety is untouched throughout:** the safety store (record, counter, session) is never read, written or reset by snapshot install, header sync or pruning. A node
that installs a snapshot keeps its recorded highest voted/timeout round; it resumes at `max(its own record, the new tip)`.

## 3. Durable pruning watermark and its crash order
A record `prune-watermark` `(height W, block_id, checksum)`, replaced atomically, monotonic (never lowered), in its own file, separate from the safety store.
Deletion of payloads at heights `<= W` is allowed only when ALL hold: the block is finalized; the executor cursor is `>= W` (durable, per the handoff) or a durable downstream
handoff retains the payload; a verified checkpoint at height `>= W` exists locally; headers and certificates for heights `<= W` remain (they are small and are what step 1 serves);
and a defined catch-up path (section 2) is implemented and tested.

Order: (1) checkpoint created and verified; (2) watermark `W` persisted; (3) payloads deleted in ascending height order, each deletion idempotent; (4) on every start, resume
deletion from the watermark. A payload missing at a height `<= W` is normal. A payload missing at a height `> W`, a watermark above the executor cursor, a watermark with no
checkpoint, or a damaged watermark file are corruption: the node refuses to start and does not reset anything. A crash between any two steps leaves a state that the next start completes or refuses.

## 4. Configuration that keeps it off
`pruning_enabled = false` by default and not settable in the devnet config until the prerequisites in `phase3-pruning-prerequisites.md` are implemented and tested; the code path
that deletes payloads does not exist before then. Anything shown against the interim application is labelled test-only.

## 5. What would be built, in order (each step a separate draft PR, none enabling pruning)
1. `BlockHeader` + header-chain verification + engine checkpoint-start, with the equivalence test to `block_id_of`. Tests: forged/gapped/foreign header chains, mutation check.
2. Manifest, chunk tree, staged bounded fetch, atomic install for `InterimApp` (labelled interim). Tests: missing/corrupt/oversize/duplicate/out-of-order chunks, wrong manifest, crash at every point of install (reusing the `MemStorage` crash model).
3. Watermark file and the deletion state machine against a mock executor, labelled TEST-ONLY. Tests: crashes around checkpoint publication, around deletion, interrupted pruning, missing/corrupt snapshot, a node rejoining after its history was pruned (must fail closed or recover, never corrupt state), and that the safety record is byte-identical before and after every case.
4. Live devnet scenario: a node offline while the others prune (test-only flag), then rejoining via section 2.
Step 2 onward needs decision S1 (B or C) to be made; step 1 is useful under every option.

## 6. Decisions needed from the owner
* **S1** authentication: stay on A, specify B separately, or wait for C (with U5/U18).
* **S2** retention policy: how many finalized payloads stay above the watermark, and the checkpoint cadence.
* **S3** the real application's snapshot format and its atomic install (blocked on the real executor / U5).
* **S4** new message kinds and their limits (header, manifest, chunk requests/responses) in the network envelope.
* **S5** whether a node with no reachable snapshot and pruned peers must wait (my recommendation: wait, fail closed) or may fall back to replay from genesis from peers that still hold history.
* Prior open items unchanged: U5, draft QC/TC approval, PO-4, D2 certificate sizing, production keys and counter.
