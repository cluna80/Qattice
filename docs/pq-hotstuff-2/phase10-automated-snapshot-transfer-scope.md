# PQ-HotStuff-2 — scope for automated, authenticated snapshot transfer and installation (documentation only; decisions locked 2026-11-09)

**Status: scope document; the six decisions below are LOCKED by the owner (2026-11-09). No activation.** Everything it builds on is in the unmerged draft stack #141, #143, #144 and #145. It keeps **network snapshot installation disabled by default and gated**, keeps **pruning unimplemented**, and does not touch Tendermint. U5, draft QC/TC approval, PO-4, D2, production keys/counter (#109) and the canonical state root for the real application remain open. The recovery demonstrated so far is **operator-staged recovery of the devnet-interim application** (Windows-run at `88c0685`, antivirus off); this proposal is about moving the same authenticated steps onto the network.

## 0. Locked decisions (owner, 2026-11-09)
| Decision | Locked |
|---|---|
| **Trust anchor** | **Genesis only.** Checkpoint evidence is verified from the node's own configured genesis. Owner-published trusted checkpoints are deferred and would need their own approval. |
| **Retention and providers** | Initially retain **three authenticated snapshots**, within an **explicit disk budget**; **pin** a snapshot while a transfer of it is active. **Any peer may serve data**; acceptance depends on verification, never on provider identity. Retention is a **devnet cache policy**, not a guarantee that future pruning is safe. |
| **Trigger** | **Operator-initiated only** for this release. Automatic recovery is a separate, later change. |
| **Installation** | **Install-then-restart.** Signing state is preserved; application publication is coordinated with durable, matching seed evidence (section 4.1, step 6). |
| **Limits** | Keep the **8 MiB envelope** and **reject unsupported configurations locally**. Separate bounds for frame buffers, decoded objects, accumulated headers, staging disk, and concurrent requests (section 4.5). |
| **Wire allocation** | Kinds **7-12** as implemented; **13-14 reserved**; kind **15** keeps its advice-only semantics. |

## 1. What already exists (on the draft stack; none of it called by a node over the network)
| Piece | State |
|---|---|
| Recovery wire messages: header request/response, manifest request/response, chunk request/response (kinds 7-12), strict codecs with exact size formulas; kinds 13-14 reserved; kind 15 (operational decoder) is the advice-only "below base" answer | Implemented, isolated from the operational decoder, **unwired** (#141, #144) |
| Request table (global and per-peer caps, correlation by id and selector, expiry), advice handling (`TOO_LARGE` and busy are advice only), cooldowns, suppression of peers that send invalid data, a stall detector | Implemented, unwired (#141) |
| `Installer`: begin, put_chunk, finish (flush barrier, rename into a generation directory, install record, pointer, forward-only generations, crash table, garbage collection of its own directories only); shadow tree **measured against an independently authenticated root** before it is published | Implemented, crash-tested in-process, unwired (#141) |
| Checkpoint authentication: `authenticate_checkpoint` (verified header chain from genesis, checkpoint block final, a FINAL header carries the identical reference, valid high QC), `SeedEvidence` codec, `Engine::authenticate_evidence` against the node's own configuration | Implemented, Windows-run (#143, #144) |
| Seeding and recovery: forward-only `Engine::seed`, the `Recovering` gate (no proposal, vote, timeout or re-send), `Driver::start` re-authenticating persisted evidence and reconciling the executor, base-aware block store | Implemented, Windows-run (#143-#145) |
| Operator-staged OFFLINE staging tool for the devnet (evidence + interim application state at a checkpoint, stale and rewind guards, crash-consistent write order) | Implemented, Windows-run (#145) |
| Catch-up after a seed (sync), with the slot-release fix | Implemented, Windows-run (#145) |

## 2. What is missing (the scope of the next work)
1. **No requester or provider logic drives the codecs.** Nothing issues header, manifest or chunk requests, assembles the answers, or serves them.
2. **No provider-side snapshot production.** Nodes hold only their latest application state; a snapshot AT a checkpoint height must be produced and retained (see 4.3).
3. **No runtime executor swap.** The executor lives inside the driver and cannot be replaced while running; the offline tool's "stop, stage, restart" is the only install path.
4. **Evidence is O(chain) from genesis**, so authentication cost and the header transfer grow without bound until anchored (incremental) evidence exists.
5. **No snapshot format for the real application** (U5, canonical state root); only the interim application's single-record state exists.
6. **No trigger policy** (when a node should fetch instead of syncing blocks) and **no activation gate** in the node.

## 3. Principles that carry over unchanged
Nothing a peer sends is trusted: a snapshot is accepted only if (a) the checkpoint authenticates from signed headers (final, with a final carrier attesting the state root), (b) the manifest is bound to that root, (c) every chunk matches its manifest hash, (d) the assembled shadow state, measured from the files alone, equals the attested root. An install record is a record of a local operation and is never evidence. Signing floors are never lowered or reset; the node does not sign while `Recovering`; installs are forward-only and never rewind committed or executed state; each committed block's effects are applied once. Responses are bounded before allocation and before expensive verification, with every limit derived from the exact encodings and checked arithmetic. Advice messages stay advice.

## 4. Proposed design
### 4.1 Flow (requester)
1. **Decide** to recover (initially only on operator command; see 4.4).
2. **Headers:** page `HeaderReq` from genesis to a tip; verify with the same header verifier the engine's rules use; collect the final QC.
3. **Pick and authenticate a checkpoint:** a reference carried by a FINAL header on the verified chain, with a valid high QC (`authenticate_checkpoint`). **There is no provider-agreement threshold.** Unauthenticated network peers have no voting power, and even authenticated validator providers must not be able to block retrieval of a cryptographically valid snapshot by disagreeing: the signatures in the headers are the whole of the authentication. Asking several providers (and trying others when one is silent, slow or invalid) improves AVAILABILITY only; it is never an acceptance condition.
4. **Manifest** for that reference (`ManifestReq`); validate structure; bind to the attested root.
5. **Chunks** (`ChunkReq`) in bounded parallel windows, each verified against the manifest hash, with per-peer caps, cooldowns and suppression of peers that send invalid data; stalled selectors are retried at other peers.
6. **Install, with this crash-consistent order (every published application generation must already have durable, matching, re-authenticatable evidence):**
   1. Assemble the shadow tree from the verified chunks and **measure it from the files alone against the attested root**; flush barrier. Nothing is published yet.
   2. **Persist the `SeedEvidence` durably** for exactly that checkpoint (forward only; fresher evidence for the same checkpoint replaces the record atomically). It must authenticate against the node's own genesis and describe the checkpoint the staged state was measured against.
   3. **Only then publish** the application generation (rename into the generation directory, install record, pointer).
   4. **Restart the driver**, which re-authenticates the evidence, requires the executor's cursor at the base to carry the attested block and state root, and rebuilds the base as it does today.
   **Crash table to be specified and tested:** before step 2 - nothing changed; after step 2 and before step 3 - evidence is ahead of the application, and the node must either complete publication from a complete verified staging for exactly that checkpoint or refuse to start (it never signs on a half-installed state, and the operator can re-run the install, which is idempotent); after step 3 - a complete generation. The reverse order (publish, then persist evidence) is not allowed: a crash between them would leave a published generation that nothing authenticates.
7. **Catch up** by sync; leave `Recovering` only through the existing completion conditions.

### 4.2 Flow (provider)
**Any peer may serve** (acceptance never depends on who served). Serve headers (bounded pages), the manifest and chunks of snapshots it holds **for final checkpoints only**, with per-peer rate limits and the existing `TOO_LARGE`/busy advice; answer a request below its own base with the existing advice message. A provider never serves a snapshot it cannot tie to a final checkpoint and a state root it computed itself.

### 4.3 Snapshot production and retention (new obligation)
At each final checkpoint height the node captures the application state at that height (for the interim application, a single record) into a bounded `snapshots/` area, keeping the newest **three** authenticated snapshots **within an explicit disk budget** (a snapshot that would exceed the budget is not retained and the node says so), and **pinning** a snapshot for as long as a transfer of it is active so that retention cannot remove it mid-transfer. **This is a devnet cache policy, not a guarantee that future pruning is safe:** while pruning stays unimplemented, payloads are all retained and a state at height H could be re-derived by replay; once pruning exists, retention becomes a hard prerequisite (QAT-PRUNE-003/004) with its own analysis, and is out of scope here.

### 4.5 Limits (locked: keep the 8 MiB envelope; reject unsupported configurations locally)
The transfer code takes its limits from configuration and **refuses to start** (locally, before any network use) if they cannot be carried by the 8 MiB envelope or are inconsistent, exactly as the node already does for proposals. Separate bounds, each enforced before allocation and before expensive verification: **frame buffers** (bytes buffered per connection before a frame is complete); **decoded objects** (bytes and counts of messages decoded and held per peer and in total); **accumulated headers** (a hard cap on headers held while a chain is assembled, which also bounds authentication work); **staging disk** (total bytes of staged chunks and shadow trees, against the disk budget); **concurrent requests** (global and per-peer, with capacity reserved per phase so that one phase cannot starve another). All arithmetic is checked; a response larger than its kind's computed maximum is dropped without being parsed.

### 4.4 Trigger and activation (kept gated)
* **Phase 1: operator-initiated only** (`install --from-peers`, devnet only): the same staged result as the offline tool, obtained over the network, behind a configuration flag that is **off by default** and a build feature that is off by default.
* **Automatic triggering is a later, separately reviewed change**: it needs a local, non-forgeable reason to recover (for example a catch-up stall detected by the node itself, not peers' advice) and an owner decision on policy. Without pruning, a node can always sync blocks from genesis, so automatic installation is an optimization until pruning exists.
* Not enabled on any existing network; no mainnet or production activation.

## 5. Threat model and required tests
**Adversarial providers:** a snapshot for a root nobody attested; a stale or non-final checkpoint; a truncated or reordered header chain; a manifest whose chunks do not hash to it; a chunk for another snapshot; oversized or malformed messages; a silent peer; an equivocating provider that answers one requester differently; a flood of requests; peers that cause the requester to hold unbounded state; **a provider that disagrees with the others (it must not be able to block a valid snapshot: provider diversity affects availability only)**. **Faults:** a crash at every install phase (the installer's crash table already covers its own steps; add transfer, persist-evidence and restart boundaries); a partition mid-transfer; two successive installs; an install while the node is ahead (refused); a restart with half-transferred staging. **Required properties:** no signing before recovery completes (monitored at the process level, including re-sends); floors never lowered; committed history never rewound; no duplicate application effects; agreement with the other nodes afterwards on committed block ids and execution roots; bounded memory and disk; every response size checked before allocation.
**Evidence conventions (unchanged):** in-process deterministic tests first, each gap pinned by a test that fails before the fix and a mutant that the test kills; real ML-DSA-65 on every integration test; a live profile-v3 test over TCP and separate processes extending the existing harness (provider nodes serving, a victim fetching) with the faults above; Linux sandbox results are never a milestone confirmation; **owner-run Windows results at a pinned commit** with `set -o pipefail` and full output kept, recording the machine's security settings as found and not changing them to obtain a pass.

## 6. Proposed slicing (each a separate draft PR, disabled by default, reviewed on its own)
| Slice | Content | Acceptance |
|---|---|---|
| **S-1** | Sans-IO requester and provider state machines over the existing codecs, tables and installer; in-memory transport; a malicious-provider simulator; the bounds of section 4.5; **no provider-agreement threshold**. **No node wiring.** | Deterministic tests for every threat in section 5 that does not need processes; mutation campaign; request/slot accounting tests that would have caught the catch-up starvation class (answered requests release their slots; a multi-hop fetch cannot starve) |
| **S-2** | Snapshot production and bounded retention for the interim application; provider serving behind the disabled flag; node wiring of requester/provider, still off | Crash tests around capture and retention; bounded disk and memory; disabled flag proven to change nothing |
| **S-3** | Operator-initiated `install --from-peers`, install-then-restart, live process test with faults | Process-level monitor (no signing or re-send while recovering), agreement and no-duplicate-execution checks, every fault in section 5, repeated runs |
| **S-4** | Owner-run Windows validation at a pinned commit | Recorded as in the existing evidence conventions |
| **Later, separately gated** | Automatic trigger policy; anchored (incremental) evidence; linear-cost catch-up; real application snapshot (after U5 and a canonical state root); anything involving pruning | Each needs its own owner decision and review |

## 7. Decisions
The six decisions this section used to ask for are **locked** (section 0). Remaining open items before S-3: the concrete numbers for the limits in section 4.5 (to be proposed with S-1's bounds and reviewed), and the disk budget for snapshot retention.

## 8. Non-goals
Pruning or any payload deletion; recovery of the real Qattice application (blocked on U5 and a canonical state root); dynamic membership; mainnet or production activation; automatic installation on any existing network; changes to Tendermint or to the separate Chain Forge repository.

## 9. Risks recorded from the review of #143-#145
* **Shared slot tables starve multi-hop work.** The catch-up defect (answered requests holding their slot) is the model failure to design against: the transfer's request tables must release capacity on answer and reserve capacity per phase.
* **Catch-up cost is superlinear in the gap** until fetched windows are kept; transfer of headers from genesis inherits the O(chain) cost of today's evidence.
* **CI does not run on the stack** (the workflow targets pull requests to `main` and builds `dis-core` only); until that changes, the evidence is the recorded Linux, mutation and owner-run Windows results.
