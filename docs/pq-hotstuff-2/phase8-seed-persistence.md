# PQ-HotStuff-2 — persisted, re-authenticated seed evidence; base-aware driver and block store; below-base sync; live profile-v3 recovery

**Status: DRAFT, DISABLED, stacked on #143.** Nothing in a node calls this. Profile v3 is off and unwired in the node; network snapshot installation and pruning are off; dynamic membership is disabled; payloads stay explicitly devnet-interim; Tendermint is unchanged. U5, draft QC/TC approval, PO-4, D2, production keys/counter (#109) and the canonical state root for a real application remain open. **Not Windows-confirmed.**

## Why this exists
#143 added an in-memory seed. A restart forgot it, so it was not durable snapshot recovery. This PR makes restart reconstruct and re-authenticate the same checkpoint base, without resetting signing floors, rewinding committed state or replaying application effects.

## What is persisted, and what authenticates it
* `seed::SeedEvidence` = the header chain from genesis, the final QC, the checkpoint reference, the high QC and optional TC. Strict codec (tag, version, counts bounded, trailing bytes refused, checksum). **The checksum detects damage only; it authenticates nothing.**
* `BlockStore::put_seed_evidence` writes `seed-<20-digit height>` (sealed, atomic). **Forward only:** older than stored is refused, the same bytes again is a no-op, different bytes at the same height are a conflict. `load_seed_evidence` returns the newest; a damaged newest is an error — an older record is never substituted (that would be a silent rewind).
* `Engine::authenticate_evidence` re-runs `authenticate_checkpoint` against THIS engine's own genesis hash, profile, chain id, validator set, leader seed and checkpoint parameters (never values carried by the evidence): the checkpoint block must be final, a FINAL header must carry the identical (height, block id, state root), and the high QC must verify and certify a header at or above the checkpoint. An install record remains a record of a local operation and is never evidence.

## Start (`Driver::start`) and what stops it
Order: load the store → if seed evidence exists: decode → authenticate against the engine's own configuration → check it describes the checkpoint its name and record claim → `Engine::seed` → load the root log → restore blocks → reconcile the executor → complete recovery if every dependency is present.
| Condition | Outcome |
|---|---|
| evidence damaged (checksum) | `Store(SeedEvidenceDamaged)`; node does not run |
| evidence parses but is not authentic (forged header, unattested root, other genesis/profile/parameters) | `SeedEvidence(..)` |
| evidence stored under another checkpoint's name | `SeedEvidence("does not describe …")` |
| evidence missing but the executor is ahead of the engine's committed history | `ExecutorAhead` (fail closed) |
| executor behind the checkpoint | `ExecutorBehindBase` |
| executor at the checkpoint height with a different state digest or a different block id | `BaseMismatch` |
| executor ahead of the checkpoint but not on this node's committed chain | `ExecutorAhead` / `Diverged` |
| a different root already logged for the checkpoint height | `BaseMismatch` |
| evidence older than what is stored | refused at write (`StaleSeedEvidence`) |
Commit markers at or below the newest checkpoint are not required (`Loaded.seeded_height`); the ones above must continue from it without a gap.
While `Recovering` the engine signs nothing (see #143); the driver tolerates the refusals and completes recovery on start or tick once the high QC's block is known and the round is not below the store's `hqr`.

## Sync below the base
* Blocks at or below the base are skipped by `accept` (final history this node deliberately does not hold). **Found by the live test:** before this, a sync window that straddled the base aborted on its first below-base block and a recovering node looped forever.
* A request for the base or a block just below it gets an explicit `SyncBelowBase` answer (wire kind 15 in the operational decoder only; kinds 7–12 are the recovery codec's and 13–14 are reserved by it): the requested id, the base height and id, the attested state root and `recovery_available`, which is **false** while network installation is disabled. It is **advice only**: a receiver counts it and changes nothing else; recovery comes from authenticated evidence, never from this message.

## Live profile-v3 test (what it is and is not)
`live_v3_snapshot_recovery_restart_successive_installs_and_agreement_without_duplicate_effects`: four real drivers exchange real encoded messages on the harness network with real execution and storage models (real ML-DSA-65 in the fips204 run). Node 3 loses its blocks and application state but keeps its SafetyStore; the state at checkpoint A is installed and the evidence stored; it starts, recovers, restarts while recovering and again after recovering (with the checkpoint's root record damaged, which the restart writes again), goes away while the network advances, installs a newer checkpoint B into the same store, recovers, and restarts again. Asserted: the SafetyStore record is bit-for-bit unchanged right after each start; floors only move forward; the base is the newest evidence; agreement at every executed height; each node's execution log is exactly the heights after its checkpoint (no duplicates, no gaps); the older checkpoint can never be installed again; an executor behind the new checkpoint refuses to run.
**It is in-process and driver-level. It is NOT the TCP devnet, which does not run profile v3, and it does not exercise the process/OS file layer.** Passing profile-v2 TCP devnet tests are regression evidence only.

## Remaining gaps
* **Evidence starts at genesis** and grows with the chain; anchored (incremental) evidence is future work.
* **Installing the application state at the checkpoint is an operator/test step.** There is no run-time executor swap and no network transfer (installation stays disabled); `Driver::start` is the single entry point.
* **The node and the TCP devnet do not run profile v3.** A live v3 test over TCP needs node wiring and a v3 genesis, which is outside this PR.
* Blocks below the base are not served (answered with advice only); pruning is not implemented.
* The deferred-vote set is volatile; a restart drops it (costs a vote, not safety).
* One mutant survives (`phase8-mutation-record.md`): the commit-marker offset, whose logical result is unchanged (shown) while its extra write/sync/rename operations are not. The earlier gap (classification of a conflicting root at exactly the checkpoint height) is closed by a test.
* Windows confirmation of the code commit, and the review this PR needs, before anything is enabled.

## Linux results (sandbox; NOT a milestone confirmation — Windows confirmation is still required)
Run on a clean tree whose code is `dc89d456ae148a66d7634c6cc617c4796950f106` (production source identical to `308d9dc`; later commits changed tests and docs only). Release mode, `PQHS_SEEDS=10`.
| Suite | Result |
|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204` | 167 passed, 0 failed, 2 ignored (158 + 9 new) |
| doubles `pq_hotstuff_engine` | 167 passed, 0 failed, 2 ignored |
| foundation / safety (doubles, fips204) / wire | 30 / 76 + 11 / 24 passed |
| consensus lib (`pq-hotstuff`, `pq-hotstuff-fips204`, default) | 98 / 98 / 98 passed |
| core lib / p2p lib | 74 / 21 passed |
| node: default check, `pq-devnet` check, `pq_devnet` unit tests | ok / ok / 4 passed |
| LIVE four-node TCP devnet (profile **v2**) | 1 passed — regression evidence only; it does not run profile v3 or seeding |
Mutation: 29 of 31 caught on `308d9dc`; the previously surviving base-root mutant and two mutants attacking the new conflict test were re-run on `dc89d45` and are all caught; one survivor remains (commit-marker offset). See `phase8-mutation-record.md`.

## What is demonstrated, and what is still missing
| Demonstrated here | Still missing |
|---|---|
| Re-authenticated evidence and checkpoint-based restart | Automated network snapshot installation |
| Four drivers recovering on an in-process network | Profile-v3 TCP/process recovery |
| No duplicate execution in the tested scenarios | Real Qattice application snapshot integration |
| Base-aware storage and explicit sync advice | Pruning and bounded evidence growth |
| A conflicting root at exactly the base height is `Mismatch` evidence and never signed for (with a matching-root control) | A run on Windows; this PR's own review |

## Windows results (supplied by the owner; MINGW64, `C:\Dev\qattice-main-wt`, branch `feat/pq-hotstuff-2-seed-persistence`) — recorded separately
`git rev-parse HEAD` printed **`e610932ec04296319f9a1b0c850dcc4f663df8cf`** after a fetch and checkout from a worktree that had been on the #142 branch (an earlier prompt on that branch was NOT counted; the branch was switched and the hash confirmed first). The worktree was clean (`git status --short` empty) and `git diff dc89d45 HEAD -- chain-forge-consensus chain-forge-node` printed nothing, so the production and test code are those validated on Linux. Release mode:
| Run | Result | Time |
|---|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204`, default seeds | 167 passed, 0 failed, 2 ignored | 198.41 s |
| doubles `pq_hotstuff_engine`, default seeds | 167 passed, 0 failed, 2 ignored | 481.06 s |
This validates the targeted tests of this revision on Windows. It does not validate profile v3 over TCP or as a process (still unwired in the node), network snapshot installation, a real application snapshot, or pruning. Those remain missing, as listed above.
