# PQ-HotStuff-2 — checkpoint-start (engine seeding) and the `Recovering` gate

**Status: DRAFT, DISABLED, stacked on #142.** Nothing in a node calls any of this. Profile v3 is off and unwired; network snapshot installation is off; pruning is off; dynamic membership is disabled; payloads remain explicitly devnet-interim; Tendermint is unchanged. U5, draft QC/TC approval, PO-4 and the production key/counter restrictions all stay open. This PR adds an engine API and tests; it does not enable a recovery path. A live profile-v3 recovery test is required before any enablement.

## What authenticates a checkpoint (and what does not)
`seed::authenticate_checkpoint` is the ONLY way to obtain a `CheckpointSeed` (its fields are crate-private). It requires, in this order:
1. A header chain from a trusted start (genesis, or a previously authenticated anchor) that passes `verify_header_chain`: every header signed by its round's leader, every parent certified by a quorum QC, every timeout certificate and every checkpoint rule R1–R4 and R6 valid, under the same code the engine runs.
2. The checkpoint block is **final** on that chain under the two-chain predicate.
3. A **final** header carries the identical reference `(height, block id, state root)`. This is what attests the state root: honest voters of that block compared it with their own execution (rule R5), or relied on an earlier final carrier.
4. The high QC (and TC, if any) verify, and the high QC certifies a verified header at or above the checkpoint.

The claim is the protocol's usual one: finalized under the stated fault (f < n/3 by voting power) and cryptographic (ML-DSA-65 unforgeability) assumptions; nothing stronger.

**An install record is not evidence.** `InstallRecord` records a LOCAL operation: this machine staged a snapshot, verified its tree against a reference, and published a generation. It cannot prove the reference is authentic or final. `seed::check_install_record` only cross-checks that a record names the same `(height, block id, state root)` as an already-authenticated seed; a record naming a root nobody attested cannot be turned into a seed (test: `an_install_record_cross_checks_a_local_operation_and_never_authenticates_anything`).

## The engine side
* `Engine::seed(seed)` makes the authenticated checkpoint block the root of the tree (`Base`: id, height, round, parent round, `F` and last reference, and the ancestor window a new reference may still name). It is committed by construction and never re-emitted. The reference rules then run from the base's own state exactly as `Start::Anchor` does in the header verifier.
* **Forward only.** A checkpoint below the committed height is refused as stale; the same checkpoint is a no-op (`AlreadyAtBase`); a different block at the committed height, or a committed history that the evidence contradicts, is refused. A refused seed changes nothing. Blocks that do not descend from the new base are dropped.
* **`Recovering`.** Seeding enters it. While it holds the engine signs **nothing**: `propose`/`propose_with` and `local_timeout` return `EngineError::Recovering`; `vote_for` (so also deferred votes released by the executor) signs nothing; `resend_last_vote` and `resend_last_timeout` send nothing. Blocks above the base arrive through `on_sync_block` (validated like proposals, never voted); live proposals are accepted into the tree but not voted.
* **Leaving it.** `complete_recovery` succeeds only when the block certified by the high QC is known (so its ancestry down to the base is) AND the high QC round is at least the SafetyStore's `hqr`, so the engine never resumes on a view older than its own record. The reason is available as `recovery_missing()`.
* **SafetyStore floors.** The store is never touched: `hvr`, `hqr`, `last_vote`, `last_timeout`, `last_proposal` and the counter are bit-for-bit unchanged across seed, dependency arrival and completion (tests compare the whole record). Seeding raises the engine's round to at least `hvr` and never lowers it.
* **No rewind, no duplicate effects.** The base is never emitted as a commit; after recovery every commit is above the base, consecutive and unique, and an interim executor holding the state at the base applies each exactly once, in order (`OutOfOrder` never fires).

## Scenarios covered (engine level; doubles and real ML-DSA-65)
The 18 tests cover: authentication refusals (wrong root, non-final block, forged header, high QC below the checkpoint, invalid or non-QC high certificate, non-final carrier, wrong chain); zero signing and floors; rejoin and agreement with a healthy node; stale snapshot, repeat and rewind; missing dependencies (first, middle, last block withheld); evidence older than the validator's own record; interrupted installation (crash before seeding and mid-recovery: the seed is volatile, the store is untouched, and the seed is redone from evidence); two successive installs (the second replaces the first, the first can never return); conflicting committed history; a genesis-certified block cannot extend a seed; the first references above the base (repeat, backwards, a new reference naming a block below the base); a late certificate for the checkpoint's child; re-sends.

## Not done here (needed before enabling anything)
* **Durable seed evidence.** A restart forgets the seed. A seeded node's blocks below the base are not in its block store, so the restart path needs the evidence (headers, final QC, reference, high certificates) persisted and re-authenticated at start, and the `BlockStore`/driver reconcile (`committed_after`, executor-cursor check) made base-aware. Until then restart returns to an unseeded engine with the SafetyStore floors intact (tested), which costs liveness only.
* **Serving sync below the base**, and the installer ↔ engine hand-off in the node (`StartOutcome::NeedsSeed`).
* **Live profile-v3 recovery test** on the four-node devnet, including a crash in each phase, a missing-dependency run, and two successive installs, before network snapshot installation is enabled.
* The canonical state root for a real application, and every owner decision listed above.

## Mutation check — complete
31 mutants of the seeding, gate and authentication code were run one at a time in a disposable git worktree (own target directory; the committed code was not touched) against the 18 seed tests on the test doubles, after a baseline run of the same command (18 passed, 18.4 s). Result: **31 caught, 0 survived, 0 timeouts, 0 build errors, 0 not applicable.** Every mutation's literal diff, result, time and failing test is in `phase7-mutation-record.md`. An earlier run of the same list had 15 survivors; each was a test gap and was closed by a new or strengthened test (not by weakening an assertion), and one redundant line was removed. The campaign was then re-run from the start on the committed code `46c2de7` (not resumed). Limits: it covers the seeding, gate and authentication code only, on the doubles backend; it says nothing about the existing #142 rules, which have their own record.

## Linux results (sandbox; NOT a milestone confirmation — Windows confirmation is still required)
Run at `826c23054911ee142546f12db136c7c68f1b2a85` on a clean tree; the code is identical to `46c2de70734fe1e3319c0f7299802da8b2cce183` (verified: no diff under `chain-forge-consensus` or `chain-forge-node`). Release mode, `PQHS_SEEDS=10`.
| Suite | Result |
|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204` | 158 passed, 0 failed, 2 ignored (140 + 18 new) |
| doubles `pq_hotstuff_engine` | 158 passed, 0 failed, 2 ignored |
| foundation / safety (doubles, fips204) / wire | 30 / 76 + 11 / 24 passed |
| consensus lib (`pq-hotstuff`, `pq-hotstuff-fips204`, default features) | 98 / 98 / 98 passed |
| core lib / p2p lib | 74 / 21 passed |
| node: default check, `pq-devnet` check, `pq_devnet` unit tests | ok / ok / 4 passed |
| LIVE four-node devnet (profile v2) | 1 passed, 38 s |
The live devnet test runs profile v2: profile v3 and the seeding path are unwired there, so it validates nothing about them. The 18 seed tests run on both backends (the real-crypto backend uses real ML-DSA-65 signatures for blocks, QCs and timeouts).
