# PQ-HotStuff-2: status note (2026-11-07)

## Where we are
Direction (owner): Qattice is PQ-HotStuff-2-native from genesis; PQ-HotStuff-2 is a selectable Chain Forge engine; Tendermint stays a Chain Forge option, unchanged.
No files are to be deleted. Work is additive, in draft PRs. Nothing is merged or activated by this work.

| PR | What | State |
|---|---|---|
| #130 | Spec draft: BlockPayload, QC/TC serialization, rounds, epoch change, proof obligations PO-1..PO-5 | Draft, open. Do NOT merge while PO-4 etc. are open |
| #132 | TLA+/TLC model harness for PO-4 (epoch transition) | Draft, open. Runs INCOMPLETE: no counterexample found, nothing verified, missing-seal failure not yet demonstrated |
| #133 | Engine foundation: BftVariant::PqHotStuff, protocol_profile validation, validator sets, limits, leader, section 5/6 rules | Draft, open. Linux tests pass; Windows not yet run |
| #134 | Fixed-set engine state machine, draft QC/TC encodings, seeded simulation (stacked on #133) | Draft, open. Linux tests pass; Windows not yet run |
| #131 | Roadmap lock | Merged (a2a662d) |

Linux evidence: core lib 74, consensus default lib 98, foundation 30, safety 76, wire 24, engine 32 (simulation: honest, silent, equivocator, crash/restart, restart+equivocator; 60-seed soak passed), mutation 21/21 (#133) and 22/23 with 1 justified (#134).

## Not done / blocked
* Windows confirmation of #133 and #134 (CLAUDE.md: nothing is closed on a sandbox run).
* U5: canonical transaction encoding. The payload is opaque, `devnet-interim`. The canonical payload codec must not be built until U5 is approved.
* PO-4 / dynamic membership: unresolved; also the safety store resets round floors at an epoch change (K1) and has no seal field (K2). Epoch changes are refused in the engine.
* Draft QC/TC layouts (spec 3.4) are unapproved; implemented behind the off-by-default `pq-hotstuff` feature.
* Production validator key storage: blocked on the independent review of #109. Production trusted counter backend: not built.
* No PQ-HotStuff-2 message-size limit exists in the repository (owner decision needed); the existing p2p default (max_tx_bytes x 2) is below max_block_bytes.
* Engine gaps: no block sync, no persistent block store, fixed-timeout pacemaker, no equivocation evidence, not wired into the node, simulation uses non-crypto test doubles.

## Next steps (in order)
1. Owner: run the targeted suites on Windows for #133 and #134 (`cargo test -p chain-forge-consensus --features pq-hotstuff` ; use `--release` for the engine simulation) and report; then decide on merging #133, then retarget and merge #134.
2. PR 3: p2p topics, block-sync protocol and a persistent block store; pacemaker with backoff.
3. PR 4: node driver (`chain-forge-node/src/pq_driver.rs`), engine enum in the node, devnet-only key-file loader (explicit flag, keys generated locally, never committed), clearly labelled non-production file-backed counter.
4. PR 5: `tests/devnet/genesis-4node-pq-hotstuff.json`, bring-up script, four-node live test (needs Windows confirmation).
5. In parallel, independent of the above: signature-verification benchmark toward the 1,000-validator, under-3-second goal (a QC of ~667 ML-DSA signatures is ~2.2 MB: expect QC v2 or committee, decision D2/M0).
6. Spec/owner decisions still needed: U5 (transaction encoding), U4 numbers (message limit, validator limit), U11-U19, review of PO-1..PO-5, and a real run of the PO-4 model (smaller knowledge abstraction) before any dynamic-membership work.

## Standing restrictions
No deletions. No merges without explicit owner approval. No Tendermint behaviour change. No activation on any existing network. Dynamic membership stays disabled until PO-4 is resolved. Production key handling stays blocked on #109.
