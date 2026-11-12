# Qattice PQ-PoP-HotStuff-2 Prerequisite

Qattice is a sovereign Layer 1 built with Chain Forge. Its protocol direction is **PQ-PoP-HotStuff-2 from fresh genesis**, with proof-of-personhood governing validator eligibility and voting-power limits, FIPS 204 ML-DSA-65 for validator and account signatures, and defensive payload pruning backed by authenticated recovery.

## How this prerequisite fits the original plan

Complete the native Phase 0 acceptance and Phase 0.5 hardening below, then resume the applicable workstreams in the [original Qattice roadmap](../ROADMAP.md). Carry forward completed work and its evidence. The original milestones keep their order and dependencies wherever they still apply.

When an original entry assumes Tendermint, Ed25519, or unpruned history, use the protocol decisions below and adapt its acceptance evidence to the native Qattice path. Skip retired QRC deliverables. Where an ongoing milestone depends on QRC, flag that dependency for a QCB-only design decision before implementation. An archived milestone or an earlier test result does not by itself authorize feature activation or release.

## Protocol decisions

- **Consensus.** Qattice uses PQ-HotStuff-2. Tendermint remains a selectable Chain Forge engine and a historical Qattice test baseline. Qattice launches from fresh genesis.
- **Identity.** DIS provides the personhood and account authorization layer. Validator consensus keys and user authorization keys have distinct roles. The `pqc-native` profile requires ML-DSA-65 for validator and account signatures. Ed25519 is retired from the Qattice protocol.
- **Storage.** Finality makes payloads eligible for pruning. Deletion requires a durable, verified recovery point, a persisted watermark, and retention of required headers, certificates, and replay dependencies. Retain genesis-to-tip header verification until a separate bootstrap design is approved.
- **Economics.** QCB is the native asset. QRC issuance, circulation, demurrage, and QRC-linked market plans are retired. Review any remaining signed or persisted QRC fields separately before changing their formats.

## Current evidence

| Work | Evidence and remaining integration |
| --- | --- |
| Native PQ-HotStuff-2 | The four-node Windows devnet reported agreement on committed block hash and state root at height 3 in 23.7 s. The result applies to the fixed-set run. [Agreement record](https://github.com/cluna80/Qattice/commit/b090318) |
| SafetyStore and epoch handoff | Windows evidence exists for write-before-broadcast, the TCP epoch-boundary harness, counter fencing, crash recovery, and the admission, rotation, and revocation components. The live same-set transition passed in 62.94 s with four-node block agreement at heights 2–5. The block record's epoch is the active engine epoch at commit. The signed QC epoch and validator-set commitment remain open integration work. Confirm the live node's signature backend against FIPS 204 before crediting it toward Phase 0. [Branch evidence](https://github.com/cluna80/Qattice/blob/0dd823793f60801bcea573cdc1930bfa4f4ae24a/ROADMAP.md#qat-07-authenticated-epoch-change-devnet-complete--2026-11-12) |
| Defensive Pruning Watermark | Standalone PQ devnet demonstrated advancing watermarks, payload deletion, and restart from pruned storage on Windows. Native-node integration with the real Qattice executor remains open. [Standalone pruning test](https://github.com/cluna80/Qattice/commit/5b6d391) |
| DIS and application execution | The original Phase 0 and later ML-DSA-only transaction tests provide prior evidence. The combined native PQ-HotStuff-2 run still needs to exercise DIS, real execution, and recovery. [Original acceptance history](https://github.com/cluna80/Qattice/blob/4042c4f6b9da8eb4926b0f770bc477674979ccf3/ROADMAP.md#phase-0--core-network-and-post-quantum-identity-validation) |

These results are pinned evidence from their respective revisions. Each release candidate needs its own acceptance record, including which earlier results apply to identical code.

## Phase 0 — Native foundation acceptance

The proposed first release candidate uses a fixed validator set. Record exact commits, genesis, feature flags, commands, and Linux and BossKing results. Dynamic validator changes have a separate activation gate.

| Original requirement | Disposition and native acceptance |
| --- | --- |
| P0-1 — Clean genesis | **Adapt.** Start four native nodes with distinct ML-DSA-65 keys from a fresh PQ-HotStuff-2 genesis across independent machines. Verify the selected engine and signing profile. |
| P0-2 — DIS continuity | **Reuse and rerun.** Confirm pilot credentials and wallet status survive a node restart on the native chain. |
| P0-3 — Transaction finalization | **Reuse and rerun.** Sign locally in DIS, submit through the normal API, and confirm the expected application effect, block hash, and state root across all four nodes. |
| P0-4–P0-6 — Signature, replay, and nonce checks | **Reuse and rerun.** Reject bad or missing signatures, disallowed schemes, replay, and incorrect nonces without applying transaction effects. |
| P0-7 — Timestamp monotonicity | **Adapt.** Check committed timestamps across both native commit paths and restart. |
| P0-8 — Safety and finality | **Replace the Tendermint-specific tests.** Carry forward QAT-06 scenarios and check stale messages, timeout and lock regressions, partition and rejoin, and process restart on the native path. |
| P0-9 — PoCD settlement | **Reuse and rerun.** Verify proof submission, authorization, replay rejection, treasury limits, and reward settlement on the actual Qattice executor. Track separately as application acceptance. |
| Defensive pruning and recovery | **Add.** Port the watermark to the native node. Run beyond retention, confirm deletion, then restart a pruned node and verify catch-up, agreement, and no duplicate execution. |

**Exit evidence.** One pinned candidate demonstrates fresh genesis, DIS-signed application execution, four-node agreement, and recovery after pruning. Record remaining feature gates with the candidate. Chain Forge separately verifies that the wizard generates the native genesis without manual edits. [Chain Forge product roadmap](https://github.com/cluna80/chain-forge-frontend/blob/main/ROADMAP.md)

## Phase 0.5 — Hardening

Harden the pinned Phase 0 baseline. Bring forward the original H0 requirements and preserve their evidence separately from native-path validation.

| Workstream | Acceptance coverage |
| --- | --- |
| H0-1–H0-3 — Consensus, state, recovery | Adversarial and sustained runs, state-root agreement, durable signing and execution, and crash injection at recovery and pruning boundaries. |
| H0-4–H0-7 — Transactions and execution | Replay and nonce bounds, atomic rollback, concurrent key binding, and QCB supply conservation. |
| H0-8 — Network and resource limits | Genesis-bound peer identity, cross-chain replay rejection, reconnect and partition recovery, malformed input, bounded message and sync resources, and transport security disposition. |
| H0-9–H0-10 — DIS recovery | Recovery payload limits, expiry, timelock, cancellation, and replay protection. |
| H0-11 and H0-11B/C/D — Validator policy | Eviction, liveness suspension, deterministic committed slashing, and bootstrap retirement. Keep policy activation tied to the relevant validator-set tests. |
| H0-12 — Governance | Verify quorum, activation rules, and deterministic execution against the approved policy. |
| Additional PQ controls | Review signed-byte versioning, key custody and counter rollback resistance, pruning integrity, and independent consensus review. Measure bandwidth, resource use, and finality under load. |

## Handoff to the original roadmap

- **Validator lifecycle and epoch changes.** Bind the signed epoch and validator-set commitment to votes and certificates. Verify outgoing and incoming certificate boundaries, delayed proof delivery, competing transition candidates, restart, and activation of rotations and revocations. Resolve the open PO-4 obligations before enabling changing membership.
- **Private testnet and release.** Complete the dependency-ordered QAT acceptance gates, including QAT-08 private multi-node fault and agreement tests, independent review, transport disposition, and explicit public launch approval. [QAT-01 through QAT-11](https://github.com/cluna80/Qattice/blob/4042c4f6b9da8eb4926b0f770bc477674979ccf3/ROADMAP.md#dependency-ordered-public-testnet-release-gates)
- **Product and application roadmap.** Retain DIS standalone authorization, QCB governance and FeeSponsor, PoCD and distributed compute research, and accountable agent and enterprise features as separate workstreams. Merchant integration and later interoperability remain subject to design review under the QCB-only model.

## Pinned evidence and historical records

The previous roadmap contains original requirements, locked decisions, test logs, and earlier product plans. These snapshots preserve the original text and evidence.

- [Previous roadmap on main](https://github.com/cluna80/Qattice/blob/4042c4f6b9da8eb4926b0f770bc477674979ccf3/ROADMAP.md)
- [QAT-07 working-branch roadmap and latest milestone evidence](https://github.com/cluna80/Qattice/blob/0dd823793f60801bcea573cdc1930bfa4f4ae24a/ROADMAP.md)
- [Original defensive pruning requirements](https://github.com/cluna80/Qattice/blob/4042c4f6b9da8eb4926b0f770bc477674979ccf3/ROADMAP.md#owner-architecture-decision--2026-11-08-defensive-pruning-and-recoverable-pq-ledger-locked-requirements-implementation-open)
- [Original Phase 0.5 hardening checklist](https://github.com/cluna80/Qattice/blob/4042c4f6b9da8eb4926b0f770bc477674979ccf3/ROADMAP.md#phase-05--protocol-hardening-and-integration)
