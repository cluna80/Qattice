# PQ-HotStuff-2 — Phase 0 and Phase 0.5 Requirements Mapping

**Date:** 2026-11-10  
**Status: DRAFT — documentation only. No code, merge, activation, test-rerun, or milestone closure is authorized.**  
**Scope:** Maps every original Phase 0 acceptance requirement and every Phase 0.5 hardening requirement to the PQ-HotStuff-2 architecture. Where a Tendermint- or Ed25519-specific requirement does not apply to PQ-HotStuff-2, the document records the replacement or adaptation. Historical Tendermint pass evidence is noted but not re-evaluated here.  
**Sources read (not reconstructed from memory):**
- `ROADMAP.md` (2026-11-07 superseding direction and all historical sections)
- `docs/PHASE-0-CLOSEOUT.md` (2026-10-31)
- `docs/PHASE0-SECURITY-ASSUMPTIONS.md` (2026-10-25 baseline)
- `docs/devnet-upgrade-phase-0-5.md`
- `docs/pq-hotstuff-001-spec.md` (locked D1–D5; §1–§4 and §12 gates read)
- `docs/pq-hotstuff-2/` — phase1 through phase11 implementation records
- `CLAUDE.md` (validation policy)

---

## 1. How to read this document

**Four status distinctions (ROADMAP policy, 2026-11-05):**
- **Implemented:** code exists on a branch.
- **Windows-confirmed:** owner ran the stated command on Windows/MINGW64 at the stated commit.
- **Merged:** in `main`.
- **Production-ready:** no gate is complete. None is claimed here.

**Scope of this mapping:** the **new PQ-HotStuff-2 path only**. Historical Tendermint passes are retained as evidence of the old path; they do not satisfy PQ-HotStuff-2 gates. The two paths are independent; this document makes no claim for either.

**What is not in scope:** PoCD settlement, FeeSponsor, DIS SDK, platform transport (QAT-10), and any item already explicitly deferred to post-Phase-2 in the ROADMAP.

---

## 2. Original Phase 0 acceptance requirements (P0-1 … P0-9)

> Source: `ROADMAP.md` §"Phase 0 Exit Criteria" and `docs/PHASE-0-CLOSEOUT.md`.

### P0-1 — Clean genesis launches across independent machines

| Field | Detail |
|---|---|
| **Original ID / source** | P0-1, `ROADMAP.md` §Phase 0 Exit Criteria |
| **Disposition** | **Replace** (Tendermint-specific genesis schema; PQ-HotStuff-2 requires a fresh genesis with `bft_variant: "pq-hotstuff"`, `cryptography.protocol_profile: "qattice-pq-hotstuff-2-v2"`, ML-DSA-65 validator keys and new chain/network IDs — `pq-hotstuff-001-spec.md` §3.1) |
| **PQ-HotStuff-2 acceptance criteria** | A fresh 4-node PQ-HotStuff-2 genesis starts on two independent machines, reaches height ≥ 5, all nodes agree on `block_id` and state root at each committed height; restarted node catches up. FIPS 204 ML-DSA-65 (`fips204` 0.5.0 or reviewed successor) signs all consensus messages. |
| **Required components** | PQ-HotStuff-2 engine (§12 Phase 2 gate); reviewed `fips204` backend (QAT-01); PQ-HotStuff genesis schema (§3.1); live driver node |
| **Dependencies** | QAT-01 (cryptographic conformance), QAT-06, QAT-07, QAT-08 |
| **Existing evidence** | None on the PQ-HotStuff-2 path. Tendermint P0-1 pass: 4-node ML-DSA devnet, state root match across two machines, restart confirmed (`docs/PHASE-0-CLOSEOUT.md`, 2026-10-31). **Historical only.** |
| **Missing work** | PQ-HotStuff-2 engine Phase 2; reviewed `fips204` backend merge; fresh genesis file; live node integration; two-machine test |
| **Gate** | Integrated acceptance (QAT-08/PQHS-P2) |

### P0-2 — DIS pilot identities survive node restart

| Field | Detail |
|---|---|
| **Original ID / source** | P0-2, `ROADMAP.md` §Phase 0 Exit Criteria |
| **Disposition** | **Reuse** (DIS identity persistence and ML-DSA-65 account keys are engine-independent; the DIS layer does not change when consensus switches) |
| **PQ-HotStuff-2 acceptance criteria** | All pilot DIS identities (at Verified tier) survive a node restart when the node runs PQ-HotStuff-2 consensus. Identity state root matches across all 4 nodes after restart. |
| **Required components** | Persistent state storage (H0-3); PQ-HotStuff-2 node with execution layer |
| **Dependencies** | P0-1 PQ-HotStuff-2 path, H0-3 state persistence |
| **Existing evidence** | Tendermint P0-2: BossKing/Laptop/Phone/OptiPlex-990 all Verified (2026-10-25). **Historical only.** |
| **Missing work** | PQ-HotStuff-2 node with DIS execution; re-run on PQ-HotStuff-2 devnet |
| **Gate** | Integrated acceptance (QAT-08) |

### P0-3 — ML-DSA-65 transaction accepted and finalized

| Field | Detail |
|---|---|
| **Original ID / source** | P0-3, `ROADMAP.md` §Phase 0 Exit Criteria |
| **Disposition** | **Reuse** (ML-DSA-65 user transactions are engine-independent; `mldsa_tx_live` logic is reusable) |
| **PQ-HotStuff-2 acceptance criteria** | An ML-DSA-65-signed Transfer transaction is accepted, finalized, and receiver balance confirmed on 4/4 nodes under PQ-HotStuff-2 consensus. `fips204` 0.5.0 (reviewed) signs the transaction. |
| **Required components** | PQ-HotStuff-2 node + execution layer; reviewed `fips204` backend |
| **Dependencies** | QAT-01, QAT-02, P0-1 (PQ-HotStuff-2 path) |
| **Existing evidence** | Tendermint `mldsa_tx_live` P0-3 (commit `b46de7c`). **Historical only.** |
| **Missing work** | Execution-path integration with PQ-HotStuff-2 engine |
| **Gate** | Integrated acceptance (QAT-08) |

### P0-4 — Invalid signatures rejected

| Field | Detail |
|---|---|
| **Original ID / source** | P0-4, `ROADMAP.md` §Phase 0 Exit Criteria |
| **Disposition** | **Reuse** (ML-DSA-65 transaction signature rejection is engine-independent; additionally, PQ-HotStuff-2 adds vote/proposal/timeout signature rejection that is new) |
| **PQ-HotStuff-2 acceptance criteria** | (a) Garbage ML-DSA-65 transaction signatures rejected at submission. (b) Invalid QC/TC entries (wrong `alg_id`, wrong length, forged signer) rejected by every node. (c) A proposal with an invalid block signature is refused. |
| **Required components** | PQ-HotStuff-2 engine safety rules; `fips204` backend |
| **Dependencies** | QAT-01, QAT-06 |
| **Existing evidence** | Tendermint P0-4: garbage 3309-byte sig rejected. **Historical only.** PQ-HotStuff-2: wire/safety tests (phase0–phase2 passes, real-crypto validation at `e0d29c8`: engine 194 passed). **Implements the safety rules; not a devnet acceptance.** |
| **Missing work** | Negative tests for PQ-HotStuff-2 QC/TC forgery in live context |
| **Gate** | Integrated acceptance (QAT-08) |

### P0-5 — Replayed transactions rejected

| Field | Detail |
|---|---|
| **Original ID / source** | P0-5, `ROADMAP.md` §Phase 0 Exit Criteria |
| **Disposition** | **Reuse** (nonce-based replay protection is execution-layer, engine-independent) |
| **PQ-HotStuff-2 acceptance criteria** | Nonce-0 transaction resubmitted after finalization is rejected with nonce/replay error on PQ-HotStuff-2 devnet. |
| **Required components** | PQ-HotStuff-2 node with execution layer |
| **Dependencies** | P0-1 (PQ-HotStuff-2 path) |
| **Existing evidence** | Tendermint `mldsa_tx_live` P0-5. **Historical only.** |
| **Missing work** | Re-run on PQ-HotStuff-2 devnet |
| **Gate** | Integrated acceptance (QAT-08) |

### P0-6 — Incorrect nonces rejected

| Field | Detail |
|---|---|
| **Original ID / source** | P0-6, `ROADMAP.md` §Phase 0 Exit Criteria |
| **Disposition** | **Reuse** (same rationale as P0-5) |
| **PQ-HotStuff-2 acceptance criteria** | Nonce-999 transaction (expected 1) rejected on PQ-HotStuff-2 devnet. |
| **Required components / dependencies / missing work** | Same as P0-5 |
| **Gate** | Integrated acceptance (QAT-08) |

### P0-7 — Timestamp monotonicity

| Field | Detail |
|---|---|
| **Original ID / source** | P0-7, `ROADMAP.md` §Phase 0 Exit Criteria |
| **Disposition** | **Adapt** (block timestamp monotonicity is engine-specific; PQ-HotStuff-2 carries a `timestamp_ms` in `BlockPayload` committed through `H(payload)` into `block_id` — `pq-hotstuff-001-spec.md` §3.2 rule 6; the commitment is new and stronger) |
| **PQ-HotStuff-2 acceptance criteria** | Committed blocks carry strictly increasing `timestamp_ms`. A proposal with a non-increasing timestamp is refused. Mutation of the timestamp field changes `block_id` and invalidates every vote. |
| **Required components** | PQ-HotStuff-2 engine (block_id commitment); `BlockPayload` canonical encoding |
| **Missing work** | `BlockPayload` canonical layout spec (marked pending in `pq-hotstuff-001-spec.md` §3.2 rule 6 note); implementation; tests |
| **Gate** | QAT-06 (PQHS-P0) |

### P0-8 — Consensus safety and finality under validator config

| Field | Detail |
|---|---|
| **Original ID / source** | P0-8, `ROADMAP.md` §Phase 0 Exit Criteria |
| **Disposition** | **Replace** (Tendermint-specific partition/equivocation tests; PQ-HotStuff-2 has its own safety rules, two-chain commit, QC threshold, timeout certificate handling — entirely different from Tendermint Algorithm 1) |
| **PQ-HotStuff-2 acceptance criteria** | (a) Safety: no two honest nodes commit different blocks at the same height under any network schedule (seeded adversarial simulation, model-based). (b) Liveness: after GST with an honest leader, blocks commit within bounded rounds. (c) Partition recovery: a partitioned set of f < T/3 nodes rejoins and converges. (d) Byzantine validators f < T/3 cannot cause a fork. (e) Equivocation is detected and slashed from committed evidence. |
| **Required components** | PQ-HotStuff-2 safety rules (two-chain commit, QC/TC, pacemaker, persisted lock guard); seeded adversarial simulation; equivocation slashing integration |
| **Dependencies** | QAT-06, QAT-07 |
| **Existing evidence** | PQ-HotStuff-2 safety tests (phase1 mutation-checked; phase2 engine core): engine 194 passed at `e0d29c8` (feature off). **Library-only; no live devnet.** Tendermint P0-8: partition/equivocation on Windows. **Historical only; different protocol.** |
| **Missing work** | PQ-HotStuff-2 adversarial simulation (thousands of seeded runs — QAT-06); live 4-node partition test; equivocation slashing in PQ-HotStuff-2 context |
| **Gate** | QAT-06 (PQHS-P0) + QAT-08 (live devnet) |

### P0-9 — PoCD proof submission and reward settlement

| Field | Detail |
|---|---|
| **Original ID / source** | P0-9, `ROADMAP.md` §Phase 0 Exit Criteria |
| **Disposition** | **Reuse** (PoCD is application/execution layer; classified as deferred application-layer work in the ROADMAP; not a consensus gate) |
| **PQ-HotStuff-2 acceptance criteria** | PoCD `ClaimResearchReward` succeeds on PQ-HotStuff-2 devnet with an ML-DSA-65 signed tx (all 7 `pocd_reward_live` cases). |
| **Missing work** | PQ-HotStuff-2 node + PoCD execution integration; re-run |
| **Gate** | Integrated acceptance (QAT-08) — not a consensus gate |

---

## 3. Phase 0.5 hardening requirements

> Source: `ROADMAP.md` §"Phase 0.5 — Protocol Foundation Hardening" and `docs/devnet-upgrade-phase-0-5.md`.

### H0-1/H0-2 — Deterministic participation / state-root binding

| Field | Detail |
|---|---|
| **Original ID / source** | H0-1/H0-2, `ROADMAP.md`; PR #17 (merged `main`, Windows-confirmed 2026-10-30) |
| **Disposition** | **Adapt** (the Tendermint fix used `last_commit` in `BlockPayload`; PQ-HotStuff-2 carries participation evidence through the QC's signer bitmap and `last_commit` in `BlockPayload` committed into `block_id` — `pq-hotstuff-001-spec.md` §3.2 rule 6 — which is stronger than the Tendermint fix) |
| **PQ-HotStuff-2 acceptance criteria** | Validator participation for epoch rewards is derived ONLY from the signer bitmap in the QC included in each block; liveness jails and epoch rewards are identical on all nodes; state-root divergence is impossible for deterministic inputs. |
| **Dependencies** | QC/TC canonical encoding; `BlockPayload` layout spec |
| **Existing evidence** | Tendermint H0-1/H0-2: Windows-confirmed at `main` (#17, 2026-10-30). **Historical; different commitment.** PQ-HotStuff-2 QC/TC commitment in `block_id` is specified but not yet implemented in the live engine. |
| **Missing work** | PQ-HotStuff-2 `BlockPayload` layout (pending spec); participation-from-QC-bitmap implementation; deterministic divergence test |
| **Gate** | QAT-07 (PQHS-P1) |

### H0-3 — Atomic state persistence (crash safety)

| Field | Detail |
|---|---|
| **Original ID / source** | H0-3, `ROADMAP.md` §Phase 0 security assumptions §3 |
| **Disposition** | **Reuse** (storage layer is engine-independent; crash-safe WAL/atomic-rename patterns are already applied in PQ-HotStuff-2 safety state — `phase1-safety-state.md`, Windows-confirmed) |
| **PQ-HotStuff-2 acceptance criteria** | (a) Safety state (`SafetyStore`, `ConsensusSigningRecord`) survives crash at any write point; never commits without write (write-before-broadcast). (b) Application/execution state survives crash with the WAL. (c) A node restarted after a crash converges to the same state root as peers. |
| **Existing evidence** | PQ-HotStuff-2 safety state: `phase1-safety-state.md`, mutation-checked, Windows-confirmed at the Phase 1 head. Application WAL: H0-5 (merged `main`, #15, Windows-confirmed 2026-10-30). |
| **Missing work** | PQ-HotStuff-2 live crash/restart test on 4-node devnet (QAT-08) |
| **Gate** | QAT-07 (persistence phase) + QAT-08 (live devnet crash test) |

### H0-5 — Execution atomicity and fee conservation

| Field | Detail |
|---|---|
| **Original ID / source** | H0-5, PR #15 (merged `main`, Windows-confirmed 2026-10-30) |
| **Disposition** | **Reuse** (execution layer; engine-independent) |
| **Existing evidence** | H0-5: Windows-confirmed (#15, `main`, 2026-10-30). |
| **Missing work** | Verify H0-5 invariants hold on PQ-HotStuff-2 node at integration |
| **Gate** | Integrated acceptance (QAT-08) |

### H0-7 — Supply conservation

| Field | Detail |
|---|---|
| **Original ID / source** | H0-7, PR #15 (merged `main`, Windows-confirmed 2026-10-30) |
| **Disposition** | **Reuse** |
| **Existing evidence** | H0-7 S-01..S-06: Windows-confirmed (2026-10-30, 2026-10-31, 2026-11-02). |
| **Missing work** | Re-verify on PQ-HotStuff-2 node |
| **Gate** | Integrated acceptance (QAT-08) |

### H0-8 — Genesis-hash peer check

| Field | Detail |
|---|---|
| **Original ID / source** | H0-8, Windows-confirmed 2026-10-31 (`616bf0e`) |
| **Disposition** | **Reuse** (P2P layer is engine-independent; genesis-hash peer check is already independent of consensus engine) |
| **Existing evidence** | H0-8: Windows-confirmed at `616bf0e`. |
| **Missing work** | Re-run on PQ-HotStuff-2 node with PQ genesis |
| **Gate** | Integrated acceptance (QAT-08) |

### H0-10 — Recovery timelock and cancellation

| Field | Detail |
|---|---|
| **Original ID / source** | H0-10, `ROADMAP.md` Phase 0.5 blockers |
| **Disposition** | **Reuse** (DIS/execution layer; engine-independent) |
| **Gate** | Integrated acceptance (QAT-08) |

### H0-11 — Validator eviction policy

| Field | Detail |
|---|---|
| **Original ID / source** | H0-11, open pending owner decision |
| **Disposition** | **Adapt** (eviction in PQ-HotStuff-2 is epoch-based with `commits_parent` two-chain finality; revocation is effective in the first block after it commits — decision D4, `pq-hotstuff-001-spec.md`) |
| **Missing work** | Owner eviction-policy decision; revocation lifecycle implementation (QAT-07/PQHS-P1) |
| **Gate** | QAT-07 |

### H0-12 — Governance proposals and quorum

| Field | Detail |
|---|---|
| **Original ID / source** | H0-12, `ROADMAP.md` Phase 0.5 blockers |
| **Disposition** | **Reuse** (governance is execution layer; engine-independent) |
| **Gate** | Integrated acceptance (QAT-08) |

### Release gate 1 — Proposal authentication (signed proposals, `pol_round`)

| Field | Detail |
|---|---|
| **Original ID / source** | Release gate 1, PR #21 (Windows-confirmed) |
| **Disposition** | **Replace** (Tendermint `CFP2` proposal tags are not reused; PQ-HotStuff-2 blocks carry a proposer signature over `block_id` using `CFH1|block|` tag and `alg_id` — `pq-hotstuff-001-spec.md` §3.2; the block signing message already covers `pol_round` implicitly through the QC field bound into `block_id`) |
| **PQ-HotStuff-2 acceptance criteria** | Every proposal carries a valid ML-DSA-65 signature over `block_id`; receivers fail closed when the proposer's key is in `V_epoch` and the signature does not verify; a proposal with a swapped or forged proposer signature is rejected. |
| **Missing work** | PQ-HotStuff-2 proposal authentication in the engine; negative tests (§3.2 rule 7); Windows-confirmed |
| **Gate** | QAT-06 (PQHS-P0) |

### Release gate 2 — HotStuff/FBA devnet-only

| Field | Detail |
|---|---|
| **Original ID / source** | Release gate 2, PR #23 (Windows-confirmed) |
| **Disposition** | **Superseded** (PQ-HotStuff-2 is Qattice's intended production consensus — ROADMAP 2026-11-07; the devnet-only gate was for the legacy `HotStuffEngine`, which is explicitly not the base for PQ-HotStuff-2; PQ-HotStuff-2 builds behind a non-default feature gate and requires a separate owner activation) |
| **Note** | The `bft_variant: "pq-hotstuff"` genesis field requires the new engine and refuses with any other binary; `bft_variant: "hotstuff"` retains the legacy devnet-only gate |
| **Gate** | ROADMAP Stage 3–4 (membership and builder option) |

### Release gate 3 — VCA quorum floor

| Field | Detail |
|---|---|
| **Original ID / source** | Release gate 3, PR #22 (Windows-confirmed) |
| **Disposition** | **Reuse** (PQ-HotStuff-2 spec §2: quorum q = ⌊2T/3⌋ + 1; the floor is an invariant of the protocol, not an optional check) |
| **PQ-HotStuff-2 acceptance criteria** | Every QC and TC counts aggregate signer power and requires ≥ q; q is never computed below the floor regardless of set size; negative test with a quorum one below the floor is rejected. |
| **Existing evidence** | PQ-HotStuff-2 engine safety tests include QC/TC threshold checks (phase2 engine core, mutation-checked). |
| **Gate** | QAT-06 (PQHS-P0) |

### Release gate 4 — Equivocation slashing from committed evidence

| Field | Detail |
|---|---|
| **Original ID / source** | Release gate 4, PR #26 (Windows-confirmed) |
| **Disposition** | **Adapt** (equivocation evidence is engine-specific: in PQ-HotStuff-2 the equivocating message is a vote or proposal; evidence is two signed QC entries with matching `(epoch, round)` but different `block_id`; canonical signed bytes from `pq-hotstuff-001-spec.md` §3.2 must be used for comparison, not signature bytes — per spec §9) |
| **PQ-HotStuff-2 acceptance criteria** | Equivocating votes detected, included in `BlockPayload.evidence`, verified at commit identically on all nodes using canonical PQ-HotStuff-2 signed bytes; offender slashed with identical state root on all nodes. |
| **Dependencies** | QAT-06; `BlockPayload` canonical layout |
| **Existing evidence** | Tendermint gate 4: Windows-confirmed (#26, `adversarial_equivocation_over_gossip` 4/4). **Historical only.** |
| **Missing work** | PQ-HotStuff-2 equivocation evidence format; committed-evidence slashing with PQ canonical bytes |
| **Gate** | QAT-06 (D5 decision: gate 4 first, then PQ-HotStuff Phase 0) |

---

## 4. Additional requirements for PQ-HotStuff-2 (new, with no prior Tendermint equivalent)

These are listed in the user's directive and in `pq-hotstuff-001-spec.md` §12. They have no Phase 0 / 0.5 counterpart.

### 4.1 Consensus safety, liveness, partition and restart recovery

| Field | Detail |
|---|---|
| **Source** | `pq-hotstuff-001-spec.md` §12, QAT-06 (PQHS-P0), QAT-08 (PQHS-P2) |
| **Status** | Safety rules implemented and mutation-checked (phase1–phase2 docs); two-chain commit, QC/TC, pacemaker, persisted lock guard tested in library mode. Engine counts: 194 passed at `e0d29c8` (feature OFF); **no live devnet yet.** |
| **Missing** | Adversarial seeded simulation (thousands of runs); live 4-node devnet; partition/rejoin test; crash/restart with persisted safety state under live consensus |
| **Gate** | QAT-06 (simulation) + QAT-08 (live) |

### 4.2 Snapshot authentication, installation and execution consistency

| Field | Detail |
|---|---|
| **Source** | `pq-hotstuff-001-spec.md` §12 recovery path; `docs/pq-hotstuff-2/phase10-s1-transfer-machines.md`, `phase10-s2b-snapshot-serving.md` |
| **Status** | S-1 transfer machines (phase10-s1, Windows-confirmed at prior session's PR #148); S-2b snapshot serving (phase10-s2b, Windows-confirmed at PR #151, frozen `9be9c18`). Both **feature-gated, library-only; no installation path, no pruning, no fresh-node bootstrap from a snapshot.** |
| **Missing** | Snapshot installation (operator-initiated path); authenticated snapshot vs. unauthenticated install gap; execution consistency verification after install; snapshot-sourced fresh-node bootstrap (explicitly deferred to a later slice) |
| **Gate** | QAT-07 (persistence/recovery) + later dedicated acceptance |

### 4.3 Anchored and segmented verification, fresh-node bootstrap

| Field | Detail |
|---|---|
| **Source** | `docs/pq-hotstuff-2/phase11-an1-anchor-record.md` (AN-1, Windows-confirmed `e0d29c8`); AN-2 (in progress, this branch) |
| **Status** | AN-1 — storage only: `AnchorRecord`, `AnchorRing`, `set_audited`. Windows-confirmed at `e0d29c8`: engine 202 passed (anchored). **AN-2 in progress** (this session): `anchor_verify.rs` — `verify_segments`, `resume_point`, `build_record`, `cross_check`, `Audit`; 7 tests (6 original + 1 survivor-cover); feature OFF engine count unchanged at 194; anchored 208. Mutation campaign in progress (12 mutants; M1–M2 caught; running). |
| **Missing** | AN-2: Windows confirmation; commit/push; PR. AN-3 (signing-disabled modes `off`/`audit_first`, ring fallback, header extension, segmented verification for the full anchor chain — scope doc section 6A) not yet implemented. Fresh-node bootstrap from anchor: not implemented (requires activation which is excluded from this scope). |
| **Gate** | AN-2 → integrated acceptance (QAT-07/08); AN-3 → later; fresh-node bootstrap blocked on engine activation |

### 4.4 Defensive pruning

| Field | Detail |
|---|---|
| **Source** | `docs/pq-hotstuff-2/phase3-pruning-prerequisites.md`; `pq-hotstuff-001-spec.md` §12 |
| **Status** | Prerequisites documented (`phase3-pruning-prerequisites.md`). **Pruning is NOT implemented** (explicitly stated in AN-1 and AN-2 scope docs). |
| **Required for acceptance** | Durable watermark ordering; dependency retention (evidence, checkpoint references, in-flight recovery proofs); recovery availability during pruning; storage failure handling; recovery after payload deletion. |
| **Gate** | Explicitly deferred — "pruning (not implemented)" in AN-1 and AN-2 scope; separate future slice |

### 4.5 DIS authorization, validator eligibility, key rotation, revocation, recovery

| Field | Detail |
|---|---|
| **Source** | `pq-hotstuff-001-spec.md` §8 (personhood power); ROADMAP QAT-07 |
| **Status** | DIS identity layer: implemented and Windows-confirmed on Tendermint (DIS-002A, DIS-002B, DIS-003A–E, Windows-confirmed per ROADMAP). ML-DSA-only user accounts: merged `main` (#35, Windows-confirmed 2026-10-30). PQ-HotStuff-2 validator admission with personhood weighting: **not implemented.** |
| **Missing** | PQ-HotStuff-2 validator set construction from personhood-weighted DIS registrations; next-block revocation (D4); key rotation lifecycle; ML-DSA-only admission policy in the PQ-HotStuff-2 engine |
| **Gate** | QAT-07 (PQHS-P1) |

### 4.6 Resource bounds, platform durability, 1,000-validator/3s benchmark

| Field | Detail |
|---|---|
| **Source** | ROADMAP Stage 5; `pq-hotstuff-001-spec.md` §10; ROADMAP note "not yet demonstrated" |
| **Status** | QC v1 format (signature list) specified; validator ceiling decision blocked on succinct proof milestone M0 (in another session). **Performance target (1,000 validators, finality < 3s) has not been demonstrated.** Smaller configurations (n=4, 7, 16, 31) are planned; 4-node devnet is the initial gate. |
| **Missing** | Formal benchmarks at 4/7/16/31 validators; certificate-size and bandwidth analysis; production resource bounds; succinct proof decision before 1,000-validator target |
| **Gate** | QAT-09 (PQHS-P3) |

### 4.7 Production key custody and signing-state rollback protection

| Field | Detail |
|---|---|
| **Source** | `pq-hotstuff-001-spec.md` §7 (safety state); ROADMAP §Phase 2 blocked note; `docs/PHASE0-SECURITY-ASSUMPTIONS.md` §2 |
| **Status** | PQ-HotStuff-2 `SafetyStore` with write-before-broadcast and monotonic-counter rollback protection: implemented and mutation-checked (`phase1-safety-state.md`). The devnet counter is a file; production keys and counter use a trusted monotonic counter — **blocked on PR #109 (encrypted key storage) review and merge.** |
| **Missing** | PR #109 merge (encrypted ML-DSA-65 key storage, ACL verification); production monotonic counter outside file reach; OS-RNG hedged signing under production path; independent security review |
| **Gate** | QAT-07 (persistence) + independent security review (QAT-09) |

---

## 5. Requirements preserved verbatim (applicable on the new path)

The following requirements from the ROADMAP and spec are explicitly applicable to PQ-HotStuff-2 and must not be dropped or weakened:

| Requirement | Source | Status |
|---|---|---|
| FIPS 204 ML-DSA-65 only; no fallback, negotiation, or cross-acceptance | ROADMAP 2026-11-05; spec §2, §3.1 | Architecture policy (not merged); backend QAT-01 |
| Algorithm identifiers cryptographically bound into every signed message | spec §3.2 | Specified; not yet live |
| Exactly one authorized signature per operation; canonical encoding | spec §3.2 | Specified; not yet live |
| VCA quorum floor q = ⌊2T/3⌋+1, never lower | spec §2; gate 3 | Implemented in library; not live |
| Write-before-broadcast safety state; rollback protection | spec §7; phase1-safety-state | Mutation-checked; not in live consensus |
| Fail-closed recovery; never silently restart from genesis | H0-3, spec §7 | Implemented; crash matrix tested |
| `bft_variant: "pq-hotstuff"` gated; older node refuses PQ-HotStuff-2 genesis | spec §3.1 | Specified; not yet implemented |
| Fresh chain/network IDs; no reuse of Tendermint devnet state or keys | ROADMAP Stage 2–3 | Architecture decision only |
| Personhood-weighted bounded voting power; one human one vote | spec §8 | Not yet implemented |
| DIS ML-DSA-only user account enforcement | #35, `main`, Windows-confirmed 2026-10-30 | Merged; needs PQ-HotStuff-2 node integration |

---

## 6. Unresolved specifications (kept visible)

The following items from `pq-hotstuff-001-spec.md` and the ROADMAP remain open and must not be invented or resolved here:

- **U5 — Canonical transaction encoding**: exact transaction preimage spec pending; affects block_id commitment.
- **PO-4 — Dynamic membership / epoch transitions**: model checking for disjoint validator sets pending; dynamic membership disabled.
- **U19 — Successor-set/revocation rules**: open.
- **BlockPayload canonical layout**: normative byte layout pending (`pq-hotstuff-001-spec.md` §3.2 rule 6 note — "must be added to this section before Phase 0 code is written").
- **Mainnet validator ceiling**: blocked on M0 succinct proof decision.
- **QC v1 → v2 migration boundary**: D2 decision ("mainnet ceiling after M0") open.
- **FN-DSA (FIPS 206)**: research-only; milestone QAT-FNDSA-001 (merged `main` as a roadmap entry) — not a dependency.
- **Transport PQ security**: QAT-10 (libp2p/Noise/gossip/TLS) — not in this mapping's scope.
- **P2P bootstrap retry (H0 follow-up)**: reproduced but unfixed; not in this mapping.
- **Production mempool TTL and gas limits**: not decided.

---

## 7. Gap summary

**Largest gaps between current state and integrated acceptance (QAT-08):**

1. **PQ-HotStuff-2 live engine**: Phases 0–2 are implemented in library mode (feature-gated, mutation-tested, Windows-confirmed per slice). No live 4-node devnet exists. The engine must be integrated with the node driver and execution layer before any P0/P0.5 requirement can be re-validated on the PQ-HotStuff-2 path.

2. **`fips204` backend merge (QAT-01)**: the existing ML-DSA-65 consensus keys use the pre-standard `dilithium3` backend (K1 nonconformant: 0/45 NIST vectors). All PQ-HotStuff-2 real-crypto tests already use the reviewed `fips204` 0.5.0 path (behind `pq-hotstuff-fips204` feature) but Windows/MINGW64 K1 parity, production-feature and hedged-signing review remain open.

3. **`BlockPayload` canonical layout spec**: not written. Required before Phase 0 engine code, equivocation evidence, participation evidence, and block_id commitment can be completed (§3.2 rule 6).

4. **Adversarial simulation**: thousands of seeded runs for safety (QAT-06); not yet run.

5. **AN-3 and fresh-node bootstrap**: signing-disabled modes, ring fallback, and bootstrap from an anchor are deferred to a later slice after AN-2 is Windows-confirmed.

6. **Independent security review (QAT-09)**: no review is claimed for any PQ-HotStuff-2 slice.

7. **Production key custody (PR #109)**: encrypted ML-DSA-65 key storage and ACL verification are Windows-confirmed but not merged; production signing-state rollback protection is blocked on a hardware monotonic counter outside file reach.

---

## 8. Proposed order: integrated acceptance, then Phase 0.5 hardening

**Preconditions** (must resolve before acceptance testing begins):
- P0: `BlockPayload` canonical layout spec; PO-4/U5/U19 decisions or explicit scoping.
- QAT-01: `fips204` 0.5.0 final review; Windows K1 parity; hedged signing production path.

**Integrated acceptance order (QAT-06 → QAT-07 → QAT-08):**

| Step | Deliverable | Gate |
|---|---|---|
| 1 | PQ-HotStuff-2 adversarial simulation (safety + liveness, thousands of seeded runs) | QAT-06 |
| 2 | `BlockPayload` canonical layout + equivocation evidence format | QAT-06 |
| 3 | Proposal authentication, VCA quorum floor, equivocation slashing in PQ-HotStuff-2 live context | QAT-06 |
| 4 | PQ-HotStuff-2 persistence: safety-state crash/restart in live 4-node devnet; H0-3 re-validation | QAT-07 |
| 5 | Personhood-weighted validator admission; revocation (D4); key rotation | QAT-07 |
| 6 | AN-2 Windows confirmation; AN-3 (signing-disabled modes, ring fallback) | QAT-07 |
| 7 | Fresh 4-node PQ-HotStuff-2 devnet: genesis, block production, state root agreement, restart, ML-DSA tx, partition recovery | QAT-08 |
| 8 | Re-validate P0-1..P0-9 and applicable H0-* on the PQ-HotStuff-2 devnet | QAT-08 |

**Phase 0.5 final hardening (after QAT-08 passes):**

| Step | Deliverable |
|---|---|
| 9 | Adversarial and independent review (QAT-09): bandwidth/finality benchmarks at n=4/7/16/31; operator runbook; no unresolved safety-critical findings |
| 10 | P2P bootstrap retry (H0 follow-up); ML-DSA signature admission at API level (not just execution) |
| 11 | Transport disposition (QAT-10): libp2p/Noise/gossip classical dependency documented and owner-approved |
| 12 | Formal launch manifest (QAT-11): reconcile G0–G7; production key ceremony; independent operators; soak and incident drills |

**Items that do NOT gate QAT-08 (deferred):**
- Pruning (explicitly excluded from AN-1 and AN-2 scope)
- AN-3 fresh-node bootstrap (blocked on engine activation)
- Succinct proof/M0 (separate session)
- FeeSponsor live authorization (FS-03)
- PQ transport (QAT-10)

---

*Document only. No gate is closed. No test is marked complete. All "Windows-confirmed" labels above refer to historical Tendermint or library-mode PQ-HotStuff-2 passes recorded in the referenced commit messages and PR descriptions; none closes a QAT-06–QAT-08 integrated acceptance gate.*
