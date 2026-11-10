# PQ-HotStuff-2 - AN-2: anchored verification — segmented verifier, build-record, cross-check and audit (DRAFT; off by default)

Scope: `phase11-anchored-evidence-scope.md` (PR #152; sections 5A, 5B and 6A; owner decisions of 2026-11-10). Stacked on AN-1 (`feat/pq-hotstuff-2-anchored-evidence-an1`, frozen at `e0d29c847d3848fa8eee880368304460dce9fab5`). **Code freeze pending Windows confirmation.**
Feature `pq-anchored-evidence`, OFF by default. **Nothing in the node, driver or network calls any of this; no anchor-start mode exists; pruning is not implemented.**

---

## Short plan (four pieces; reviewer brief of 2026-11-10)

### A. Segmented verifier (`verify_segments`)
Splits a long header chain into bounded segments and re-verifies each segment using the existing `verify_header_chain` rule set. The boundary survives an unfinished finality relationship:

**Verification state carried between segments** — an `Anchor` at the highest block the run itself finalized (never the tip):
```
Anchor {
    id:           BlockId     // block hash of the finalized block
    height:       u64
    round:        u64         // the round in which that block was proposed
    parent_round: u64         // round of the finalized block's parent (prev-round chain rule)
    final_height: u64         // highest block finalized by that QC
    last_ref:     BlockId     // last checkpoint reference inside the finality window
    ancestors:    Vec<(u64, Vec<BlockId>)>  // sliding window, used by the reference rule
}
```

**Unfinished finality at a boundary** — when a segment ends before the pending `commits_parent` QC arrives, `resume_point` returns `None` (no new anchor). `verify_segments` re-presents the unfinalized suffix (the last `consumed - finalized_count` headers) to the NEXT segment, prepended before the next batch. The next segment then has a chance to advance finality across the boundary. If an intermediate segment makes no progress at all (every header falls in a TC-heavy region where nothing can finalize) the verifier returns `SegmentError::NoProgress { at }` rather than silently advancing the cursor — fail-closed by design.

### B. Build-record (`build_record`)
Accepts only a `CheckpointSeed` (constructible only by `authenticate_checkpoint`, which runs the full `verify_header_chain` rule set). The seed pins the carrier block and the two consecutive-round blocks that constitute the finality proof. `build_record` locates those blocks in the provided headers, re-decodes the proof under the configured limits, and records the result. Because the seed can only come from verified evidence, the resulting `AnchorRecord` can only summarize the node's own verification (trust rule T2: a record cannot be forged from arbitrary headers, only from successfully verified ones).

### C. Cross-check (`cross_check`)
Re-verifies the finality proof in an `AnchorRecord` against the genesis validator set. This proves that a genesis-keyed quorum certified the anchor block's round. It does **not** prove that every block from genesis to the anchor was rule-valid — that gap is intentional (the cross-check is a lightweight sanity check, not a full re-audit). The gap is closed by the Audit.

**Persisted anchor fields checked against verified evidence:**
The cross-check re-derives `AnchorBinding` from `ChainParams` and requires it to match the stored binding exactly. It then requires that the proof's final `CommitPoint` carries a reference at exactly `anchor.height` with `anchor.id`. It also runs `verify_header_chain(Start::Anchor(rec.anchor), ...)` on the proof headers, so the proof must be valid under the anchor's own state — but the anchor itself was written by this node's prior verified run, not re-established from genesis.

### D. Resumable audit (`Audit`)
Advances from genesis to the anchor, verifying rule-valid history one segment at a time. At each step it compares every field a `Start::Anchor` trusts against what the verifier found:
- `id` at the anchor height
- `round` of the anchor block
- `parent_round` (the prev-round rule)
- `final_height` and `last_ref` (combined: the finality window must end at the same place)
- `ancestors` window (all checkpoint references in the sliding window)

Progress is capped at `anchor.height` — the audit never claims to have gone beyond the block it was given, even if the provided headers extend further. The audit is resumable: the caller feeds windows of headers and calls `advance` until `AuditStep::complete` is true.

**Re-verifying certificates alone does not turn an arbitrary persisted anchor into trusted history.** A caller who has forged or corrupted `anchor.last_ref` or `anchor.ancestors` will see `Mismatch("final height or last reference")` or `Mismatch("ancestors window")` from `Audit::advance`. A forked or substituted chain at the anchor height yields `Mismatch("block id at the anchor height")`. The cross-check alone cannot detect these: it validates the finality proof but cannot see that the anchor fields disagree with the actual rule-valid history from genesis.

---

## What it adds (`chain-forge-consensus/src/pq_hotstuff/anchor_verify.rs`)

```rust
// Error types
pub enum SegmentError { Headers(HeaderError), NoProgress { at: usize }, ZeroSegment }
pub enum CrossCheckError { Binding, Structure(&'static str), Headers(HeaderError), ReferenceNotAttested }
pub enum AuditError { Segments(SegmentError), NotContiguous, Mismatch(&'static str) }

// Segmented verifier
pub fn resume_point(p: &ChainParams, start: &Start, vc: &VerifiedChain) -> Option<(Anchor, usize)>
pub struct Segmented { pub tip, pub finalized, pub resume: Option<Anchor>, pub segments: usize }
pub fn verify_segments<V: ConsensusVerifier>(p, v, start, headers, final_qc, seg) -> Result<Segmented, SegmentError>

// Build-record (only from an authenticated seed)
pub fn build_record(seed: &CheckpointSeed, headers, final_qc, generation, provenance,
                    audited_height, binding, lim) -> Result<AnchorRecord, AnchorError>

// Cross-check (finality proof re-verification; does not prove rule-valid history)
pub struct ProofChecked { pub anchor_height: u64, pub proof_headers: usize }
pub fn cross_check<V: ConsensusVerifier>(rec, p, v, lim) -> Result<ProofChecked, CrossCheckError>

// Resumable audit (closes the gap cross_check leaves)
pub struct AuditStep { pub audited_height: u64, pub complete: bool }
pub struct Audit { /* anchor, cur, next_height, audited, seg, checked_anchor */ }
impl Audit {
    pub fn new(rec: &AnchorRecord, seg: usize) -> Audit
    pub fn next_height(&self) -> u64
    pub fn resume(&self) -> &Start
    pub fn advance<V: ConsensusVerifier>(&mut self, p, v, headers) -> Result<AuditStep, AuditError>
}
```

---

## Evidence at the AN-2 commit (Linux, release, REAL FIPS 204 ML-DSA-65; NOT milestone confirmation)

Required engine run: the named real-crypto binary only. All statuses 0.

| Configuration | engine (`pq_hotstuff_engine_fips204`) | anchored+snapshot |
|---|---|---|
| `pq-hotstuff-fips204` (feature OFF) | **194** passed, 2 ignored | — |
| `pq-hotstuff-fips204,pq-anchored-evidence` | **209** passed, 2 ignored | — |
| `pq-hotstuff-fips204,pq-snapshot-transfer,pq-anchored-evidence` | **218** passed, 2 ignored | — |

The feature-off engine count is **unchanged** (194). The node tests were NOT rerun on Linux at this commit (no node, driver or network code changed). Counts above are from background sandbox runs (see notification); Windows-confirmed counts are the milestone gate.

**15 new tests over AN-1 (194 → 209; AN-1 added 8, AN-2 adds 7):**

| # | Test name | What it tests |
|---|---|---|
| 1 | `segmented_verification_equals_uninterrupted_verification_on_healthy_and_timeout_chains_at_every_segment_size` | Segmented equals uninterrupted for every seg size ≥ min-progress on both a healthy chain and a TC-heavy chain; `NoProgress` on a small window inside a TC-heavy region is correct fail-closed behavior |
| 2 | `a_restart_boundary_carries_exactly_the_resume_state_and_the_unfinalized_suffix_is_represented_never_skipped` | Resume point is the highest finalized block (never the tip); re-presenting the unfinalized suffix to the next run finalizes the same blocks exactly once; skipping the suffix is structurally impossible (parent link fails) |
| 3 | `a_returning_node_extending_from_its_own_anchor_record_authenticates_the_same_checkpoint_as_from_genesis` | A node that persisted AN-1-style verification as its own anchor can continue from that anchor and authenticate the next checkpoint identically to a from-genesis run; the extended record round-trips and cross-checks |
| 4 | `the_cross_check_reverifies_the_proof_against_the_genesis_validator_set_and_rejects_every_tampering` | Correct genesis-keyed proof → `ProofChecked`; tampered binding, structure, headers, and reference are each rejected |
| 5 | `the_finality_cross_check_does_not_establish_history_and_the_audit_closes_exactly_that_gap` | Forged `last_ref` / ancestors PASS cross_check; forked chain PASSES cross_check; both FAIL audit at the specific mismatched field (the cross-check / history distinction pinned) |
| 6 | `the_audit_compares_every_anchor_field_a_start_would_trust_and_progress_is_capped_at_the_anchor` | Covers M6–M10: each forged field (`round`, `parent_round`, `final_height`+`last_ref`, `ancestors`) caught individually; `audited_height ≤ anchor.height` throughout even when headers extend beyond |
| 7 | `the_audit_reverifies_genesis_to_the_anchor_in_bounded_segments_with_forward_only_durable_progress` | Full genesis-to-anchor audit completes; `audited_height == anchor.height`; progress is durable and forward-only |

---

## Mutation record (real crypto; a spot check of chosen mutants, not a proof)

12 mutants applied; **all 12 caught** after the 7th test was added.

| ID | Mutation | First caught by | Test added |
|---|---|---|---|
| M1 | `resume_point` returns tip instead of finalized top | T1 (segmented equals uninterrupted) | No |
| M2 | Skips suffix re-presentation on segment boundary | T1 | No |
| M3 | Skips `AnchorBinding` check in `build_record` | T4 (binding mismatch) | No |
| M4 | Skips `ReferenceNotAttested` path in `cross_check` | T5 (trust gap pin) | No |
| M5 | Skips audit `id` check | T5 | No |
| M6 | Skips audit `round` comparison | T7 (survivor cover) | Yes |
| M7 | Skips audit `parent_round` comparison | T7 | Yes |
| M8 | Skips audit `final_height`/`last_ref` check | T7 | Yes |
| M9 | Skips audit `ancestors` window comparison | T7 | Yes |
| M10 | Removes `audited_height ≤ anchor.height` cap | T7 | Yes |
| M11 | Skips proof re-decode in `cross_check` | T3 (cross_check validates proof) | No |
| M12 | Skips structural reference check (`reference.height == anchor.height`) | T3 | No |

**5 of 12 required a new test** (M6–M10). The 5 survivors from the initial 6-test suite used real chains where all anchor fields match by construction; the 7th test forges each field explicitly.

---

## Limits

- **Not implemented**: node wiring, anchor-start mode, pruning, snapshot installation from anchor, fresh-node bootstrap, network distribution of anchor records.
- **Not tested here**: multi-node liveness under real network conditions; adversarial peers; production key custody; signing-state rollback protection.
- The mutation campaign is a spot check of chosen mutants, not a proof of absence of bugs.
- Counts above are from a Linux sandbox run. Per CLAUDE.md, the milestone is NOT marked ✅ until the developer confirms the Windows run.

---

## Pinned Windows commands (owner must run, MINGW64)

```bash
git pull origin feat/pq-hotstuff-2-anchored-evidence-an2
cargo build -p chain-forge-node
cargo test -p chain-forge-consensus --test pq_hotstuff_engine_fips204 --features pq-hotstuff-fips204,pq-anchored-evidence -- --nocapture 2>&1 | tail -3
# expect: 209 passed, 2 ignored
cargo test -p chain-forge-consensus --test pq_hotstuff_engine_fips204 --features pq-hotstuff-fips204,pq-snapshot-transfer,pq-anchored-evidence -- --nocapture 2>&1 | tail -3
# expect: 218 passed, 2 ignored
cargo test -p chain-forge-consensus --test pq_hotstuff_engine_fips204 --features pq-hotstuff-fips204 -- --nocapture 2>&1 | tail -3
# expect: 194 passed, 2 ignored (feature-off unchanged)
```
