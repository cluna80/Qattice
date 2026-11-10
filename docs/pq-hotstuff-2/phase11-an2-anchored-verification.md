# PQ-HotStuff-2 - AN-2: anchored verification — segmented verifier, build-record, cross-check and audit

✅ AN-2 anchored-verification components: all 8 targeted tests passed on Windows at the recorded revision (`e639fea`, 2026-11-10). The full 194/210/219-test configurations were not run to completion on Windows and are not claimed here. Node activation, anchored startup and pruning remain gated.

Scope: `phase11-anchored-evidence-scope.md` (PR #152; sections 5A, 5B and 6A; owner decisions of 2026-11-10). Stacked on AN-1 (`feat/pq-hotstuff-2-anchored-evidence-an1`, frozen at `e0d29c847d3848fa8eee880368304460dce9fab5`). **Frozen code commits: `f7ffded38465c4249c3c1dc9e75ce52fc55ab691` (initial AN-2 implementation) and `7f2416d` (adds M11 survivor test).**
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

The re-decode step (`AnchorRecord::decode(&rec.encode(), lim)`) enforces that the stored record is exactly what a later open would accept. A proof that exceeds `lim.max_proof_headers` or `lim.max_proof_bytes` is refused here, not at open time.

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

**An audit establishes historical validity only after it completes successfully.** Until `AuditStep::complete` is true (every field matched, anchor height finalized), the local-storage trust assumption from AN-1 remains in effect: the record was written by this node's own prior verified run, but the re-verification from genesis has not yet confirmed it. A partial audit provides no additional trust; a failed audit invalidates the record.

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

// Build-record (only from an authenticated seed; re-decoded under lim before returning)
pub fn build_record(seed: &CheckpointSeed, headers, final_qc, generation, provenance,
                    audited_height, binding, lim) -> Result<AnchorRecord, AnchorError>

// Cross-check (finality proof re-verification; does not prove rule-valid history)
pub struct ProofChecked { pub anchor_height: u64, pub proof_headers: usize }
pub fn cross_check<V: ConsensusVerifier>(rec, p, v, lim) -> Result<ProofChecked, CrossCheckError>

// Resumable audit (closes the gap cross_check leaves; establishes history only on completion)
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

## Evidence at the frozen commits (Linux, release mode, REAL FIPS 204 ML-DSA-65; NOT milestone confirmation)

Exact command for each run (sequential, no overlap, working tree clean):
```
cargo test --release --features <FEATURES> --test pq_hotstuff_engine_fips204 -- --nocapture
```

**Commit `7f2416d`** (adds M11 survivor test; head of the branch):

| Features | `running` reported | Final summary | Runtime | Cargo exit |
|---|---|---|---|---|
| `pq-hotstuff-fips204` (feature OFF) | 196 | **194 passed; 0 failed; 2 ignored** | 38.15 s | 0 |
| `pq-hotstuff-fips204,pq-anchored-evidence` | 212 | **210 passed; 0 failed; 2 ignored** | 41.34 s | 0 |
| `pq-hotstuff-fips204,pq-snapshot-transfer,pq-anchored-evidence` | 221 | **219 passed; 0 failed; 2 ignored** | 43.57 s | 0 |

The feature-off engine count is **unchanged** (194). The node tests were NOT rerun on Linux (no node, driver or network code changed).

**16 new tests over AN-1 baseline (194 → 210; AN-1 added 8, AN-2 adds 8):**

| # | Test name | What it tests |
|---|---|---|
| 1 | `segmented_verification_equals_uninterrupted_verification_on_healthy_and_timeout_chains_at_every_segment_size` | Segmented equals uninterrupted for every seg size ≥ min-progress on both a healthy chain and a TC-heavy chain; `NoProgress` on a small window inside a TC-heavy region is correct fail-closed behavior |
| 2 | `a_restart_boundary_carries_exactly_the_resume_state_and_the_unfinalized_suffix_is_represented_never_skipped` | Resume point is the highest finalized block (never the tip); re-presenting the unfinalized suffix to the next run finalizes the same blocks exactly once; skipping the suffix is structurally impossible (parent link fails) |
| 3 | `a_returning_node_extending_from_its_own_anchor_record_authenticates_the_same_checkpoint_as_from_genesis` | A node that persisted AN-1-style verification as its own anchor can continue from that anchor and authenticate the next checkpoint identically to a from-genesis run; the extended record round-trips and cross-checks |
| 4 | `the_cross_check_reverifies_the_proof_against_the_genesis_validator_set_and_rejects_every_tampering` | Correct genesis-keyed proof → `ProofChecked`; tampered binding, structure, headers, and reference are each rejected |
| 5 | `the_finality_cross_check_does_not_establish_history_and_the_audit_closes_exactly_that_gap` | Forged `last_ref` / ancestors PASS cross_check; forked chain PASSES cross_check; both FAIL audit at the specific mismatched field (cross-check / history distinction pinned) |
| 6 | `the_audit_compares_every_anchor_field_a_start_would_trust_and_progress_is_capped_at_the_anchor` | Each forged field (`round`, `parent_round`, `final_height`+`last_ref`, `ancestors`) caught individually; `audited_height ≤ anchor.height` throughout even when headers extend beyond |
| 7 | `the_audit_reverifies_genesis_to_the_anchor_in_bounded_segments_with_forward_only_durable_progress` | Full genesis-to-anchor audit completes; `audited_height == anchor.height`; progress is durable and forward-only |
| 8 | `build_record_re_decodes_under_the_caller_limits_and_rejects_a_proof_that_exceeds_them` | `build_record` with limits one header tighter than the proof returns `ProofTooLarge`; confirms the re-decode step is enforced (M11) |

---

## Mutation record (real crypto, release mode; a spot check of chosen mutants, not a proof)

**Baseline**: commit `f7ffded` (initial AN-2 implementation, 7 tests). Final campaign run with all 8 tests at commit `7f2416d`. **Result: 12 attempted, 10 detected by assertions, 2 invalid because they did not compile, no surviving executable mutants.**

| ID | Mutation | Verdict | Caught by |
|---|---|---|---|
| M1 | `resume_point` returns `vc.tip` instead of `*vc.finalized.last()?` | CAUGHT | T1 |
| M2 | Skips suffix re-presentation; advances `consumed` by full `seg` instead of `k` | CAUGHT | T1 |
| M3 | Removes `AnchorBinding` equality check in `cross_check` | CAUGHT | T4 |
| M4 | Removes `ReferenceNotAttested` guard in `cross_check` | CAUGHT | T5 |
| M5 | Removes `id` comparison in `Audit::advance` | CAUGHT | T5 |
| M6 | Removes `round` comparison in `Audit::advance` | CAUGHT | T6 |
| M7 | Removes `parent_round` comparison in `Audit::advance` | CAUGHT | T6 |
| M8 | Removes `final_height`/`last_ref` comparison in `Audit::advance` | CAUGHT | T6 |
| M9 | Replaces ancestors for-loop with empty iterator | COMPILE ERROR | — |
| M10 | Removes `.min(self.anchor.height)` cap on `self.audited` | COMPILE ERROR | — |
| M11 | Replaces `AnchorRecord::decode(&rec.encode(), lim)` with `Ok(rec)` | CAUGHT | T8 (added) |
| M12 | Removes structural reference check in `cross_check` | CAUGHT | T4 |

M9 and M10 produce ill-typed code that Rust's type checker rejects; they cannot be live mutants and require no test. M11 survived the initial 7-test suite (the existing tests all use limits generous enough that the proof fits); test 8 (`build_record_re_decodes_under_the_caller_limits_...`) was added and confirmed to catch it.

**History note**: the initial 7-test run at `f7ffded` produced 9 assertion-caught, 2 compile-error, 1 genuine survivor (M11). Test 8 was added at `7f2416d` to close M11. Future campaigns should use a disposable worktree so mutated files never appear in the working branch's status.

---

## Limits

- **Not implemented**: node wiring, anchor-start mode, pruning, snapshot installation from anchor, fresh-node bootstrap, network distribution of anchor records.
- **Not tested here**: multi-node liveness under real network conditions; adversarial peers; production key custody; signing-state rollback protection.
- An audit establishes historical validity only after `AuditStep::complete` is true; a partial audit provides no additional trust.
- The mutation campaign is a spot check of chosen mutants, not a proof of absence of bugs.
- Counts above are from Linux sandbox runs. Per CLAUDE.md, the milestone is NOT marked ✅ until the developer confirms the Windows run.

---

## Windows validation request (MINGW64, owner must run)

**Scope of this validation**: the AN-2 library components only — `anchor_verify.rs` and its 8 tests, exercised through the real FIPS 204 ML-DSA-65 engine binary (`pq_hotstuff_engine_fips204`). Node activation, anchored startup and pruning are not part of this validation and remain gated.

**Binary**: `pq_hotstuff_engine_fips204` only. The test-doubles engine suite (`pq_hotstuff_engine`) is not required here.

```bash
git pull origin feat/pq-hotstuff-2-anchored-evidence-an2
cargo build -p chain-forge-node
cargo test -p chain-forge-consensus --test pq_hotstuff_engine_fips204 --features pq-hotstuff-fips204,pq-anchored-evidence -- --nocapture 2>&1 | tail -3
# expect: test result: ok. 210 passed; 0 failed; 2 ignored
cargo test -p chain-forge-consensus --test pq_hotstuff_engine_fips204 --features pq-hotstuff-fips204,pq-snapshot-transfer,pq-anchored-evidence -- --nocapture 2>&1 | tail -3
# expect: test result: ok. 219 passed; 0 failed; 2 ignored
cargo test -p chain-forge-consensus --test pq_hotstuff_engine_fips204 --features pq-hotstuff-fips204 -- --nocapture 2>&1 | tail -3
# expect: test result: ok. 194 passed; 0 failed; 2 ignored (feature-off unchanged)
```

Please report the exact `test result:` lines and Cargo exit statuses. Per CLAUDE.md, the milestone is NOT marked ✅ until these pass on Windows.

---

## Windows validation result (MINGW64, 2026-11-10; commit `e639fea`)

Machine: `krizz@BossKing`, MINGW64. All 8 AN-2 tests run individually with `--features pq-hotstuff-fips204,pq-anchored-evidence` against the real FIPS 204 ML-DSA-65 binary (`pq_hotstuff_engine_fips204`). Debug profile (unoptimized). Each test printed `1 passed; 0 failed; 0 ignored`.

| Test | Runtime |
|---|---|
| `segmented_verification_equals_uninterrupted_verification_on_healthy_and_timeout_chains_at_every_segment_size` | 121.84 s |
| `a_restart_boundary_carries_exactly_the_resume_state_and_the_unfinalized_suffix_is_represented_never_skipped` | 74.00 s |
| `a_returning_node_extending_from_its_own_anchor_record_authenticates_the_same_checkpoint_as_from_genesis` | 76.52 s |
| `the_cross_check_reverifies_the_proof_against_the_genesis_validator_set_and_rejects_every_tampering` | 64.62 s |
| `the_finality_cross_check_does_not_establish_history_and_the_audit_closes_exactly_that_gap` | 89.23 s |
| `the_audit_compares_every_anchor_field_a_start_would_trust_and_progress_is_capped_at_the_anchor` | 86.05 s |
| `the_audit_reverifies_genesis_to_the_anchor_in_bounded_segments_with_forward_only_durable_progress` | 77.88 s |
| `build_record_re_decodes_under_the_caller_limits_and_rejects_a_proof_that_exceeds_them` | 64.57 s |

**All 8 passed. Cargo exit 0 for each run.** AN-2 library validation complete on Windows. Node activation, anchored startup and pruning remain gated.
