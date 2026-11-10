# PQ-HotStuff-2 - scope: anchored (incremental) evidence and bounded evidence growth (PROPOSAL; documentation only; nothing here is implemented)

Status: a scope document for owner review. **No code, no activation, no consensus-profile change, dynamic membership stays disabled, pruning stays disabled.** It follows the owner direction of 2026-11-10:
preserve **genesis as the trust root**; returning nodes persist checkpoints they have already verified; fresh nodes verify from genesis unless a separately reviewed bootstrap mechanism is approved;
never trust a checkpoint merely because an owner or several peers publish it.

## 1. Corrections to how this was first described
* **Anchors do not automatically remove the 10,000-header limit.** Verification between checkpoints can be bounded, but the growth of whatever is retained, certificate sizes and the resource limits still need a design (section 6).
  The 10,000-header ceiling is today a MEMORY and EVIDENCE-SIZE limit of one authentication; it is not by itself a limit on how much history a node can verify (section 5, Option B).
* **Anchored evidence is not universally required for safe pruning.** Genesis-verified headers can authenticate a snapshot while a node retains those headers; pruning PAYLOADS while keeping headers is possible without anchors.
  Anchors address the growing verification and evidence burden; pruning HEADERS is a different question that does require a bootstrap decision (section 4).

## 2. What exists now (and what it costs: measured)
* `authenticate_checkpoint` verifies the whole header chain from genesis with the same verifier as the engine's rules, requires the checkpoint block FINAL, a FINAL header carrying the identical reference, and a valid high QC
  (`SeedEvidence` persisted and re-authenticated at every start, against the node's own genesis, profile, validator set and checkpoint parameters).
* `header::Start::Anchor(Anchor)` already exists: a chain of headers can be verified from a block the CALLER vouches for (`Anchor` = id, height, round, parent round, final height, last reference, ancestors window). It is
  tested (segment verification from a final anchor gives the same finality; a wrong anchor is caught). **Nothing in the node produces or persists anchors, and the caller's "vouching" is exactly the open trust question.**
* Cost, measured by the existing diagnostic (`diag_header_verification_and_restart_replay_cost`, release, real ML-DSA-65, 4 validators, this sandbox; illustrative, not a benchmark of any target machine):
  **0.76 ms and 13,430 bytes per header** (151 headers: 114.6 ms, 2,027,938 bytes). Block restart replay: 0.85 ms per block.
  Extrapolation, explicitly an ESTIMATE that assumes one block per second and cost linear in signers: the 10,000-header ceiling is about 134 MB and about 7.6 s of verification at n=4; a quorum certificate carries
  about two thirds of n signatures of about 3.3 KB each, so a header is roughly 14 KB at n=4 and roughly 220 KB at n=100, i.e. about 1.2 GB per day of retained headers at n=4 and about 19 GB per day at n=100.
  **Retaining every header forever is itself a growth problem that scales with signature size.**

## 3. Trust rules (proposed; they preserve genesis as the root)
| # | Rule |
|---|---|
| T1 | The only trust root is the node's own configured genesis (its validator set, profile, chain id and checkpoint parameters, as `Engine::authenticate_evidence` already binds them). |
| T2 | A **returning node** (one that previously verified a checkpoint from genesis) may persist that verified checkpoint as a LOCAL anchor and continue verification from it. The anchor is the node's own verified past, never imported. |
| T3 | A **fresh node** verifies from genesis. A bootstrap mechanism that skips this needs separate review and an explicit owner approval; it is not introduced by this work and never becomes a silent default or fallback. |
| T4 | A checkpoint is never trusted because an owner, or one or several peers, published or agree on it. Peers only supply EVIDENCE; acceptance is verification (as decided for providers). |
| T5 | An anchor record is a LOCAL operation record: it cannot prove authenticity. At every start it is re-checked against the node's own history/evidence, and a damaged, missing or inconsistent anchor makes the node fall back to genesis verification or refuse - it never trusts the damaged record. |
| T6 | Dynamic membership stays disabled. Anchors are valid only while the validator set is the genesis set; any future validator transition needs its OWN verified authentication rules before anchors may span it. |
| T7 | Failure never relaxes safety: if evidence is too large for the bounds, or unavailable, the result is `EvidenceLimitExceeded` / no install, with local state and signing floors untouched (as in S-2a), and ordinary verified block replay where available. |

## 4. Fresh-node bootstrap vs returning-node recovery
| | Returning node | Fresh node |
|---|---|---|
| Starting point | its own persisted, previously verified checkpoint P (T2) | genesis (T1, T3) |
| Evidence needed | headers from P to the new checkpoint C, plus C's carrier/finality (a span, not the whole chain) | headers from genesis to C |
| Work | proportional to the distance P to C | proportional to the chain length |
| Needs from providers | headers from P onward | **headers from genesis** |
| What it removes | re-verification of everything it already verified | nothing (it has no past) |
**Consequence for pruning.** A provider that prunes headers below some height can no longer serve fresh nodes who verify from genesis. Pruning payloads while retaining headers is compatible with T3; pruning headers is not, unless a
reviewed bootstrap mechanism exists. That is the real dependency between pruning and this work, and it is a decision for the owner, not an implementation detail.

## 5. Options
**A. Returning-node incremental verification (recommended first step).** Persist the latest checkpoint this node authenticated as a local anchor record (an `Anchor` plus the reference and block-store position, in the existing
forward-only, atomically replaced style). On a later recovery, request headers from P (not from genesis), verify with `Start::Anchor`, authenticate C, and replace the anchor only after the new evidence verified. No new signed
objects, no profile change, trust root unchanged.
**B. Segmented verification for any node (recommended with A).** Verify a long chain in bounded SEGMENTS (a fixed number of headers and bytes per segment, as in the S-2a bounds), persisting after each verified segment a
local anchor so progress survives restarts and memory stays bounded by the segment size, not the chain length. This turns the 10,000-header ceiling into a per-segment memory bound; verification WORK stays proportional to the
distance (about 0.76 ms per header measured at n=4), so a fresh node on a long chain pays a long but bounded, resumable, crash-safe verification, with every intermediate anchor derived from its own verification from genesis.
**C. Bootstrap from a published checkpoint (NOT proposed; not approved).** Starting a fresh node from an owner- or peer-published checkpoint is a weak-subjectivity assumption (the node trusts the publication, not its own verification).
Per T3/T4 it would need a separate review and an explicit owner decision, with its own threat model (what is the publication channel, how is it authenticated, how old may it be). It is listed only so that the dependency of header pruning on it (section 4) is visible.
**D. Checkpoint finality proof by skipping (a research question; not proposed for implementation).** With static membership, a quorum certificate verifies from the genesis validator set alone, so a compact proof - the checkpoint
block's header, its carrier, and the two-chain finality certificates, without the intervening history - could in principle authenticate a checkpoint from genesis-rooted keys with no trust beyond genesis. This resembles BFT
light-client "skipping verification". Its safety argument relies on the same fewer-than-one-third-faulty assumption that finality itself relies on, and it does NOT address long-range key-compromise (which full verification from genesis does not address either);
it also gives up re-checking historical reference rules, and it breaks as soon as membership can change (T6). It needs consensus and cryptography review before anyone writes code, and is recorded here only as the likely long-term
direction that would make fresh-node cost independent of chain length without a new trust assumption.
**E. Smaller certificates / proofs of certificate validity (deferred, as decided).** The dominant cost is signature size (about 3.3 KB each, no aggregation in ML-DSA). Committee sampling or hash-based proofs of certificate validity are separate, larger designs.

## 6. Bounded evidence growth (what must be specified before any implementation)
1. **Per-authentication bounds** (already in S-2a): headers, bytes and a per-segment limit; exceeding them yields `EvidenceLimitExceeded`, never a silent downgrade. Option B makes the bound per segment instead of per chain.
2. **Persisted anchors:** at most one current verified anchor per node plus, optionally, a small ring (N configurable, default 1-2) for rollback of a damaged record. Size is constant, independent of chain length.
3. **Provider retention:** providers must keep headers from genesis (T3) until the owner approves a bootstrap mechanism; the disk this costs is the section 2 estimate (about 14 KB per header at n=4, growing with the validator count). The per-node retention budget for headers needs its own accounting alongside the snapshot budget; a node that cannot afford it must say so (a clear resource error), not prune headers silently.
4. **Serving bounds:** header pages are already bounded by the transport limit and the serve gate; serving from an arbitrary start point (P) must not become cheaper to abuse than serving from genesis (same spacing, caps and pins).
5. **Work bounds:** segment verification is CPU-bound (about 0.76 ms per header at n=4, measured, sandbox); the requester needs an overall deadline and resumability so a slow machine makes progress rather than restarting.
6. **Crash safety:** an anchor is replaced atomically and only after the evidence it summarises has verified; a crash at any point leaves either the old anchor or the new one, and the install path's rule stays: evidence durable before any application generation is published.
7. **Tests to write first (fail-first, real ML-DSA-65):** a forged/damaged/rolled-back anchor is rejected or falls back to genesis; an anchor from another genesis, profile or parameter set is refused; a returning node's result equals a from-genesis result for the same checkpoint; segment boundaries do not change finality (including a segment that ends between a block and its certifying child); crash at every operation of anchor replacement; resource-exhaustion and malicious-provider cases from the S-1 simulator applied to non-genesis start points; and mutation checks for each.

## 7. Recommended order
1. Owner review of T1-T7 and the A+B direction (this document). Decide: retain headers from genesis for now? default anchor-ring size? Is Option D worth a separate research review?
2. Implement A and B behind the existing disabled gates (new feature, off by default), docs and tests first, validated on Windows at a pinned commit as before.
3. Only then revisit pruning (payload pruning first; header pruning needs a bootstrap decision, Option C or D).
Out of scope here: node wiring of the requester, the operator `install --from-peers` command, automatic triggering, real application recovery (U5, canonical state root), production keys (#109), dynamic membership, any consensus-profile change.

## 8. Risks
A wrongly trusted anchor is a wrongly trusted checkpoint (T5 and the fall-back rule address this); segment resumption bugs could skip verification (the fail-first tests above); retaining all headers is expensive and grows with validator count (section 6.3); Option D's safety argument, if ever pursued, must not be accepted from this document alone.
