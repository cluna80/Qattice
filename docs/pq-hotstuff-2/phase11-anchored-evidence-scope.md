# PQ-HotStuff-2 - scope: anchored (incremental) evidence and bounded evidence growth (documentation only; nothing here is implemented; owner decisions recorded 2026-11-10)

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
| T5 | An anchor record is a LOCAL record. **A checksum cannot authenticate it.** Section 6A states exactly what is re-checked at every start (integrity, binding to the node's OWN genesis parameters, a re-verified compact finality proof, cross-checks against local evidence), what is NOT re-checked at start (that the history below the anchor was rule-valid), the local-storage trust boundary that follows, and the audit that closes the gap against genesis. A damaged, foreign, missing or inconsistent anchor never is trusted: the node falls back to the other generation, then to genesis verification, or refuses. |
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
**D. Checkpoint finality proof by skipping (a RESEARCH question only; separate review; no implementation).** With static membership a quorum certificate verifies from the genesis validator set, so a compact proof - the checkpoint
block's header, its carrier, and the two-chain finality certificates, without the intervening history - might authenticate a checkpoint from genesis-rooted keys. Whether that adds **no additional trust assumption is something the review
must ESTABLISH; it is not an established result.** Static genesis keys alone do not prove every checkpoint acceptance rule: the reference rules R1-R4 and R6, the attested state root (which rests on honest validators applying the voting rule R5 to
their own execution) and the genesis-bound parameters are properties of the history, not of any single certificate. Its safety argument would lean on the fewer-than-one-third-faulty assumption that finality itself needs, it does not address
long-range key compromise, and it breaks as soon as membership can change (T6). Section 6A uses a compact finality proof only as a CHEAP CROSS-CHECK on a locally stored anchor, never as the authentication of the history.
**E. Smaller certificates / proofs of certificate validity (deferred, as decided).** The dominant cost is signature size (about 3.3 KB each, no aggregation in ML-DSA). Committee sampling or hash-based proofs of certificate validity are separate, larger designs.

## 6. Bounded evidence growth (what must be specified before any implementation)
1. **Per-authentication bounds** (already in S-2a): headers, bytes and a per-segment limit; exceeding them yields `EvidenceLimitExceeded`, never a silent downgrade. Option B makes the bound per segment instead of per chain.
2. **Persisted anchors:** at most one current verified anchor per node plus, optionally, a small ring (N configurable, default 1-2) for rollback of a damaged record. Size is constant, independent of chain length.
3. **Provider retention:** providers must keep headers from genesis (T3) until the owner approves a bootstrap mechanism; the disk this costs is the section 2 estimate (about 14 KB per header at n=4, growing with the validator count). The per-node retention budget for headers needs its own accounting alongside the snapshot budget; a node that cannot afford it must say so (a clear resource error), not prune headers silently.
4. **Serving bounds:** header pages are already bounded by the transport limit and the serve gate; serving from an arbitrary start point (P) must not become cheaper to abuse than serving from genesis (same spacing, caps and pins).
5. **Work bounds:** segment verification is CPU-bound (about 0.76 ms per header at n=4, measured, sandbox); the requester needs an overall deadline and resumability so a slow machine makes progress rather than restarting.
6. **Crash safety:** an anchor is replaced atomically and only after the evidence it summarises has verified; a crash at any point leaves either the old anchor or the new one, and the install path's rule stays: evidence durable before any application generation is published.
7. **Tests to write first (fail-first, real ML-DSA-65):** a forged/damaged/rolled-back anchor is rejected or falls back to genesis; an anchor from another genesis, profile or parameter set is refused; a returning node's result equals a from-genesis result for the same checkpoint; segment boundaries do not change finality (including a segment that ends between a block and its certifying child); crash at every operation of anchor replacement; resource-exhaustion and malicious-provider cases from the S-1 simulator applied to non-genesis start points; and mutation checks for each.

## 6A. Anchor authentication, retained evidence and crash recovery (the resolution of T5; corrected 2026-11-10 after owner review)
**The problem.** Today a restart re-authenticates the stored `SeedEvidence` from genesis, so even a tampered local seed is caught; that costs O(chain). An anchor exists to avoid that cost, and a checksum only detects accidents. So the design must say what replaces the
re-verification at start, and what trust it relies on.
**Local-storage trust boundary and the signing-floor assumptions (explicit).** The node's data directory is inside its own trust boundary for everything this work adds: an anchor is never imported from a peer (T2/T4), and a peer can never cause one to be written except by this node having verified it itself.
**Signing floors are protected only to the extent of the SafetyStore's own assumptions, which this work neither strengthens nor weakens.** Per the SafetyStore's documentation: a crash leaves the old or the new record; the record carries an integrity checksum, NOT an authentication tag (someone who can write the file can forge it, although the stored signatures are
verified on load); **rollback of the file is detectable only through the `MonotonicCounter`, which must be a trusted mechanism outside the file's reach** (hardware counter, HSM, remote witness); the counters in this repository are test doubles and the devnet counter is a FILE, so on the devnet a party who can rewrite the data directory can roll
back the safety record and the counter together. Production key storage and counter are blocked on #109. Therefore: **anchor code never lowers or rewrites a floor itself and never signs**; whether a disk-writing adversary could lower floors is a property of the SafetyStore and its counter backend, not of anchors, and no claim is made here that such an adversary cannot.
**What an anchor record holds (the retained evidence).** `AnchorRecord`, versioned, strictly decoded: (1) the binding the node recomputes from its OWN configuration (genesis hash, profile, chain id, validator-set hash, checkpoint parameters) - never trusted from the record;
(2) the `Anchor` fields (id, height, round, parent round, final height, last reference, ancestors window); (3) the **finality proof**: the anchor block's header, the headers up to a final carrier of the reference it attests, and the certificates that make the checkpoint block FINAL;
(4) the reference (height, block id, state root); (5) provenance: `Genesis` (created by this node's own genesis verification) or `Anchor(generation)` (extended by this node from an earlier anchor); (6) `audited_height`: the highest height this node has itself re-verified from genesis through this anchor's lineage;
(7) a generation number and a checksum (integrity only).
**Bounds on the proof (specified, not "a handful").** The freshness bound lets a reference name a block up to `max_age` below the final height (R6), so the proof can span on the order of `max_age` plus the finality margin headers, which is NOT small for a large `max_age` (the devnet uses 24; a header is about 13.4 KB at n=4 and about 220 KB at n=100, estimates).
Two configured limits apply and are validated locally at start: `max_anchor_proof_headers` and `max_anchor_proof_bytes`. A genesis `max_age` whose proof cannot fit them makes anchored start UNSUPPORTED (refused locally, genesis verification stays); an over-limit proof is rejected at decode, never truncated.
**Cost of the start checks, stated precisely.** The anchor-proof check is bounded by those limits and is **independent of chain length**. The **retained tail is not**: re-validating the stored blocks above the anchor costs time proportional to the number of retained blocks above it (measured 0.85 ms per block on this sandbox, illustrative).
A third limit, `max_tail_blocks`, bounds this: the node advances its anchor (only after verifying the evidence) so the tail stays under it; a tail over the limit is reported and the node continues from genesis verification or refuses; it is never skipped.
**What is re-checked at every start.** (a) decode, checksum, version and the limits above; (b) the binding equals the values recomputed from the node's own configuration; (c) the finality proof is RE-VERIFIED against the genesis validator set (a bounded number of ML-DSA verifications; to be measured on a real proof) and its ids recomputed from the headers, so a record that claims finality its certificates do not show is rejected;
(d) the `Anchor` fields agree with the headers; (e) the executor is at or above the anchor and its history agrees with the anchor through the stored committed blocks and the root log (never rewound; this is the existing base-aware reconcile); (f) the stored blocks above the anchor chain from it and re-validate as they do today; (g) the SafetyStore opens under its own rules.
**What is NOT re-checked at start.** That the chain from genesis to the anchor was rule-valid (R1-R4, R6, the attested root). That rests on this node's earlier verification and, until the audit completes, on the assumption that its local storage was not tampered with.
**The audit is DETECTION, not prevention.** A resumable, bounded background re-verification of genesis to the anchor in segments (option B), from retained headers (T3) or from providers, advancing `audited_height` durably after each verified segment, reported in the status. **It can only detect a bad anchor LATER; it cannot undo anything signed in the meantime.** Under the trusted-local-storage assumption it detects tampering or an earlier error;
it does not close the gap before participation. An audit failure fails closed: signing stops, `ANCHOR_AUDIT_FAILED` is reported, and the operator must remediate (genesis verification from scratch); the node never repairs itself.
**Modes (all opt-in except the default).** `off` (DEFAULT): re-authenticate from genesis at every start; no anchor is used at start. `audit_first`: start from the anchor after the checks above for syncing and serving, with **signing disabled (the engine stays `Recovering`) until the audit has verified genesis to the anchor**; this is what applies whenever anchor provenance is uncertain, namely whenever `audited_height` is below the anchor height, a record failed any check,
or the older generation had to be used. `trust_local`: an explicit operator choice that allows signing on a checked anchor before the audit completes, accepting the trusted-local-storage assumption knowingly; the status states that the node is running on an unaudited anchor. Only `off` and `audit_first` are proposed for the first implementation; `trust_local` needs its own decision.
**Anchor ring of two generations (crash recovery only).** Generations g and g-1 are kept. A new anchor is written as a new generation (temporary name, flush, atomic rename, directory sync) and only AFTER the evidence it summarises verified; g-1 is removed only after g is durable. At start the newest generation that passes the checks is used; if g fails, g-1 is used (and provenance is then treated as uncertain); if both fail, the node falls back to genesis verification, or refuses if the evidence is unavailable.
**Falling back to an older anchor.** The older anchor will generally NOT match the executor's current cursor (the executor is ahead of it). The fallback therefore resumes verification FROM the older anchor FORWARD to the existing application state: through the retained tail blocks and, if they are missing, headers fetched from providers, re-verifying each and agreeing with the committed history and the root log up to the executor's cursor.
**Nothing is rewound:** the executor and the signing floors stay where they are, the node stays non-signing (`Recovering`) until this verification reaches the executor's height, and if the needed headers are unavailable it stays non-signing and reports it. It never guesses and never trusts the failing record.
**Crash points to specify and test (fail-first, real ML-DSA-65).** Before the temporary write; after it, before the rename; after the rename, before g-1 is removed; during g-1's removal; during an audit-progress update; during the install path (the existing rule stays: evidence durable before any application generation is published). In every case the node starts from g, g-1 or genesis, with identical application state, and floors as the SafetyStore keeps them.
**Consistency check against T1-T7.** T1: the root remains genesis (binding recomputed; audit and default mode re-verify from it). T2: an anchor is only this node's own verified past, never imported. T3: fresh nodes verify from genesis; anchors do not change that. T4: peers supply headers for audits and updates, never trust. T5: stated above, with the boundary and the floor assumptions explicit, default off, and signing disabled while provenance is uncertain.
T6: the binding includes the validator-set hash, so an anchor never spans a membership change (there is none today; a future transition needs its own rules). T7: every failure path ends in fall-back, refusal or `EvidenceLimitExceeded`, with state untouched and floors as the SafetyStore keeps them. No rule contradicts another; the residual weakness is the explicit trusted-local-storage assumption of `trust_local`, which is not part of the first implementation.

## 7. Owner decisions (2026-11-10)
| Decision | Recorded |
|---|---|
| T1-T7 and A+B | Direction accepted, **subject to the T5 resolution in section 6A** |
| Genesis headers | Retained for now, **with explicit disk accounting** (section 6.3) |
| Anchor ring | **2 generations**, for crash recovery; the fallback never rewinds application state or lowers a signing floor (resumes verification from the older anchor to the existing state) |
| Option D | **Separate research review only; no implementation**; "no additional trust assumption" is for the review to establish |

## 8. Recommended order
1. Owner review of section 6A (anchor authentication). The decisions of section 7 are recorded.
2. Implement A and B behind the existing disabled gates (new feature, off by default), docs and tests first, validated on Windows at a pinned commit as before.
3. Only then revisit pruning (payload pruning first; header pruning needs a bootstrap decision, Option C or D).
Out of scope here: node wiring of the requester, the operator `install --from-peers` command, automatic triggering, real application recovery (U5, canonical state root), production keys (#109), dynamic membership, any consensus-profile change.

## 9. Risks
A wrongly trusted anchor is a wrongly trusted checkpoint (T5 and the fall-back rule address this); segment resumption bugs could skip verification (the fail-first tests above); retaining all headers is expensive and grows with validator count (section 6.3); Option D's safety argument, if ever pursued, must not be accepted from this document alone.
