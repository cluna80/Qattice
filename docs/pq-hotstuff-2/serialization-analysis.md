# PQ-HotStuff-2: BlockPayload and QC/TC serialization — analysis, acceptance matrix, open decisions

**Status:** DRAFT, docs only. **Revision 2** (after independent review; revision 1 was head `24fa807`). Baseline: `main` at `b966ce7ac726cce44be6acef00459fec00f0d5b1`.
**Normative text proposed in:** `docs/pq-hotstuff-001-spec.md` §3.3 (BlockPayload), §3.4 (certificates, genesis certificate, limits), §3.5 (serialization versus validity, timestamp, evidence, cross-epoch, timeout rationale).
**Nothing here is implemented, activated or approved.** No Rust, Tendermint, consensus-engine, key-storage, counter or roadmap change accompanies it.

## 0. Revision 2: what changed and what was found

Requested items 1–10 map to: U1 → spec §3.4.2; U4 → §3.4.3; U5 → §3.3 "Blocked dependency"; U6 → §3.4.7; U7 → §3.5.1; U8 → §3.5.6; U9 → §3.4.6; U10 → §3.3 EvidenceItem and §3.5.3; cross-epoch TC → §3.5.4; address and signer order → §3.4.1.

Defects in revision 1 found while revising (all fixed in text; disclosed here):
1. **Double-proposal evidence was under-specified.** The block signing message holds only `alg_id` and `block_id`, so it states no round, epoch or proposer. `EvidenceItem` now carries, for kind 2, the `CFH1|blockid|` preimage of each block id.
2. **The vote message names no voter.** Offender identity comes only from which registered key verifies both envelopes; §3.5.3 requires both signatures under the same offender key.
3. **The TC could not express "no QC yet"** (round-1 timeouts have `high_qc_round = 0`). The nested field is now a certificate that may be a `GenesisCert` only when all rounds are 0.
4. **Block budget mixing.** Revision 1 left unclear whether certificates count against `max_block_bytes`; they now have a separate budget.
5. **Genesis hash is SHA-256 over compact `serde_json`** (`compute_genesis_hash`, 64 hex characters), not SHA3-256 and not a binary canonical form. The genesis certificate uses it as given (decoded to 32 bytes) and the mismatch with the SHA3-256 profile is recorded as U16.
6. **Round numbering across epochs is unspecified** in §3 and §8. The cross-epoch rules assume chain-global rounds; this is U15.
7. The block as transmitted has no specified wire layout (only its `block_id` input, payload and certificates do); recorded as U18.

Nothing in the approved signed-message formats, the merged wire code or any Rust file changed.

## 1. Compatibility analysis (field level, against the merged spec and code)

### 1.1 Against `docs/pq-hotstuff-001-spec.md` (merged)

| Item in the merged spec | This proposal | Compatible? |
|---|---|---|
| §3.2 primitives (`u16/u32/u64` big-endian, `bytes32`, `string`, `bytes`, `option`, `list`, `bitmap`) | Uses only these; adds no primitive | Yes |
| §3.2 tags are prefix-free | New tags `CFH1|payload|`, `CFH1|qc|`, `CFH1|tc|`, `CFH1|valset|`; none is a prefix of `CFH1|vote|`, `|timeout|`, `|block|`, `|blockid|`, `|pop|` or of each other | Yes (needs owner approval of the tags, U12) |
| §3.2 `block_id` input uses `H(payload)`, `H(qc)`, `tc option<bytes32>` | Defines the three hashes as SHA3-256 of the full canonical object including its tag. The `block_id` layout itself is unchanged | Yes |
| §3.2 rule 6 "payload layout must be added before Phase 0 code" | §3.3 supplies it | Yes (closes the stated gap) |
| §3.2 rule 6 lists "participation evidence" as part of `H(payload)` | Participation is carried by the block's `qc` signer bitmap, which `H(qc)` commits to. §3.3 has no duplicate participation field | **Differs in location, not in coverage** (U9). Rule 6 wording would need a one-line edit if approved |
| §3 `Block.payload` comment: "existing v1 payload: txs, last_commit -> replaced by qc, prev_state_root" | Matches: no `last_commit`; `prev_state_root` kept; evidence kept; `timestamp_ms` added (rule 6 lists the block timestamp) | Yes |
| §3 `QuorumCert{epoch, round, block_id, parent_id, parent_round, signers, signatures}` | Adds `version`, `alg_id`, `validator_set_hash`. All original fields keep their meaning and relative order | **Additive; the struct gains three fields** (U1, U13) |
| §3 `TimeoutCert{epoch, round, high_qc_rounds, signers, signatures, high_qc}` | Same fields plus `version`, `alg_id`, `validator_set_hash`; adds the alignment rule (entry `j` of `high_qc_rounds` and of `signatures` belongs to the `j`-th signer) | **Additive**; alignment was implicit and is now explicit |
| §3 "signers by validator index, ascending" | Defines the index: rank in ascending bytewise order of the address string, all registered validators included | Fills an undefined term (U2, U3) |
| §3 QC validity (power ≥ q, each signer once, alg_id matches) | Kept; adds the `validator_set_hash` equality, exact bitmap length, `u128` power sum, ordered checks (§3.5) | Yes (stricter, not different) |
| §3 TC validity (`high_qc.round == max(high_qc_rounds)`) | Kept; adds `high_qc.round < tc.round` | Stricter. If an owner-approved rule allows `high_qc.round == tc.round` the line is wrong; §5/§6 do not allow it, but this needs a reviewer's check |
| §3.1 contexts and `alg_id` rules | Unchanged. The verifier reconstructs signed messages with the profile's `alg_id`, so a certificate cannot choose its algorithm | Yes |
| §3.2 vote and timeout **signed** messages | Unchanged. They bind `chain_id`, `epoch`, `round`, `alg_id` but not `validator_set_hash` | Yes; binding the set hash would change them (U1) |
| §8 "a QC or TC is verified against the set of its own epoch" | `validator_set_hash` + `epoch` make the intended set explicit and checked | Yes |
| §9 evidence compares canonical messages, not signature bytes; deduplicate by hash of the canonical pair | `EvidenceItem` stores the two canonical messages and orders them; `evidence_id` hashes the canonical pair | Yes |
| §10 QC size ~3309 bytes per signature | Exact sizes computed from the layout (3315-byte envelope) | Yes |
| §12 Phase 0 "types, signing bytes" | These are the missing type encodings for Phase 0 | Yes |
| §3.2 rule 7 field-substitution tests | Extended by the matrix below (new fields) | Yes |

### 1.2 Against the merged code

| Code | Finding |
|---|---|
| `chain-forge-consensus/src/pq_hotstuff/wire` (#125): `VoteMessage`, `TimeoutMessage`, `BlockSigningMessage`, `BlockIdInput`, `PopMessage`, `SignatureEnvelope`, `KeyRegistration`, `encode_bitmap/decode_bitmap`, `AlgId`, `WireError` | All new objects compose these (envelope, bitmap, `BlockIdInput` fields). `BlockIdInput` already takes `H(payload)`, `H(qc)` and `tc_hash: Option<[u8;32]>` as opaque 32-byte values, so no change to merged wire code is needed; new types would be additions. `decode_bitmap` computes `(n + 7) / 8`; on a 32-bit target a large `n` overflows `usize`. Observation for the implementation phase (use `checked_add`, and cap `n` by `MAX_CERT_VALIDATORS` before arithmetic). Not changed here |
| `pq_hotstuff::safety` (#127) | Stores canonical message bytes and the envelope of the last signed vote/timeout/proposal. Unaffected: signing messages are unchanged |
| FIPS 204 adapter (#128), `chain-forge-crypto::fips204_backend` | Fixes envelope length 3309 for `alg_id = 1`. The context strings used by §3.4 are exactly the adapter's `qattice/vote/v2` and `qattice/timeout/v2`. Unaffected |
| `chain-forge-node::node::BlockPayload` (legacy) | Tendermint-era JSON, `serde_json::to_vec(..).unwrap_or_default()` (an encode failure yields empty bytes), `Option<String>` hex state root, `last_commit: CommitCertificate`, decode falls back to a bare tx array. Not canonical, not suitable for hashing in PQ-HotStuff-2. The new payload is a separate type; the legacy one is not touched. Its limits (`MAX_EVIDENCE_PER_BLOCK = 16`, `EVIDENCE_MAX_AGE_BLOCKS = 1000`) are reused as the proposed bounds |
| `chain-forge-slashing::EquivocationEvidence` | Hash strings, `round: u64`, `vote_type_byte`; made for Tendermint prevote/precommit and "Phase 0: empty signatures". Not reusable as the canonical PQ-HotStuff-2 evidence; `EvidenceItem` (§3.3) is proposed instead. Slashing application (gate 4) stays as is |
| `chain-forge-execution::Transaction` | Struct with `id: String`, `body: TxBody`, `signature`, `pq_signatures`, `sig_scheme`, ...; there is no canonical binary transaction encoding in the repository, only serde and a signing-bytes function. The payload therefore carries each transaction as opaque canonical bytes and leaves their definition to U5 |
| `chain-forge-core`: `ValidatorInfo { id: ValidatorId(String), voting_power, pop_verified, public_key }`, `ValidatorSet` | Address is a `String` (matches the `string` primitive, ≤ 255 bytes). `total_power` is an unchecked `u64` sum and `quorum_power = total * 2 / 3 + 1` is unchecked `u64` arithmetic; the proposal requires `u128` for the power sum and for `2T` (the existing helpers can overflow for very large totals; noted, not changed) |
| `GenesisConfig.limits.max_block_bytes / max_tx_bytes` | Used as the payload and per-transaction bounds |

### 1.3 Findings outside this PR's scope (reported, not changed)

1. Spec §7.1 and §7.1.1 headings still read "PROPOSED amendment, owner review pending" although the text was merged (#129) and the implementing PRs (#127, #128) are merged. Editorial; needs authorization to change.
2. The `decode_bitmap` `(n + 7) / 8` observation above.
3. Spec §3 data-type comment calls the payload "existing v1 payload"; after this proposal that wording should say "PQ-HotStuff-2 payload (§3.3)". Needs authorization to change normative text.

## 2. Design summary of the proposal

- Every object has one tag, one `u16` version, then its fields in a fixed order; its hash is SHA3-256 of its full canonical encoding.
- `block_id` already commits to everything through direct inputs, `H(payload)`, `H(qc)` and `tc`; this proposal defines those objects, so the commitment is complete (spec §3.2 rules 6 and 7).
- Certificates carry no chain identifier. The verifier supplies `chain_id` and the profile `alg_id` when it rebuilds each signed message, so replay is rejected by signature verification, not by trusting a field the sender chose.
- `validator_set_hash` makes the intended validator set explicit and checked without changing any signed message.
- Canonical order is defined as ascending bytewise address; the bitmap makes duplicate or reordered signers inexpressible, and misalignment between bitmap, rounds and signatures fails at decode (count) or verification (signature).
- Serialization and validity are separate stages (§3.5).

## 3. Test and security acceptance matrix

Method (as for #125): tests first with a recorded red run; golden vectors from an **independent** Python oracle written before and separately from the Rust code; mutation testing of the codec and the validity checks, every mutant must fail a test; Linux sandbox run, then Windows confirmation by the owner before any ✅. IDs below are proposed names; the "expected failure" column is the required behaviour.

### 3.1 Serialization (decoder/encoder)

| ID | Test | Expected result |
|---|---|---|
| P-01 | Golden hex vector for payload (empty, one tx, many txs, with/without `prev_state_root`, with evidence) | Bytes equal the oracle's |
| P-02 | Round trip decode→encode for each P-01 vector | Identical bytes |
| P-03 | Encode twice, encode in two processes | Byte-identical |
| P-04 | Truncate each P-01 vector at every offset | `WireError`, never a partial value or panic |
| P-05 | Append one byte to each vector | Rejected (trailing bytes) |
| P-06 | Wrong tag, wrong `payload_version` (0, 2), `option` byte other than 0/1 | Rejected, distinct error per cause |
| P-07 | `txs` count claims more elements than remaining bytes; count `u32::MAX` | Rejected before allocation (allocator-guarded test) |
| P-08 | Encoded length > `max_block_bytes`; tx > `max_tx_bytes` | Rejected |
| P-09 | Same tx id twice (needs U5) | Rejected |
| P-10 | Reordering two transactions | Different bytes, different `H(payload)` |
| P-11 | Evidence: out-of-order, duplicate `evidence_id`, `message_a == message_b`, `message_a > message_b`, 17 items, unknown `kind`, messages with different epoch/round/alg_id | Each rejected |
| P-12 | Evidence message that does not decode under §3.2 or does not re-encode identically | Rejected |
| P-13 | Variable-field split ambiguity (`offender`, tx boundaries) | Different bytes |
| Q-01..Q-06 | As P-01..P-06 for QC (n = 1, 4, 31, max); bitmap pad bit set; `signers` bit count ≠ expected | Golden equal; round trip; truncation/trailing/tag/version rejected; pad bit rejected |
| Q-07 | `count(signatures)` ≠ popcount(bitmap) (fewer and more) | Rejected before allocation |
| Q-08 | Envelope with wrong length (3308, 3310), `alg_id` 0 or unpermitted | Rejected before any crypto |
| Q-09 | Bitmap declared larger than `MAX_CERT_VALIDATORS` | Rejected before allocation |
| T-01..T-08 | As Q for TC; `count(high_qc_rounds)` ≠ popcount; nested QC with its own malformed field; nested QC truncated; nested QC trailing bytes absorbed by outer fields | Each rejected; no length confusion between the nested and outer parser |
| V-01 | `validator_set_hash` golden vector; unsorted or duplicate address or duplicate key | Golden equal; unsorted/duplicate rejected by the builder |
| X-01 | A payload/QC/TC/vote/timeout/block-signing/PoP byte string is never valid as another type | Rejected (tag prefix-freeness test over all pairs) |

### 3.2 Validity (against local state; none of these is a serialization property)

| ID | Test | Expected result |
|---|---|---|
| C-01 | Valid QC (n = 4, 3 signers, real FIPS 204 test keys) | Accepted |
| C-02 | Canonically encoded QC with bad signature bytes, right length | Decodes; **rejected as invalid** (canonical ≠ valid) |
| C-03 | Quorum threshold: signer power exactly `q-1` vs `q`; weighted sets where count ≥ q but power < q; power sum that would overflow `u64` | `q-1` rejected, `q` accepted; weighted case rejected; no wrap-around |
| C-04 | Zero-power validator as signer (U3) | Rejected |
| C-05 | Signer index ≥ `|V_epoch|`, bitmap length ≠ `|V_epoch|` | Rejected |
| C-06 | Duplicate signer (same signature repeated, same key under two bits) | Duplicate key impossible by V-01; repeated envelope with count/bitmap mismatch rejected; two bits sharing one signature fail verification |
| C-07 | Reordered signatures (swap two envelopes) | Rejected (signature does not verify under the other signer's key) |
| C-08 | `validator_set_hash` of another epoch's or another chain's set | Rejected at step 1 even when signatures verify under shared keys |
| C-09 | Validator-set mismatch: QC built for set A verified against set B with one changed power or key | Rejected |
| C-10 | Cross-chain replay: valid QC for chain A verified with chain B's `chain_id` | Rejected (signature fails) |
| C-11 | Cross-epoch replay: QC for epoch e verified as epoch e+1 | Rejected |
| C-12 | Cross-round replay: change `round` or `parent_round` or `block_id` only | Rejected |
| C-13 | Domain substitution: QC signatures made in the timeout, proposal or PoP context; TC signatures made in the vote context | Rejected, one test per ordered pair of contexts |
| C-14 | `alg_id` relabel (envelope or certificate) | Rejected before crypto |
| C-15 | TC: `high_qc.round ≠ max(high_qc_rounds)`; `high_qc` invalid; `high_qc.round ≥ tc.round`; `high_qc_rounds` misaligned with signers | Each rejected |
| C-16 | TC: signer `j` verified with signer `k`'s round | Rejected |
| C-17 | Order of checks: a malformed-alg QC with garbage signatures is rejected at step 1 and performs zero signature verifications (counting verifier) | Pass |
| C-18 | Failed QC/TC changes no safety state, produces no vote, no evidence (§3.5 failure behaviour) | Pass |

### 3.3 Block identifier and substitution (extends §3.2 rules 6–7)

| ID | Test | Expected result |
|---|---|---|
| B-01 | For each of `timestamp_ms`, `prev_state_root` (present/absent/changed), `txs` (add/remove/swap/alter a byte), `evidence` (add/drop/alter), `payload_version`: change only that field | `block_id` changes; old votes/QC do not validate the altered block |
| B-02 | Change one QC signature byte, swap two signers, add a signer, drop a signer | `H(qc)` and `block_id` change |
| B-03 | Add, remove or alter the TC; alter its nested `high_qc` | `block_id` changes |
| B-04 | Keep the old `block_id` and proposer signature with an altered body; and recompute `block_id` keeping the old signature | Both rejected |
| B-05 | The verifier ignores any `block_id` carried on the wire | Pass |

### 3.3a Additions in revision 2 (the revision-1 matrix above is preserved unchanged)

| ID | Test | Expected result |
|---|---|---|
| U1-01 | Two different validator sets (any change of address, key or power) produce different `validator_set_hash`; the same set in a different input order is refused by the builder | Pass |
| U1-02 | Reconfiguration (revocation, rotation, power change) always yields a new epoch number; an epoch-change block that reuses an epoch number is invalid | Pass |
| U1-03 | Certificate for epoch e+1 arriving before the epoch-change block is committed | Unverifiable: not accepted, not counted, no vote, no evidence; accepted after commit |
| U1-04 | QC whose `validator_set_hash` is another epoch's, with signatures valid under keys present in both sets | Rejected at step 1 |
| L-01 | `MAX_CERT_VALIDATORS` exceeded by a declared bitmap; `|V_e| > V_profile` at genesis or at an epoch change | Decode rejected before allocation; startup / block refused |
| L-02 | QC and TC at `QC_max(n)`, `TC_max(n)` accepted; one byte more rejected; formulas match the encoder for n = 1, 4, 31, 1024 | Pass |
| L-03 | Envelope budget: genesis whose `max_block_bytes + QC_max + TC_max + 3315 + 512` exceeds the network message limit | Startup refused |
| L-04 | Adding validators does not change the payload limit; a payload valid at n=4 stays valid at n=31 | Pass |
| L-05 | Version 2 QC bytes under a v1 profile and v1 under a v2 profile; mixed versions in one epoch; version inferred from length | Rejected at the version field before any length-dependent step |
| A-01 | Address with uppercase variant, trailing space, NUL, non-UTF-8, 256 bytes, empty; two spellings of one identity at registration | Rejected / second spelling refused |
| A-02 | Validator order uses bytewise UTF-8 (a vector where locale/case-insensitive order differs) | Bytewise order |
| A-03 | Signature list in descending order, duplicated, or one signature repeated for two bits | Count mismatch at decode or signature failure; never accepted |
| G-01 | `GenesisCert` golden vector; round trip; truncation and trailing bytes | Pass / rejected |
| G-02 | `GenesisCert` bytes in the QC decoder and QC bytes in the genesis decoder | Tag mismatch |
| G-03 | Empty-bitmap, zero-signature QC for the genesis block | Decodes as a QC, rejected: power 0 < q, and `block_id == genesis_block_id` |
| G-04 | `GenesisCert` as parent of a block with height > 1; as nested cert in a TC with a non-zero `high_qc_rounds` entry; as a counted QC anywhere | Rejected |
| G-05 | `GenesisCert` with wrong chain_id, profile, `genesis_hash`, epoch-0 set hash, `alg_id` | Rejected (equality with the locally derived value) |
| G-06 | Vote for a height-1 block with `parent_id` ≠ `genesis_block_id` or `parent_round` ≠ 0 | Rejected |
| G-07 | QC with `round == 0` | Rejected |
| G-08 | `genesis_block_id` collides with no `block_id` input (distinct tags) | Pass |
| TS-01 | Timestamp equal to or below the parent's; height 1 at or below `genesis_time_ms` | Invalid, no vote |
| TS-02 | Validity result identical with the local clock set to 1970, now, and year 2100 | Identical (no clock input) |
| TS-03 | Proposal ahead of the local clock by more than the skew parameter | Vote delayed only; block not marked invalid; accepted on replay/sync regardless of clock; no evidence |
| TC-X1 | Cross-epoch TC: nested QC from epoch e verified against V_e in a TC of epoch e+1 | Accepted when valid |
| TC-X2 | Nested QC with epoch later than the TC's; with an epoch label that does not equal `epoch_of(round)`; with `nested.round ≥ tc.round`; nested epoch commitment not held | Rejected / unverifiable |
| TC-X3 | Nested QC valid under V_{e+1} but labelled epoch e (or the reverse) | Rejected (checked against its own epoch's hash) |
| TC-X4 | TC signer from V_e inside a TC of epoch e+1 | Rejected |
| TM-01 | Timeout signed with `high_qc_round` lower than the signer's persisted `hqr` | Refused by the safety store (existing #127 tests extended) |
| TM-02 | TC maximum taken over unverified or misaligned rounds | Cannot occur: any change breaks a signature (mutation target) |
| PA-01 | Bitmap membership is not used as a reward/penalty input (no code path reads it for that) | Reviewed in the codec PR; absent |
| E-01 | Evidence with signature A invalid; with signature B invalid; both valid | Rejected; rejected; accepted |
| E-02 | Both signatures valid but under two different validators' keys; offender claim naming a third validator; offender not in `V_epoch`; offender key of another epoch | Each rejected |
| E-03 | Kind 2 without preimages; preimage hash ≠ `block_id`; preimages naming different round/epoch/proposer than the item; proposer ≠ offender; offender not the leader of the round | Each rejected |
| E-04 | Wrong context for the kind (vote context on a proposal pair and the reverse) | Rejected |
| E-05 | Block containing one invalid evidence item | The whole block is invalid; nothing is slashed |
| E-06 | Same `evidence_id` already committed; older than `EVIDENCE_MAX_AGE_BLOCKS` | Rejected |

### 3.4 Mutation targets (each mutant must be caught)

Remove or weaken: the tag check; version check; trailing-byte check; re-encode check; count-before-allocation check; pad-bit check; bitmap length equality; signature-count equality; alignment of rounds with signers; envelope length check; evidence ordering check; evidence uniqueness; `validator_set_hash` comparison; chain-id injection (use a constant); `alg_id` injection; context per message type (vote/timeout swapped); power threshold (`>=` to `>`; `q` off by one; `u64` wrap); duplicate-signer handling; each `block_id` input field (spec rule 7); `max(high_qc_rounds)` check; `high_qc.round < tc.round` check. Revision 2 adds: remove each evidence check of §3.5.3 (signature A only, signature B only, same-key check, offender membership, leader check, preimage hash); genesis equality check; `round == 0` and `block_id == genesis_block_id` rejection; nested-epoch label check; nested-epoch ≤ tc.epoch check; use TC epoch's set for the nested QC; timestamp comparison direction; any use of the local clock in deterministic validity; envelope-budget and `V_profile` checks; version-before-length ordering.

### 3.5 Security acceptance criteria

1. All 3.1–3.3 tests pass on Linux and on the owner's Windows machine, with the failing-before run recorded.
2. Every mutant of 3.4 is caught (target 100%); any survivor is disclosed and fixed or justified.
3. Golden vectors come from an independent oracle; the Rust code is not used to produce them.
4. No decoder allocates from an unchecked length; a fuzz/property test with random truncation and bit flips never panics, never returns a value that fails the re-encode check.
5. Independent cryptographic review of §3.2–§3.5 before Phase 0 engine code consumes them (as for §3.1).
6. No change to Tendermint, defaults, or activation; the objects live behind the existing `pq-hotstuff` feature.

## 4. Decisions

Status legend: **Proposed-resolved** = revision 2 contains a concrete rule that I recommend the owner approve; **Open** = needs an owner decision or an upstream specification; **Blocked** = cannot proceed until a named dependency exists. Nothing is decided by this document.

| # | Decision | Status and recommendation |
|---|---|---|
| U1 | Validator-set commitment and reconfiguration | **Proposed-resolved** (§3.4.2): one immutable commitment per epoch, fixed by genesis or by the committed epoch-change block; every set change is a new epoch number; signed messages unchanged. Depends on U17 |
| U2 | Canonical validator order key | **Proposed-resolved** (§3.4.1): bytewise UTF-8 of the address; unique addresses and keys |
| U3 | Zero-power validators | **Proposed-resolved**: occupy an index; may not sign |
| U4 | Limits and budgets | **Proposed-resolved** (§3.4.3): four separate limits; QC v1 formulas; v2 versioned and unspecified. **Open:** the numeric `V_profile` for mainnet (D2/M0), `MAX_CERT_VALIDATORS` (1024 proposed), the network message limit the budget is checked against |
| U5 | Canonical transaction bytes, id, `count(txs)` bound | **Blocked, prerequisite.** Payload codec must not be implemented until a separate approved spec exists (§3.3). QC/TC are independent of it |
| U6 | Genesis certificate | **Proposed-resolved** (§3.4.7): distinct `GenesisCert`, valid by equality only, never a QC, negative tests G-01…G-08. **Open:** U16 |
| U7 | Timestamp | **Proposed-resolved** (§3.5.1): deterministic rule (strictly increasing; height 1 after `genesis_time`) separate from node-local skew admission. **Open:** whether to add a consensus `MAX_TS_STEP_MS` (recommended no) |
| U8 | Timeout signs `high_qc_round` | **Proposed-resolved with proof obligations** (§3.5.6): keep the approved format; PO-1…PO-5 remain for the §5–§6 review |
| U9 | Participation versus rewards | **Proposed-resolved** (§3.4.6): the bitmap is a certificate fact only. **Open:** the reward/liveness rule needs its own specification (related to N10) |
| U10 | Evidence verification | **Proposed-resolved** (§3.3, §3.5.3): both signatures, same offender key, identity in `V_epoch`, leader check for kind 2; kind-2 items carry block-id preimages |
| U11 | Any signer set ≥ q is allowed in a QC | Open. Recommended yes; consequences stated in §3.4.4 and U9 |
| U12 | New tags `CFH1\|payload\|`, `\|qc\|`, `\|tc\|`, `\|valset\|`, and (revision 2) `\|gcert\|`, `\|gblock\|` | Open, recommend approve |
| U13 | Per-object `u16` version | Open, recommend keep |
| U14 | Editorial PR: stale "PROPOSED" headings of spec §7.1/§7.1.1, rule 6 wording on participation, §3 payload comment | Open, needs authorization; recommend a separate small docs PR |
| U15 | Round numbering across epochs (chain-global recommended) | **Open, new.** §3.5.4 depends on it |
| U16 | Genesis hash is SHA-256 over compact JSON; the profile hash is SHA3-256 | **Open, new.** Use as given inside the genesis certificate (proposed) or define a canonical binary genesis commitment |
| U17 | The epoch-change rule of §8 must make the one-commitment invariant true, including which set certifies the commit of the epoch-change block under the two-chain rule | **Open, new proof obligation** for the §5–§8 review |
| U18 | Wire layout of the proposal message as transmitted (header, parent certificate, optional TC, payload, proposer envelope) | **Open, new.** Needed before block codec work; budgets in §3.4.3 assume the listed components |

## 5. Recommended next steps (after owner review; none authorized)

1. The owner reviews revision 2 and answers the Open items (U11–U18 and the numeric parts of U4, U7).
2. A separate docs-only PR specifies the canonical transaction encoding (U5); the payload codec waits for it.
3. A docs-only follow-up fixes the editorial items (U14) and records the approved decisions in spec §15.
4. Tests-first QC/TC/genesis codec PR (independent Python oracle and golden vectors first, then additive Rust types, mutation run, Linux evidence, Windows confirmation). The payload codec is a later PR after U5.
5. Independent review of §3.2–§3.5 together with §5–§8 before any engine consumes the encodings.
