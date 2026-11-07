# PQ-HotStuff-2: BlockPayload and QC/TC serialization — analysis, acceptance matrix, open decisions

**Status:** DRAFT, docs only. Baseline: `main` at `b966ce7ac726cce44be6acef00459fec00f0d5b1`.
**Normative text proposed in:** `docs/pq-hotstuff-001-spec.md` §3.3 (BlockPayload), §3.4 (QC/TC), §3.5 (serialization versus validity).
**Nothing here is implemented, activated or approved.** No Rust, Tendermint, consensus-engine, key-storage, counter or roadmap change accompanies it.

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

### 3.4 Mutation targets (each mutant must be caught)

Remove or weaken: the tag check; version check; trailing-byte check; re-encode check; count-before-allocation check; pad-bit check; bitmap length equality; signature-count equality; alignment of rounds with signers; envelope length check; evidence ordering check; evidence uniqueness; `validator_set_hash` comparison; chain-id injection (use a constant); `alg_id` injection; context per message type (vote/timeout swapped); power threshold (`>=` to `>`; `q` off by one; `u64` wrap); duplicate-signer handling; each `block_id` input field (spec rule 7); `max(high_qc_rounds)` check; `high_qc.round < tc.round` check.

### 3.5 Security acceptance criteria

1. All 3.1–3.3 tests pass on Linux and on the owner's Windows machine, with the failing-before run recorded.
2. Every mutant of 3.4 is caught (target 100%); any survivor is disclosed and fixed or justified.
3. Golden vectors come from an independent oracle; the Rust code is not used to produce them.
4. No decoder allocates from an unchecked length; a fuzz/property test with random truncation and bit flips never panics, never returns a value that fails the re-encode check.
5. Independent cryptographic review of §3.2–§3.5 before Phase 0 engine code consumes them (as for §3.1).
6. No change to Tendermint, defaults, or activation; the objects live behind the existing `pq-hotstuff` feature.

## 4. Unresolved design decisions requiring owner approval

Each item has a recommendation; none is decided.

| # | Decision | Recommendation |
|---|---|---|
| U1 | Bind `validator_set_hash` into the signed vote and timeout messages? Doing so changes merged layouts (#125) and requires a new profile identifier or version. Without it, the set is bound through `chain_id` + `epoch` + the on-chain epoch record | Do not change the signed messages in profile v2; keep the hash in the certificate as a checked field. Revisit only if reconfiguration can produce two different sets with one epoch number |
| U2 | Canonical validator order key | Ascending bytewise UTF-8 of the address; addresses and keys unique |
| U3 | Validators with power 0: occupy an index? may they sign? | All registered validators occupy an index; a zero-power signer makes the certificate invalid |
| U4 | `MAX_CERT_VALIDATORS` and the block budget for QC + TC | 1024 as a decoder ceiling only; real ceiling from D2/M0; confirm devnet `max_block_bytes` (1 MiB) fits one QC + TC at the devnet n (about 30 KB at n = 4) |
| U5 | Canonical bytes and id of a transaction (no canonical binary encoding exists today); bound on `count(txs)` | A separate spec item: define `tx_bytes` and `tx_id = SHA3-256(tx_bytes)` before payload code; until then the payload treats transactions as opaque |
| U6 | Genesis: `prev_state_root` absent at height 1? Representation of the QC certifying the genesis block (a block at height 1 needs a `qc`) | Absent only at height 1; define a genesis QC as a distinguished object accepted only by equality with the genesis-derived value, never by signature |
| U7 | Timestamp validity rules (monotonic? bound against the median of the parent QC? maximum skew) | Validity rule, not serialization: strictly greater than the parent's, and within a genesis-set skew of local time; needs a proposal |
| U8 | The timeout signature signs `high_qc_round`, not the QC; should it sign the QC's `block_id` too? (changes the signed timeout message) | Keep as merged; safe because two valid QCs for one round must certify one block unless more than f validators equivocate; reviewer to confirm in the §5 review |
| U9 | Participation evidence as the parent QC's bitmap only (no duplicate field in the payload), and which participation records derive from it | Bitmap only; edit rule 6's wording accordingly |
| U10 | Evidence item carries full canonical messages (about 7 KiB) vs hashes plus lookup | Full messages (self-verifying, as §9 requires); limit 16 per block |
| U11 | A QC may carry any signer set with power ≥ q (leader's choice), or must be a canonical minimal subset | Allow any set ≥ q; document that different subsets yield different `block_id`s and that double-proposal evidence applies |
| U12 | Approve the new tags `CFH1|payload|`, `CFH1|qc|`, `CFH1|tc|`, `CFH1|valset|` | Approve |
| U13 | Per-object `version` field vs relying on the protocol profile alone | Keep the per-object `u16`; QC v2 (D2) gets its own value |
| U14 | Authorize a separate editorial PR for the stale "PROPOSED" headings of spec §7.1 and §7.1.1 and for rule 6 / §3 wording noted in §1.1 | Yes, as a small docs-only PR after this one |

## 5. Recommended next steps (after owner review; none authorized)

1. Owner reviews this draft and answers U1–U14 (or amends them).
2. A docs-only follow-up fixes the editorial items (U14) and records the decisions in spec §15.
3. Tests-first Phase 0 PR for the codec: independent Python oracle and golden vectors first, then Rust types in `pq_hotstuff/wire` (additions only), then mutation run, Linux evidence, Windows confirmation.
4. Independent review of §3.2–§3.5 together with the §5–§6 safety rules before the engine consumes the encodings.
