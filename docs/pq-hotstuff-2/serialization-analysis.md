# PQ-HotStuff-2: BlockPayload and QC/TC serialization — analysis, acceptance matrix, open decisions

**Status:** DRAFT, docs only. **Revision 3** (final specification revision; revision 2 was head `ba559bb`, revision 1 was `24fa807`). Baseline: `main` at `b966ce7ac726cce44be6acef00459fec00f0d5b1`.
**Normative text proposed in:** `docs/pq-hotstuff-001-spec.md` §3.3 (BlockPayload), §3.4 (certificates, genesis certificate, limits, genesis commitment), §3.5 (serialization versus validity), §3.6 (global rounds and epochs), §3.7 (epoch-change protocol), §3.8 (proof obligations PO-1 to PO-5).
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

## 0a. Revision 3: what changed, and contradictions found

Requested items: U15 → spec §3.6; U17 → §3.7 (rules EC-1 to EC-10; safety **not** established); limits → §3.4.3a; U16 → §3.4.8; U8 → §3.8 (PO-1 to PO-5, all OPEN, no proof claimed); U5 blocker preserved in §3.3. One payload field was added (`epoch_change`, U19). No signed-message layout, wire code, Rust, Cargo, Tendermint, key or roadmap file changed.

**Contradictions and gaps between the proposed rules and the merged text or code** (reported, not fixed):

| # | Finding | Where | Effect |
|---|---|---|---|
| K1 | The merged safety store **resets `hvr`, `hqr` and the stored vote/timeout/proposal when the epoch increases** ("a new epoch starts clean", `store.rs` `sign_core`; it only rejects a *lower* epoch). With chain-global rounds (R1) a validator could sign a lower round in the next epoch | `pq_hotstuff/safety/store.rs` vs §3.6 R1/R4 | Needs a separately authorized store change; recorded as the known conflict of PO-2 |
| K2 | The store has no `sealed` field (EC-6) and its `high_water()` is the pair `(epoch, round)` compared lexicographically | safety record v2 | Future record-format change; atomicity with the vote is required |
| K3 | §4 `leader = sorted(V_e)[(round + seed_e) mod |V_e|]`: the sort key is unspecified, `seed_e` (a block hash) is not reduced to an integer, and the filter is "p(v) > 0" whereas the bitmap index counts all registered validators (§3.4.1) | §4 | Same sort key must be used (bytewise address); define the hash→integer reduction; with `seed_{e+1} = block_id(P)` there is no circularity |
| K4 | §8 says certificates are verified "using the existing `historical_validator_sets`"; in the node that map is keyed by **height** (`BTreeMap<u64, ValidatorSet>`) for the Tendermint engine | §8 vs `node.rs` | PQ-HotStuff-2 needs an epoch-keyed table and the boundary table (R3) |
| K5 | §8/D4: revocation takes effect "in the first block after the one that commits the revocation" (blocks do not commit; certificates do). In EC-7 it takes effect at round `z+1`, after the suffix rounds | §8 vs §3.7 | Same intent; the extra suffix latency needs owner confirmation |
| K6 | §6 commit rule has no notion of epochs; at a boundary `Z` is certified by `V_e` and committed by `QC(X)` of `V_{e+1}` | §6 vs §3.7 | Cross-set commit: unproved (PO-4 point i) |
| K7 | §5 vote rule 1 lists "participation evidence" among payload checks; the payload has none (U9), and the suffix-empty and epoch-change checks are not in §5 | §5 | Wording and rule additions needed (U14) |
| K8 | §5 timeout rule 3 and vote rule 3 are consistent with global rounds; the first timeout of epoch `e+1` has `high_qc_round = z` | §5 | No conflict |
| K9 | §3 `Timeout` carries a full QC, so the timeout message is as large as a QC; no document sizes it | §3 / §10 | Included in §3.4.3a F3 |
| K10 | `compute_genesis_hash` is SHA-256 of re-serialized JSON; the profile hash is SHA3-256; unknown JSON fields are dropped before hashing | `chain-forge-core` | Documented in §3.4.8 (U16); not changed |
| K11 | `check_message_size`/`max_message_bytes` appear unused outside tests; the default (`max_tx_bytes × 2` = 524,288 on devnet) is below `max_block_bytes` (1,048,576) | `chain-forge-p2p` | F1; the repository defines no PQ-HotStuff-2 message limit |
| K12 | §8.1 requires proof of possession for genesis keys; a key introduced by an epoch change needs the same | §8.1 vs EC-2 | EC-2 requires a verified PoP for every key in `next_set` |

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

### 3.3b Additions in revision 3 (earlier matrices preserved)

| ID | Test | Expected result |
|---|---|---|
| R-01 | Boundary table: epochs 0→1→2 as in §3.6 (rounds 1–13, 14–31, 32+) | `epoch_of` matches for every round; rows append-only |
| R-02 | Epoch-1 object with round ≤ `end(0)`; epoch-0 object with round > `end(0)` (row held) | Rejected |
| R-03 | Certificate whose epoch label ≠ `epoch_of(round)` | Rejected |
| R-04 | Safety store: epoch increase with a round lower than the previous floor | Refused (fails against the merged store; documented K1) |
| R-05 | Lagging validator receives epoch-1 object before the proof | Unverifiable: no vote, no timeout, no counting; after proof it acts |
| EA-01 | Conflicting transitions: second epoch-change block inside the suffix; two epoch-change blocks at one round (equivocating leader); two different `next_set` for one epoch; `X` that cites an uncommitted `P'` | Each rejected; at most one `P` reaches a QC (PO-1) |
| EA-02 | Delayed validators: epoch-1 `X` arrives first; proof fetched; restart in the middle | Abstains until verified; resumes with persisted floors and seal |
| EA-03 | Revoked validator signs an epoch-1 vote; signs an epoch-0 vote at round `z+1`; appears in an epoch-1 bitmap | Rejected: key not in `V_1`; epoch-0 object above `end(0)` refused; bitmap index/hash mismatch |
| EA-04 | Rotated validator uses its old key in epoch `e+1` | Rejected (key differs from the committed entry) |
| EA-05 | Competing QCs: `QC(W)` of epoch 0 at round > `z` signed by unsealed and Byzantine signers | Not counted once the row is held; held as unverifiable before |
| EA-06 | Nested QC replaced by another valid QC of the same round (different subset) and by one of a different block | Same round/different subset: valid, `H(tc)` differs; different block: rejected, alarm |
| EA-07 | Epoch label forged to select a convenient set (label 0 on a round-20 QC) | Rejected |
| EA-08 | Round reuse after a transition (any of R-02) and floor reset | Rejected; store refuses |
| EA-09 | Crash between the vote for `Z` and the seal write | Impossible by construction: vote and seal are one atomic record; fault injection at every durability point never yields a vote without `sealed` |
| EA-10 | Suffix block with a transaction, evidence or an `epoch_change` | Not voted for |
| EA-11 | `next_set` altered after `QC(P)` (power, key, order, count) | `block_id` differs; votes do not validate; `X` rejected |
| EA-12 | `V_1` disjoint from `V_0`, and strongly overlapping, and shrinking by more than the quorum floor | Simulation: no conflicting commits within the stated adversary bounds; the floor violation makes `P` invalid (EC-2) |
| EA-13 | `Z` committed by `QC(X)` of `V_1` while a `V_0` branch exists at the same height | No second commit; counterexample search by the model checker |
| EA-14 | TC at the boundary: timeouts for round `z+1` signed by a `V_0` member that is not in `V_1`; TC mixing signers of both epochs | Rejected |
| EA-15 | Fresh syncing node without the boundary table (long-range keys) | Documented unresolved trust assumption (PO-4 point ii); test pins the behaviour |
| NL-01 | QC and TC encoded at `QC_max(n)`, `TC_max(n, n_h)` for n = 1, 4, 31, 1024 and n_h ≠ n | Sizes equal the formulas of §3.4.3 and §3.4.3a |
| NL-02 | Proposal envelope maxima of §3.4.3a F2 | Equal the encoder's output; refused above `M_pq` |
| NL-03 | Configuration with `M_pq < max_block_bytes + certificate allowance` | Startup refused |
| NL-04 | Bitmap size with `n` near `u32::MAX` on a 32-bit build | Decode error, no overflow, no allocation |
| NL-05 | Counts of `u32::MAX` for every list in payload, QC, TC, `EpochChange` | Rejected before any allocation (allocator-guarded) |
| NL-06 | Oversized, malformed, wrong-epoch or sub-quorum-claimed certificates | Rejected with zero signature verifications (counting verifier) |
| NL-07 | Maximum signature verifications for a proposal | At most `n + n + n_h`; a repeated certificate verified once (cache by `H(cert)`) |
| GH-01…10 | Genesis commitment tests of §3.4.8 | As listed there |

### 3.4 Mutation targets (each mutant must be caught)

Remove or weaken: the tag check; version check; trailing-byte check; re-encode check; count-before-allocation check; pad-bit check; bitmap length equality; signature-count equality; alignment of rounds with signers; envelope length check; evidence ordering check; evidence uniqueness; `validator_set_hash` comparison; chain-id injection (use a constant); `alg_id` injection; context per message type (vote/timeout swapped); power threshold (`>=` to `>`; `q` off by one; `u64` wrap); duplicate-signer handling; each `block_id` input field (spec rule 7); `max(high_qc_rounds)` check; `high_qc.round < tc.round` check. Revision 2 adds: remove each evidence check of §3.5.3 (signature A only, signature B only, same-key check, offender membership, leader check, preimage hash); genesis equality check; `round == 0` and `block_id == genesis_block_id` rejection; nested-epoch label check; nested-epoch ≤ tc.epoch check; use TC epoch's set for the nested QC; timestamp comparison direction; any use of the local clock in deterministic validity; envelope-budget and `V_profile` checks; version-before-length ordering. Revision 3 adds: reset floors at an epoch change; omit the seal; accept epoch-`e` objects above `end(e)`; accept `V_{e+1}` before the completing certificate; allow a second epoch change in the suffix; accept a non-empty suffix payload; skip the `epoch == epoch_of(round)` check; use the TC's epoch set for the nested QC; compute sizes in `usize` or without `checked_*`; allocate before the count checks; verify signatures before the claimed-power check; non-strict hex for `genesis_hash`.

### 3.5 Security acceptance criteria

1. All 3.1–3.3 tests pass on Linux and on the owner's Windows machine, with the failing-before run recorded.
2. Every mutant of 3.4 is caught (target 100%); any survivor is disclosed and fixed or justified.
3. Golden vectors come from an independent oracle; the Rust code is not used to produce them.
4. No decoder allocates from an unchecked length; a fuzz/property test with random truncation and bit flips never panics, never returns a value that fails the re-encode check.
5. Independent cryptographic review of §3.2–§3.5 before Phase 0 engine code consumes them (as for §3.1).
6. No change to Tendermint, defaults, or activation; the objects live behind the existing `pq-hotstuff` feature.

## 4. Decisions

Status legend: **Proposed-resolved** = revision 3 contains a concrete rule that I recommend the owner approve; **Open** = needs an owner decision or an upstream specification; **Blocked** = cannot proceed until a named dependency exists; **Unproved** = the rule is proposed but its safety is an open proof obligation. Nothing is decided by this document.

| # | Decision | Status and recommendation |
|---|---|---|
| U1 | Validator-set commitment | **Proposed-resolved** (§3.4.2); authoritative at the completing certificate (EC-4). Depends on U17/PO-4 |
| U2, U3 | Validator order key; zero-power validators | **Proposed-resolved** (§3.4.1) |
| U4 | Limits and budgets | **Proposed-resolved in structure** (§3.4.3, §3.4.3a). **Open with numbers:** `M_pq` (no PQ-HotStuff-2 limit exists in the repository), `V_profile` (D2/M0), `MAX_CERT_VALIDATORS` (1024 proposed). Finding F1: the existing default message limit is below `max_block_bytes` |
| U5 | Canonical transaction bytes, id, count bound | **Blocked, prerequisite.** The payload codec must not be implemented until a separate spec is approved |
| U6 | Genesis certificate | **Proposed-resolved** (§3.4.7) |
| U7 | Timestamp | **Proposed-resolved** (§3.5.1); open: whether to add `MAX_TS_STEP_MS` (recommend no) |
| U8 | Timeout signs `high_qc_round` | **Proposed-resolved with obligations** (§3.5.6, §3.8 PO-1…PO-5, all OPEN) |
| U9 | Participation versus rewards | **Proposed-resolved** (§3.4.6); the reward rule needs its own spec |
| U10 | Evidence verification | **Proposed-resolved** (§3.3, §3.5.3) |
| U11 | Any signer set ≥ q allowed | Open, recommend yes |
| U12 | New tags `CFH1\|payload\|`, `\|qc\|`, `\|tc\|`, `\|valset\|`, `\|gcert\|`, `\|gblock\|` | Open, recommend approve |
| U13 | Per-object `u16` version | Open, recommend keep |
| U14 | Editorial PR: stale §7.1/§7.1.1 headings, §3 payload comment, rule 6 participation wording, §5 rule 1 wording (K7) | Open; needs authorization |
| U15 | Chain-global rounds | **Proposed-resolved** (§3.6 R1–R6). Needs the safety-store change (K1) before any implementation |
| U16 | Genesis commitment compatibility | **Proposed-resolved** (§3.4.8): keep `compute_genesis_hash` as is. Open: canonical binary commitment under a future profile |
| U17 | Epoch-change protocol | **Unproved** (§3.7 EC-1…EC-10, PO-4). The rules are a proposal; sealing, cross-set commit, long-range keys and closing-window liveness are open |
| U18 | Wire layout of the proposal message as transmitted | Open; needed before block codec work |
| U19 | `epoch_change` payload field carrying the full successor set (versus deriving it from transactions, blocked on U5); how recent revocations are reflected given the one-block state lag | **Open, new** |

## 5. Remaining blockers and review obligations

1. **U5** canonical transaction encoding (blocks the payload codec).
2. **PO-1 … PO-5** independent review and, for PO-4, a machine-checked model of the transition; no obligation is discharged.
3. **K1/K2** safety-store changes (global floors, `sealed`) need a separately authorized implementation PR and their own review before the engine can rely on §3.6/§3.7.
4. **`M_pq`** and the numeric validator limits (owner).
5. **U17/U19** the epoch-change content and the closing-window liveness.
6. Editorial items (U14).

## 6. Recommended next steps (after owner review; none authorized)

1. Independent review of revision 3, in particular §3.7 and §3.8.
2. Owner decisions on U4 numbers, U11–U14, U18, U19.
3. A separate docs-only canonical-transaction-encoding specification (U5).
4. A model-checking exercise for the epoch transition (PO-4) before any engine work.
5. Then, with authorization: QC/TC/genesis-certificate codec (tests first, independent oracle, mutation, Linux and Windows evidence); store changes for K1/K2; the payload codec only after U5.
