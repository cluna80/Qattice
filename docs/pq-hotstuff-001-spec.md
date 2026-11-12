# PQ-HOTSTUFF-001 — PQ-HotStuff-2 Consensus: Protocol Specification

Status: **Decisions D1–D5 locked (owner, 2026-10-28). Designation and cryptographic interface adopted (owner, 2026-11-06; §3.1, §15). Revision for review: not yet approved.** Implements the locked direction of 2026-10-28 ("Qattice PQ-HotStuff Consensus Specification"). No code yet. No activation on any network.
Date: 2026-10-28 (revised 2026-11-06)
Designation: **PQ-HotStuff-2** is the official name of this protocol (the first planned HotStuff-based Qattice consensus; not a successor to a shipped "PQ-HotStuff-1"). This file name, the document ID `PQ-HOTSTUFF-001`, the config value `pq-hotstuff` and the module path stay unchanged until a separately reviewed change renames them. In this document "PQ-HotStuff" means PQ-HotStuff-2.
Scope: Qattice mainnet consensus; a selectable Chain Forge `ConsensusEngine`.

This document turns the locked direction into a buildable protocol: message formats, safety rules, commit rule, pacemaker, persistence, reconfiguration, and the acceptance gates each phase must pass. Items marked **[decision]** need an owner choice; each has a recommendation.

---

## 1. Relationship to what exists

| Component | Status | Role here |
|---|---|---|
| Tendermint engine (`tendermint/engine.rs`) | Hardened (#18, gates 1–3), Windows-confirmed | **Stable devnet baseline** until PQ-HotStuff passes every gate in §12. Its patterns (engine-driven actions, persisted sign guard, model-based simulation) are reused. |
| ML-DSA-65 consensus keys (#24) | Windows-confirmed on Tendermint, **on the pre-standard `dilithium3` backend** (K1: 0 of 45 NIST signing vectors matched) | **Not reused for signing.** PQ-HotStuff-2 signs and verifies only through the FIPS 204 signer interface (§3.1, `docs/fips204-migration/PLAN.md` in PR #119). The existing Tendermint devnet is not migrated or modified. Registration/PoP *structure* (PQ-VAL-001/2/3) is reused, with the new PoP context. |
| Legacy `HotStuffEngine` (`lib.rs`) | Devnet-only (gate 2). No engine-driven voting, no persisted lock, `verify_commit` checks no signatures | **Not a base.** PQ-HotStuff is a new module. The legacy engine stays devnet-only and is retired once PQ-HotStuff lands. |
| Equivocation slashing | Committed-evidence slashing landed (gate 4, #26, Windows-confirmed) | Reused; evidence is compared on canonical signed messages, not signature bytes (§9). |
| Succinct committee proof (M0, `docs/succinct-proof-prototype-scope.md` on `docs/validator-sampling-spec`) | Scoped, in progress in another session | Decides the mainnet validator-set ceiling (§10). |

No consensus code is borrowed. The safety rules below follow the published two-chain HotStuff variant (DiemBFT v4 / Jolteon: Gelashvili et al., "Jolteon and Ditto", FC 2022; Diem team, "DiemBFT v4", 2021). They are implemented from the papers, and the arguments are re-checked in review (§12, Phase 3).

**Tendermint scope (owner, 2026-11-07).** The PQ-HotStuff-2 workstream makes **no change** to the Tendermint implementation or to the existing Tendermint devnet, and adds no Tendermint wiring. This statement concerns this workstream only. It does not supersede, authorize or forbid test-only research on Tendermint that is independently approved under PR #119 (for example a test-only signer integration); any such research is governed by that PR and its own approvals, and it must not change this engine's design or schedule.

**Consensus separation: Qattice versus Chain Forge (owner, 2026-11-07).** Chain Forge is the blockchain creation engine and keeps a modular consensus library; Qattice is one blockchain built with it.
- **Qattice** will ultimately replace Tendermint with PQ-HotStuff-2 as its **exclusive production consensus engine**. This is a Qattice-specific configuration and deployment decision.
- **Chain Forge** keeps Tendermint as an independently selectable engine for developers building other blockchains. Removing Tendermint from Qattice's configuration is not a removal from the Chain Forge codebase, and nothing in this workstream removes, disables or modifies Tendermint.
- **Current state:** Tendermint remains Qattice's devnet baseline until PQ-HotStuff-2 passes the gates below. No existing Qattice network is migrated automatically.
- **Conditions for the transition:** PQ-HotStuff-2 must first pass the safety, persistence, four-node devnet, adversarial testing and independent security-review gates of §12. Removing Tendermint from Qattice's configuration then requires a **separate owner approval** after successful testing.
- **Shared APIs stay modular:** the `ConsensusEngine` interface, the engine safety-state type and the genesis schema must stay engine-agnostic and must not be hard-coded to Qattice's choice (§11).

---

## 2. Model and assumptions

- **Validators:** an epoch-fixed set V_e. Each v has voting power p(v) ≥ 0, a registered ML-DSA-65 key, and verified personhood. Power comes from the personhood layer (bounded per human; §8). Total T = Σp.
- **Faults:** Byzantine power f < T/3. **Quorum:** q = ⌊2T/3⌋ + 1 (gate 3 floor: never lower).
- **Network:** partial synchrony. After an unknown GST, messages between honest validators arrive within Δ.
- **Signatures:** FIPS 204 ML-DSA-65 only, selected by the versioned protocol profile and carrying an explicit algorithm identifier (§3.1). A message signed by any other algorithm, or whose identifier does not match the profile, is invalid; there is no fallback, negotiation or retry with another algorithm. The engine refuses to start unless every key in V_e is 1952 bytes and was registered with the profile's algorithm identifier.
- **Safety:** no two honest validators commit different blocks at the same height, under any network schedule.
- **Liveness:** after GST, with an honest leader, a new block commits within a bounded number of rounds.

---

## 3. Data types

Integers in canonical preimages and wire encodings are unsigned and **big-endian (network byte order)**; §3.2 is normative for every byte layout (this replaces the earlier "little-endian" statement; confirmed by the owner, 2026-11-07). Hashes are the chain's `ChainHash` (SHA3-256 at hash width 256). `epoch` and `round` are u64; round numbers never reset within an epoch.

```
Block {
  epoch, round, height,            // height = parent.height + 1
  parent_id,                        // = qc.block_id
  qc: QuorumCert,                   // certifies the parent
  tc: Option<TimeoutCert>,          // present iff round != qc.round + 1
  payload: BlockPayload,            // existing v1 payload: txs, last_commit -> replaced by qc, prev_state_root
  proposer,
  signature,                        // Sig envelope over the block signing message (§3.2); covers block_id
}
block_id = SHA3-256(canonical block_id input of §3.2)   // commits to every consensus-critical field of the proposal (§3.2 rule 6)

Vote      { epoch, round, block_id, parent_id, parent_round, voter, signature }
QuorumCert{ epoch, round, block_id, parent_id, parent_round, signers: Bitmap, signatures: [Sig] }   // v1 format (§10)
Timeout   { epoch, round, high_qc: QuorumCert, voter, signature }    // signs (epoch, round, high_qc.round)
TimeoutCert{ epoch, round, high_qc_rounds: [u64], signers: Bitmap, signatures: [Sig], high_qc: QuorumCert }
```

Every signature is carried in an envelope `Sig { alg_id, bytes }` (§3.1), and the QC/TC `signatures` lists hold such envelopes. Signing bytes are domain-separated, bind the chain and epoch, and **bind `alg_id`**:

| Message | Canonical bytes (the message passed to the signer, with the FIPS 204 context of §3.1) |
|---|---|
| Block | `"CFH1\|block\|" ‖ alg_id ‖ block_id` |
| Vote | `"CFH1\|vote\|" ‖ alg_id ‖ chain_id ‖ epoch ‖ round ‖ block_id ‖ parent_id ‖ parent_round` |
| Timeout | `"CFH1\|timeout\|" ‖ alg_id ‖ chain_id ‖ epoch ‖ round ‖ high_qc_round` |

Tag `CFH1` cannot collide with the Tendermint tags (`CFV|`, `CFP2`), so a signature from one engine is never valid in the other. The `CFH1` tag is **retained** (owner, 2026-11-07); the FIPS 204 context additionally separates it from every pre-standard signature. There is no automatic compatibility with, or fallback to, any earlier tag or algorithm. This table is a summary: the byte layouts in §3.2 are normative.

**QC validity:** every signer is in V_epoch, each counted once. Each signature envelope has the profile's `alg_id` and verifies under §3.1 against the signer's key. Signer power sums to at least q.
**TC validity:** the same, over timeout bytes for the same `(epoch, round)`. `high_qc` is valid, and `high_qc.round == max(high_qc_rounds)`.

### 3.1 Cryptographic profile (owner decisions 3, 4, 5, 2026-11-06)

1. **Backend derived from the versioned protocol profile.** The chain's profile determines which signature algorithm is permitted for each signing domain. The profile is named by a **mandatory, versioned genesis field `cryptography.protocol_profile`**; the devnet profile identifier is `qattice-pq-hotstuff-2-v2`. There is no separate backend switch and no fallback; for this profile exactly one algorithm is permitted. Compatibility with the existing schema (read against `main` at `1eabe37`; each point needs a test in the implementation PR):
   - `GenesisCryptography` has no `deny_unknown_fields`, so a node that predates the field would silently ignore it. Fail-closed comes from `consensus.bft_variant`: `GenesisConfig::bft_variant` rejects any value other than `tendermint`, `hotstuff` or `xrpl`, so an older node refuses a `pq-hotstuff` genesis outright. The new variant is an additive change to that function.
   - The genesis hash is the compact `serde_json` serialisation of the whole struct (`compute_genesis_hash`). The field must therefore be `Option<String>` with `skip_serializing_if = "Option::is_none"` (the technique `commitment_profile` already uses), so every existing genesis file keeps its hash.
   - "Mandatory" is enforced by validation, not by the type: `bft_variant = pq-hotstuff` without the field is refused, and the field present with any other engine is refused (never silently ignored). An unknown value is refused at startup.
   - The profile is consistent with the existing fields or the node refuses to start: it requires `commitment_profile = "qattice-v2"`, `signature_scheme = "pqc-native"` with `pqc_algorithm = "ml-dsa"`, and every validator key 1952 bytes. The existing label `validator_scheme: "ml-dsa-65"` stays for schema compatibility only and is not the source of the backend choice; the profile is.
2. **Explicit algorithm identifiers, rejected on mismatch.** `alg_id` is an **unsigned 16-bit integer encoded big-endian (network byte order), always exactly 2 bytes**. Value `1` is reserved for FIPS 204 ML-DSA-65; value `0` is reserved and always invalid; any value the profile does not permit is invalid. `alg_id` appears in every validator key registration (including PoP) and in every signature envelope, and is bound into the signed bytes of every message (§3.2). A registration, vote, proposal, timeout, QC entry or TC entry whose `alg_id` is not the one the profile permits for that domain is invalid. Verification never retries with another algorithm, and nothing is negotiated.
3. **One signer implementation.** The engine consumes the FIPS 204 signer interface planned in PR #119 (`MlDsa65Fips204Scheme`, pure ML-DSA-65 over `fips204`, explicit context, hedged). It adds no cryptographic implementation of its own and never calls the pre-standard `MlDsaScheme` / `dilithium3` code.
4. **Hedged signing.** Each signature uses fresh randomness (as signing v2). Two signatures over the same vote therefore differ; §5 and §9 are written so that this never matters.
5. **Contexts (domain separation):**

| Domain | FIPS 204 context | Status |
|---|---|---|
| Vote | `qattice/vote/v2` | approved |
| Block proposal | `qattice/proposal/v2` | approved |
| Validator proof of possession | `qattice/validator-pop/v2` | approved |
| Timeout | `qattice/timeout/v2` | approved (owner, 2026-11-07) |

A signature produced for one domain must fail verification in every other domain (a required negative test). Contexts are at most 255 bytes.

### 3.2 Canonical message serialization (normative)

Every signed or hashed preimage has exactly one valid byte string. Decoders reject everything else, and decode followed by encode is the identity.

**Primitive encodings** (no separators; fields are concatenated in the order shown):

| Type | Encoding |
|---|---|
| `u16`, `u32`, `u64` | unsigned, big-endian, fixed width (2, 4, 8 bytes) |
| `bytes32` | exactly 32 bytes (the profile fixes hash width at 256; any other width is refused) |
| `string` | UTF-8, `u32` byte length, then the bytes; no NUL bytes; at most 255 bytes for `chain_id` and addresses |
| `bytes` | `u32` length, then the bytes |
| `tag` | constant ASCII, **no** length prefix; the tags below are prefix-free (none is a prefix of another) |
| `option<T>` | one byte `0x00` (absent, nothing follows) or `0x01` followed by `T`; any other first byte is invalid |
| `list<T>` | `u32` count, then the elements in canonical order (signers by validator index, ascending; duplicates invalid) |
| `bitmap` | `u32` bit count, then `⌈n/8⌉` bytes, most significant bit first; unused trailing bits must be zero |

**Layouts:**

| Item | Fields, in order |
|---|---|
| Vote message | tag `CFH1\|vote\|` · `alg_id` u16 · `chain_id` string · `epoch` u64 · `round` u64 · `block_id` bytes32 · `parent_id` bytes32 · `parent_round` u64 |
| Timeout message | tag `CFH1\|timeout\|` · `alg_id` u16 · `chain_id` string · `epoch` u64 · `round` u64 · `high_qc_round` u64 |
| Block signing message | tag `CFH1\|block\|` · `alg_id` u16 · `block_id` bytes32 |
| `block_id` hash input | tag `CFH1\|blockid\|` · `alg_id` u16 · `protocol_profile` string · `chain_id` string · `epoch` u64 · `round` u64 · `height` u64 · `parent_id` bytes32 · `H(payload)` bytes32 · `H(qc)` bytes32 · `tc` option<bytes32> · `proposer` string |
| Proof-of-possession message | tag `CFH1\|pop\|` · `alg_id` u16 · `chain_id` string · `address` string · `public_key` bytes |
| Signature envelope | `alg_id` u16 · `signature` bytes |
| Key registration | `alg_id` u16 · `public_key` bytes |

For `alg_id = 1` the public key length must be exactly 1952 and the signature length exactly 3309. Length limits are checked before any allocation, and trailing bytes after a complete item are an error.

**Rules:**
1. **Context is separate from the message.** The FIPS 204 context (§3.1) is passed to the signer as its context argument and is never concatenated into the message; a signature must verify under both the message and the context.
2. **Binding.** `alg_id` is inside every signed message above, so a signature cannot be re-labelled as another algorithm. A mismatched or unknown `alg_id` is rejected before any cryptographic operation.
3. **Equality and deduplication** of signed votes use the canonical message bytes (or their SHA3-256 hash), never the signature bytes (§9).
4. **Tags approved** (owner, 2026-11-07): `CFH1|blockid|` and `CFH1|pop|` join the retained `CFH1` family. **Clarification of the earlier draft.** The `block_id` hash input previously reused the `CFH1|block|` tag that the block signing message also uses. This revision gives it its own tag, `CFH1|blockid|`, so the hash input and the signed message can never coincide. The `CFH1` family is retained.
5. **Required tests (serialization):** a golden hex vector for every layout above; round-trip for each; mutating any single field changes the bytes; two messages that differ only in how a variable field is split (for example `chain_id` `"ab"` against `"a"` followed by a shifted field) produce different bytes; trailing bytes, an `option` byte other than 0 or 1, a bitmap with a non-zero pad bit, a non-ascending signer list and `alg_id` 0 or an unpermitted value are all rejected; a message of one type is never valid as another; and mutation tests that weaken each of these checks must fail a test.
6. **The block identifier commits to every consensus-critical proposal field.** A field is consensus-critical if changing it could change what any honest node accepts, votes for, executes or commits. `block_id` is the SHA3-256 of the canonical input above, so each such field is either a direct input or is committed through a hash that is a direct input:
   - **direct:** `protocol_profile`, `alg_id`, `chain_id`, `epoch`, `round`, `height`, `parent_id`, `proposer`, and the presence and content of `tc`;
   - **through `H(payload)`:** the complete canonical encoding of `BlockPayload`: the transactions (set and order), the state root the block commits to, participation evidence, committed equivocation evidence, the block timestamp, and every other payload field, including any added later. The exact payload byte layout must be added to this section before Phase 0 code is written; a payload field that is not part of that encoding is a specification defect;
   - **through `H(qc)`:** the complete canonical encoding of the QC, including its signer bitmap and every signature envelope, so signatures cannot be swapped after the block is formed.

   Only data that is not consensus-critical is outside the commitment: the proposer's own block signature (it signs `block_id`), local receive time and gossip metadata. A verifier **recomputes** `block_id` from the received fields and never trusts an identifier carried on the wire. Votes, timeouts and QCs bind to `block_id`, so a substituted field in a proposal invalidates every vote that was cast for the original.
7. **Required tests (field substitution), all negative:** for each field in the list above, taking an otherwise valid proposal and changing only that field (while keeping the original `block_id` and the original proposer signature, and separately recomputing `block_id` and keeping the old signature) is rejected, and a vote or QC for the original block never validates for the altered one. This includes: swapping or reordering transactions, altering the state root, dropping or altering evidence, changing the timestamp, replacing the QC's signatures or bitmap, adding, removing or altering `tc`, changing `proposer`, `height`, `round`, `epoch`, `chain_id` or `protocol_profile`, and replaying the block under a different profile. Mutation tests that remove each field from the `block_id` input must fail at least one of these tests.


### 3.3 BlockPayload serialization (PROPOSED, owner review pending; revision 3)

**Status.** Proposed on 2026-11-07 as a docs-only draft and revised after an independent review. It fills the gap named in §3.2 rule 6 ("the exact payload byte layout must be added to this section before Phase 0 code is written"). It is not a decision until the owner approves it, and it changes no existing normative layout or approved signing-message format. The companion document `docs/pq-hotstuff-2/serialization-analysis.md` holds the compatibility analysis, the acceptance matrix and the open decisions (**U1…U19**).

**Blocked dependency (U5).** The payload carries transactions as opaque canonical bytes, and **no canonical transaction encoding exists** in the repository (`Transaction` is a serde struct with a `String` id). Until a separate, owner-approved specification defines the canonical transaction bytes, the transaction id, and the bound on `count(txs)`, **the payload codec must not be implemented** and §3.3 is a layout proposal only. Nothing in this section defines or implies the internal format of a transaction. The QC/TC objects of §3.4 do not depend on it.

**Relation to the code.** The `BlockPayload` in `chain-forge-node` (`node.rs`) is the legacy Tendermint-era JSON envelope carried in `BlockProposal::tx_data`. It is not canonical, and PQ-HotStuff-2 does not reuse it. The type below is a separate encoding selected by the protocol profile; the legacy type is untouched.

**Layout** (new tag `CFH1|payload|`, prefix-free with the existing tags):

| Field | Type | Rule |
|---|---|---|
| tag | `CFH1\|payload\|` | constant |
| `payload_version` | `u16` | exactly `1`; any other value is refused (no negotiation) |
| `timestamp_ms` | `u64` | proposer-chosen milliseconds since the Unix epoch; validity rules in §3.5.1 |
| `prev_state_root` | `option<bytes32>` | the state root after committing `height - 1`; absent only when `height == 1` (U6) |
| `epoch_change` | `option<EpochChange>` | present only in an epoch-change block (§3.7); a branch has at most one uncommitted (U19) |
| `txs` | `list<bytes>` | execution order, **not sorted** (order is semantic); each element is one transaction's canonical bytes (blocked on U5) |
| `evidence` | `list<EvidenceItem>` | committed equivocation evidence (§9), canonical order below |

**EpochChange** (canonical): `next_epoch` u64 · `next_set` `list<entry>` with `entry = address string · public_key bytes · voting_power u64` in canonical validator order (§3.4.1); keys have the exact profile length; addresses and keys are unique. `validator_set_hash(next_epoch)` (§3.4.2) is computed from this list. A *canonically empty payload* has `epoch_change = None`, `txs = []`, `evidence = []`; suffix blocks of an epoch-change block must have one (§3.7 EC-3). The field is new in revision 3 (decision U19); the alternative, deriving the set change from transactions, is blocked on U5.

`H(payload)` in the `block_id` input is `SHA3-256` of the complete canonical encoding above, tag included. There is no separate transaction root: `txs` are inside the hashed encoding, so the set, the order and every byte are committed (§3.2 rule 6).

**Not in the payload.** `epoch`, `round`, `height`, `parent_id`, `chain_id`, `protocol_profile`, `proposer` and the parent certificate and `tc` are direct inputs to `block_id` (§3.2) and are not repeated here, so they cannot disagree. There is no `last_commit`: the block's parent certificate certifies the parent, and its signer bitmap is a *certificate-signing* fact (§3.4.6), not a reward statement. Execution results are not in the block that executes them; the new state root is committed by the next block's `prev_state_root`.

**EvidenceItem** (canonical, self-contained; `kind` 1 and 2 are the two types of §9):

| Field | Type | Rule |
|---|---|---|
| `kind` | `u8` | `1` double vote, `2` double proposal; other values refused |
| `offender` | `string` | the validator address (§3.4.1), at most 255 bytes |
| `epoch`, `round` | `u64`, `u64` | the position both messages claim |
| `message_a`, `message_b` | `bytes`, `bytes` | the two canonical signed messages of §3.2: vote messages (kind 1) or block signing messages (kind 2) |
| `preimage_a`, `preimage_b` | `option<bytes>`, `option<bytes>` | present **iff** `kind == 2`: the canonical `CFH1\|blockid\|` input whose SHA3-256 equals the `block_id` in the corresponding block signing message |
| `envelope_a`, `envelope_b` | signature envelope ×2 | one per message |

Why the preimages: the block signing message contains only `alg_id` and `block_id` (§3.2), so it states neither round, epoch nor proposer. A double-proposal item is meaningful only together with the `block_id` input that shows both blocks were proposed by the offender for the same `(epoch, round)`. A vote message states epoch, round and block but **not the voter**; the voter is established only by which registered key verifies the envelope (§3.5.3).

Canonical rules (serialization only): `message_a` is strictly smaller than `message_b` bytewise, so equal messages (not evidence, §9) and swapped pairs are both non-canonical; both messages decode under §3.2 and re-encode identically; `evidence_id = SHA3-256` of the canonical `(kind, offender, epoch, round, message_a, message_b)`; items appear in ascending `evidence_id` order, each at most once. Whether the signatures verify, whether the offender is in `V_epoch`, and the age limit are **validity** (§3.5.3).

**Limits** (checked before allocation):
- encoded payload length ≤ `limits.max_block_bytes` (devnet 1,048,576). This limit is for the payload only; certificates have their own budget (§3.4.3);
- each `txs` element ≤ `limits.max_tx_bytes`; the bound on `count(txs)` comes from U5, and until then a decoder must not preallocate from the count;
- `|next_set| ≤ V_profile` (§3.4.3), so `EpochChange` is at most `12 + V_profile · 2,223` bytes (8-byte epoch and 4-byte count, then per entry a 255-byte address, 1,952-byte key, 8-byte power and two 4-byte length prefixes) and is inside `max_block_bytes`;
- `count(evidence) ≤ 16` (`MAX_EVIDENCE_PER_BLOCK`, gate 4); each item ≤ 16 KiB (two vote messages, two 3315-byte envelopes and, for kind 2, two block-id inputs fit well below this);
- `string` limits as in §3.2.

**Strict decoding.** Exactly one payload from the bytes, in this order: length against the limit; tag; `payload_version`; each field in order with every `list` count checked against the remaining bytes before any allocation; `option` byte 0 or 1; evidence order and uniqueness; **no trailing bytes**; then re-encode and require identical bytes. A duplicate transaction id, non-canonical evidence order, repeated `evidence_id`, unknown version or tag, or truncation is an error. A decoder never returns a partial result.

### 3.4 Certificate serialization (PROPOSED, owner review pending; revision 3)

**Status.** Proposed, as §3.3. The data types of §3 gain fields (`version`, `alg_id`, `validator_set_hash`), a defined signer order and a genesis certificate. The **signed message layouts of §3.2 (vote, timeout, block signing, PoP) are not changed** by this section.

#### 3.4.1 Validator address and signer order

- **Address representation.** A validator address is the registered `ValidatorId` string **byte for byte** as it appears in the chain's validator registry and genesis (for the devnet, strings such as `qcb1alice` under `address_prefix` `qcb`). Canonical form: valid UTF-8, 1 to 255 bytes, no NUL, **no case folding, no Unicode normalization, no trimming, no alternative spellings**. The registry refuses at registration any string that is not already in the chain's one canonical address form, so two spellings of one identity cannot coexist. In every certificate, evidence item and hash input the address is encoded as the `string` primitive. Address validation beyond this (prefix, checksum, length) is the account-address rule of the chain, not of this specification.
- **Canonical validator order.** The registered validators of `V_e` sorted by ascending **bytewise comparison of the address's UTF-8 bytes** (not locale or collation order). Addresses are unique, and public keys are unique, within one `V_e`.
- **Index.** A validator's index is its position in that order. Every registered validator occupies an index, including one with power 0, so the bitmap length is `|V_e|` and fixed within the epoch (U3).
- **Signer order in a certificate.** Signers are identified only by set bits of the `signers` bitmap; the signature list (and in a TC the `high_qc_rounds` list) is in **ascending index order**, element `j` belonging to the `j`-th set bit. No other order is expressible. A reordered or duplicated signature list is therefore not a different canonical encoding but a *misaligned* certificate: it fails the count check at decode when the counts differ, and otherwise fails signature verification (§3.5.2).

#### 3.4.2 Validator-set commitment (U1)

**Invariant: each epoch has exactly one immutable validator-set commitment.** For epoch `e`, `validator_set_hash(e)` = `SHA3-256( tag "CFH1|valset|" · version u16 (=1) · alg_id u16 · epoch u64 · list<entry> )`, `entry = address string · public_key bytes · voting_power u64`, in canonical validator order. It is computed by each node from its own committed copy of `V_e` and is never taken from a peer.

- **When it is fixed.** The commitment for epoch 0 is fixed by genesis. The commitment for epoch `e+1` is declared by the `next_set` of the epoch-change block `P` (hash-committed into every certificate of `P`) and becomes **authoritative** only when the commit of `P` is established by the completing certificate (§3.7 EC-4), and by no other event. Once fixed it never changes: there is no in-place edit of `V_e`.
- **Reconfiguration never reuses an epoch number.** Every change that alters any `(address, public key, voting power)` entry, including a revocation (the "mini-epoch" of §8), a key rotation and a power change, produces a new epoch number `e+1`, with its own commitment, through a committed epoch-change block. The map `epoch → commitment` is therefore a function, not a relation. Two nodes that hold the same committed chain hold the same commitment for every epoch.
- **No ambiguous membership.** A certificate names its epoch and its `validator_set_hash`; the verifier checks that hash against its own commitment for that epoch (step 1 of §3.5.2). A certificate whose hash differs is refused even when its signatures verify. A node that has not yet established the commit of the epoch-change block that fixes `e+1` (§3.7 EC-4) **cannot verify** any epoch-`e+1` object: it treats it as *unverifiable* (held or dropped, never accepted, never counted, never evidence) until it holds the commitment.
- **Why the signed messages need not carry the hash.** Because the epoch determines the commitment, and the signed vote and timeout messages already bind `chain_id` and `epoch`, binding the hash would add no information while changing the approved layouts. U1 is therefore proposed as *resolved by this invariant*, not by a layout change. The invariant is made concrete by the epoch-change protocol of §3.7 (EC-1 to EC-10) and depends on proof obligation PO-4 (§3.8), which is open.

#### 3.4.3 Limits and budgets (U4)

Four separate limits, never merged into one number:

| Limit | Meaning | Value / source |
|---|---|---|
| **Decoder validator ceiling** `MAX_CERT_VALIDATORS` | the largest bitmap a decoder will parse before it knows the epoch | 1024 (decoder protection only) |
| **Profile validator limit** `V_profile` | the largest `|V_e|` the chain's profile permits | QC v1: devnet/testnet n ≤ ~31 (§10); the mainnet ceiling is decision D2 after M0. Startup refuses a genesis, and an epoch-change block, that would give `|V_e| > V_profile` |
| **Certificate byte limits** (QC v1) | maximum encoded size of one certificate, from `n = |V_e|` | `QC_max(n) = 140 + ⌈n/8⌉ + 3315·n`; `TC_max(n) = 72 + ⌈n/8⌉ + 3323·n + QC_max(n_h)` where `n_h` is the validator count of the nested QC's epoch. Checked before parsing the lists |
| **Block-envelope budget** | maximum size of a proposal as transmitted | `max_block_bytes` (payload only, unchanged meaning) `+ QC_max + TC_max + 3315` (proposer envelope) `+ 512` (fixed header allowance), which must not exceed the PQ-HotStuff-2 message limit `M_pq`, which the repository does **not** define (§3.4.3a); startup refuses a configuration for which it does |

Worked maxima (all signers present, `k = n`; `TC` includes its nested QC of the same `n`; `QC+TC` is a block carrying both): n = 4: QC 13,401, TC 26,766, QC+TC 40,167; n = 31: QC 102,909, TC 205,998, QC+TC 308,907; n = 100: QC 331,653, TC 664,038, QC+TC 995,691; n = 1024: QC 3,394,828, TC 6,797,780, QC+TC 10,192,608. Certificates are charged to the envelope budget, not to the payload. The quorum-sized typical sizes (k = q) are in the table of §3.4.5. Certificates are **not** charged against `max_block_bytes`, so adding validators never reduces the room for transactions and never retroactively invalidates a payload; conversely a growing `n` can exceed the network message limit, which is why the envelope budget is checked against it at genesis and at every epoch change.

**QC v1 versus QC v2.** The `version` field selects layout *and* byte limit. v1 is the signature list (this section). A future v2 (succinct proof or committee, D2/M0) gets `version = 2`, its own layout and its own size bound that does not scale as `3315·n` (the M0 target is ≤ 100 KiB at C = 512). A profile permits exactly one QC version per epoch; a v1 decoder refuses `version = 2` immediately after reading the version, before any length-dependent step, and vice versa; versions are never mixed within an epoch, never negotiated, and never inferred from size. The bitmap, `validator_set_hash` and `epoch` semantics of §3.4.2 carry into v2, but v2 is **not specified here** and needs its own review.

#### 3.4.3a Reconciliation with the repository's network limits (revision 3)

**What the repository defines (read, not invented).**
- Genesis `limits.max_block_bytes` (devnet 1,048,576) and `limits.max_tx_bytes` (devnet 262,144); validation requires `max_tx_bytes ≤ max_block_bytes`.
- `chain-forge-p2p::NetworkConfig.max_message_bytes`, built as `max_tx_bytes × 2` (devnet **524,288**), documented "checked before broadcasting" through `check_message_size`. In the sources I searched (p2p and node), `check_message_size` has no caller outside its own tests, and the node never reads `max_message_bytes`; so I could not confirm that this limit is applied to consensus messages.
- The real libp2p gossip service sets `max_transmit_size` to a fixed **16 MiB**.
- The safety store accepts a signed message of at most `MAX_MESSAGE_LEN = 4096` bytes (a vote or timeout message is far below this).
- **Missing:** the repository defines **no PQ-HotStuff-2 message-size limit**, no limit for a proposal envelope, a timeout message (which carries a QC, §3) or a TC broadcast, and no `V_profile`. This document does not invent one; it states the constraint a limit must satisfy and the check to run (below). The value is an owner decision (U4).

**Findings.**
- **F1.** At devnet values the existing default `max_message_bytes` (524,288) is smaller than `max_block_bytes` (1,048,576), so a maximum-size payload alone would not pass that guard. The legacy code already documents the effect (`select_block_txs`: a proposal that outgrows the gossip limit is never received).
- **F2.** A PQ-HotStuff-2 proposal adds certificates and a proposer envelope to the payload. Complete maxima (payload at `max_block_bytes`, QC and TC with all signers, a nested QC of the same `n`, proposer envelope 3,315, header allowance 512; computed from the §3.4.4/§3.4.5 layouts):

| n | QC_max | TC_max (with nested QC) | proposal envelope maximum | above 524,288? | above 16 MiB? |
|---|---|---|---|---|---|
| 4 | 13,401 | 26,766 | 1,092,570 | yes | no |
| 31 | 102,909 | 205,998 | 1,361,310 | yes | no |
| 100 | 331,653 | 664,038 | 2,048,094 | yes | no |
| 1024 | 3,394,828 | 6,797,780 | 11,245,011 | yes | no |

- **F3 (other messages).** A timeout message carries a full QC (§3), so it is at most `QC_max(n) + 3,315 + fixed fields`; a broadcast TC is at most `TC_max(n)`. A vote is under 4 KiB.
- **F4 (cross-epoch).** A TC's nested QC may belong to an earlier epoch with its own `n_h` (§3.5.4), so the bound for a TC is `72 + ⌈n/8⌉ + 3,323·n + QC_max(n_h)` with `n_h ≤ V_profile`; the table above assumes `n_h = n`, and the bound for any epoch pair uses the larger of the two sizes. An epoch-change block adds `EpochChange` up to `12 + V_profile · 2,223` bytes to the payload (inside `max_block_bytes`).

**Constraint on the future limit `M_pq`** (to be set by the owner, not by this document): `M_pq ≥ max_block_bytes + QC_max(V_profile) + TC_max(V_profile, V_profile) + 3,315 + 512` for the proposal, and `M_pq ≤` the transport cap. Startup and every epoch-change block must be refused if this fails. If the owner prefers a smaller `M_pq`, the effective payload limit becomes `M_pq − (certificate allowance)` and `max_block_bytes` must be lowered accordingly; the two must never be configured independently. The cap on `n` that fits is a consequence of `M_pq`, not an input.

**Overflow-safe size arithmetic.** All size computations use `u64` with checked operations (never `usize`, whose width differs by platform; the merged bitmap decoder computes `(n + 7) / 8` in `usize`, which can overflow on a 32-bit target): `bitmap_bytes(n) = n/8 + (n % 8 != 0)`; a list of `c` fixed-size elements needs `c.checked_mul(size)`; every sum of lengths uses `checked_add`; a failed check is a decode error. Power sums and thresholds use `u128`. With `n ≤ MAX_CERT_VALIDATORS = 1024` all certificate sizes stay below 2^23, so overflow is excluded by the bounds as well as by the checks.

**Decoder allocation bounds.** The input slice length is first compared with the message limit and with the maximum for the object type (and for the `version`). Every `u32` count is then checked against (a) its semantic bound (bit count equals `|V_epoch|` or is `≤ MAX_CERT_VALIDATORS` before the epoch is known; signature count equals the popcount; `count(evidence) ≤ 16`; `count(next_set) ≤ V_profile`), and (b) the remaining input (`count × min_element_size ≤ remaining`). No `Vec::with_capacity`, `reserve` or `vec![_; n]` is called before both checks pass; the allocation never exceeds the remaining input length.

**Order of rejection before expensive cryptography.** Cheapest first, all before the first signature verification: (1) transport and object length limits; (2) tag, `version`, `alg_id`; (3) structural counts and bitmap padding; (4) trailing bytes and re-encode equality; (5) epoch known, boundary-row label check, `validator_set_hash` equality, `round` and `block_id` rules (§3.5.2 step 1); (6) signer powers and the quorum arithmetic on the *claimed* signers (a certificate whose claimed signers cannot reach `q` is refused without any signature check); (7) only then signature verification, in ascending signer order, stopping at the first failure. Worst-case signature verifications: a QC at most `n`, a TC at most `n + n_h` (its signatures plus its nested QC), a proposal at most `n + n + n_h`, all bounded by `V_profile`. A verified certificate is cached by its `H(cert)` so that it is verified once per node.

#### 3.4.4 QuorumCert v1 (tag `CFH1|qc|`)

| Field | Type | Rule |
|---|---|---|
| tag | `CFH1\|qc\|` | constant |
| `version` | `u16` | exactly `1` |
| `alg_id` | `u16` | the profile's algorithm (1); mismatch refused before any crypto |
| `epoch`, `round` | `u64`, `u64` | `round ≥ 1` (round 0 is reserved for the genesis certificate, §3.4.7) |
| `block_id`, `parent_id` | `bytes32`, `bytes32` | |
| `parent_round` | `u64` | |
| `validator_set_hash` | `bytes32` | equals the verifier's `validator_set_hash(epoch)` |
| `signers` | `bitmap` | bit count exactly `|V_epoch|`; bit `i` set ⇔ validator index `i` signed |
| `signatures` | `list<signature envelope>` | count = number of set bits, ascending index order |

The fields `epoch … parent_round` are those of the §3.2 vote message, so the verifier **reconstructs** each signer's vote message from the QC fields, its own `chain_id` and the profile `alg_id`, and verifies each envelope with context `qattice/vote/v2`. The certificate has no `chain_id` field: a sender-supplied chain id would be an unauthenticated claim, whereas the local chain id is inside every reconstructed message, so a QC from another chain fails verification (§3.5.2). `H(qc)` is `SHA3-256` of the full canonical encoding, tag included; it commits to the bitmap and every envelope (§3.2 rule 6). Because signing is hedged, two QCs for one block built from different signers or signatures have different `H(qc)` and so yield different `block_id`s; that is intended, and a leader that signs two such blocks in one round has double-proposed (§9).

#### 3.4.5 TimeoutCert v1 (tag `CFH1|tc|`)

| Field | Type | Rule |
|---|---|---|
| tag | `CFH1\|tc\|` | constant |
| `version`, `alg_id` | `u16`, `u16` | as for the QC |
| `epoch`, `round` | `u64`, `u64` | `epoch` is the epoch of `round` (§3.5.4); `round ≥ 1` |
| `validator_set_hash` | `bytes32` | `validator_set_hash(epoch)` |
| `signers` | `bitmap` | as for the QC |
| `high_qc_rounds` | `list<u64>` | count = set bits, ascending index order: entry `j` is the `high_qc_round` signer `j` signed |
| `signatures` | `list<signature envelope>` | aligned the same way |
| `high_qc` | a *certificate*: `QuorumCert v1` or `GenesisCert` | the full canonical encoding, nested; the nested object's own tag identifies which one (the tags are prefix-free). A `GenesisCert` is allowed only when every `high_qc_rounds` entry is 0 |

The verifier reconstructs signer `j`'s timeout message (§3.2: `alg_id · chain_id · epoch · round · high_qc_round`, local `chain_id`) from `high_qc_rounds[j]` and verifies with context `qattice/timeout/v2`. `H(tc)` is `SHA3-256` of the full canonical encoding, so it commits to the nested certificate.

Quorum-sized sizes (k = q signers; QC and TC with a nested QC of the same n): n = 4: 10,086 / 20,128; n = 7: 16,716 / 33,404; n = 16: 36,607 / 73,234; n = 31: 69,759 / 139,618; n = 100: 222,258 / 444,984.

The **signature envelope** is the existing `{ alg_id u16 · signature bytes }` of §3.2; for `alg_id = 1` its length is exactly 3309, so each envelope is 3315 bytes, and any other length is refused at decode.

#### 3.4.6 Certificate-signing participation versus reward-eligible duties (U9)

The `signers` bitmap of a QC records **which signatures the proposer chose to include** (any set of signatures with total power ≥ q, U11). It is a *certificate-signing* fact: "validator `i`'s vote on block `B` is among the signatures that certify `B`". It is **not**:
- proof that a validator voted (an honest vote the proposer did not include, or received too late, is absent), nor proof that it did not;
- a statement that the validator performed any other duty.

*Reward-eligible validator duties* (proposing when leader, timely voting, availability, liveness windows, anything feeding rewards, penalties or `LivenessWindow`) are a separate matter. They are **not defined by this document** and are not derived from the bitmap alone. Using bitmap membership for rewards or penalties would let a leader influence another validator's income by omitting its signature, and would penalize a validator for network delay. Any such rule requires its own specification stating the evidence it uses, which party can influence it, and a bound on that influence; until then the bitmap is used only for certificate verification. The payload therefore has no participation field.

#### 3.4.7 Genesis certificate (U6)

The first block (height 1) must name a parent certificate, but nothing has been voted on yet. The **genesis certificate** is a distinct object, never a QC:

`GenesisCert` (tag `CFH1|gcert|`) · `version` u16 (=1) · `alg_id` u16 · `protocol_profile` string · `chain_id` string · `genesis_hash` bytes32 · `validator_set_hash` bytes32 (epoch 0)

`genesis_hash` is the chain's genesis hash (`compute_genesis_hash`) decoded from its 64 lowercase hex characters to 32 bytes. (Today it is SHA-256 over the compact `serde_json` form of the re-serialized struct; this document uses it as given and does not change it; the exact behaviour, assumptions and tests are in §3.4.8, U16.) The genesis block identifier is `genesis_block_id = SHA3-256( tag "CFH1|gblock|" · alg_id u16 · protocol_profile string · chain_id string · genesis_hash bytes32 )`. The tags `CFH1|gcert|` and `CFH1|gblock|` are prefix-free with every other tag and distinct from `CFH1|qc|` and `CFH1|block|`.

Semantics:
- `H(qc)` in the `block_id` input of a height-1 block is `SHA3-256` of the canonical `GenesisCert`. Its parent is `genesis_block_id`, round 0; a vote for a height-1 block has `parent_id = genesis_block_id` and `parent_round = 0`.
- A `GenesisCert` is **valid only by equality**: every field must equal the value the verifier derives from its own genesis. It carries no signature, contributes no power and is never counted toward any quorum.
- It is acceptable only (a) as the parent certificate of a block with `height == 1`, and (b) as the nested certificate of a TC whose `high_qc_rounds` are all 0. Everywhere else a `QuorumCert` is required and a `GenesisCert` is refused.
- A `QuorumCert` is invalid if `round == 0` or `block_id == genesis_block_id`: the genesis block is certified by derivation only, so no signature set can "certify" it.
- Domain separation: the decoder selects the object by tag; `GenesisCert` bytes fed to the QC decoder, and QC bytes fed to the genesis decoder, fail at the tag. A QC-shaped encoding with an empty bitmap and zero signatures decodes only as a QC and then fails the quorum check (power 0 < q); it is never converted into a genesis certificate.

#### 3.4.8 Genesis commitment compatibility (U16, revision 3)

**Existing behaviour (documented, not changed).** `chain-forge-core::compute_genesis_hash` parses the genesis file into `GenesisConfig`, **re-serializes the struct** with `serde_json::to_vec` (compact, no whitespace), and returns the SHA-256 digest as 64 lowercase hexadecimal characters. Consequences:
- *Key order* is the struct field declaration order; the two free-form `serde_json::Value` fields (`pocd`, `genesis_challenges`) serialize object keys in sorted order unless the `serde_json` feature `preserve_order` is enabled somewhere in the build graph. The workspace manifests do not enable it; a transitive dependency could (feature unification). Assumption A1, with a required test.
- *File bytes do not matter*: whitespace, key order, line endings (CRLF), `\uXXXX` escapes versus literal characters, and a trailing newline in the file do not change the hash, because the input is the re-serialized struct.
- *Ignored fields do not count*: unknown JSON fields are dropped by parsing (for example `GenesisCryptography` has no `deny_unknown_fields`), so two files that differ only in an unknown field have the **same** genesis hash. The hash commits to what the node understands, not to every byte the operator wrote. This is a property to know about, not a change proposed here.
- *Numbers inside `Value` fields* are re-emitted by `serde_json` in its canonical number form; `1`, `1.0` and `1e0` are different parsed values (integer versus float) and can hash differently from the operator's spelling; the output is deterministic for a given `serde_json` version.
- *Platform independence*: the output contains no endianness, locale or path dependence; it depends on the pinned `serde_json` version (formatting of floats and escapes), recorded in `Cargo.lock` (assumption A2). A behaviour change in `serde_json` would change the hash of existing chains.
- *Hash function*: SHA-256, whereas the PQ-HotStuff-2 hash is SHA3-256 (`hash_width = 256`). The two are unrelated functions; the value is used only as an opaque 32-byte identifier.

**Relationship to the genesis certificate (§3.4.7).** The certificate carries `genesis_hash` as 32 raw bytes. The verifier derives it from its **own** genesis config by `compute_genesis_hash` and hex-decodes it **strictly**: exactly 64 characters, only `[0-9a-f]`, no uppercase, no whitespace, no `0x`. The wire value is then compared bytewise; a certificate is never trusted to supply it. `genesis_block_id` re-hashes it under the `CFH1|gblock|` tag with SHA3-256 (§3.4.7), so the SHA-256 value is domain-separated and never used directly as a block identifier.

**Independent golden-vector requirements** (the Rust function is never the oracle):
- A Python oracle that reads the genesis fixture, orders keys per the Rust struct declaration order taken from the source, emits compact JSON, and hashes with SHA-256 (and SHA3-256 where the certificate needs it). Vectors for at least: the devnet `genesis-4node-mldsa.json`; a minimal genesis; a genesis with `pocd` and `genesis_challenges` present with nested objects in non-sorted source order.
- Vectors for `GenesisCert` bytes and `genesis_block_id` from the same oracle.
- Vectors are produced before the Rust test and committed; they are regenerated by the script, never by the code under test.

**Negative and compatibility tests.**
- GH-01 the same document pretty-printed, key-reordered, with CRLF, with a trailing newline, and with `é` escapes instead of literal characters: **same** hash.
- GH-02 a document with an extra unknown field: same hash (documents the behaviour; flagged for owner awareness).
- GH-03 any change to a known field (one bit of one validator key; `chain_id`; `genesis_time`; a power): different hash.
- GH-04 `pocd` containing nested objects in different source key orders: same hash; with the `preserve_order` feature forced on in a test build the test must fail loudly (guards A1).
- GH-05 number spellings inside `Value` fields (`1`, `1.0`, `1e0`, `100000000000000000000`): behaviour recorded as the vector says.
- GH-06 `GenesisCert` with uppercase hex, 63 or 65 characters, a `0x` prefix, or another chain's genesis hash: rejected.
- GH-07 `GenesisCert` built from a differently spelled file that parses to the same struct: accepted (equal commitment); with an unknown-field difference: accepted too, recorded as the GH-02 consequence.
- GH-08 `genesis_block_id` for two chains with the same hash bytes but different `chain_id` or `protocol_profile`: different identifiers.
- GH-09 the same genesis hashed on Linux and on the owner's Windows machine: identical.
- GH-10 the existing `compute_genesis_hash` tests are untouched and still pass.

**Open (U16).** Keep this behaviour inside the genesis certificate (proposed, because it requires no change to deployed chains), or define a canonical binary genesis commitment under a future profile. Either way `compute_genesis_hash` is not modified by this work.

### 3.5 Serialization versus validity (normative principle for §3.3 and §3.4)

A **canonical** object is one whose bytes decode under §3.3 or §3.4 and re-encode identically. A **valid** object is a canonical object that also satisfies every check below against the verifier's own state. **Canonical does not imply valid**, and the decoder performs no check that needs signatures, the validator set, or chain state. A node acts on an object only after both stages.

#### 3.5.1 Timestamp validity versus clock admission (U7)

Two separate things, never mixed:

- **Deterministic timestamp validity (consensus rule).** A pure function of the block, its parent and genesis, so every honest node and every replay gives the same answer, today or in ten years: `timestamp_ms > parent.timestamp_ms`; for height 1, `timestamp_ms > genesis_time_ms` (the genesis `genesis_time` converted to milliseconds). A block failing this is invalid and is not voted for. An upper bound on the step from the parent (`MAX_TS_STEP_MS`) is **not** proposed as a consensus rule, because a long network stall would then make every later proposal invalid (U7). It uses no local clock.
- **Local-clock admission policy (node-local, not consensus).** A node MAY delay its *vote* on a proposal whose `timestamp_ms` is more than `MAX_FUTURE_SKEW_MS` (an operator parameter) ahead of its own clock, and re-evaluate it later. This policy can only withhold or delay a vote: it never marks a block invalid, never produces evidence, is never applied when replaying or syncing committed blocks, and never changes `block_id` or any commitment. A committed block is never rejected because of a node's clock.

#### 3.5.2 QC and TC validity

**QC validity** (checked in this order, stopping at the first failure, nothing counted before it passes):
1. `version` and `alg_id` equal the profile's; `epoch` is known and its commitment is held (else *unverifiable*, §3.4.2); `validator_set_hash` equals the local `validator_set_hash(epoch)`; bitmap bit count equals `|V_epoch|`; `round ≥ 1` and `block_id ≠ genesis_block_id`.
2. Every set bit indexes a validator with power > 0 (U3); signature count equals signer count.
3. For each signer in ascending index order: the envelope's `alg_id` is the profile's and its length is exact; the reconstructed vote message (local `chain_id`) verifies under the validator's registered key for that epoch with context `qattice/vote/v2`.
4. Total signer power, summed in `u128`, is at least `q = ⌊2T/3⌋ + 1` for the epoch's total power `T` (also in `u128`).
5. `block_id`, `parent_id`, `parent_round` agree with the block the certificate is attached to or certifies, where the rule that uses the QC says so (§5, §6).

**TC validity:** the same steps over timeout messages, using each signer's own `high_qc_rounds[j]`; the nested certificate is valid under §3.5.4; `high_qc.round == max(high_qc_rounds)`; `high_qc.round < tc.round`; and the power condition of step 4.

**Replay and substitution.** Every signed message binds `chain_id`, `epoch`, `round` and `alg_id`, and the verifier supplies `chain_id` and the profile itself, so a certificate copied from another chain, epoch, round or algorithm fails step 3. Vote, timeout, proposal and PoP use different tags and contexts, so a signature never validates in another role (§3.1). A `validator_set_hash` that names another set is refused at step 1 even if the signatures would verify under the keys of both.

#### 3.5.3 Evidence validity (U10)

An `EvidenceItem` in a block is valid only if **all** of the following hold; any failure invalidates the whole block (the proposer included it) and slashes nothing:
1. It is canonical (§3.3) and not older than `EVIDENCE_MAX_AGE_BLOCKS`; its `evidence_id` has not already been committed (a registry of committed evidence ids).
2. **Offender identity.** `offender` is a registered validator address in `V_epoch` (via the held commitment), canonical per §3.4.1, and has a registered public key for that epoch. For kind 2 it is also the leader of `(epoch, round)` under §4, and the `proposer` in both block-id inputs.
3. **Both signatures.** `envelope_a` verifies over `message_a`, **and** `envelope_b` verifies over `message_b`, each under the *same* registered key of that offender, with the right context (`qattice/vote/v2` for kind 1, `qattice/proposal/v2` for kind 2) and the profile `alg_id`. Verifying only one signature, or verifying them under different keys, is a rejection. A vote message names no voter, so a pair whose signatures verify under two different validators' keys is *not* evidence against either.
4. Both messages carry the local `chain_id` (kind 1), the item's `epoch` and `round`, and the profile `alg_id`; for kind 2, `SHA3-256(preimage_x) == block_id` of `message_x` for both, and both preimages name the item's `epoch` and `round`, the local `chain_id`, and the offender as `proposer`. The two `block_id`s differ.
5. Evidence is applied identically on every node from the committed block, never from local observation (§9).

#### 3.5.4 Cross-epoch rules for nested certificates (U15, revision 3)

Rounds are chain-global and epochs are contiguous round ranges recorded in the boundary table (§3.6, R1–R6); the epoch-change protocol is §3.7. Under those definitions:
- **A TC's signers are in its own epoch only.** Every TC signer belongs to `V_{tc.epoch}`, the timeout messages bind `epoch = tc.epoch`, and `tc.epoch == epoch_of(tc.round)` from the boundary table (EC-9).
- **The nested certificate may come from an earlier epoch.** At the first rounds of epoch `e+1` the highest QC is `QC(Z)`, certified by `V_e`. It is permitted when `nested.epoch ≤ tc.epoch`, `nested.epoch == epoch_of(nested.round)` (so an epoch label cannot be forged to select a convenient set), and `nested.round < tc.round`. A nested epoch later than `tc.epoch` is refused. A `GenesisCert` is permitted only as in §3.4.7.
- **It is validated against its own epoch's set,** never the TC's: `validator_set_hash(nested.epoch)` from the verifier's retained commitments (an epoch-keyed table; the repository's `historical_validator_sets` is keyed by height, K4), with every check of §3.5.2. If the verifier does not hold that epoch's commitment or boundary row, the TC is *unverifiable*, not invalid.
- **Rounds.** `max(high_qc_rounds)` is compared with `nested.round` as plain integers, valid because rounds are global. The normal post-boundary case is `nested.round == z` with `nested.epoch == e` inside a TC of epoch `e+1` (§3.6 example).
- **Only the unlabelled tail is branch-relative.** For a nested or parent certificate whose round lies above the last completed boundary row, `epoch_of` is judged relative to the branch that carries it (§3.6 R3); a verifier without that branch treats it as unverifiable.
- **A block's parent certificate** follows the same rule: `qc.epoch ≤ block.epoch`, `qc.epoch == epoch_of(qc.round)`, validated against `V_{qc.epoch}`. Which `block.epoch` may follow a given `qc.epoch` is fixed by EC-5: the first block of epoch `e+1` is the only one whose `qc.epoch` is `e` and `block.epoch` is `e+1`.

#### 3.5.5 Failure behaviour

A decode error or a failed validity step makes the node discard the enclosing message (proposal, vote bundle, timeout bundle) without voting, without changing safety state and without counting power. A node never repairs, re-orders or re-encodes a received certificate to make it pass, and never forwards an object it rejected. *Unverifiable* objects (unknown epoch commitment) are held or dropped by local policy and never accepted. Evidence of misbehaviour arises only through §9 committed evidence, never from a rejected certificate.

#### 3.5.6 Why timeouts sign `high_qc_round` and not a QC identifier (U8)

The merged timeout message signs `(epoch, round, high_qc_round)`. The question is whether that is enough for safety, or whether it should also sign the QC's `block_id`.

*How the TC is used.* A proposal after a timeout round extends only a QC whose round is at least `max(high_qc_rounds)` of the TC (the DiemBFT-v4 / Jolteon voting rule of §5). That rule uses **round numbers only**. Each entry of `high_qc_rounds` is individually signed by its signer, and the verifier checks every entry against its own signature, so a TC assembler cannot lower any entry, cannot drop a signer without losing power, and cannot change an entry. The aligned-list layout (§3.4.1) exists so the maximum is taken over exactly the signed values.

*Why no QC identifier is needed for safety.* Suppose block `B` at round `r` commits through the two-chain rule. Then a quorum voted for `B`'s child at round `r+1`, having already seen the QC for `B`; by quorum intersection any later TC quorum contains a signer who did so, whose honest high-QC round is at least `r`. So `max(high_qc_rounds) ≥ r`, and any later proposal must carry a QC of round ≥ `r`. That QC extends `B` by the standard chain argument, using the lemma that **two valid QCs of the same round certify the same block unless more than the tolerated weight equivocates**. The identifier of the QC the signer holds adds nothing to this argument: only its round does. The nested `high_qc` inside the TC exists to let lagging nodes catch up; it is checked as an ordinary QC and is a liveness aid, not a safety input.

*What signing the identifier would cost.* A new signed timeout layout, a new profile version and a coupling of the timeout to a particular QC encoding (whose signature subset varies, §3.4.4), for no change in the argument above. Hence the recommendation to keep the approved format.

*Proof obligations.* The five obligations that this argument relies on are stated, with assumptions, required tests and review requirements, in §3.8 (PO-1 same-round QC uniqueness, PO-2 persisted monotonic state, PO-3 verified timeout maxima, PO-4 epoch-transition quorum safety, PO-5 nested-certificate substitution). **None is proved.** This section is a rationale, not a proof.

### 3.6 Chain-global rounds and epochs (PROPOSED, resolves U15)

**R1. Rounds are chain-global.** A round number is a `u64` that is **never reset** at an epoch boundary. The genesis certificate has round 0 (§3.4.7); every block has `round ≥ 1`; along any chain of blocks, rounds strictly increase (`B.round > B.qc.round`, §5). The persisted `hvr` and `hqr` of a validator (§5, §7) are therefore comparable across epochs and must **not** be reset at an epoch change (see contradiction K1 in the analysis).

**R2. Epochs are contiguous round ranges fixed by committed state.** Epoch 0 begins at round 1. Epoch `e` occupies rounds `start(e) … end(e)` with `start(e+1) = end(e) + 1`. `end(e)` is the round `z` of the certificate that completes the commit of epoch `e`'s epoch-change block (§3.7, EC-4). Epoch numbers increase by exactly 1, only through that event. The latest epoch has no `end` yet.

**R3. The boundary table.** Each node keeps, from committed state, a table of `(epoch, start, end, validator_set_hash)` rows, one per completed epoch, plus the open row for the current epoch. A row is appended when the epoch-change block commits (EC-4) and is never edited. For any round `r ≤ end(latest completed epoch)`, `epoch_of(r)` is a function of this table. For rounds above the last completed boundary the epoch is the current one, or the next one on a branch that carries a justified boundary (§3.7, EC-5); such rounds are judged relative to the branch that carries the certificate, and otherwise the certificate is *unverifiable* (not invalid).

**R4. Round numbers are not reused after a transition.** Every epoch-`e+1` block has `round ≥ end(e) + 1`, and a verifier that holds the row for `e` refuses (a) any epoch-`e+1` certificate with a round `≤ end(e)` and (b) any epoch-`e` certificate with a round `> end(e)`. The persisted floors of a signer survive the epoch change, so a signer cannot sign epoch-`e+1` round `r'` after signing any round `≥ r'` in an earlier epoch. Along one chain no round number ever carries two epochs. Across competing uncommitted branches a round number may be labelled differently (a branch without a justified boundary still calls it epoch `e`); the seal rule (EC-6) and the boundary table make an epoch-`e` object above `end(e)` uncountable, which is proof obligation PO-4, not an established fact.

**R5. Historical references.** Every QC and TC states `(epoch, round)`. The verifier requires `epoch == epoch_of(round)` from the table, then verifies against `V_epoch` (via `validator_set_hash(epoch)`). A TC's nested certificate may have an earlier epoch and an earlier round (§3.5.4). Nothing in a certificate refers to a "round within an epoch".

**R6. Validators that have not yet learned the new epoch.** A lagging validator holds the table up to epoch `e`. When it receives an epoch-`e+1` object whose round is above `end(e)` it cannot know the boundary: it treats the object as *unverifiable*. It must not vote, time out or count power on it. The first epoch-`e+1` block carries the proof (its `qc` completes the commit of the epoch-change block, EC-5), so the validator fetches the epoch-change block and that certificate, verifies the proof under `V_e` (which it holds), appends the row, and only then acts. A lagging validator that is still signing epoch-`e` messages at rounds above `end(e)` produces objects that every up-to-date verifier refuses (R4).

**Examples (illustrative round numbers).**

| Epoch | Events | Boundary row |
|---|---|---|
| 0 → 1 | Epoch-change block `P0` proposed at round 12 (epoch 0). Round 13: empty suffix block `B` certified by `V_0` (QC round 13). The pair `(P0, B)` has consecutive rounds, so `QC(B)` commits `P0`: `z = 13`. Round 14: first epoch-1 block `X`, `X.qc = QC(B)`, signed by `V_1`. | epoch 0: rounds 1–13; epoch 1 starts at 14 |
| 0 → 1, leader failure | Round 14's leader fails. Validators of `V_1` time out in round 14 (messages bind `epoch = 1`, `high_qc_round = 13`). `TC(14)` is a TC of epoch 1 whose nested `high_qc` is `QC(B)` of **epoch 0**, round 13: allowed (§3.5.4). Round 15 block has `qc = QC(B)` and `tc = TC(14)`. | unchanged |
| 1 → 2 | Epoch-change block `P1` at round 28. Round 29 times out (TC of epoch 1). Round 30: empty suffix `Y` with `qc = QC(P1)` and `tc = TC(29)`. Round 31: empty suffix `Z`, `qc = QC(Y)`. Rounds 30, 31 are consecutive, so `QC(Z)` commits `Y` and its ancestor `P1`: `z = 31`. Round 32: first epoch-2 block, `qc = QC(Z)`, signed by `V_2`. | epoch 1: rounds 14–31; epoch 2 starts at 32 |

In the second transition the commit is completed by a non-adjacent pair, which is why the boundary is "the round of the completing certificate", not "the round after the epoch-change block".

### 3.7 Epoch-change protocol (PROPOSED, addresses U17)

Status of this section: the rules below are **proposed definitions**. Their safety against the two-chain invariants of §5–§6 is **not established**; each place where it depends on an unproven claim is marked and collected in proof obligation PO-4 (§3.8). Nothing here may be read as a completed proof.

**Terms.** An *epoch-change block* `P` of epoch `e` is a block whose payload has `epoch_change = Some(EpochChange { next_epoch = e+1, next_set })` (§3.3). A *suffix block* of `P` is any block on a branch that contains `P` while `P` is not yet committed on that branch. The set `next_set` is the full successor validator set; `validator_set_hash(e+1)` is its commitment (§3.4.2), computed from the list in `P`'s payload.

- **EC-1. Who certifies the epoch-change block.** `P` is an ordinary block of epoch `e`: proposed by `leader(e, P.round)`, voted and certified by `V_e` only. Its `next_set` is therefore hash-committed into `block_id(P)` and into every vote and `QC(P)` of `V_e`.
- **EC-2. Validity of `P`** (checked by voters before voting): `next_epoch == e+1`; the branch has no other uncommitted epoch-change block and `P` is not itself a suffix block; `next_set` is canonical (§3.4.1 order, unique addresses and keys, exact key length); every key in `next_set` is a registered key with a verified proof of possession (§8.1); the powers and membership follow §8 (personhood cap, then gating, then the gate-3 floor) from the state the block's `prev_state_root` identifies plus the operations the chain has committed; `|next_set| ≤ V_profile`; total power > 0 and the quorum floor holds. **Open (U19):** the exact operations that may change the set, and how a revocation committed in the last one or two blocks (the state lags by one block, §3.3) is reflected, are defined by §8 and the transaction specification (U5), not here.
- **EC-3. Suffix blocks.** From `P` until `P` is committed on that branch, every block is a suffix block: epoch `e`, certified by `V_e`, with a canonically **empty payload** (`txs = []`, `evidence = []`, `epoch_change = None`). Voters refuse any other payload. This keeps the ledger changes between `P` and the boundary empty and forbids a second epoch change.
- **EC-4. Commit and the boundary.** `P` is committed by the ordinary rule of §6, possibly through suffix blocks. Let `(Y, Z)` be the pair, with `Y` equal to `P` or a suffix descendant of `P`, whose consecutive rounds and `QC(Z)` first make `P` committed on the branch. Then `z = Z.round`, `end(e) = z`, `start(e+1) = z + 1`, and `V_{e+1}` is `next_set` of `P`. **This is the moment `validator_set_hash(e+1)` becomes authoritative**: not at proposal, not at `QC(P)`, but when the commit of `P` is established by `QC(Z)` under `V_e`. The row `(e, start(e), z, hash)` and the set itself are appended to committed state.
- **EC-5. First epoch-`e+1` block.** The first block of epoch `e+1` on a branch, `X`, has `X.epoch = e+1`, `X.round ≥ z+1` and **`X.qc = QC(Z)`**, the completing certificate. If `X.round == z+1` no TC is needed; if `X.round > z+1`, `X.tc` is a TC of epoch `e+1` for round `X.round − 1` and `X.qc.round = z ≥ max(high_qc_rounds)` as usual (§5 rule 3). `X` is signed by `leader(e+1, X.round)`, with `seed_{e+1} = block_id(P)` (§4). The verifier checks that `X.qc` and the block chain behind it (it must hold `P` and the suffix blocks) establish the commit of `P` under EC-4; otherwise `X` is unverifiable or invalid. Every later block on that branch is epoch `e+1` until the next epoch change.
- **EC-6. Seal.** A validator of `V_e` that signs a vote for a block `Z` that is the second block of a consecutive pair `(Y, Z)` with `Y ∈ {P} ∪ suffix(P)` — i.e. a vote that may complete the commit of `P` — must **in the same atomic safety-state write** record `sealed = e` and must never again sign a vote, timeout or proposal with `epoch = e` and `round > Z.round`. Its later messages are epoch `e+1` messages if it is in `V_{e+1}`, and nothing otherwise. The rationale is a counting argument (not a proof): if `QC(Z)` exists, a quorum of `V_e` is sealed, so the unsealed power of `V_e` plus the Byzantine power cannot reach a quorum for an epoch-`e` round above `z`. **Not established:** this is PO-4. The persisted `sealed` field does not exist in the merged safety record (#127) and its addition is future work.
- **EC-7. Authorization of revoked and rotated validators.** A validator absent from `next_set`, or present with a different key, has no authority in epoch `e+1`: its old key does not match the entry of `validator_set_hash(e+1)`, so step 3 of §3.5.2 fails for any signature it makes under epoch `e+1`. Its authority in epoch `e` ends at `end(e)`: verifiers that hold the row refuse epoch-`e` objects above `z` (R4). This is the effective time required by decision D4 ("the first block after the one that commits the revocation"), with the cost that the suffix rounds up to `z` still run under `V_e`.
- **EC-8. Historical verifiability.** A QC or TC is verified against the set of its own epoch (§3.5.2, §3.5.4). Every node retains, for each epoch within its retention window, the full set (it is in the epoch-change block's payload, which is committed) and the boundary row. An object older than the retention window is unverifiable, not invalid. A syncing node needs the table from a trusted starting point (genesis or a checkpoint); the choice of checkpoint trust is **open** (PO-4, long-range keys).
- **EC-9. Timeout certificates at the boundary.** A TC of round `r` is signed by `V_{epoch_of(r)}` only: `r ≤ end(e)` is `V_e`, `r ≥ start(e+1)` is `V_{e+1}`. No TC combines signers of two epochs. Timeouts for round `z+1` are epoch-`e+1` messages and carry `high_qc_round = z`; their nested certificate is `QC(Z)` of epoch `e`. An epoch-`e` TC of round `z` or lower can never justify a block of epoch `e+1`, because EC-5 requires `X.qc = QC(Z)`.
- **EC-10. Delayed validators.** A validator that has not seen the proof (R6) abstains until it has; a validator that restarts keeps `sealed` and the global floors from its persisted record, so it cannot be tricked into signing epoch-`e` round `> z` by replay.

**Checks the committed-state machine must make.** A node refuses to append a boundary row unless the commit of `P` is established by a `QC(Z)` valid under `V_e` and `end(e)` is greater than the previous row's `end`; it refuses a second row for the same epoch; it refuses a `next_set` whose hash differs from the one in `P`'s payload; and it never edits a row.

### 3.8 Proof obligations (OPEN; no formal proof has been completed)

These are the safety claims the rules above rely on. **None is proved by this document.** Each lists its assumptions, the tests the implementation must carry, and what independent review is still required. A test passing is evidence for a bug-free implementation of a claim, never a proof of the claim. These replace the five obligations of revision 2 (old PO-2 → new PO-2/PO-3 split; old PO-4 → PO-4; old PO-5 → PO-5).

| | PO-1 Same-round QC uniqueness under weighted quorum |
|---|---|
| **Claim** | For one `(epoch, round)`, at most one `block_id` has a valid QC. |
| **Assumptions** | Quorum `q = ⌊2T/3⌋ + 1` over the epoch's total power `T`, computed in `u128`; two quorums share power at least `2q − T ≥ (T + 2)/3`; the power of validators that sign two different votes in one round is strictly below that bound; power is the post-cap, post-gating power of §8; the personhood system keeps Sybil power within the assumed fraction (outside this document, N10); zero-power validators cannot sign (§3.5.2 step 2). |
| **Required tests** | Exhaustive enumeration of all weight vectors for small `n` and small powers (every pair of quorums intersects in at least `2q − T`); the three residues of `T mod 3`; a counterexample test showing two QCs when the double-signing power reaches the bound; `u128` overflow cases; double-sign detection yields §9 evidence, not local slashing. |
| **Review** | Independent check of the weighted-intersection arithmetic and of the rounding of `q`. |
| **Status** | OPEN. |

| | PO-2 Persisted, monotonic highest-QC and floor state |
|---|---|
| **Claim** | For each validator, `hvr`, `hqr` (and `sealed`) never decrease over its lifetime, including across restarts, epoch changes and counter recovery, and every timeout it signs reports a `high_qc_round` it actually holds and is not below `hqr`. |
| **Assumptions** | The safety store is the only signing path (§7); the trusted counter and record chaining of §7.1/§7.1.1 hold; rounds are chain-global (R1). |
| **Required tests** | Restart at every durability point (existing #127 suite) plus: an epoch increase with a lower round is refused; floors survive an epoch change; `sealed` survives restart and refuses epoch-`e` rounds `> z`; a timeout with `high_qc_round < hqr` is refused. Mutation: reset floors at an epoch change must be caught. |
| **Known conflict** | The merged store resets `hvr`, `hqr` and the stored items when the epoch increases (K1). Resolving it needs a future, separately authorized change; this document does not change the code. |
| **Review** | Review of the store against R1 and EC-6. |
| **Status** | OPEN. |

| | PO-3 Verified timeout-round maxima |
|---|---|
| **Claim** | The maximum used by vote rule 3 is taken over exactly the `high_qc_rounds` entries of a verified TC, each individually signed by its signer, and no assembly of a TC can lower it below the true maximum held by the signers whose timeouts it uses. |
| **Assumptions** | PO-1; PO-2 (honest signers report their true `hqr`); signature unforgeability and context separation (§3.1); the aligned layout of §3.4.5. The TC assembler may leave out high timeouts: safety needs only that the TC's quorum intersects a commit quorum in an honest signer, not that it includes every timeout. |
| **Required tests** | C-15, C-16, TM-02; a TC that excludes the signers with the highest rounds is accepted if valid and still forces `B.qc.round ≥ max` of what it contains; misaligned and swapped entries; mutation: `min` instead of `max`, max over unverified entries, ignoring one entry. |
| **Review** | Independent review of §5 rule 3 against the DiemBFT v4 argument with weighted quorums. |
| **Status** | OPEN. |

| | PO-4 Epoch-transition quorum safety |
|---|---|
| **Claim** | After the epoch-change block `P` is committed (EC-4): (a) no block of epoch `e` with round above `z` can obtain a valid QC that any honest verifier counts; (b) epoch `e+1` blocks extend `P` through the completing `QC(Z)`; (c) no two conflicting blocks commit across the boundary, including the commit of `Z` by a quorum of `V_{e+1}`. |
| **Assumptions** | EC-6 sealing, persisted atomically with the vote; Byzantine power below the PO-1 bound **in `V_e` and separately in `V_{e+1}`**; the two sets may overlap little or not at all; boundary rows are authentic. |
| **Unresolved points** | (i) cross-set commit of `Z` (certified by `V_e`, committed by `V_{e+1}`); (ii) validators leaving `V_e` are no longer bound after `z` and may later hold compromised old keys: the table defence needs a trusted starting point (long-range attack), which is an open trust assumption; (iii) the epoch-`e` suffix when `P` is certified but round `z` never completes (liveness of the closing window, in particular the timeout rule of §5 when the only valid continuation extends `P`); (iv) the lag of the state used to validate `next_set` (U19); (v) whether the sealing counting argument holds when `V_e ∖ V_{e+1}` is large. None is resolved. |
| **Required tests** | EA-01 to EA-14 (analysis document); a model-based simulation with epoch changes between disjoint, overlapping and shrinking sets and adversaries within the bound of each set; exhaustive small-state model check of the transition; mutations: remove the seal, accept epoch-`e` objects above `end(e)`, allow a second epoch change in the suffix, take `V_{e+1}` before `QC(Z)`. |
| **Review** | Independent review and a machine-checked model are recommended before any engine implementation. |
| **Status** | OPEN; the rules of §3.7 are proposed, not established. |

| | PO-5 Nested-certificate substitution and conflicting certificates |
|---|---|
| **Claim** | Replacing the nested `high_qc` of a TC by another valid QC of the same round (a different signer subset) changes `H(tc)` and `block_id` but not safety; two valid QCs of one round for different blocks, or a QC and a conflicting certificate under another epoch label, cannot both exist while the assumptions of PO-1 and PO-4 hold, and observing them proves the assumption was violated. |
| **Assumptions** | PO-1, PO-3, PO-4; the label check `epoch == epoch_of(round)`. |
| **Required tests** | TC-X1 to TC-X4, EA-06, EA-07; two same-round QCs for different blocks produced with double-signing power above the bound are detected, not silently accepted; nested round above the maximum, below it, wrong epoch, wrong label. |
| **Behaviour on detection** | The node refuses both objects, keeps its safety state unchanged and raises an operational alarm; evidence is created only through §9 committed evidence, never locally. |
| **Review** | Independent review together with PO-1 and PO-4. |
| **Status** | OPEN. |

---

## 4. Leader selection

`leader(epoch, round) = sorted(V_e)[ (round + seed_e) mod |V_e| ]`, over validators with p(v) > 0. `seed_e` is the hash of the epoch-change block.

- With personhood weighting at power 1 per human (the current cap), round-robin is already power-proportional. **[decision D3]** Weighted or reputation-based rotation (leaders that time out are skipped) is a Phase 3 option. Recommendation: plain round-robin until devnet data shows a need.
- Leader selection uses only committed state, so every node computes the same leader.

---

## 5. Safety rules (per validator)

Persisted safety state (§7): `highest_vote_round` (hvr), `highest_qc_round` (hqr; this is the lock), and `last_signed` (the last vote or timeout signed in round hvr).

**Vote on block B** only if all hold:
1. B is well formed. Its signature verifies under `leader(B.epoch, B.round)`. B.qc is valid. B.parent_id = B.qc.block_id. The payload passes the existing checks (txs, state root, participation evidence).
2. `B.round > max(hvr, B.qc.round)`.
3. Either `B.round == B.qc.round + 1`, or B.tc is valid for round `B.round − 1` and `B.qc.round ≥ max(B.tc.high_qc_rounds)`.

Then set `hvr = B.round` and `hqr = max(hqr, B.qc.round)`, **persist**, and only then send the Vote to `leader(B.round + 1)`.

**Sign a timeout for round r** only if all hold:
1. `high_qc.round ≥ hqr`.
2. `r > max(hvr − 1, high_qc.round)`.
3. Either `r == high_qc.round + 1`, or the node holds a valid TC for round `r − 1`.

Then set `hvr = max(hvr, r)`, **persist**, and broadcast the Timeout to all validators.

**Never** sign two different votes in one round, or two different timeouts in one round. Voting in round r and then timing out in round r is allowed (rule 2 permits `r == hvr`). After a restart, re-send `last_signed` byte-for-byte; never re-derive it.

These are the DiemBFT v4 `safe_to_vote` and `safe_to_timeout` rules. Rule 3 of the vote is what makes a two-chain commit safe across view changes: a leader can only extend a QC at least as high as every QC that 2f+1 validators reported when they timed out.

---

## 6. Commit rule (two-chain) and round advance

**[decision D1] Two-chain or three-chain commit.** Recommendation: **two-chain** (as above).

| | Two-chain (Jolteon / DiemBFT v4) | Three-chain (original HotStuff) |
|---|---|---|
| Commit latency | 2 rounds after proposal | 3 rounds |
| View change | Quadratic: timeouts broadcast, TC carries high-QC rounds | Linear |
| Responsiveness | Not optimistically responsive after a view change | Optimistically responsive |
| Track record | Ran in production (Diem/Aptos) | The textbook protocol |

At expected Qattice sizes the quadratic view change is a rare-path cost. Commit latency is paid on every block.

**Commit:** when a node holds a valid QC for block B, and B.qc certifies B's parent P with `B.round == P.round + 1`, then P and all its uncommitted ancestors commit, in height order. Execution, state root and rewards run on commit, exactly as today.

**Round advance:** a node enters round r + 1 on its first valid QC for round r, or its first valid TC for round r. It carries the highest QC and TC it has seen.

**Proposal:** the leader of round r proposes once it holds a QC for round r − 1, or a TC for round r − 1 (attached). It extends the highest QC it knows.

**Communication:** in the common case, votes go to the next leader only and the leader broadcasts one block, so the message count is O(n). Timeouts are broadcast, O(n²), on the view-change path only.

---

## 7. Persistence and restart

- **Safety state:** `{epoch, profile, hvr, hqr, last_signed}` is written atomically to `persist/pq_hotstuff_safety.json` **before** any vote or timeout leaves the node. This is the same write-before-broadcast discipline as the Tendermint `SignGuard`. If the file is present but unreadable, the node refuses to sign (fail closed).
- **Exact signed message and envelope (crash safety).** `last_signed` is not a summary. It stores, for the last vote or timeout, the **canonical message bytes (§3.2) and the complete signature envelope (`alg_id`, length, signature bytes)**, plus the message type and round. Order of operations, with no step skipped or reordered: (1) check the §5 rules against the persisted state; (2) build the canonical message; (3) sign it (hedged, §3.1); (4) write the updated safety state **including that exact message and envelope** to a temporary file, `fsync` it, rename it over the old file, and `fsync` the directory; (4b) advance the trusted monotonic counter (§7.1); (5) only then send. The same rule covers proposals the node signs as leader.
  - *Crash before step 4 completes:* the signature never left the process, so nothing is on the network; the old state is intact and the node may sign again. *Crash after step 4, before or during step 5:* on restart the node re-sends the stored message and envelope **byte-for-byte**. It never re-signs that message and never signs a different message of the same type in that round.
  - *On load:* the record must pass an integrity check; the message must decode under §3.2 and re-encode to identical bytes; the envelope must carry the profile's `alg_id`, the exact length, and a signature that verifies over the stored message under the node's own key and the right context. The stored profile must equal the chain's profile. Any failure, a torn or empty file, or a failed RNG at step 3, makes the node refuse to sign (fail closed); it never repairs a record by re-signing.
  - Required tests: a fault injected at every step (before, during and after each write, `fsync` and rename) never yields two different signed messages for one (type, round), never a re-sign of a persisted message, and never a send before step 4.
- **A missing safety-state file never resets signing history, and a fresh validator is explicitly distinguishable.**
  - *Explicit initialization.* Safety state is created only by an explicit operator initialization step for a key that has never signed (a new key, or genesis). A node never creates safety state implicitly on start. Initialization writes, atomically, a record with `state = "fresh"`, the profile, the validator public key, a random `instance_id`, and `last_signed = null` (an explicit "nothing signed yet", never a default of round 0). The same atomic write that stores the first signed message (above) moves the record from `fresh` to `active`.
  - *Existing validator, missing or damaged state.* If the node is configured as a validator and the safety-state file is missing, empty, torn, unreadable, or from a different profile or `instance_id`, or if the node has any evidence that this key has signed before (an initialization marker, the key in the committee at a non-genesis committed height, or committed participation evidence naming it) while the file is absent, then the node **refuses to sign and refuses to create new state**. It may keep running as a non-signing observer. It never treats absence as `fresh`.
  - *Stale file.* If the chain shows the validator's key signing in a round higher than the file's `hvr` (for example a restored old backup), the file is stale: the node abstains until its state is brought past that round by a reviewed procedure, and never signs below it.
  - *Fresh initialization is refused for a key that has already participated.* Initialization checks the committed chain the node holds or has synced; if the key appears in any committed QC, TC, vote evidence or participation record at a height above the key's activation, initialization is refused.
  - *Recovery.* Loss of safety state is not recoverable by re-initializing the same key. The safe options are to keep abstaining or to rotate to a new key (PQ-VAL-003), which then starts with an explicit fresh initialization. A reviewed recovery procedure may be specified in Phase 1; until then fail closed.
  - *Required tests (negative unless stated):* start with the file deleted after prior signing, with the file truncated to 0 bytes, torn at every offset, with `instance_id` or profile mismatched, and with an old backup restored: in each case no signature is produced and no new file is created. A fresh validator with explicit initialization signs normally (positive) and its `fresh` state is distinguishable from every damaged state. A key that already appears in committed participation cannot be initialized fresh. Mutation tests that treat absence as `fresh`, or skip the `fresh` to `active` transition, must fail a test. Phase 0 exercises all of this against an in-memory storage abstraction with injected failures; no key or state file is written to disk.
- **Block store:** the uncommitted blocks on the path from the highest committed block to the highest QC, plus that QC and the highest TC. On restart these are reloaded and the node resumes from round `max(hqr, highest TC round) + 1`.
- **Engine interface:** the `ConsensusEngine` lock hooks (`lock_state` / `restore_lock_state`) currently take a Tendermint-shaped `LockState`. They become a versioned enum `EngineSafetyState::{Tendermint(LockState), PqHotStuff(PqSafetyState)}`, with a serde tag so existing data dirs keep loading.

### 7.1 Trusted monotonic counter and rollback detection (PROPOSED amendment, owner review pending)

**Status.** Proposed on 2026-11-07 and implemented in draft PR #127 (`chain-forge-consensus`, `pq_hotstuff::safety`). Not a decision until the owner approves this section.

**Two different problems.** Crash recovery (an interrupted write) is solved by the atomic replace in §7. *Rollback* is different: an older but perfectly valid safety-state file restored from a backup, a snapshot revert or a cloned virtual machine. The file cannot detect this about itself, because the old file is internally consistent. A validator that signs from a rolled-back file can sign a message that conflicts with one it already broadcast, which is slashable equivocation. Only a record kept *outside the reach of whoever can restore the file* can detect it. That is the trusted counter. The checksum on the file detects corruption; it does not authenticate.

**Interface.** `read() -> u64`, `acquire_session() -> Session` and `advance(expected_previous, session) -> Result`. The session is the exclusive-writer credential of the signing-session requirement below. The record carries a `counter` field; every committed write increases it by exactly one, and the counter is advanced to match **after** the file is durable and **before** the signature is returned (step 4b).

**Properties a counter must have** (each is a requirement on the backend, not something the safety code can check):
1. **Durable:** survives power loss, process crash and reboot of the validator host.
2. **Atomic and compare-and-advance:** `advance(expected_previous)` succeeds only if the counter currently equals `expected_previous`, then becomes `expected_previous + 1`; otherwise it fails and changes nothing. It never succeeds for two callers with the same `expected_previous`. (This also stops two live copies of one validator from both progressing.)
3. **Monotonic and unresettable from the validator host:** there is no decrement and no reset reachable by the validator process, by the host's operating-system users, or by anyone who can restore the safety-state file or its backups. A reset, if it exists at all, needs a separate owner-controlled authority and is treated as key loss (below).
4. **Bound to one validator instance** (public key and `instance_id`): created at initialization with value 0 and never reused for another key or instance.
5. **Authenticated:** only that validator's signing path can advance it.
6. **Honest failures:** an unavailable or failing counter returns an error; it never reports success it did not achieve.
7. **Exclusive writer:** at most one signing session per validator identity is valid at any time, and this is enforced by the backend on **every** `advance`, not only checked when the node starts (see "Duplicated validators" below).

Acceptable families, not chosen by this document: a hardware or TPM non-volatile monotonic counter, an HSM, a remote witness with replicated durable storage. **Not acceptable:** a file or database on the validator host, anything the host's users can overwrite or restore, and the in-repository `TestCounter` (an in-memory test double with no durability and no protection).

**Rules at open** (file counter `f`, trusted counter `t`):

| Condition | Meaning | Action |
|---|---|---|
| `f == t` | normal | open |
| `f == t + 1` | the file is durable but the counter advance did not happen; nothing from this record was ever returned or sent | complete the advance with `advance(t, session)` (only after every other check passes); the node is not open, and returns and broadcasts nothing, until that call succeeds |
| `f < t` | rollback, or storage that lost data it had acknowledged | refuse (fail closed) |
| `f > t + 1` | counter reset or replaced, or a forged file | refuse (fail closed) |
| counter unreadable | | refuse to sign; the node may run as a non-signing observer |

**Recovery advance (`f == t + 1`).** Completing the outstanding advance is itself a compare-and-advance and follows the same rules as a normal commit:
1. **No signature is returned or broadcast, and no signing session is considered open, until the recovery advance has succeeded.** A failure of the call leaves the node not open and non-signing.
2. **It is `advance(t, session)`, never an unconditional set.** If another process advanced the same counter in the meantime, the call fails because the counter is no longer `t`. The node must treat that as a **fail-closed** event (it is evidence of a second writer or of a stale file), must not assume the advance succeeded, must not retry with a new expected value on its own, and must not sign. Re-reading the counter and restarting the open sequence from the beginning is allowed; it will then find `f < t` and refuse.
3. **A crash during the recovery advance is safe because the state is re-derived, not remembered:** after the crash the counter is either still `t` (the same rule applies again) or already `f` (the normal `f == t` case). No recovery step is repeated blindly.

**What happens when the counter advances and the file write fails.** By construction this cannot happen in the normal order: the counter advances only after the file and its directory entry are durable (steps 4 to 6). Every other interleaving is covered:

| Event | Durable state afterwards | Outcome |
|---|---|---|
| failure or crash before the rename is durable (steps 4 to 6) | old file, old counter | nothing was returned; continue normally; a different message for that round may still be signed |
| file durable, counter advance fails or the process dies (step 4b) | `f == t + 1` | nothing was returned; open completes the advance; the message is now durable, so a conflicting one for that round is refused (conservative) |
| counter advance succeeds, the acknowledgement is lost | `f == t` | normal; nothing to repeat |
| **storage acknowledged `fsync` but lost the data** (lying disk, write cache, power loss) | `f < t` | open reports rollback and **fails closed**; a loss of liveness, not of safety; recover by key rotation |
| counter reset, replaced or unreachable | `f > t + 1`, or unreadable | fail closed; the same key is never re-initialized (initialization requires counter 0, no marker or state, and no chain participation); rotate the key (PQ-VAL-003) |
| a snapshot revert or a cloned machine | file older than the counter | refused on open; a stale copy cannot commit (its expected value is behind); see "Duplicated validators" for what this does not cover |

**Duplicated validators: what is and is not guaranteed.** Compare-and-advance, with `expected_previous` taken from the record's own previous counter, gives these guarantees: two processes cannot both commit the same counter value, and a copy of the safety state that is behind the counter can never commit again (its advance fails and the store latches; on restart `f < t` refuses it). Two processes can therefore only take turns if they share one consistent safety state, in which case they behave as one validator. **It does not guarantee:**
1. **A signature is never computed by a stale or duplicate process.** In the commit sequence the signature is computed (step 3) before the counter is advanced (step 4b). A process that is paused and resumed, or a clone, can compute a valid signature over a conflicting message and then fail to commit it. The safety code discards that signature (it is never returned), but the signing key was used.
2. **Anyone holding the key material can sign outside the store.** The store protects against software and operator mistakes (rollback, restore, clone, restart). It does not stop an operator or an attacker who has copied the signing key from signing arbitrary messages directly. Deterrence there is slashing, and prevention is hardware.

**Production requirement: an exclusive signing session, enforced on every signing operation.** A production deployment must provide at least one of:
1. **A hardware-enforced exclusive signing session:** the signing key is non-exportable and lives in the same trusted boundary as the counter (HSM, TPM or secure enclave), which signs only when its own monotonic state matches, so a clone cannot obtain a signature at all; or
2. **A fenced single-writer lease tied to the validator identity:** acquiring the lease returns a **fencing token** that increases monotonically across holders; every `advance` presents the token; the backend rejects any token lower than the highest it has seen and any token whose lease has been superseded. The lease must be enforced by the backend **on every signing operation, not merely checked at startup**, must not depend on the validator host's clock for correctness, and a process that loses or cannot confirm its lease latches and stops signing. The lease is bound to the validator's public key and `instance_id`.

**Limit of option 2, stated plainly.** A fenced counter operation is not a fenced *cryptographic signing* operation. A lease controls who may **commit** signing state; it does not control who may **sign**. If the signing key is exportable, a lease does not and cannot prevent a holder of the key from producing signatures outside the store, and the remote counter must not be described as preventing unauthorized signatures. A deployment that relies on a lease alone gets rollback detection, containment of honest-software duplicates, and (through slashing) deterrence, not prevention. **Prevention of unauthorized signatures requires option 1: the signing operation itself controlled by a trusted signing boundary** that holds a non-exportable key and signs only when the exclusive-session and counter conditions hold.

This matters most for a network of personhood-weighted validator identities, where one human's duplicated validator is both a safety risk and an identity-integrity risk. Neither mechanism is implemented or reviewed yet; until one is, no backend is production-ready.

**How counter state survives restarts.** It lives in the counter backend, not in the safety directory, so restoring or deleting the safety directory does not touch it. On open, the counter is read first and compared with the file as above; initialization creates the counter at 0 and refuses a counter that is not 0.

**Backend direction (initial target, non-binding).** The interface stays technology-neutral. The first private implementation should target a **remotely enforced, authenticated counter with fencing and replicated durable state**, because it provides atomic compare-and-advance, exclusive-writer fencing and durability together. A TPM or HSM implementation remains an alternative and must meet the same requirements: strict atomicity, rollback resistance, identity binding and exclusive-writer enforcement. **No backend may be called production-ready until it has been independently reviewed.** The remotely operated counter is the choice for a **private prototype only**: it is not an approved production signer, because with an exportable key it cannot prevent signing outside the store (see the limit of option 2).

**Lease policy.** Leases are **renewable and enforced by the server**, carry **monotonically increasing fencing tokens**, and are checked on every advance. **No lease duration or renewal interval is fixed by this document;** both are to be determined by failure and latency testing of the chosen backend, and correctness must not depend on them. The validator **stops signing whenever it cannot establish that its session is valid**: a lease that has lapsed, a renewal that has failed, or a counter that cannot be reached all mean no signing.

**Recovery policy.** Fail closed. The only recovery authorized from a confirmed rollback, an inconsistent counter, a lost counter or a duplicated validator is **key rotation** (PQ-VAL-003) to a new key with a new counter and an explicit fresh initialization. The counter interface has no reset, decrement or set operation; if a backend offers one, it must be disabled for validator instances. An operator cannot reset a counter and continue signing with the same key.

### 7.1.1 Digest-bound counter commits (PROPOSED amendment, owner review pending; not approved for implementation)

**The gap this closes.** The commit sequence writes the state file (steps 4 to 6) before the counter advances (step 4b), and a counter that stores only a number cannot tell two different records with the same counter value apart. Found while writing the two-store tests for PR #127 and asserted there by `known_limitation_a_fenced_out_writer_leaves_an_uncommitted_record_the_counter_cannot_tell_from_the_committed_one`:
1. Writers A and B are both open on the same committed record (counter `t`); B acquires a later session, so A is fenced out.
2. B commits and broadcasts vote `m_B` for round `r` (counter `t + 1`).
3. A, on its own disk, signs a *different* vote `m_A` for the same round. It writes its file (counter `t + 1`) and then fails at the counter advance. Nothing is returned, but the record stays on A's disk.
4. A is restarted on its own disk. Its file counter equals the trusted counter, so it opens as if committed, holds `m_A`, and would re-send a vote that conflicts with the one B broadcast: slashable equivocation.

The same happens on a shared directory if the fenced-out writer overwrites the file after the new holder committed.

**The amendment.** The counter commits to *which record* each value belongs to, not only to the value.
1. **Counter state** is `(value, digest)`. The initial state is `(0, 0x00 x 32)`. `read()` returns both.
2. **Record digest.** The digest of a record is the SHA3-256 checksum already carried by its encoding (the 32 bytes that seal the record's canonical body). The body therefore must contain everything the digest should bind: the record gains a field `prev_digest`, the digest of the record it replaces (`0x00 x 32` for the first record), so records form a chain.
3. **Commit.** Step 4b becomes `advance(expected = (n - 1, d_(n-1)), new_digest = d_n, session)`: it succeeds only if the counter's current state equals `expected` exactly (value **and** digest) and the session is the latest, and then becomes `(n, d_n)`. Otherwise it fails and changes nothing.
4. **Open rules** (file counter `f`, file digest `d_f`, file `prev_digest` `p_f`; counter `(t, d_t)`):

| Condition | Meaning | Action |
|---|---|---|
| `f == t` and `d_f == d_t` | normal | open |
| `f == t` and `d_f != d_t` | **a fork: a record with the committed counter value that is not the committed record** (a fenced-out writer's leftover, or a file overwritten after the commit) | refuse (fail closed) |
| `f == t + 1` and `p_f == d_t` | the file is a durable successor of the committed record; its advance did not happen; nothing from it was ever returned or sent | complete with `advance((t, d_t), d_f, session)`, as in 7.1 (gated, fail closed if the counter moved) |
| `f == t + 1` and `p_f != d_t` | a successor of some other record | refuse |
| `f < t` | rollback | refuse |
| `f > t + 1` | counter reset or forged file | refuse |

**Crash and fork behavior.**
1. *Crash between file and counter (the 7.1 window).* Unchanged: the file is a successor of the committed record, the recovery advance commits it, and nothing was returned before.
2. *Two writers' files both one ahead (A fenced out, B crashed before its advance).* Both are valid successors of `(t, d_t)`, and **neither signature was ever returned**, so either may be committed. Whichever restarts first completes the advance; the other, on its next open, finds `f == t` with a different digest and is refused. No conflicting message is ever broadcast, because only a committed record's signature is returned.
3. *Fenced-out leftover after the new holder committed (the scenario above).* A's restart finds `d_f != d_t` and refuses. Recovery is key rotation, as for every fail-closed case.
4. *Overwrite after commit on a shared directory.* B's restart finds `d_f != d_t` and refuses; B's own committed record is lost to the file, so B also rotates its key (fail closed, not unsafe).

**Restart validation.** `open` performs, in this order: identity and binding checks; the table above; content verification and chain-evidence staleness; only then session acquisition and any recovery advance. A failed open still never supersedes the running store.

**Cost and compatibility.** The counter backend stores 32 more bytes and must treat the `(value, digest)` pair atomically. The record format gains `prev_digest` and moves to format version 2 (PR #127 is unmerged, so no deployed state exists). The digest reveals nothing about the record's contents beyond a hash of it.

**What it does not change.** It does not stop a holder of the signing key from signing outside the store, and it does not make a lease a signing control (7.1); it only makes the *state* a fenced-out writer leaves behind unusable.

**Required tests once approved** (each must fail on the current implementation): the two-disk scenario above is refused on A's restart; the shared-directory overwrite is refused on B's restart; both files one ahead: the first restart commits, the second is refused, and no conflicting message was ever returned; the recovery advance with `p_f != d_t` is refused; mutants that drop the digest comparison, compare only the value, drop `prev_digest` from the body, or accept `p_f != d_t` are caught. The record format golden vectors are regenerated from the independent oracle.

**Complementary checks, not replacements:** the chain-evidence staleness rule (§7, "Stale file") and the fresh-initialization refusal stay in force; the counter adds detection that does not depend on the chain.

**Operational acceptance requirements** (before any validator runs on a real network; these are not satisfied by the unit tests):
1. A production counter backend, with a written threat model, independently reviewed, and tested against reset, rollback, replacement and two-live-copies attempts on that backend.
2. **Storage durability acceptance on the target hardware, operating system and filesystem:** repeated hard power-loss (or equivalent hard stop with write caches enabled) during signing, showing no torn state file and no `f < t` anomaly. On NTFS this includes establishing what the directory flush actually guarantees. The Windows unit runs show only that the calls succeed.
3. A backup and restore rule: a backup of the safety directory must never be restored onto a live key; restoring is key rotation.
4. Monitoring and an operator procedure for the rollback, inconsistent-counter and unreadable-counter errors.

**What the tests established and did not** (PR #127): in an in-memory model every crash point and every post-crash state reopens and never allows two messages for one round; a restored old file is refused when the counter is separate, and a test asserts that with the file *and* the counter both restored the rollback is invisible. They do not establish durability on any real disk or filesystem, and `TestCounter` proves nothing about a real counter.

**Required changes to PR #127 once this section is approved** (found while writing this section and in the owner's review). Items 1 to 6 are the compare-and-advance and session work; the digest-bound commits of 7.1.1 are a further, separately approved change (item 7):
1. The counter trait becomes compare-and-advance, `advance(expected_previous, session)`, not "advance to the current value or the current value plus one": the current idempotent form lets two live copies sharing one counter both succeed, and the lost-acknowledgement case does not need idempotence.
2. The recovery advance on open (`f == t + 1`) uses the same call, does not open the store or return anything until it succeeds, and fails closed if the counter is no longer `t`. Regression tests: a recovery advance that loses a race; a crash during the recovery advance (both outcomes reopen correctly); no signing before the advance has succeeded.
3. A session (fencing token) is acquired when the store opens and presented on every advance; a stale session is rejected and latches the store. Regression tests with two stores sharing one simulated counter: a stale store cannot commit; a store whose session was superseded latches and stops; the superseded store never returns a signature; the new holder is unaffected.
4. The counter handle is constructed bound to one validator instance.
5. Documentation and tests that call the double a "trusted counter" must say it is not, and the test double must implement the strict semantics.
6. Fresh Linux and Windows validation of the changed implementation.
7. If 7.1.1 is approved: the digest-bound counter state, `prev_digest` in the record (format version 2), the open rules and the required tests of 7.1.1, and regenerated golden vectors; then fresh Linux and Windows validation again.

---

## 8. Personhood weighting and reconfiguration

- **Power:** every validator-set update applies, in this order: `apply_personhood_cap` (bounded per human), then `gate_voting_power` (no personhood or no key gives power 0), then the gate-3 quorum floor. This is the same path the Tendermint engine uses and cannot be bypassed.
- **Epochs:** V_e changes only through a committed epoch-change block. The new set takes effect from the first round of epoch e + 1. A QC or TC is always verified against the set of its own epoch, using the existing `historical_validator_sets`.
- **Revocation:** "without delay" means the revocation takes effect in **the first block after the one that commits the revocation**. That block starts a mini-epoch with the revoked validator at power 0. It cannot take effect mid-round: changing the set inside a round breaks the quorum-intersection argument that §5 relies on. **[decision D4]** Recommendation: apply revocations at the next block, not at the next regular epoch boundary.
- **Key rotation:** reuses PQ-VAL-003 (rotation takes effect at the next block, with a one-block power gap). The same set-change rule applies.

### 8.1 Fresh FIPS 204 validator keys and proof of possession (Phase 2 genesis)

- **Newly generated keys only.** Every genesis validator's ML-DSA-65 key pair is generated fresh through the FIPS 204 signer interface for this genesis. No key is converted, imported or derived from a pre-standard (`dilithium3`) key, a Tendermint devnet key, or any existing key file. Genesis holds **public keys only**; private keys never appear in genesis, in the repository or in a pull request.
- **Genesis entry per validator:** address, `alg_id` 1, the 1952-byte public key, and a proof-of-possession signature envelope.
- **Proof of possession:** the signature is over the §3.2 PoP message with context `qattice/validator-pop/v2`. It binds `chain_id`, the validator address, the public key and `alg_id`, so it fails for another chain, another validator, a substituted key, another algorithm or another context. These are required negative tests (they mirror the existing ML-DSA PoP tests: wrong chain id, cross-validator replay, key substitution).
- **Verification:** at startup, before any consensus state is built, every PoP is verified. Any failure, wrong length, wrong or unpermitted `alg_id`, duplicate key, or a key shared by two validators makes the node refuse to start. Post-genesis registration and rotation use the same message and context.
- **Running nodes need their private keys from somewhere.** How a Phase 2 node stores and loads its key is **not specified here**: persistent validator key storage stays blocked on the independent review of PR #109 (and PR #119 decision 6). Phase 0 uses in-memory keys only, and Phase 2 cannot begin until the owner approves a key-handling approach.
- The key generator, `genesis-4node-pq-hotstuff.json` and their tests are Phase 2 deliverables. Nothing is generated by this revision.

---

## 9. Equivocation

Evidence types:
- **double vote:** two votes, same `(epoch, round)`, different `block_id`.
- **double proposal:** two blocks from the leader of the same round.

Each item of evidence is self-verifying: both signatures check under the offender's key for that epoch (under §3.1, with the right context and `alg_id`).

**Evidence compares canonical signed messages, not signature bytes.** Because signing is hedged (§3.1), two signatures over the *same* canonical vote message differ in bytes and are **not** evidence (a restarted node that re-signs, or a relay that re-sends, never causes slashing). A double vote is two votes by the same voter for the same `(epoch, round)` whose canonical vote messages differ (different `block_id`). Evidence is deduplicated by the hash of the canonical message pair, never by signature bytes. Required tests: re-signing the same vote produces different bytes and no evidence; two different messages produce evidence; the same evidence cannot be included twice.

(A vote followed by a timeout in the same round is **not** evidence; §5 allows it. Lock-violation evidence, such as a timeout whose high QC is below a QC the signer already voted on, is a Phase 3 candidate.)

**Handling must be committed evidence (release gate 4).** Evidence is included in a block's payload. It is validated during proposal checks and applied during execution, identically on every node. A node never slashes from its own local observation. The #24 live run showed what happens otherwise: each node slashes when it happens to see the double vote, node states diverge, and the chain halts. Gate 4 builds this for Tendermint first. PQ-HotStuff reuses it unchanged.

---

## 10. Certificate size under ML-DSA

ML-DSA signatures do not aggregate. A v1 QC carries 2f+1 signatures of 3,309 bytes each.

| Validators n | Quorum | v1 QC size | Leader egress per block (n × QC) |
|---|---|---|---|
| 4 | 3 | ~10 KB | ~40 KB |
| 31 | 21 | ~70 KB | ~2.2 MB |
| 100 | 67 | ~222 KB | ~22 MB |
| 512 | 342 | ~1.13 MB | ~580 MB |

The message count is linear, but bytes grow roughly as n². At one-second blocks, n = 100 already needs about 180 Mbit/s of leader egress.

**[decision D2] Mainnet validator-set ceiling and QC format.**
- **QC v1** (signature list): devnet and testnet, n ≤ ~31.
- **QC v2** (succinct proof of the 2f+1 signatures): this is exactly the M0 question. The M0 targets are ≤ 100 KiB at C = 512 and verify ≤ 50 ms. If M0 meets them, v2 removes the n² term.
- If M0 does not meet them, the fallback is a committee: a per-epoch sample of the personhood pool (the other session's Option C), with n bounded by the v1 budget.

Recommendation: specify the QC as a versioned type now (`QuorumCert::V1 | V2`), build v1, and fix the mainnet ceiling only after M0 reports. Phase 2 measures the real bandwidth.

---

## 11. Chain Forge integration

- **Selection:** `consensus.bft_variant: "pq-hotstuff"`. The engine is **feature-gated**: it is compiled only with an explicit Cargo feature that is not in any default feature set (name proposed: `pq-hotstuff`), and a default build refuses the value. Startup also refuses it unless the genesis profile selects the FIPS 204 backend (§3.1); the label `validator_scheme: "ml-dsa-65"` is not sufficient because on existing chains it means the pre-standard backend. No classical path. Until the §12 Phase 2 gate passes, it is devnet-only, enforced by the same check as gate 2.
- **Engine:** a new module `chain-forge-consensus/src/pq_hotstuff/`. It implements `ConsensusEngine` with `drives_own_votes() = true`, and drives the node through the existing `ConsensusAction` / `next_action` / `on_step_timeout` / `gossip_messages` hooks. It gains new actions: `SendVoteTo(leader)` and `BroadcastTimeout`.
- **Reused unchanged:** the *structure* of key registration, PoP, activation and rotation (PQ-VAL-001/2/3, with the §3.1 identifiers and contexts); payload validation; block-hash agreement; state-root binding; committed-evidence slashing. Signing and verification go through the FIPS 204 signer interface, not `sign_consensus` / `verify_consensus` on the pre-standard backend.
- **Modularity:** shared Chain Forge interfaces (`ConsensusEngine`, `EngineSafetyState`, the genesis `consensus` and `cryptography` sections, engine selection by `consensus.bft_variant`) stay generic, so Tendermint and PQ-HotStuff-2 are selected independently per chain. Qattice-specific choices (this engine, the FIPS 204 profile, personhood weighting) live in the chain's genesis and deployment configuration, never in shared code paths. Adding PQ-HotStuff-2 must not change Tendermint behaviour for any chain that selects it.
- **Other chains:** the engine takes the power function as input. Personhood weighting is mandatory in **Qattice's** genesis profile, where startup refuses `pq-hotstuff` without `personhood_weighted: true`. Another Chain Forge chain can supply stake or equal weights.

---

## 12. Phases and acceptance gates

Each gate follows the project rule: failing tests first, then mutation checks, then sandbox, then **Windows confirmation** before ✅.

**Phase 0 — prerequisites and core engine** (authorized by the owner 2026-11-06 as tests-first draft PRs after this revision is approved)
- **Gate 4** (committed-evidence slashing, on Tendermint) has landed (#26).
- Scope: consensus message types and canonical signing bytes (§3, §3.1); the two-chain commit rule and safety invariants (§5, §6); pacemaker and timeout handling; feature-gated engine selection (§11); deterministic simulation and adversarial safety testing; mutation tests showing that removing each essential safety check makes a test fail. Phase 0 uses in-memory test keys only (no key files).
- Types, signing bytes, the §5 safety rules, the §6 commit rule and the pacemaker. Single-process unit tests:
  - Each safety rule individually.
  - The scripted counterexamples: voting without rule 3 forks across a view change; committing on a non-consecutive QC forks.
  - Each must fail when its rule is removed (mutation-checked).
- **Model-based simulation:** port `tendermint/engine/sim.rs` (staggered start, slow links, crash/restart, Random / SplitBrain / Withhold adversaries within f, fork detection beyond f) to drive PQ-HotStuff.
  - Gate: thousands of seeded runs with agreement, no unsafe signing, and termination after GST.

**Phase 1 — personhood and persistence**
- Wire §7 persistence and §8 reconfiguration.
- Gates:
  - A restarted validator never signs a conflicting vote or timeout.
  - A revocation removes power from the next block.
  - Mid-epoch rotation works.
  - The node refuses non-ML-DSA keys.

**Phase 2 — devnet candidate**
- `genesis-4node-pq-hotstuff.json` (ML-DSA keys from #24).
- The live suite parametrized like `CF_CONSENSUS_KEYS`, with `CF_BFT=pq-hotstuff`: `devnet_4node` (liveness, partition), `consensus_safety_live` (crash/restart, block-hash agreement), `h0_5_atomicity_live`, `mldsa_tx_live`, and an equivocation live test that slashes through committed evidence.
- Bandwidth and finality measured at n = 4, 7, 16, 31.

**Phase 3 — hardening and audit preparation**
- Adversarial cases: revocation mid-round, rotation during a view change, partial participation, leader withholding.
- Independent review of §5–§6 against the papers.
- Operator runbook.

**Phase 4 — mainnet genesis**
- A fresh genesis: PQ-HotStuff, ML-DSA from block 0, the D2 ceiling and QC format, no devnet state.

The Tendermint devnet stays the default until Phase 2 passes on Windows. Phase 2 uses a **fresh genesis and a separate four-node development network** with newly generated keys; the existing Tendermint devnet is not migrated or modified. Removing Tendermint from Qattice's configuration is a separate owner decision after PQ-HotStuff-2 passes its gates and independent review (§1); Tendermint stays available in Chain Forge for other chains in all cases.

**Restrictions on all PQ-HotStuff-2 work (owner, 2026-11-06):** no default consensus change; no network activation; no mainnet change; no automatic signature downgrade or fallback; no change to the existing Tendermint implementation; no production validator key-file change; no merge without separate owner approval. Each implementation PR must carry tests, reviewable changes and documented Windows results before merge approval.

---

## 13. Decisions (locked by the owner, 2026-10-28: all five as recommended)

| # | Decision | Recommendation |
|---|---|---|
| D1 | Two-chain or three-chain commit | Two-chain (DiemBFT v4 / Jolteon rules, §5–§6) |
| D2 | Mainnet validator ceiling and QC format | Versioned QC; build v1 now; set the ceiling after M0 reports |
| D3 | Leader rotation | Round-robin; revisit with devnet data |
| D4 | When a revocation takes effect | The block after the revocation commits (never mid-round) |
| D5 | Order of work | Gate 4 (committed-evidence slashing) first, then PQ-HotStuff Phase 0 |

## 14. Corrections to the direction document

These keep the locked direction. They make two claims precise:
- **"Linear communication":** linear in messages, not bytes. Under ML-DSA the bytes grow roughly as n² until QC v2 or committees (§10).
- **"Identity revocations respected without delay":** effective from the next block, never mid-round (§8). Immediate mid-round removal would break safety.

---

## 15. Owner decisions and open items for review

**Decisions recorded in this revision:**

| | Decision |
|---|---|
| N1 (2026-11-06) | The protocol is designated **PQ-HotStuff-2**; identifiers are unchanged until a reviewed rename. |
| N2 (2026-11-06) | Cryptography decisions 3, 4, 5 of PR #119: backend derived from the versioned profile with explicit algorithm identifiers and no fallback; FIPS 204 ML-DSA-65 hedged signing with equivocation compared on canonical signed messages; the v2 contexts (vote, proposal, validator PoP). |
| N3 (2026-11-06) | The standard signer is consumed by PQ-HotStuff-2 directly; there is no Tendermint wiring in this workstream (PR #119 decision 1). |
| N4 (2026-11-06) | Fresh genesis and a separate four-node development network; the existing Tendermint devnet is not migrated or modified. |
| N5 (2026-11-07) | The timeout context `qattice/timeout/v2` is approved. |
| N6 (2026-11-07) | `alg_id` is an unsigned 16-bit integer, big-endian; value 1 is ML-DSA-65 (FIPS 204); the algorithm identifier is bound into every signed message. |
| N7 (2026-11-07) | The mandatory versioned genesis field is `cryptography.protocol_profile`; the devnet value is `qattice-pq-hotstuff-2-v2` (schema compatibility is in §3.1 and must be verified by tests). |
| N8 (2026-11-07) | The `CFH1` domain tag is retained. No automatic compatibility or signature fallback. |
| N9 (2026-11-07) | Phase 0 uses in-memory keys. Persistent validator key storage stays blocked pending the independent review of PR #109. |
| N10 (2026-11-07) | DIS remains a separate P4 workstream and is not part of this specification. |
| N17 (2026-11-07) | Consensus separation: Qattice will ultimately use PQ-HotStuff-2 as its exclusive production consensus engine, conditional on the safety, persistence, four-node devnet, adversarial and independent-review gates; Tendermint remains the Qattice devnet baseline until then, stays selectable in Chain Forge for other blockchains, is not removed, disabled or modified now, and no existing network is migrated automatically. Removal from Qattice's configuration needs separate approval (§1). |

**Confirmed in the final review (2026-11-07), now reflected in the text:** N11 all canonical integers are big-endian, including `alg_id`; N12 the tags `CFH1|blockid|` and `CFH1|pop|` are approved and `CFH1` is retained; N13 the `cryptography.protocol_profile` design is kept and its documented compatibility tests are required; N14 Phase 0 uses in-memory test keys only; N15 the block identifier commits to all consensus-critical proposal fields with negative substitution tests (§3.2 rules 6 and 7); N16 a missing safety-state file never resets signing history and a fresh validator has an explicit initialization state (§7).

**Proposed, awaiting owner decision (2026-11-07):** §7.1, the trusted monotonic counter as a required security interface, with the failure matrix and the operational acceptance requirements (production counter backend; storage durability acceptance on the target platform). Owner conditions of 2026-11-07, now written into §7.1: the recovery advance returns and broadcasts nothing until it succeeds and fails closed on a concurrent advance; duplicated validators need an exclusive signing session (hardware-enforced, or a fenced lease enforced on every signing operation); key rotation is the only authorized recovery; the first private backend targets a remotely enforced, authenticated, fenced, replicated counter; no backend is production-ready before independent review. Recommended by the owner's review (not yet an approved decision): accept §7.1 as the design basis with the limit of option 2 retained; the first backend is a remotely operated, authenticated, replicated, fenced counter **for the private prototype only**; renewable server-enforced leases with monotonically increasing fencing tokens, duration to be set by failure and latency testing; fail closed and key rotation for rollback recovery, with no counter reset for the same key. This is enough to proceed with updating PR #127's tests and interface once the specification direction is approved; it is **not** enough to declare the production validator security architecture complete. Proposed in 7.1.1 (development of the specification approved by the owner as a proposed amendment; implementation and merge not approved): digest-bound counter commits that close the fenced-out-writer residue. Open choices for the owner: the operator and deployment of the prototype backend; whether and when a trusted signing boundary (option 1) becomes a requirement for a public network.

**Still blocked:** Phase 2 persistent validator key handling. It waits for the independent review of PR #109 and separate owner approval (§8.1). No other specification question is open in this revision; the next gate is owner approval of this text before any implementation.
