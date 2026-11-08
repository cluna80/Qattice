# Payload-free headers and header-chain verification (Step 1)

Code: `chain-forge-consensus/src/pq_hotstuff/header.rs`, header codec in `netmsg.rs`. **Block identity is unchanged.** DRAFT; payloads are `devnet-interim`. Nothing here
installs a snapshot or prunes anything; both stay gated.

## 1. Demonstration: a payload-free header reconstructs the existing signed block id
`block_id_of` hashes a `BlockIdInput { alg_id, protocol_profile, chain_id, epoch, round, height, parent_id, payload_hash = SHA3-256(payload), qc_hash = H(qc),
tc_hash = H(tc), proposer address }`. The payload enters only through its 32-byte hash, and the parent certificate and TC only through their hashes. A header that keeps every
other field and replaces the payload bytes with that hash therefore feeds the same input and gets the same id. `PayloadFreeBlock::id` builds exactly that input;
test `a_payload_free_header_reconstructs_the_same_block_id_and_binds_exactly_one_payload` asserts equality with `block_id_of` for every block of a real run (including blocks
with timeout certificates), that a different payload is a different block while the header still binds the original, and that changing the payload hash or round changes the id.
The proposer signature covers `BlockSigningMessage { alg_id, block_id }`, so it verifies from the header alone. **No specification change is needed for this step.**

## 2. What the verifier checks (`verify_header_chain`)
For a linear, oldest-first run of headers from genesis (or a trusted FINAL anchor): epoch; round non-zero; proposer is the round's leader (same `leader_index` and seed as the
engine); the id; the proposer signature; parent link (`parent_id` equals the previous header's id, or the genesis id / anchor id for the first); the parent certificate
(`verify_cert`: validator-set hash, bitmap length, signer power at least the quorum, every vote signature); the certificate certifies `parent_id`; height is previous plus one;
the certificate's round equals the parent's round (stricter than the engine, which relies on honest voters signing their block's own round; fail closed); the round is above
the certificate's round; the timeout certificate is present exactly when the round is not the certificate's successor, verified, and for the previous round (`verify_tc`);
chain and genesis binding (the genesis certificate is derived from profile, chain id, genesis hash and validator-set hash, and every certificate must match it). Finality uses the
engine's own predicate `commits_parent`: when a header's QC certifies block C and C's parent P is exactly one round earlier, P and its ancestors are final; a genesis parent is never
"committed"; an optional QC for the last header finalizes one more block. Differential tests assert the verifier's final blocks equal `Engine::committed_after(0)` on healthy runs and
on runs with a silent validator (timeout certificates and round gaps), and that a chain verified in segments from a final anchor gives the same finality as the whole.

## 3. What it does NOT establish
* **Application state.** No block commits to a state digest, so headers authenticate committed history (ids, payload hashes, finality) and nothing about state. A snapshot cannot be
  verified from them. That needs a state commitment inside the signed id (option C below) or a separately specified attestation.
* **The payload size limit.** The id commits to the payload's hash, not its length. A header cannot enforce `max_block_payload_bytes`; `check_payload` does, with the hash, when a payload is fetched.
* **Anything about forks or the unfinalized tip.** Valid and linked is not final. Only `finalized` is final.
* **Anchors.** An `Anchor` is trusted input; it must be a block already verified and final.

## 4. Actual certificate and header sizes (equal power; signer count matters)
Encodings: `QC(n, k) = 140 + ceil(n/8) + 3315 k`; `TC(n, k, nested QC(n, k')) = 72 + ceil(n/8) + 3323 k + QC(n, k')`; header `= 3410 + QC`, plus `4 + TC` when it carries one.
`k` is the number of signers. The quorum is `floor(2n/3) + 1` signers for equal power. A certificate may legally carry MORE signers than the quorum (`check_header` requires only power at
least the quorum), so a protocol bound must assume `k = n` unless the specification caps it.

| n | quorum k | QC (k) | QC (all n) | TC (k, nested k) | TC (all n) | header, plain (k) | header with TC (k) | proposal, 64 KiB payload (k) | proposal, empty payload (all n) |
|---|---|---|---|---|---|---|---|---|---|
| 4 | 3 | 10,086 | 13,401 | 20,128 | 26,766 | 13,496 | 33,628 | 99,148 | 43,565 |
| 31 | 21 | 69,759 | 102,909 | 139,618 | 205,998 | 73,169 | 212,791 | 278,311 | 312,305 |
| 100 | 67 | 222,258 | 331,653 | 444,984 | 664,038 | 225,668 | 670,656 | 736,176 | 999,089 |
| 1000 | 667 | 2,211,370 | 3,315,265 | 4,428,008 | 6,638,462 | 2,214,780 | 6,642,792 | 6,708,312 | 9,957,125 |

**Corrections to earlier reports.** (1) A 1,000-validator TC with exactly 667 signers is 4,428,008 bytes (the 4.4 MB figure). My earlier 6,638,462 and "3.3 MB" figures were the
all-1,000-signers maximum, not the cost of a minimal certificate. (2) The statement that an 8 MiB limit "does not fit a 1,000-validator proposal" (9,957,125 bytes) is true only for the
all-signers worst case with an empty payload; with quorum-sized certificates a proposal carrying a QC, a TC and a 64 KiB payload is 6,708,312 bytes and fits. The driver's startup
rejection is correct for the current rules (a legal certificate may carry up to n signatures) but conservative. Whether to cap the signer count (for example a canonical minimal quorum)
is a specification decision, not made here; it would also bound header-sync cost at 1,000 validators to about 2.2 MB per plain header (6.6 MB with a TC), which is still large.

## 5. Measured verification and replay cost (real FIPS 204 ML-DSA-65, four validators, Linux release build; one run)
* Header-chain verification: 151 headers in 84 ms = **0.56 ms per header** (a plain header costs one proposer signature plus three vote signatures, so about 0.14 ms per verification), average 13,430 bytes per header.
* Full restart of a node with 152 stored blocks (every block re-validated, 150 heights replayed into a fresh executor): 93 ms = **0.61 ms per block**.
* Scaling (computed from the per-signature figure, NOT measured): cost is proportional to the signer count. A header at 1,000 equal-power validators carries 667 vote signatures, about 94 ms to verify, so 1,000 headers take about 94 s and a header with a TC about twice that.
At four validators replay is cheap (1,000 blocks in well under a second); the S2 checkpoint interval is therefore not driven by replay cost on the devnet, only by the future real executor and by validator count.

## 6. Validation (Linux, sandbox) — NOT closed; Windows confirmation pending (CLAUDE.md)
Base `ac3624f391ba5ea5e6015232500067b59b6c83ba` (PR 4 head); this is Step 1 on a separate stacked branch `feat/pq-hotstuff-2-block-headers`.
| Suite | Result | Time |
|---|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204` | 77 passed, 2 ignored (diagnostics) | 20 s |
| same, `PQHS_SEEDS=60` | 77 passed, 2 ignored | 107 s |
| doubles `pq_hotstuff_engine` | 77 passed, 2 ignored | 43 s |
| foundation / safety / safety_fips204 / wire | 30 / 76 / 11 / 24 passed | <1 s |
| consensus lib / core lib / p2p lib | 98 / 74 / 21 passed | — |
| node default check, `--features pq-devnet` check, `pq_devnet` unit tests, LIVE four-node test | ok, ok, 4 passed, 1 passed | 38 s live |
New tests (shared body, so each runs on the doubles and on real signatures): header id equals `block_id_of` for every block of a run with timeout certificates, and binds exactly one payload; header codec round trip, canonical re-encoding,
every truncation and trailing byte rejected; verifier agrees with `Engine::committed_after(0)` on healthy and silent-validator runs; finality equals an independent oracle at EVERY prefix, with and without a final certificate; segments from a
final anchor give the same finality; each check rejects a correctly re-signed invalid chain (epoch, round 0, leader, height, parent link, certificate/parent mismatch, round ordering, TC presence/forgery/wrong round, sub-quorum and forged QC,
signature, payload hash, missing/duplicated/swapped headers, other chain/genesis/profile/validator set/seed, final-certificate block and round); size formulas match the real encodings.

Mutation check (`mut_header.py`, 28 mutants of `header.rs` and the header codec, doubles suite, build errors not counted): first run 21 of 28 caught. Survivors and causes: finality across round gaps (the end-of-chain comparison hid it, because later
commits cover earlier ancestors), certificate-block / round-ordering / TC-verification / TC-round / final-certificate block and round checks (each masked by a neighbouring check unless a valid certificate aimed only at it was used). Tests added
(the prefix oracle and valid-certificate-per-check cases); second run **28 of 28 caught**.

Changes outside the new files: `netmsg.rs` gains `encode_header`/`decode_header` and one import; `mod.rs` one module line; the shared test suite and its two crates' imports. Block identity, the engine, the driver, the safety store and the node are unchanged.

## 7. Windows (owner to run; record separately)
```
git fetch origin feat/pq-hotstuff-2-block-headers && git checkout feat/pq-hotstuff-2-block-headers && git rev-parse HEAD
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204 2>&1 | grep -E "test result|FAILED"
cargo test --release -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine 2>&1 | grep -E "test result|FAILED"
```
Add `-- --ignored --nocapture diag_header` to the first command to print the replay-cost diagnostic on Windows.

## 8. Windows results (supplied by the owner; MINGW64, `C:\Dev\qattice-main-wt`, branch `feat/pq-hotstuff-2-block-headers`) — recorded separately
`git rev-parse HEAD` printed **`6d45a7fb658ebb13185459e8008e33daa9a5c90a`** in the paste, so the revision is confirmed by the output. Release mode:
| Run | Result | Time |
|---|---|---|
| real ML-DSA-65 `pq_hotstuff_engine_fips204`, default seeds | 77 passed, 0 failed, 2 ignored | 183.77 s |
| doubles `pq_hotstuff_engine`, default seeds | 77 passed, 0 failed, 2 ignored | 423.08 s |
Not run on Windows for this revision: the 60-seed soak, the live four-node test, and the ignored replay-cost diagnostic. This closes no milestone; Step 1 only authenticates committed history.
