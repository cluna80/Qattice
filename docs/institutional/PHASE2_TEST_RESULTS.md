# Phase 2 Test Results — Sovereign Chain Generator

## Summary

**Status: sandbox-confirmed, awaiting local Windows verification**

24 tests passed, 0 failed on `cargo test -p chain-forge-institutional` in the
cloud sandbox (Linux, x86-64). Per CLAUDE.md policy, this milestone is marked
complete only after the developer confirms passing on Windows (MINGW64).

---

## Test Run

```
running 24 tests
test domain::domain_tests::rejects_different_genesis_hash ... ok
test domain::domain_tests::rejects_different_chain_id ... ok
test quorum::quorum_tests::test_bft_quorum_larger_sets ... ok
test quorum::quorum_tests::test_bft_quorum_rejects_insufficient ... ok
test domain::domain_tests::signing_context_differs_across_chains ... ok
test domain::domain_tests::signing_context_is_deterministic ... ok
test tests::test_all_four_templates_validate ... ok
test tests::test_cross_chain_domain_separation ... ok
test quorum::quorum_tests::test_bft_quorum_table ... ok
test tests::test_p2_bft_quorum_table ... ok
test tests::test_p2_cli_validation_errors ... ok
test tests::test_p2_cross_chain_replay_rejection ... ok
test tests::test_p2_duplicate_validator_rejection ... ok
test tests::test_chain_isolation ... ok
test tests::test_genesis_determinism ... ok
test tests::test_p2_genesis_determinism ... ok
test tests::test_p2_invalid_chain_id_rejection ... ok
test tests::test_p2_ml_dsa_key_length_validation ... ok
test tests::test_validate_rejects_low_validator_count ... ok
test tests::test_validate_valid_healthcare_spec ... ok
test tests::test_p2_all_four_templates_genesis ... ok
test tests::test_p2_genesis_no_private_keys ... ok
test tests::test_p2_genesis_mutation_detection ... ok

test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

---

## Phase 2 Test Coverage

### Genesis Determinism (`test_p2_genesis_determinism`)

Builds the same chain spec twice with the same fixed timestamp and validator
keys. Asserts the genesis hashes are identical. Verifies the determinism
guarantee.

### All Four Templates Genesis (`test_p2_all_four_templates_genesis`)

Builds a genesis for each of `healthcare`, `corrections`, `education`, and
`enterprise`. Asserts each succeeds and each produces a unique genesis hash
(domain separation across template types).

### No Private Keys in Genesis (`test_p2_genesis_no_private_keys`)

Verifies that `genesis.json` and `deployment.json` output do not contain
any string matching common private key indicators (`private_key`, `secret`,
`signing_key`, `seed`, `mnemonic`). This is a negative-space safety test.

### Genesis Mutation Detection (`test_p2_genesis_mutation_detection`)

Builds two genesis artifacts with different validator keys. Asserts the
genesis hashes differ. Demonstrates that the hash commits to key material.

### ML-DSA Key Length Validation (`test_p2_ml_dsa_key_length_validation`)

Attempts to register a validator with a 32-byte key under `CryptoPolicy::MlDsa65`.
Expects `InstError::InvalidValidatorKey` (expected 1952 bytes, got 32).

### Duplicate Validator Rejection (`test_p2_duplicate_validator_rejection`)

Attempts to register two validators with the same ID. Expects
`InstError::DuplicateValidator`. Also tests duplicate key bytes under a
different ID.

### Cross-Chain Replay Rejection (`test_p2_cross_chain_replay_rejection`)

Creates two `TransactionDomain` values for two different chains (different
chain IDs, different genesis hashes). Verifies that `accepts()` returns
`false` when chain IDs differ and when genesis hashes differ.

### Invalid Chain ID Rejection (`test_p2_invalid_chain_id_rejection`)

Tests that `validate_chain_id` rejects: empty string, uppercase letters,
underscores, spaces, leading hyphen, trailing hyphen, and strings over 64
characters. Tests that valid lowercase-hyphenated IDs pass.

### BFT Quorum Table (`test_p2_bft_quorum_table`)

Verifies the exact BFT parameter values from the Phase 2 directive:
- n=4 → f=1, quorum=3
- n=7 → f=2, quorum=5
- n=10 → f=3, quorum=7

### CLI Validation Errors (`test_p2_cli_validation_errors`)

Tests `ChainSpec::validate()` rejects: validator count < 4, block_time_ms = 0,
governance threshold 0 and 101, PQ-HotStuff with Ed25519 crypto.

---

## Phase 1 Tests (also passing)

| Test | Status |
|---|---|
| `test_validate_valid_healthcare_spec` | ok |
| `test_validate_rejects_low_validator_count` | ok |
| `test_all_four_templates_validate` | ok |
| `test_genesis_determinism` | ok |
| `test_chain_isolation` | ok |
| `test_cross_chain_domain_separation` | ok |

---

## Windows Verification Command

```bash
git pull origin feature/institutional-chain-forge
cargo build -p chain-forge-institutional
cargo test -p chain-forge-institutional -- --nocapture
```

Expected: `test result: ok. 24 passed; 0 failed`

---

## Known Limitations (Phase 2)

1. **Placeholder keys only**: The CLI and builder tests use test-vector keys
   (repeating byte patterns). Real ML-DSA-65 key generation requires
   `chain-forge-crypto::MlDsaScheme::generate()`, which calls the `pqcrypto`
   native library. This is deferred to Phase 3 key provisioning.

2. **No RNG in genesis**: Genesis production does not call any random number
   generator. Randomness is supplied by the caller (explicit timestamp,
   explicit key bytes). This is by design for determinism.

3. **CLI uses test-vector keys**: The `chain-forge-institutional-cli create`
   command always uses placeholder keys. Production deployment requires
   replacing these with real keys before launch (documented in CLI_GUIDE.md).
