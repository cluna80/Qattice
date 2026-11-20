# Chain Forge Institutional — Security Invariants

## Status: ACTIVE — Do not weaken without owner approval.

These invariants are enforced by the codebase and must remain intact across
all future changes. Any PR that breaks an invariant must not be merged.

---

## INV-001: No Private Key Storage

**Invariant:** No type in `chain-forge-institutional` accepts, stores, or
serializes private key material.

**Enforcement:** `ValidatorPublicKey`, `RoleCredential`, and all genesis
artifact types accept only public key bytes. The `GenesisBuilder::with_validator`
method accepts `ValidatorPublicKey` (public key only).

**Test coverage:** `test_genesis_no_private_keys_in_artifact` (genesis_tests)

---

## INV-002: Duplicate Validator Rejection

**Invariant:** `GenesisBuilder` rejects duplicate validator IDs and duplicate
public key bytes, even under different IDs.

**Enforcement:** `GenesisBuilder::with_validator` checks both ID uniqueness and
key-byte uniqueness before inserting.

**Test coverage:** `test_genesis_rejects_duplicate_validator_id`,
`test_genesis_rejects_duplicate_validator_key`

---

## INV-003: BFT Quorum Invariant

**Invariant:** All institutional chains must satisfy `n ≥ 3f + 1` with
`quorum = n − f`. Chains with fewer than 4 validators are rejected.

**Enforcement:** `bft_quorum(n)` returns an error for `n < 4`. `ChainSpec::validate`
enforces `validator_count ≥ 4`.

**Test coverage:** `test_bft_quorum_table`, `test_bft_quorum_rejects_insufficient`

---

## INV-004: Cross-Chain Replay Protection

**Invariant:** Transaction signing contexts are chain-scoped. A valid signature
on chain A cannot be replayed on chain B.

**Enforcement:** `TransactionDomain::signing_context()` binds every signed payload
to `chain_id`, `genesis_hash`, and `protocol_version`. `accepts()` requires all
three to match exactly.

**Test coverage:** `rejects_different_chain_id`, `rejects_different_genesis_hash`,
`signing_context_differs_across_chains`

---

## INV-005: Deterministic Genesis Hash

**Invariant:** Given the same inputs (chain ID, validators, template, timestamp),
`GenesisCommitment::hash()` always produces the same SHA-256 hex output.

**Enforcement:** Validator commitments are sorted by `validator_id` before
serialization. Timestamp is explicit when reproducibility is required.

**Test coverage:** `test_genesis_hash_is_deterministic`,
`test_genesis_hash_changes_with_validator_key`

---

## INV-006: Domain Separator Isolation

**Invariant:** Each chain's domain separator is unique: `SHA-256(chain_id | template_id | template_version)`. Different chains with the same template get different separators.

**Enforcement:** `ChainSpec::domain_separator()` includes the `chain_id` in the
pre-image.

**Test coverage:** `test_domain_separator_differs_across_chains`

---

## INV-007: Credential Chain Binding

**Invariant:** `CredentialVerifier` rejects credentials issued for a different
chain. A credential from chain A cannot be used to authorize on chain B.

**Enforcement:** `CredentialVerifier::verify_structural` checks
`cred.chain_id == verifier.chain_id` before any other check.

**Test coverage:** `verifier_rejects_wrong_chain`

---

## INV-008: Key Rotation Revokes Old Key

**Invariant:** When a key is rotated in `KeyRegistry`, the old key is immediately
moved to the revoked set. It cannot be re-enrolled or re-used.

**Enforcement:** `KeyRegistry::rotate` calls `revoked_keys.insert(old_hex)` before
inserting the new key.

**Test coverage:** `key_registry_rotate_revokes_old`

---

## INV-009: No Sensitive Institutional Data in Tests

**Invariant:** No test fixture contains real patient, student, correctional, or
enterprise-sensitive information. All test identifiers are opaque strings or
numeric indices.

**Enforcement:** Code review policy. Test labels use generic strings like
`"org-1"`, `"identity-1"`, `"hospital-network"` — never real names, IDs, or
records.

---

## INV-010: ML-DSA-65 Key Length Enforcement

**Invariant:** All `ValidatorPublicKey` and `RoleCredential` instances with
type `MlDsa65` must have exactly 1952 bytes. Ed25519 keys must have exactly
32 bytes.

**Enforcement:** `ValidatorPublicKey::validate()` and `RoleCredential::new()`
both perform byte-length checks and return errors on mismatch.

**Test coverage:** `test_valid_mldsa_key_accepted`, `test_invalid_mldsa_key_rejected`,
`role_credential_rejects_wrong_key_length`
