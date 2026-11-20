# Cryptographic Test Matrix — chain-forge-institutional

## Coverage status: sandbox-confirmed; local Windows verification pending.

## Key Management

| Test ID | Description | Phase | Tier |
|---------|-------------|-------|------|
| CK-001 | ML-DSA-65 key: 1952 bytes accepted | 1 | T0 |
| CK-002 | ML-DSA-65 key: wrong length rejected | 1 | T0 |
| CK-003 | Ed25519 key: 32 bytes accepted | 1 | T0 |
| CK-004 | Ed25519 key: wrong length rejected | 1 | T0 |
| CK-005 | Duplicate validator ID rejected | 2 | T0 |
| CK-006 | Duplicate validator key bytes rejected | 2 | T0 |

## Domain Separation

| Test ID | Description | Phase | Tier |
|---------|-------------|-------|------|
| CD-001 | Domain separator differs across chains | 2 | T0 |
| CD-002 | `signing_context()` differs across chains | 2 | T0 |
| CD-003 | `signing_context()` is deterministic | 2 | T0 |
| CD-004 | `accepts()` rejects different chain_id | 2 | T0 |
| CD-005 | `accepts()` rejects different genesis_hash | 2 | T0 |
| CD-006 | `accepts()` accepts matching domain | 2 | T0 |

## Genesis Commitment

| Test ID | Description | Phase | Tier |
|---------|-------------|-------|------|
| CG-001 | Genesis hash is deterministic (same inputs → same hash) | 2 | T0 |
| CG-002 | Genesis hash changes on validator key change | 2 | T0 |
| CG-003 | Genesis hash changes on chain_id change | 2 | T0 |
| CG-004 | Genesis mutation detection (hash covers all fields) | 2 | T0 |

## Credential & Identity

| Test ID | Description | Phase | Tier |
|---------|-------------|-------|------|
| CI-001 | `RoleCredential` accepts valid 1952-byte ML-DSA-65 key | 3 | T0 |
| CI-002 | `RoleCredential` rejects 32-byte key | 3 | T0 |
| CI-003 | `RoleCredential` rejects inverted expiry | 3 | T0 |
| CI-004 | Credential ID is deterministic | 3 | T0 |
| CI-005 | `CredentialVerifier` accepts valid credential | 3 | T0 |
| CI-006 | `CredentialVerifier` rejects wrong chain | 3 | T0 |
| CI-007 | `CredentialVerifier` rejects expired credential | 3 | T0 |
| CI-008 | `CredentialVerifier` rejects revoked credential | 3 | T0 |

## Pending (require `real-pqc` feature + T3)

| Test ID | Description | Phase |
|---------|-------------|-------|
| CP-001 | Sign + verify round-trip with real FIPS 204 ML-DSA-65 | 3+ |
| CP-002 | Forged signature rejected by `verify_consensus` | 3+ |
| CP-003 | Cross-chain signature rejected by `CredentialVerifier` | 3+ |

## Notes

- All tests in Tiers T0–T2 use structural (key-length) checks only.
- Algebraic ML-DSA-65 verification (`chain_forge_crypto::verify_consensus`) is
  called via the `real-pqc` feature, which requires the FIPS 204 backend.
- Production deployments MUST enable `real-pqc` and pass CP-001–003 at T3.
