# Genesis Specification — Institutional Chain Forge

## Overview

The institutional genesis system produces a **deterministic, cryptographically committed
genesis document** for each sovereign L1 chain. Every field that affects consensus
(validator identity, cryptographic policy, protocol version, governance parameters)
is included in the genesis hash. Changing any field changes the hash.

---

## Genesis Hash Computation

```
genesis_hash = SHA-256(canonical_bytes(GenesisCommitment))
```

### GenesisCommitment fields (in canonical serialization order)

| Field | Type | Description |
|---|---|---|
| `chain_id` | string | Lowercase, hyphen-separated chain identifier |
| `template_id` | string | `healthcare` / `corrections` / `education` / `enterprise` |
| `template_version` | string | Semver string, e.g. `0.1.0` |
| `consensus_profile` | string | `tendermintbft` or `pqhotstuff2` |
| `crypto_policy` | string | `pqc-native` / `classical` / `hybrid` |
| `protocol_version` | string | Protocol semver, e.g. `0.1.0` |
| `genesis_timestamp` | u64 | Unix seconds (must be fixed for reproducibility) |
| `validator_commitments` | array | Sorted by `validator_id` (lexicographic) |
| `governance_config_hash` | hex string | SHA-256 of canonical governance JSON |
| `initial_state_root` | hex string | SHA-256 of initial state (all-zero for empty) |
| `domain_separator` | hex string | Chain domain separator (see below) |

### ValidatorCommitment fields

| Field | Type |
|---|---|
| `validator_id` | string |
| `public_key_bytes` | byte array (ML-DSA-65: 1952, Ed25519: 32) |
| `public_key_type` | `"ml-dsa-65"` or `"ed25519"` |
| `voting_weight` | u64 (always 1 for institutional chains) |

Validator commitments are **sorted by `validator_id`** before hashing to ensure
canonical ordering regardless of registration order.

---

## Domain Separator

Each chain has a unique domain separator that binds transactions to exactly
one chain, preventing cross-chain replay attacks.

```
domain_separator = SHA-256(chain_id_bytes || template_id_bytes || template_version_bytes)
```

This is a one-way commitment. Two chains with identical parameters but different
chain IDs have different domain separators. The domain separator is included in
the genesis hash.

### TransactionDomain

The `TransactionDomain` struct (in `chain_forge_institutional::domain`) carries:
- `chain_id: String`
- `genesis_hash: [u8; 32]`
- `protocol_version: u32`

Its `signing_context()` method produces a deterministic byte string for use
as a signing context. Its `accepts(tx_domain)` method rejects any transaction
whose chain_id, genesis_hash, or protocol_version does not exactly match.

---

## Determinism

For reproducible genesis hashes:

1. **Fix the timestamp**: pass `--timestamp <unix-secs>` to the CLI, or call
   `GenesisBuilder::with_explicit_timestamp(ts)` in code.
2. **Same validator keys**: use the same public key bytes for each validator slot.
3. **Same spec fields**: all fields in `ChainSpec` are deterministic.

Without a fixed timestamp, each build produces a different genesis hash.

---

## Key Length Requirements

| Crypto Policy | Public Key Size | Key Type String |
|---|---|---|
| ML-DSA-65 (default) | 1952 bytes | `ml-dsa-65` |
| Ed25519 | 32 bytes | `ed25519` |
| Hybrid | 1952 bytes (ML-DSA-65 component) | `hybrid-mldsa65-ed25519` |

The genesis builder validates key lengths and rejects incorrect sizes with
`InstError::InvalidValidatorKey`.

---

## BFT Quorum Requirements

The minimum validator count is **4** (the minimum for `f=1` with the `3f+1` model).

| n | f (max faulty) | quorum (min votes) |
|---|---|---|
| 4 | 1 | 3 |
| 7 | 2 | 5 |
| 10 | 3 | 7 |
| 13 | 4 | 10 |

Formula: `f = floor((n-1)/3)`, `quorum = n - f`.

---

## Governance Config Hash

The governance configuration is serialized to canonical JSON and hashed:

```json
{
  "approval_threshold_pct": 51,
  "execution_delay_blocks": 100,
  "constitutional_governance": false
}
```

The hash binds the governance parameters to the genesis without including the
full governance object in the genesis hash input (which could be large).

---

## Artifact Files

The CLI produces four files:

| File | Contents |
|---|---|
| `genesis.json` | Full genesis document (chain-forge-core compatible) |
| `validator-enrollment.json` | Per-validator identity and quorum params |
| `deployment-manifest.json` | Chain ID, template, consensus, genesis hash |
| `validation-report.json` | Validated fields and warnings |

---

## Production Key Replacement

**All generated artifacts use test-vector placeholder keys** (repeating byte patterns).
Before launching any chain (devnet, testnet, or mainnet), replace every
`public_key_hex` in `genesis.json` and every entry in `validator-enrollment.json`
with real ML-DSA-65 public keys from a secure key-provisioning process.

Private keys must never appear in genesis files or source control.
