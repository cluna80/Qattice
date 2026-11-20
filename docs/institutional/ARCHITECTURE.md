# Chain Forge Institutional Edition — Architecture

**Branch:** `feature/institutional-chain-forge`
**Audited commit:** `7e716771c83ad662b0e3c2d157b040c0de6180d2`
**Date:** 2026-11-20

---

## 1. Existing Architecture

### Workspace layout

The Chain Forge workspace contains 33 crates. The institutional framework adds one more: `chain-forge-institutional`.

| Crate | Role |
|---|---|
| `chain-forge-core` | Shared primitives: `GenesisConfig`, `ChainHash`, `Address`, `HashWidth`. Every other crate imports this. |
| `chain-forge-crypto` | Crypto-agility layer: `SignatureScheme` trait, `ClassicalScheme` (Ed25519), `PqcScheme` (ML-DSA/Dilithium), `HybridScheme`. Features: `real-crypto`, `real-pqc`, `fips204-backend`. |
| `chain-forge-consensus` | Pluggable BFT interface: `ConsensusEngine` trait. Variants: Tendermint (default), HotStuff, XRPL-FBA. Personhood-weighted voting power is an opt-in config. |
| `chain-forge-state` | Merkleized account state tree; snapshots; persistence to `state.json`. |
| `chain-forge-execution` | Sequential transaction dispatch. Module gating via genesis `modules` list. Gas models: fixed, dynamic, EIP-1559-style. |
| `chain-forge-identity` | Proof-of-personhood: `VerificationTier`, `IdentityRecord`, `IdentityStore`, attestation graph, liveness enforcement. |
| `chain-forge-governance` | Two-tier governance: ordinary (simple majority) and constitutional (two-thirds supermajority). |
| `chain-forge-validators` | Validator set management, bonding, epoch rotation. |
| `chain-forge-slashing` | Evidence collection and deterministic slash penalties. |
| `chain-forge-p2p` | libp2p transport, Gossipsub, bootstrap / mDNS discovery, state sync. |
| `chain-forge-agents` | Sponsored agent authorization for verified human sponsors. |
| `chain-forge-node` | Binary: wires all crates; HTTP API; CLI argument parsing. |
| `chain-forge-service` | Service binary for the wizard frontend: manages local chain processes. |
| `chain-forge-keygen` | Key generation tool. |
| `chain-forge-vca-pq` | Personhood-weighted adaptive quorum (`VcaRegistry`, `WeightConfig`). |

### Genesis flow

1. The Chain Forge wizard (frontend) produces a JSON file matching `GenesisConfig` in `chain-forge-core`.
2. `chain-forge-node` deserializes and validates it via `GenesisConfig::validate()` and related resolvers.
3. `compute_genesis_hash()` in `chain-forge-core` produces a deterministic SHA3-256 hex hash of the canonical JSON.
4. The node initializes state, consensus, identity, and execution using the validated config.

### Crypto stack

- **Ed25519** via `ed25519-dalek` (feature `real-crypto`): transaction signing and legacy validator keys.
- **ML-DSA-65 / Dilithium** via `pqcrypto-dilithium` (feature `real-pqc`) and `fips204` crate (feature `fips204-backend`): post-quantum signing and validator keys for PQ-HotStuff-2.
- Genesis `cryptography.signature_scheme` selects the active policy: `"classical"`, `"hybrid"`, or `"pqc-native"`.
- `AccountSignaturePolicy::MlDsaOnly` enforces ML-DSA-65 at API admission, gossip intake, and execution.

### BFT variants

Resolved from `genesis.consensus.bft_variant`:
- `"tendermint"` (default) — Tendermint BFT with proposer rotation and lock safety.
- `"hotstuff"` — HotStuff-style BFT.
- `"xrpl"` — XRPL-inspired federated Byzantine agreement.
- `"pq-hotstuff"` — PQ-HotStuff-2 with ML-DSA-65 validator signatures (devnet gate 2).

---

## 2. Proposed Institutional Extension

### New crate: `chain-forge-institutional`

Located at `chain-forge-institutional/` (workspace root level, matching existing crate layout).

**Responsibility:** Institutional template engine — validates chain specs for institutional deployments, generates deterministic genesis artifacts compatible with the existing `GenesisConfig` schema, and provides a CLI entry point for `chain-forge institutional create`.

**Dependencies:** `chain-forge-core` (for `GenesisConfig` compatibility), `serde`, `serde_json`, `sha2`, `thiserror`, `chrono`.

**Does not depend on:** `chain-forge-node`, `chain-forge-consensus`, `chain-forge-execution`, or any network/runtime crate. The template engine is a build-time tool, not a runtime component.

### Integration points

| Existing interface | How institutional crate attaches |
|---|---|
| `GenesisConfig` (`chain-forge-core`) | `GenesisBuilder::build()` produces a `GenesisConfig` value. No fields added or removed — purely constructing the existing type. |
| `compute_genesis_hash()` (`chain-forge-core`) | Called on the produced `GenesisConfig` to get the canonical genesis hash. |
| `BftVariant` enum (`chain-forge-core`) | Read for validation; not modified. |
| `AccountSignaturePolicy` (`chain-forge-core`) | Read for validation; not modified. |
| `chain-forge-node` CLI | Additive: `institutional` subcommand added as a separate match arm in `main.rs`, or as a separate binary `chain-forge-institutional-cli`. |

### Four institutional templates

Each template maps to a `GenesisConfig` profile:

| Template | `consensus_type` | `signature_scheme` | `modules` | Key policy |
|---|---|---|---|---|
| Healthcare L1 | `proof-of-authority` | `pqc-native` (ML-DSA-65) | `bank`, `identity`, `governance` | ML-DSA-65 required |
| Corrections L1 | `proof-of-authority` | `pqc-native` | `bank`, `identity`, `governance` | ML-DSA-65 required |
| Education L1 | `proof-of-authority` | `pqc-native` | `bank`, `identity`, `governance` | ML-DSA-65 required |
| Enterprise L1 | `proof-of-authority` | `hybrid` or `pqc-native` | `bank`, `identity`, `agents`, `governance` | Configurable |

All institutional chains:
- Use `proof-of-authority` consensus by default (permissioned validator set, no token staking).
- Disable `faucet_enabled`.
- Set `relaxed_limits: false`.
- Omit `native_token.max_supply` (no circulating cryptocurrency required).
- Use `environment.mode = "devnet"` for initial generated configs.

### Domain separation

Each institutional chain gets a `domain_separator` field in its genesis (stored in `GenesisConfig`'s extensible JSON structure via a metadata wrapper):

```
domain_separator = SHA-256(chain_id || "|" || template_id || "|" || template_version)
```

This ensures:
- Validator credentials from one chain cannot authenticate on another.
- Transactions signed for one chain cannot be replayed on another (cross-chain replay protection).

---

## 3. What is NOT changed

- No existing crate files are modified except additive changes to workspace `Cargo.toml` and optionally `chain-forge-node/src/main.rs`.
- No existing `GenesisConfig` fields are removed or renamed.
- No Qattice-specific chain behavior is altered.
- No consensus safety rules are changed.
- No cryptographic verification is weakened.
