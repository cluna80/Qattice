# Compatibility Matrix — Institutional Extension

**Audited commit:** `7e716771c83ad662b0e3c2d157b040c0de6180d2`

Status legend:
- **COMPATIBLE** — additive; no changes to existing interfaces required.
- **ADAPTER** — requires a small adapter; existing interface unchanged.
- **INCOMPATIBLE** — requires approval before proceeding.

---

## chain-forge-core

| Interface | Status | Notes |
|---|---|---|
| `GenesisConfig` struct | COMPATIBLE | `GenesisBuilder` constructs it; no fields added. |
| `compute_genesis_hash(genesis: &GenesisConfig) -> String` | COMPATIBLE | Called directly; not modified. |
| `GenesisConsensus` struct | COMPATIBLE | Populated by builder; `consensus_type = "proof-of-authority"` is an existing recognized value. |
| `GenesisCryptography` struct | COMPATIBLE | `signature_scheme = "pqc-native"` is an existing recognized value. |
| `GenesisEnvironment` struct | COMPATIBLE | Used as-is. |
| `BftVariant` enum | COMPATIBLE | Read-only by template engine for validation. |
| `AccountSignaturePolicy` enum | COMPATIBLE | Read-only. |
| `HashWidth` enum | COMPATIBLE | Used for domain separator computation. |
| `ChainHash` | COMPATIBLE | Used for domain separator computation. |
| `EnabledModules` struct | ADAPTER | Institutional templates specify modules as `Vec<String>` in genesis. No struct change needed; the existing `modules` field in `GenesisConfig` is already `Vec<String>`. |
| `GenesisToken` struct | COMPATIBLE | Institutional chains set a placeholder token with no max supply. |

## chain-forge-crypto

| Interface | Status | Notes |
|---|---|---|
| `SignatureScheme` trait | COMPATIBLE | Institutional crate does not implement this trait; it only references scheme names as strings in genesis config. |
| `fips204-backend` feature | COMPATIBLE | Used by node at runtime; template engine does not invoke crypto directly. |
| `CryptoPolicy` (new institutional enum) | COMPATIBLE | Institutional crate defines its own enum that maps to genesis string values. No collision with existing types. |

## chain-forge-consensus

| Interface | Status | Notes |
|---|---|---|
| `ConsensusEngine` trait | COMPATIBLE | Not touched by template engine. |
| BFT variant selection via genesis string | COMPATIBLE | Template engine sets `bft_variant = None` (Tendermint default) or `"hotstuff"`. PQ-HotStuff-2 available when feature-gated. |
| Validator set size validation | COMPATIBLE | Template engine independently validates `3f+1` quorum before passing to genesis. |

## chain-forge-identity

| Interface | Status | Notes |
|---|---|---|
| `IdentityStore`, `IdentityRecord` | COMPATIBLE | Not used by template engine. Runtime use unchanged. |
| `identity` module gating | COMPATIBLE | Templates include `"identity"` in genesis modules list. |

## chain-forge-governance

| Interface | Status | Notes |
|---|---|---|
| `GovStore`, `Proposal` | COMPATIBLE | Not used by template engine. |
| `governance` module gating | COMPATIBLE | Templates include `"governance"` in modules list. |

## chain-forge-validators

| Interface | Status | Notes |
|---|---|---|
| `ValidatorSet` | COMPATIBLE | Template produces genesis accounts with `role = "validator"`. Existing validator admission logic unchanged. |

## chain-forge-node

| Interface | Status | Notes |
|---|---|---|
| Existing `--genesis` / `--validator` / `--api-port` CLI args | COMPATIBLE | Not changed. `institutional` subcommand added as a new match arm only. |
| `main()` argument parsing | ADAPTER | Add one `"institutional"` arm to the existing `match` on `args[1]`. If this requires structural refactor, use a separate binary `chain-forge-institutional-cli` instead. |

## chain-forge-service

| Interface | Status | Notes |
|---|---|---|
| `POST /api/chains` | COMPATIBLE | Not changed. Institutional chains use the same endpoint after genesis is generated. |
| `POST /api/qattice-devnets` (PR #6) | COMPATIBLE | Separate endpoint; no collision. |

## Flags requiring approval before proceeding

None identified. All institutional additions are additive. The only near-incompatibility is the `chain-forge-node` CLI adapter — if the existing argument parsing is too rigid to add a subcommand cleanly, a separate binary is used instead, avoiding any modification to the existing node binary.

## Pre-existing compile errors (not caused by institutional work)

| Crate | Error | Action |
|---|---|---|
| `chain-forge-intelligence` | `NewTask`, `NewExperimentResult` missing fields in tests | Pre-existing; do not fix in this branch. |
| `chain-forge-consensus` | `CommitCertificate`, `Vote` missing `epoch` field in tests | Pre-existing; do not fix in this branch. |
| `chain-forge-vca-pq` (tests) | `VcaValidatorRecord` missing fields | Pre-existing; do not fix in this branch. |
