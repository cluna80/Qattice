# Chain Forge Institutional Visual Builder — Architecture

## Overview

The Institutional Visual Builder is a React browser UI that wraps the Rust
`chain-forge-institutional` crate. The browser never runs a blockchain engine;
all genesis generation, cryptographic validation, BFT quorum enforcement, and
domain-separator computation run in Rust via the local `chain-forge-service`.

## Component boundaries

```
┌───────────────────────────────────────────────────────────┐
│  Browser (React + TypeScript)                             │
│                                                           │
│  InstitutionalBuilder.tsx  ←→  src/lib/nodeApi.ts         │
│        5-step wizard               fetch wrappers         │
└──────────────────────────────┬────────────────────────────┘
                               │ HTTP  127.0.0.1:7700
┌──────────────────────────────▼────────────────────────────┐
│  chain-forge-service (Rust binary)                        │
│                                                           │
│  GET  /api/institutional/templates                        │
│  POST /api/institutional/validate                         │
│  POST /api/institutional/generate                         │
│  GET  /api/institutional/artifacts/{chain_id}/{filename}  │
│                                                           │
│  Calls: chain-forge-institutional crate                   │
│         ChainSpec::validate()                             │
│         GenesisBuilder::new(spec).build()                 │
└───────────────────────────────────────────────────────────┘
```

## Wizard steps

| Step | Name | Responsibility |
|------|------|---------------|
| 1 | Template | Pick one of 4 institutional templates (GET /templates) |
| 2 | Chain Config | chain_id, chain_name, validator_count, block_time_ms |
| 3 | Advanced | Consensus, cryptography, governance, network |
| 4 | Review | Display summary, POST /generate on confirm |
| 5 | Artifacts | Show genesis_hash, domain_separator, download artifacts |

## Security properties

- The service listens only on 127.0.0.1 and enforces the CORS origin of the wizard UI.
- No private keys are generated or returned by any institutional endpoint.
- Artifact filenames are allowlisted (`genesis.json`, `manifest.json`); the chain_id is validated against the service's `validate_chain_id()` before path construction.
- All sensitive institutional content (patient data, inmate IDs, student PII) is structurally excluded: the genesis only contains cryptographic commitments.

## Privacy model

The `chain-forge-institutional` templates enforce that only `[u8; 32]`
commitment fields (SHA-256 hashes) are written to chain state. Raw
names, identifiers, records, and diagnoses cannot appear on-chain by design.
