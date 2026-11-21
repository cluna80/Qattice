---
name: codebase-design
description: >
  Structural design reference for Qattice / Chain Forge. Load this skill before
  adding a new crate, module, public API, or cross-crate abstraction. Triggers on:
  "where should I put this", "which crate owns X", "how should this be structured",
  "new module for", "new crate for", "refactor into", "split out", or any task
  that introduces new files, types, or crate boundaries. Also load it when
  onboarding to the codebase for the first time in a session, or before any task
  that touches more than one crate.
---

# Codebase Design

A living map of the workspace structure, ownership rules, and design conventions
for Chain Forge / Qattice. Keep this file up to date when new crates are added.

## Crate map

| Crate | Owns | Do not put here |
|-------|------|-----------------|
| `chain-forge-core` | Genesis config, primitive types, shared constants | Business logic, networking |
| `chain-forge-crypto` | Key generation, signing, verification, ML-DSA / Ed25519 | State, storage, networking |
| `chain-forge-consensus` | Validator sets, votes, certificates, engine trait, PQ-HotStuff engine | Execution, storage, API |
| `chain-forge-execution` | Tx execution, state machine, gas, account model | Consensus, networking |
| `chain-forge-validators` | Validator registry, jail records, bond tracking, epoch logic | Crypto primitives, execution |
| `chain-forge-identity` | Identity registry, attestation ledger, sybil detection | Validator logic, consensus |
| `chain-forge-slashing` | Slashing logic, equivocation evidence processing | Validator registry state |
| `chain-forge-agents` | Agent store, capacity advertisements | Consensus, execution |
| `chain-forge-node` | Node wiring, HTTP API, P2P, sync, test harness entry points | Core logic — keep this crate thin |

## Where does new code go?

1. **New type used by multiple crates** → `chain-forge-core` if it's a primitive
   (a hash, an address, a genesis field); otherwise the crate that owns its domain.
2. **New crypto operation** → `chain-forge-crypto`. Never implement signing,
   verification, or key derivation in any other crate.
3. **New consensus rule or engine behaviour** → `chain-forge-consensus`.
   Never add consensus logic in `chain-forge-node`.
4. **New validator lifecycle rule** (jail, unbond, epoch transition) →
   `chain-forge-validators`.
5. **New transaction type or execution rule** → `chain-forge-execution`.
6. **New HTTP API endpoint** → `chain-forge-node/src/api.rs`. Handler must be
   thin: validate input, call a `Node` method, return JSON. No logic in the handler.
7. **New node-level integration test that spawns processes** →
   `chain-forge-node/tests/`. Unit logic stays in `#[cfg(test)]` inside the owning crate.
8. **New genesis config field** → `chain-forge-core::GenesisConfig`, then update
   every genesis JSON file in `tests/devnet/` and document the field in ROADMAP.md.

## Naming conventions

- Crate names: `chain-forge-<domain>` (kebab-case)
- Module files: `snake_case.rs`, one clear concept per file
- Public types: `PascalCase`; internal helpers: `snake_case`
- Integration test files: `<feature>_live.rs` (spawns real node processes)
- Genesis files: `genesis-<descriptor>.json` in `tests/devnet/`

## Cross-crate dependency rules

Dependency flow is strictly downward — lower crates must never import higher ones:

```
chain-forge-node          ← top of stack, may import any crate
  chain-forge-execution
  chain-forge-validators
  chain-forge-identity
  chain-forge-slashing
  chain-forge-agents
    chain-forge-consensus
      chain-forge-crypto
        chain-forge-core  ← bottom, no workspace imports
```

Before adding a new inter-crate dependency, load `arch-guard` and confirm it
does not create a cycle or pull in conflicting crypto versions.

## Memory and resource conventions

- `chain-forge-node` in-memory bounds (as of this writing):
  - `CHAIN_STORE_KEEP = 20` — block payloads retained for peer sync
  - `MAX_RECENT_BLOCKS = 20` — explorer block history (includes ML-DSA signatures)
  - `historical_validator_sets` — pruned to `CHAIN_STORE_KEEP` entries on every commit
  - `MAX_GC_RECEIPTS = 500` — grand challenge receipts
- Any new unbounded `Vec`, `HashMap`, or `BTreeMap` that grows per-block **must**
  include a prune/evict step. No exceptions — the devnet runs 5 nodes on a single
  Windows machine and OOM kills are real.

## Design constraints

- `chain-forge-node` is a wiring layer. If logic is growing there, extract it to
  the right domain crate.
- No `unwrap()` on code paths that run in production. Use `?` and typed errors.
- Genesis files in `tests/devnet/` are test fixtures. Changes need an explicit
  reason in the commit message.
- Locked architectural decisions (ML-DSA keys, consensus engine, mainnet genesis)
  are enforced by `arch-guard`. Load it before touching those areas.
- Per CLAUDE.md test policy: never mark a milestone ✅ until it passes on BossKing
  (Windows / MINGW64), not just in the sandbox.
