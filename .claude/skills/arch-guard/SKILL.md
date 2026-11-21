---
name: arch-guard
description: >
  Architecture decision enforcement for Qattice. Load this skill before making any change that
  touches cryptographic primitives, consensus engines, key types, signature schemes, genesis
  configuration, or inter-crate boundaries. Triggers on: any mention of Ed25519, ML-DSA, HotStuff,
  Tendermint, PQ-HotStuff, key generation, signature verification, genesis files, validator sets,
  or adding/changing crate dependencies. Also triggers when introducing a new abstraction that
  spans multiple crates, or when removing/replacing an existing one. If in doubt, load it.
---

# Architecture Guard

Qattice has locked architectural decisions that must not be changed without an explicit owner
decision. This skill makes sure you check before you act.

## Locked decisions (as of CLAUDE.md)

Read `CLAUDE.md` for the authoritative list. Summary:

| Area | Decision | Status |
|------|----------|--------|
| Devnet consensus keys | ML-DSA-65 | Locked |
| Ed25519 devnet | Retired | Do not re-enable |
| Supported devnet genesis | `genesis-4node-mldsa.json` | Locked |
| User accounts on ML-DSA chains | ML-DSA-only (`pqc-native`) | Locked |
| HotStuff / FBA | Devnet-only, release gate 2 | Do not ship to mainnet |
| Consensus engine (devnet) | Tendermint | Do not change |
| Consensus target (mainnet) | PQ-HotStuff | New engine module, not legacy HotStuffEngine |
| Mainnet genesis | Fresh all-ML-DSA | Do not reuse devnet genesis |

## Before making an architectural change

1. **Identify the decision category.** Which row above does your change touch?

2. **Check if it's locked.** If the row says "Locked" or "Do not X", you cannot proceed without
   an explicit owner decision. Stop and present the conflict to the user.

3. **If it's not locked, justify it.** Write one paragraph explaining:
   - What you're changing and why
   - That it doesn't conflict with any locked decision
   - Which crates are affected

4. **Check for cascading effects.** A crypto primitive change typically affects:
   - `chain-forge-crypto` (implementation)
   - `chain-forge-keygen` (key generation)
   - `chain-forge-identity` (identity layer)
   - `chain-forge-validators` (validator set)
   - Any crate that imports and uses the changed type

   List every affected crate before changing anything.

5. **Never silently swap implementations.** If you're changing a crypto backend, signature scheme,
   or consensus module, it must be visible in the PR description and flagged to the user.

## Adding dependencies

Before adding a new crate dependency to any `Cargo.toml`:
- Is there an existing crate in the workspace that already provides this?
- Is the crate actively maintained and compatible with the workspace's MSRV?
- Does it pull in conflicting versions of crypto primitives (e.g., mixing PQ and classical)?

If any answer is uncertain, ask the user rather than guessing.
