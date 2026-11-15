# Claude Code — Project Notes

## Test validation policy

**Never mark a test or milestone ✅ based only on a sandbox/CI compile or run.**

All acceptance tests (`*_live` integration tests) must be confirmed passing on the
developer's local machine (Windows, MINGW64) before a milestone is closed.

Workflow:
1. Write the test, compile-check in sandbox (`cargo test --no-run`).
2. Commit and push.
3. Developer runs on their machine:
   ```
   git pull origin main
   cargo build -p chain-forge-node --features pq-hotstuff
   cargo test -p chain-forge-node --test <name> -- --nocapture
   ```
4. Only after the developer confirms it passes locally does the ROADMAP entry get ✅.

If a test passes in sandbox but fails locally, treat it as **not done** and investigate
the discrepancy before closing the milestone.

## Ed25519 is retired — never use it in new tests

**Do not write new test genesis files, key references, or test helpers that
use Ed25519 keys.** Ed25519 was retired from Qattice (owner, 2026-10-30).
All new tests must use ML-DSA-65 keys (`keys/mldsa/`) and
`"signature_scheme": "pqc-native"` / `"validator_scheme": "ml-dsa-65"`.
The existing `genesis-val-jail.json` and `{alice,bob,carol,dave}.key.json`
(root of `keys/`) survive only as classical-compatibility fixtures — do not
copy their crypto scheme into new test genesis files.

## Consensus engine: PQ-HotStuff-2 only (locked 2026-11-15)

**Tendermint is retired from all Qattice acceptance tests.**

Owner decision 2026-11-15: PQ-HotStuff-2 (`bft_variant: "pq-hotstuff"`) is the
only consensus engine used in Qattice test genesis files. Tendermint was the
original devnet engine but was a mistake; PQ-HotStuff-2 is the correct target.

All test genesis files use:
- `"signature_scheme": "pqc-native"`
- `"validator_scheme": "ml-dsa-65"`
- `"bft_variant": "pq-hotstuff"` (inside `consensus`)
- Keys from `tests/devnet/keys/mldsa/` or `chain-forge-node/tests/devnet/keys/mldsa/`

The node binary **must** be built with `--features pq-hotstuff` for any test that
spawns a node process. Without this flag the node will refuse to start with a
pq-hotstuff genesis and tests will fail with "no libp2p peer id".

Standard build command for all Qattice live tests:
```
cargo build -p chain-forge-node --features pq-hotstuff
```

Tendermint genesis files (`genesis-4node-mldsa.json`, `genesis-auto-suspend.json`)
are retained as historical / compatibility references only. Do not write new test
genesis files using Tendermint.

## Cryptographic architecture (locked)

See ROADMAP.md § "Cryptographic Architecture Decision". Do not re-litigate during Phase 0/1.

Owner decision 2026-10-28 (supersedes the earlier "devnet validators stay Ed25519"):
the devnet moves to **ML-DSA-65 consensus keys**. The ML-DSA devnet passed on
Windows (#24); the Ed25519 fallback devnet is retired (owner, 2026-10-30).
User accounts on ML-DSA chains are ML-DSA-only (`signature_scheme = "pqc-native"`, #35).
Mainnet is a fresh all-ML-DSA, all-PQ-HotStuff-2 genesis.
