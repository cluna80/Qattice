# Consensus Test Matrix — chain-forge-institutional

## Coverage status: sandbox-confirmed; local Windows verification pending.

| Test ID | Description | Phase | Tier confirmed |
|---------|-------------|-------|----------------|
| CX-001 | `bft_quorum(4)` → f=1, q=3 | 2 | T0 |
| CX-002 | `bft_quorum(7)` → f=2, q=5 | 2 | T0 |
| CX-003 | `bft_quorum(10)` → f=3, q=7 | 2 | T0 |
| CX-004 | `bft_quorum(n < 4)` rejected | 2 | T0 |
| CX-005 | BFT invariant `n ≥ 3f+1` holds for n=13,19,31,100 | 2 | T0 |
| CX-006 | `quorum > n/2` for all tested n | 2 | T0 |
| CX-007 | `ChainSpec::validate` rejects `validator_count < 4` | 1 | T0 |
| CX-008 | Tendermint + ML-DSA-65 is a valid consensus/crypto pair | 1 | T0 |
| CX-009 | PQ-HotStuff requires PQ or Hybrid crypto | 1 | T0 |
| CX-010 | Healthcare template validates with 4 validators | 1 | T0 |

## Pending tests (Phase 3+)

| Test ID | Description | Phase |
|---------|-------------|-------|
| CX-P3-001 | Live Tendermint round with ML-DSA-65 keys (devnet) | 3 |
| CX-P3-002 | PQ-HotStuff 3-of-4 quorum round (devnet) | 3 |
| CX-P3-003 | View-change under 1 Byzantine fault | 3 |

## Definitions

- **T0**: Sandbox (Claude Code cloud, ubuntu-latest) — compile + unit tests pass.
- **T1**: Local Windows (MINGW64) — owner confirmed.
- **T2**: GitHub CI — automated run on push/PR.
- **T3**: Independent security review.
