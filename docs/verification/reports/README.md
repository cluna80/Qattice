# Verification Reports

This directory holds milestone verification reports for `chain-forge-institutional`.

## Naming convention

```
YYYY-MM-DD_<phase>_<tier>_<result>.md
```

Examples:
- `2026-11-20_phase1_T0_sandbox-confirmed.md`
- `2026-11-20_phase2_T0_sandbox-confirmed.md`
- `2026-11-21_phase1_T1_local-windows-confirmed.md`

## Required for milestone closure

Per `VERIFICATION_POLICY.md`, a Phase milestone is **not closed** until:
1. A T0 report exists (sandbox compile + test pass).
2. A T1 report exists (owner confirms local Windows run).

## Current milestone status

| Phase | Description | T0 | T1 |
|-------|-------------|----|----|
| Phase 1 | Core ChainSpec + Templates | sandbox-confirmed | PENDING |
| Phase 2 | Genesis, Validators, Domain, Quorum, CLI | sandbox-confirmed | PENDING |
| Phase 3 | Identity Framework + Verification Infrastructure | sandbox-confirmed | PENDING |

T1 confirmation command (run on Windows/MINGW64):
```
git pull origin main
cargo build -p chain-forge-institutional
cargo test -p chain-forge-institutional -- --nocapture
```
