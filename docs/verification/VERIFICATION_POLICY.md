# Chain Forge Institutional — Verification Policy

## Purpose

This document defines the verification tiers required before any milestone,
security invariant, or test result for `chain-forge-institutional` is considered
confirmed.

## Verification Tiers

| Tier | Method | Who | Closes milestone? |
|------|--------|-----|------------------|
| T0 | Claude sandbox compile + unit tests | Claude Code | No |
| T1 | Local developer machine (Windows, MINGW64) | Repository owner | Yes (Phase 0–2) |
| T2 | GitHub CI (ubuntu-latest) | Automated | No standalone |
| T3 | Independent security review | Third party | Required for mainnet |

## Policy Rules (from CLAUDE.md, non-negotiable)

1. **Sandbox results are never marked ✅.** `cargo test` passing in the CI or
   Claude's sandbox environment confirms compilation and unit logic only.
2. **Local Windows (MINGW64) confirmation is required** to close any Phase
   milestone. Command:
   ```
   git pull origin main && cargo build -p chain-forge-institutional &&
   cargo test -p chain-forge-institutional -- --nocapture
   ```
3. **Security invariants** (see `SECURITY_INVARIANTS.md`) require T3 (independent
   review) before any production or mainnet deployment.
4. **Cryptographic paths** that use real FIPS 204 ML-DSA-65 signatures require
   the `real-pqc` feature flag and T3 review before production use.

## What "sandbox-confirmed" Means

When this document or any test result says "sandbox-confirmed", it means:
- The code compiled without errors or warnings in the Claude Code cloud environment.
- All unit tests passed on ubuntu-latest.
- **Local Windows verification is still pending** unless the owner has explicitly
  confirmed it in writing.

## Escalation Path

If a test passes in sandbox but fails locally, treat it as **not done**:
1. Record the failure in `docs/verification/reports/`.
2. Investigate the discrepancy (platform-specific behavior, feature flags, etc.).
3. Fix and re-verify at both T0 and T1 before closing the milestone.
