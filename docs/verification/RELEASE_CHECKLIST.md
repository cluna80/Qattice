# Release Checklist — chain-forge-institutional

Use this checklist before tagging any release of `chain-forge-institutional`.
Each item must be checked off by the owner or a designated reviewer.

## Phase Gate: Devnet (current)

- [ ] All unit tests pass on Windows (MINGW64): `cargo test -p chain-forge-institutional -- --nocapture`
- [ ] All unit tests pass on GitHub CI (ubuntu-latest).
- [ ] `cargo clippy -p chain-forge-institutional -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] CLI smoke test: generate genesis for all 4 templates (healthcare, corrections, education, enterprise).
- [ ] Genesis hash determinism verified: same inputs → same hash across two runs.
- [ ] All 10 security invariants in `SECURITY_INVARIANTS.md` confirmed by test run.
- [ ] No real institutional data (patient, student, corrections, enterprise) in any test fixture.
- [ ] No private key material in any generated artifact.
- [ ] `docs/verification/RISK_REGISTER.md` reviewed; no CRITICAL unmitigated risks.

## Phase Gate: Testnet (not yet reached)

- [ ] Independent security review complete (T3).
- [ ] `real-pqc` feature enabled; all CP-* tests in `CRYPTOGRAPHIC_TEST_MATRIX.md` pass.
- [ ] All CX-P3-* tests in `CONSENSUS_TEST_MATRIX.md` pass on a live devnet.
- [ ] Qattice devnet unaffected by institutional crate (no regressions on existing tests).
- [ ] Key provisioning process documented and reviewed.

## Phase Gate: Mainnet (requires owner + independent approval)

- [ ] All testnet gates passed.
- [ ] Formal security audit complete.
- [ ] Penetration test on genesis key provisioning workflow.
- [ ] No `PLACEHOLDER KEY` warnings in any mainnet deployment artifact.
- [ ] Owner explicit written authorization to deploy.
