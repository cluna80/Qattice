# Risk Register — chain-forge-institutional

Last updated: 2026-11-20

| ID | Risk | Severity | Likelihood | Mitigation | Status |
|----|------|----------|------------|------------|--------|
| R-001 | Placeholder ML-DSA-65 keys used in production deployment | CRITICAL | Medium | CLI and artifacts emit explicit "PLACEHOLDER KEY" warnings; validation-report.json includes warning list | OPEN — mitigated by warning only |
| R-002 | Genesis hash changes if `--timestamp` omitted (non-reproducible) | HIGH | High | `GenesisBuilder` uses `SystemTime::now()` without `--timestamp`; CI smoke test always passes `--timestamp`; docs warn operators | OPEN — mitigated by docs |
| R-003 | Structural-only key validation (no algebraic ML-DSA-65 verify) | HIGH | Low | `CredentialVerifier` performs key-length checks only; real verify requires `real-pqc` feature; TODO comment in code | OPEN — requires T3 |
| R-004 | Cross-chain replay if `TransactionDomain` not enforced by node | MEDIUM | Low | `TransactionDomain` is a helper; enforcement is the node's responsibility; SECURITY_INVARIANTS.md documents INV-004 | OPEN — node enforcement pending |
| R-005 | Test vector keys (0x01×1952, etc.) committed as placeholder patterns | MEDIUM | Low | Keys have distinct byte patterns; labeled "test" in all code; never used in production genesis without replacement | MITIGATED |
| R-006 | Qattice regression from institutional crate changes | MEDIUM | Low | Institutional crate is a separate workspace member with no Qattice runtime dependency; existing CI still runs DIS Core CI | MITIGATED |
| R-007 | Sensitive data introduced in test fixtures by future contributors | MEDIUM | Medium | SECURITY_INVARIANTS.md INV-009; CLAUDE.md directive; code review policy | OPEN — policy only |
| R-008 | `IdentityRegistry` suspended org can be reinstated without audit trail | LOW | Low | `reinstate_org` does not log; reinstatement is a manual operation; audit trail is out of scope for Phase 3 | OPEN — deferred |

## Severity definitions

- **CRITICAL**: Can cause direct harm, data breach, or asset loss in production.
- **HIGH**: Significant security gap; must be resolved before testnet.
- **MEDIUM**: Important gap; must be resolved before mainnet.
- **LOW**: Minor gap; can be deferred with documented rationale.
