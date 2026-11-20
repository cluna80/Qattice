# Implementation Plan — Chain Forge Institutional Edition

**Branch:** `feature/institutional-chain-forge`

---

## Phase 0 — Repository Audit (this commit)

**Status:** Complete.

Tasks:
- [x] Inspect workspace structure and all crate roles.
- [x] Identify genesis flow, crypto stack, consensus variants, validator admission.
- [x] Run baseline tests; record results.
- [x] Write ARCHITECTURE.md, COMPATIBILITY_MATRIX.md, THREAT_MODEL.md, IMPLEMENTATION_PLAN.md.
- [x] Identify pre-existing compile errors (chain-forge-intelligence, chain-forge-consensus, chain-forge-vca-pq test suite).

Acceptance criteria: Documents exist and are grounded in the actual codebase. No existing code modified.

---

## Phase 1 — Institutional Template Engine

**Status:** Implemented in this branch.

Tasks:
- [x] Create `chain-forge-institutional` crate.
- [x] Implement `ChainSpec`, `InstitutionalTemplate` enum, `ConsensusProfile`, `CryptoPolicy`.
- [x] Implement `ChainSpec::validate()` with BFT quorum enforcement.
- [x] Implement `GenesisBuilder::build()` producing a `GenesisConfig`-compatible JSON structure.
- [x] Implement domain separator: `SHA-256(chain_id || "|" || template_id || "|" || template_version)`.
- [x] Implement four template configs: `HealthcareConfig`, `CorrectionsConfig`, `EducationConfig`, `EnterpriseConfig`.
- [x] Add crate to workspace `Cargo.toml`.
- [x] Write 6 automated tests.
- [x] Confirm all tests pass.
- [x] Confirm existing stable crate tests still pass.

Acceptance criteria:
- Two independently generated institutional chains have different genesis hashes and domain separators.
- Validator credentials cannot authenticate across chains (domain separator is chain-specific).
- Transactions cannot be replayed across chains (chain_id binding).
- 2-validator spec is rejected.
- All four templates produce valid specs.
- Existing Chain Forge functionality unmodified.

---

## Phase 2 — Sovereign Chain Generator CLI

**Status:** Stub implemented. Full implementation planned.

Tasks:
- [ ] Wire `chain-forge-institutional create` subcommand to `chain-forge-node` or standalone binary.
- [ ] Accept `--template`, `--name`, `--validators`, `--consensus` flags.
- [ ] Generate and write genesis JSON to disk.
- [ ] Generate validator enrollment config (public key slots, no private keys in output).
- [ ] Generate `network-manifest.json` (ports, bootstrap addresses).
- [ ] Generate `local-dev.md` instructions.
- [ ] Validate that the generated genesis is accepted by `chain-forge-node --genesis`.

Acceptance criteria: `chain-forge institutional create --template healthcare --name test-hospital --validators 4` produces a genesis file that `chain-forge-node` can load without modification.

Risks:
- CLI integration with existing node argument parsing may require a separate binary (assessed as low-risk; adapter identified in COMPATIBILITY_MATRIX.md).

---

## Phase 3 — Institutional Identity and Authorization

**Status:** Planned.

Tasks:
- [ ] Define `OrganizationID`, `HumanID`, `RoleCredential`, `DeviceID`, `AgentID` types in `chain-forge-institutional`.
- [ ] Implement credential verification using domain separator binding.
- [ ] Implement credential expiration and revocation anchors.
- [ ] Implement key rotation support.
- [ ] Implement agent sponsorship with chain-specific authorization.
- [ ] Integration tests: verify cross-chain credential presentation is rejected.

Dependencies: Phase 1 complete; `chain-forge-identity` crate stable.

Risks:
- Must not duplicate `IdentityRecord` from `chain-forge-identity`. New types extend the existing model additively.

---

## Phase 4 — Four Institutional Templates (full)

**Status:** Minimal configs implemented in Phase 1. Full vertical slices planned.

### Healthcare L1

Tasks:
- [ ] HL7 FHIR commitment schema (hash of FHIR resource, not raw FHIR).
- [ ] `EmergencyAccessPolicy` enforcement rules.
- [ ] Clinician role credential verification.
- [ ] Protected audit log anchor type.
- [ ] Synthetic FHIR integration test (no real patient data).

### Corrections L1

Tasks:
- [ ] Interagency transfer authorization credential type.
- [ ] Chain-of-custody evidence anchor.
- [ ] Oversight node configuration (read-only validator role).
- [ ] Record correction / appeal proposal type.

### Education L1

Tasks:
- [ ] W3C Verifiable Credential envelope for diplomas and transcripts.
- [ ] FERPA mode: student record access policy config.
- [ ] Credential revocation anchor.
- [ ] Accreditation organization identity type.

### Enterprise L1

Tasks:
- [ ] Multi-organization governance quorum config.
- [ ] AI agent authorization chain.
- [ ] Supply chain provenance hash anchor.
- [ ] Contract attestation type.

Dependencies: Phase 3 complete.

---

## Phase 5 — Visual Builder Foundation (after backend acceptance)

**Status:** Planned. Depends on Phase 1 and Phase 2 passing acceptance tests.

Tasks:
- [ ] Extend Chain Forge frontend wizard with institutional template selector.
- [ ] Wire wizard to `POST /api/institutional-chains` endpoint in `chain-forge-service`.
- [ ] Service endpoint calls `chain-forge-institutional` library code (not a second genesis implementation).
- [ ] Display generated genesis JSON in wizard.
- [ ] Export deployment artifacts from wizard.

---

## Known risks and open questions

| Risk | Severity | Mitigation |
|---|---|---|
| Pre-existing test failures in chain-forge-intelligence and chain-forge-consensus | Low (not our code) | Exclude from CI for this branch; file separate issue. |
| Domain separator not yet wired into transaction signing context | Medium | Phase 2 task; tracked in THREAT_MODEL.md §1. |
| `chain-forge-node` CLI refactor required for subcommand | Low | Use separate binary if needed. |
| Institutional chains may accidentally enable staking module | Medium | Template validation rejects staking module for PoA templates. |
