# Threat Model — Chain Forge Institutional Edition

**Scope:** Threats specific to multi-chain institutional deployments built on Chain Forge.
**Audited commit:** `7e716771c83ad662b0e3c2d157b040c0de6180d2`

---

## 1. Cross-Chain Transaction Replay

**Attack:** An attacker captures a valid signed transaction from Chain A (e.g., a healthcare credential update) and submits it on Chain B (e.g., an education chain with the same module set).

**Existing mitigations:**
- `chain_id` is included in the transaction commitment hash in `chain-forge-execution`. A transaction signed for `hospital-network-1` cannot be accepted by `university-network-1` if the execution layer binds the chain ID.
- ML-DSA-65 signing (when `pqc-native` policy is active) includes a context string.

**Required new mitigations:**
- `domain_separator = SHA-256(chain_id || "|" || template_id || "|" || template_version)` is embedded in genesis. The execution layer must include the domain separator in the signing payload (tracked as CF-INST implementation item).
- Institutional chains must enforce `require_signatures = true` at genesis.
- Validator key pairs must be generated with chain-specific context strings per FIPS 204 §5.4.

**Residual risk:** Low, once domain separator is wired into signing context.

---

## 2. Unauthorized Validator Admission

**Attack:** An unauthorized party generates a validator keypair and attempts to join an institutional validator set.

**Existing mitigations:**
- `proof-of-authority` consensus type: validator set is defined entirely at genesis. No permissionless stake-bond onboarding.
- Validator public keys are listed in genesis accounts with `role = "validator"`. The node rejects any proposal or vote from a key not in the genesis validator set.

**Required new mitigations:**
- Institutional governance must control the `validator_bonding` module. By default, disable the staking module on institutional chains.
- Validator key rotation must follow an explicit governance proposal approved by the existing validator set.
- Key generation must use chain-specific context strings so a key generated for one institutional chain cannot be presented on another.

**Residual risk:** Low for permissioned PoA chains. Medium if staking module is inadvertently enabled.

---

## 3. Credential Forgery

**Attack:** An attacker forges a role credential (e.g., `RoleCredential::Clinician`) to gain unauthorized access to a downstream application gateway.

**Existing mitigations:**
- The `chain-forge-identity` module anchors identity records on-chain with attestation requirements.
- Credential assertions are signed by validator keys; forging requires compromising a validator.

**Required new mitigations:**
- Institutional identity (`OrganizationID`, `HumanID`, `RoleCredential`) must be separate types from Qattice's `IdentityRecord`. Role credentials must include the institutional chain's domain separator in their commitment.
- Credential expiration must be enforced: expired credentials must be rejected at the application gateway even if the on-chain record has not been explicitly revoked.
- Revocation anchors must be committed to chain state within a bounded number of blocks.

**Residual risk:** Medium. The on-chain commitment is strong; the application gateway's enforcement of expiration and revocation is out of scope for this crate and must be verified per deployment.

---

## 4. Privacy Leakage via On-Chain State

**Attack:** Sensitive institutional data (patient records, custody records, student transcripts) is inadvertently written to replicated blockchain state, becoming permanently visible to all validators.

**Existing mitigations:**
- Chain Forge execution does not enforce what application data is written; it is the application's responsibility.

**Required new mitigations:**
- All four institutional templates must enforce a strict off-chain data policy: only commitments (hashes, Merkle roots, audit anchors) are written on-chain. Raw records must remain in external systems.
- The `chain-forge-institutional` template validation layer must reject genesis configurations that enable modules capable of storing raw PII (if such modules are added in future).
- Test suites must use only synthetic data (no real patient, student, custody, or enterprise records).

**Residual risk:** High if application developers ignore the off-chain policy. The blockchain itself cannot prevent misconfigured applications from writing PII. Operational guidance and gateway-layer filtering are essential.

---

## 5. Byzantine Validator Behavior

**Attack:** `f` validators out of `n = 3f+1` behave Byzantine (send conflicting votes, refuse to vote, sign invalid blocks).

**Existing mitigations:**
- Chain Forge's Tendermint implementation requires `>2/3` precommits for finality. With `n = 4` validators, `f = 1` Byzantine validator is tolerated.
- PQ-HotStuff-2 preserves the same `>2/3` safety threshold with ML-DSA-65 signatures.

**Required new mitigations:**
- Institutional validator counts must satisfy `n >= 4` (3f+1 with f=1). The template engine enforces this at spec validation.
- For 7-validator institutional consortia, `f = 2` Byzantine validators are tolerated. Governance procedures must require `>=5` validator approvals for key changes.
- Slashing evidence from `chain-forge-slashing` must be enabled on institutional chains to create accountability for Byzantine behavior.

**Residual risk:** Low for honest-majority configurations. A coordinated insider attack by `f+1` validators breaks safety; this is a fundamental BFT bound.

---

## 6. Cross-Chain Credential Presentation

**Attack:** A credential issued on the healthcare chain is presented to an application gateway that validates against the education chain, exploiting shared infrastructure.

**Existing mitigations:** None currently — multi-chain credential presentation is a new threat surface.

**Required new mitigations:**
- Each institutional chain's credential anchors must include the `domain_separator` in the signed commitment.
- Application gateways must verify the credential's embedded `chain_id` matches the expected institutional chain before accepting it.

**Residual risk:** Medium. Gateway enforcement is out of scope for this crate.

---

## 7. Supply Chain / Upgrade Attacks

**Attack:** A malicious upgrade to `chain-forge-institutional` or a dependency introduces a backdoor that weakens key generation or genesis determinism.

**Existing mitigations:**
- The workspace uses pinned dependency versions (Cargo.lock).
- `fips204 = "=0.5.0"` is pinned exactly.

**Required new mitigations:**
- `chain-forge-institutional` must maintain pinned versions for all cryptographic dependencies.
- Genesis determinism tests must fail if output changes unexpectedly (canary hashes).

**Residual risk:** Low with pinned deps and determinism tests.

---

## Out of Scope

- Physical access to validator hardware.
- Compromise of the organization's CA or key management infrastructure.
- Application-layer vulnerabilities in EHR, corrections management, or student record systems.
- Network-layer DDoS against validator nodes.
