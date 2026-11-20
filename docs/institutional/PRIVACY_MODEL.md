# Institutional Chain Privacy Model

**Phase**: CF-INST-004  
**Status**: Design + implementation — pending Windows verification

## Principle

All four institutional templates enforce the same core privacy invariant:

> **No identifiable personal, medical, student, custody, or business-sensitive
> data is written to on-chain state. Only cryptographic commitments (SHA-256
> hashes), opaque identifiers, and policy metadata are stored on-chain.**

This is not a configuration option. It is enforced structurally by the
executor logic: all commitment fields are validated to be exactly 64
hex-encoded characters before being written to state. Plain-text content
that is 64 characters long and all-hex would pass the structural check,
so off-chain systems must ensure they hash their data before submitting.

## Per-template controls

### Healthcare
- FHIR resources: SHA-256(FHIR JSON) only. The hash is not reversible.
- Clinician IDs: opaque institution-issued tokens, not names.
- Emergency access events: commitment hash of event metadata, not the reason.

### Corrections
- Custody IDs: opaque facility-generated tokens.
- Transfer records: commitment hash, not names or case numbers.
- Evidence anchors: immutable after first write (tamper-evidence guarantee).

### Education
- Credential subject IDs: DIDs or hashed student IDs.
- FERPA mode enforced by policy: credential_hash is a hash of the signed VC,
  not the VC content. Revocation markers carry only a reason code.

### Enterprise
- Member and agent IDs: org-scoped opaque tokens.
- Provenance events: commitment hash of the event JSON.
- Governance proposals: commitment hash of the proposal body.

## Threat model

| Threat | Mitigation |
|--------|-----------|
| PHI/PII in state | Structural 64-hex-char validation on all commitment fields |
| Cross-chain replay | `TransactionDomain` binds signing context to chain_id + genesis_hash |
| Cross-template confusion | Executor checks `ExecutionContext.template` on every call |
| Evidence tampering | `AnchorEvidence` and `AnchorBatchCredentials` are immutable after first write |
| Credential reactivation after revocation | `IssueCredential` checks for revocation marker before allowing issue |

## Off-chain responsibility

The blockchain is not a storage system for institutional records.
Operators are responsible for:
1. Maintaining off-chain records with appropriate access controls.
2. Ensuring commitment hashes are computed correctly before submission.
3. Verifying on-chain commitments against off-chain records during audits.
4. Applying applicable privacy law (HIPAA, FERPA, etc.) to their off-chain systems.

Chain Forge Institutional provides the cryptographic anchoring layer.
Legal compliance is the operator's responsibility.
