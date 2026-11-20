# Healthcare L1 Template

**Template ID**: `healthcare-l1`  
**Phase**: CF-INST-004

## Purpose

Healthcare L1 chains provide a permissioned Layer-1 blockchain for healthcare
institutions needing immutable audit trails, clinician credential anchoring,
and HL7 FHIR commitment anchoring — without storing any Protected Health
Information (PHI) on-chain.

## Privacy architecture

All medical record content remains off-chain.
On-chain state contains only:
- SHA-256 commitment hashes of FHIR resources
- SHA-256 hashes of clinician credentials
- SHA-256 hashes of emergency access event metadata

The chain cannot be used to reconstruct patient data from commitments alone.
Off-chain systems must maintain the actual records and can verify integrity
by re-computing the commitment and comparing to the on-chain anchor.

## Transaction types

### `AnchorFhirCommitment`
Writes a commitment hash of an HL7 FHIR resource to the `hc/fhir/<type>/<hash>` state key.

### `RegisterClinicianCredential`
Registers a clinician's credential hash at `hc/credential/<clinician_id>`.
Duplicate registration is rejected; revoke first.

### `RecordEmergencyAccess`
Writes an emergency (break-glass) access audit anchor at
`hc/emergency/<clinician_id>/<block_height>`. Multiple events at different
block heights are permitted for the same clinician.

### `RevokeClinicianCredential`
Removes the credential entry and writes a revocation marker at
`hc/revoked/<clinician_id>`.

## Configuration (`HealthcareConfig`)

| Field | Default | Description |
|-------|---------|-------------|
| `fhir_integration` | `true` | Enable FHIR commitment anchoring |
| `emergency_access_policy` | `BreakGlass` | Emergency access behavior |
| `audit_log_policy` | `RetainIndefinitely` | How long audit anchors are kept |
| `clinician_credential_attestation` | `true` | Require institutional attestation |

## Threat model notes

- Commitment-only design prevents PHI leakage even if chain state is fully public.
- Clinician credential revocation is enforced before re-registration.
- Emergency access events are always written to chain, ensuring accountability.
