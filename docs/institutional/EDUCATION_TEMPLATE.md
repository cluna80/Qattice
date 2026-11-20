# Education L1 Template

**Template ID**: `education-l1`  
**Phase**: CF-INST-004

## Purpose

Education L1 chains provide a permissioned blockchain for educational
institutions needing verifiable credential issuance, revocation, and
accreditation identity anchoring — without storing FERPA-covered student
record data on-chain.

## Privacy architecture (FERPA alignment)

FERPA (Family Educational Rights and Privacy Act) and equivalent laws
require that student education records not be disclosed without consent.

The Education L1 template enforces this architecturally:
- Student credential subjects are referenced by opaque DIDs or hashed IDs
- Actual transcripts, grades, and education records remain off-chain
- On-chain state contains only credential anchor hashes and revocation markers

Verifiers can confirm credential validity without learning any record content.

## Transaction types

### `IssueCredential`
Issues a verifiable credential anchor at `edu/credential/<credential_id>`.
Value encodes `<issuer_id>:<credential_hash>`.
Duplicate issuance and re-issuance after revocation are both rejected.

### `RevokeCredential`
Removes the credential entry and writes a revocation marker at
`edu/revoked/<credential_id>`.

### `RegisterAccreditation`
Registers an accreditation body's key hash at `edu/accreditor/<accreditor_id>`.
Duplicate registration is rejected.

### `AnchorBatchCredentials`
Writes a Merkle root of a batch credential issuance at
`edu/batch/<batch_id>`. Batch anchors are immutable. Count must be ≥ 1.

## Configuration (`EducationConfig`)

| Field | Default | Description |
|-------|---------|-------------|
| `vc_standard` | `W3cVc` | Verifiable credential standard |
| `ferpa_mode` | `true` | Enforce FERPA-compatible privacy |
| `credential_revocation` | `true` | Support credential revocation |
| `accreditation_identity` | `true` | Support accreditation body registration |

## Verifiable credential standards

`VcStandard::W3cVc` — W3C Verifiable Credentials (https://www.w3.org/TR/vc-data-model/)  
`VcStandard::ChainForgeNative` — Simplified on-chain-only format for lower overhead

Both standards store only the commitment hash on-chain; the signed credential
document remains with the holder or in an off-chain registry.
