# Corrections L1 Template

**Template ID**: `corrections-l1`  
**Phase**: CF-INST-004

## Purpose

Corrections L1 chains provide a permissioned blockchain for correctional
institutions needing tamper-evident custody chain-of-custody records,
interagency transfer coordination, and evidence anchoring. Identifiable
custody records and sensitive case information remain off-chain.

## Privacy architecture

No inmate names, case numbers, or sentencing records appear on-chain.
Custody identifiers are opaque tokens (facility-generated random IDs).
All `commitment` fields are SHA-256 hashes of off-chain transfer records.

The on-chain record proves the sequence and integrity of custody events
without revealing the identity of the individual in custody.

## Transaction types

### `AnchorCustodyTransfer`
Records a custody transfer event at `cor/custody/<custody_id>/<block_height>`.
Value encodes `<from>-><to>:<commitment>`.

### `AcknowledgeCustody`
Records a receiving facility's acknowledgment at `cor/ack/<custody_id>/<block_height>`.

### `AnchorEvidence`
Writes an evidence commitment at `cor/evidence/<evidence_id>`.
Evidence anchors are immutable: re-anchoring the same evidence_id is rejected.

### `OversightNodeRegistration`
Registers an oversight node's key hash at `cor/oversight/<node_id>`.
Duplicate registration is rejected.

## Configuration (`CorrectionsConfig`)

| Field | Default | Description |
|-------|---------|-------------|
| `interagency_transfer` | `true` | Allow interagency transfer coordination |
| `oversight_nodes` | `1` | Minimum number of oversight (read-only) nodes |
| `chain_of_custody` | `true` | Enable chain-of-custody anchoring |
| `record_appeals` | `true` | Enable on-chain governance for record appeals |

## Immutability guarantees

Evidence anchors (`cor/evidence/*`) are write-once. Any attempt to overwrite
an evidence anchor is rejected with an error indicating the record is immutable.
This provides tamper-evidence for the chain-of-custody log.
