# Template Execution Framework

**Phase**: CF-INST-004  
**Status**: Sandbox compiled — pending Windows verification

## Overview

The execution framework provides a shared layer for applying institutional
transactions to on-chain state. It is located in
`chain-forge-institutional/src/execution.rs`.

## Core types

| Type | Purpose |
|------|---------|
| `StateEntry` | A single key-value record written to chain state |
| `TemplateState` | Mutable key-value store for one block execution |
| `TxResult` | Result of applying a transaction: `success`, `error`, `mutations` |
| `ExecutionContext` | Per-block context: chain_id, block height, submitter ID, template |
| `TemplateDomain` | Domain label binding a transaction to a specific chain+template pair |
| `TxBody` | Top-level transaction envelope, dispatched by template |

## State key namespaces

Each template owns a distinct prefix:

| Template | Prefix |
|----------|--------|
| Healthcare | `hc/` |
| Corrections | `cor/` |
| Education | `edu/` |
| Enterprise | `ent/` |

Cross-namespace writes are impossible by construction: each executor checks
the `ExecutionContext.template` variant before processing any transaction and
returns `TxResult::cross_template_rejected()` on mismatch.

## Transaction dispatch

`TxBody` wraps one of the four template transaction enums. The caller selects
the matching executor based on the `TxBody::template_id()` string. No shared
runtime dispatch table exists in this phase; dispatch is explicit at the call
site.

## Privacy invariant

`StateEntry` values MUST be:
- Hex-encoded SHA-256 commitment hashes (64 hex chars)
- Policy metadata strings (e.g., reason codes, role names, facility names)
- Merkle root commitments (64 hex chars)

`StateEntry` values MUST NOT be:
- Patient names, identifiers, or health record content
- Student names, grades, or FERPA-covered record content
- Inmate names, case numbers, or custody record content
- Employee names, PII, or business-sensitive record content

This invariant is enforced structurally: all executor `apply()` methods
validate that commitment fields are exactly 64 hex characters before writing
to state.
