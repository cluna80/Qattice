# PQ-HotStuff-2 PR 3 — pruning: status and prerequisites

**Status: NOT IMPLEMENTED. Pruning is disabled; PR 3 contains no deletion path for finalized payloads.**

Owner amendment to PR 3 (2026-11-08): finality makes a block a *candidate* for pruning; it is not the deletion
trigger. Storage and crash recovery come first. A block is "finalized under the protocol's stated fault and
cryptographic assumptions" (two-chain commit, f < n/3 by voting power, ML-DSA-65 unforgeability); this document
makes no stronger claim. Pruning reduces storage only; it does not make block creation easier or faster.

## What PR 3 does

`BlockStore` persists blocks, commit records, high QC and high TC and recovers via `Engine::restore`
(re-validating everything). All finalized payloads are retained. `committed_after(executor_height)` is the replay
source, so retaining payloads is required until execution is integrated.

## Prerequisites before any payload deletion (all must be implemented and tested)

Deletion is permitted only below a **durable pruning watermark**, after:

1. The block is finalized under the implemented commit predicate.
2. Its effects and execution cursor are durably committed, or an explicitly durable downstream execution handoff
   retains the required payload. (No executor exists yet.)
3. A recoverable checkpoint exists, and the consensus headers, certificates and signing-safety dependencies
   (safety store, high QC/TC, ancestors needed by the commit rule) remain available.
4. A defined catch-up path can recover a node that missed the pruned history (authenticated snapshot sync; not
   designed or built).

A history accumulator is a commitment, not a replacement for execution state or data availability. This work
introduces no new consensus state root and no checkpoint-certification protocol; either would need a separate,
owner-approved spec.

## Required tests when pruning is eventually implemented

Crashes around checkpoint publication and around deletion; interrupted pruning; missing or corrupt snapshots; a
node rejoining after its required history was pruned. All must fail closed and never reset or lower signing
safety. Any pruning shown against a mock executor must be labelled test-only.

## Decisions needed from the owner

Execution/handoff interface, snapshot format and authentication, checkpoint semantics, and the watermark's
storage and ordering relative to the safety store.
