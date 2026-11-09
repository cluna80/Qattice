# PQ-HotStuff-2 - S-1: isolated snapshot-transfer requester and provider (DRAFT; not wired; installation over the network and pruning stay disabled)

Scope: `docs/pq-hotstuff-2/phase10-automated-snapshot-transfer-scope.md` (decisions locked by the owner, 2026-11-09). This change is slice **S-1** only.
Code under test: `chain-forge-consensus/src/pq_hotstuff/recovery/transfer.rs` and `Installer::finish_with`. **Frozen code commit: `26872ce5110b2e8205c7e03bb9c87000b0c33b1b`.**

## What it is, and what it is not
* Sans-IO `Provider` (serves under the existing `ServeGate`; an answer the peer's decoder would refuse is degraded to advice) and `Requester` (headers from ONE
  source at a time, genesis-anchored authentication through an injected `Authenticator`, manifest, chunks, install through `InstallSink`).
* **Not wired:** nothing in the driver or the node calls it; `netmsg::decode` still rejects kinds 7-14; no operator command exists; no pruning. v3 stays off by default.
* Policy implemented: genesis-only trust anchor (the node's own `authenticate_evidence`); any peer may serve; **no provider-agreement threshold**; operator-initiated only
  (there is no automatic trigger); the interim application only (a hash chain of opaque payloads, not Qattice transaction state).
* **Install ordering:** `Installer::finish_with` runs a caller hook after the staged state is measured against the authenticated root and flushed, and BEFORE anything is
  published. The seed evidence is made durable there, so every published application generation already has durable, matching, re-authenticatable evidence.
* Separate bounds, refused locally if unsupported: headers per page, accumulated headers, staging bytes, outstanding requests (total and per peer, across all kinds),
  request and overall timeouts.

## Evidence at the frozen commit (Linux, release mode; NOT milestone confirmation - see CLAUDE.md)
Both full `chain-forge-consensus` runs exited 0: `--features pq-hotstuff` and `--features pq-hotstuff-fips204` (real ML-DSA-65).
Library: 101 passed (3 are the transfer unit tests). Engine suite: 187 passed, 2 ignored, in the test-double file; and in the real-ML-DSA-65 file (feature
`pq-hotstuff-fips204`) 187 passed, 2 ignored. Foundation 30, safety 76, wire 24; safety (fips204 file) 11. **18 transfer integration tests per signature backend**
(the shared bodies are `include!`d into both files).

What the transfer tests establish (in-process; a real driver network; in-memory transport; a malicious-provider simulator):
* an honest provider installs the authenticated snapshot with durable evidence; one honest provider among liars and silent peers is enough (no agreement threshold);
* forged headers never authenticate and never reach evidence; a chain with no checkpoint yet is not blamed on the provider; flipped chunks are refused by the manifest hash;
  a self-consistent snapshot of the WRONG state is measured, discarded unpublished, and its id is not trusted again; an over-budget manifest is refused without blame;
* evidence that cannot be made durable stops the transfer with nothing published; unsolicited, late, duplicate and wrong-peer responses change nothing;
* slot accounting: outstanding requests never exceed the caps; every slot is released (also with silent providers); a transfer completes from messages alone, with no timer;
* a provider degrades oversized answers to advice, ignores responses, and answers a flood with BUSY;
* **recovery boundary:** an in-process driver restarts from the installed state and the persisted evidence with no signing floor moved and executes each block once;
  a crash matrix over every mutating operation from before the evidence write to the end of the install and over every possible post-crash disk state checks that a published
  generation always has durable, matching, re-authenticating evidence and that the node's own files are untouched; evidence-ahead-of-application makes a driver refuse to start
  (`ExecutorBehindBase`) and the install can be redone;
* **local storage failure** (a chunk fsync fails; the generations directory cannot be made durable): the requester fails closed within 120 messages, blames nobody, the prior
  published generation is byte for byte intact, and after the disk recovers the install completes and the driver restarts with every floor where it was.
The crash matrix found a real defect in the first S-1 revision (a filesystem failure while staging was retried without end); it is fixed and the test fails without the fix.

## Mutation record
Campaign 1 (against the first S-1 commit): **9 of 12 mutants caught; 3 survived.** Survivors: (1) no pump after a message, (2) per-peer capacity check removed,
(3) chunk-for-another-snapshot check removed. Follow-up: a message-driven test killed (1). At `41be391` (with the direct tests of the next paragraph for (2); and (1)):
(1) caught, (2) caught, (3) **still survived**, and a new mutant (storage failure retried) was caught by the crash matrix.
At the frozen commit `26872ce`: all four of (1), (2), (3) and the storage-failure mutant are **caught** - (2) by a unit test that shares one peer's capacity across request kinds
(the request table's own cap is per kind), (3) by a unit test that calls the chunk logic directly with a chunk naming another snapshot (the request table normally refuses such
a response first on the echoed selector, so (3) cannot be reached through the public API while the table is correct).
These two checks are therefore **defence in depth behind the request table**; they were not shown equivalent to anything, they were killed by direct tests. Whether to keep them
is a design choice, not an unresolved test gap. Mutation is a spot check of 12 chosen mutants, not a proof.

## Open / not covered
* Not wired: no operator command, no network decoder, no node integration (S-2), no automatic trigger (separate decision), no pruning.
* The Installer's own QC check is a stub in these tests (the authenticator verifies the certificate); its real check is covered by the earlier installer tests.
* A crash INSIDE the block store's evidence write is covered by the earlier seed-persistence tests (atomic rename), not by this matrix.
* Concrete limit numbers and the retention disk budget remain open (scope document, section 7). Evidence is still O(chain) from genesis. U5, draft QC/TC approval, PO-4,
  D2, production keys/counter (#109) and the canonical state root remain open.

## Windows confirmation (owner-run; pin the commit; preserve full output; record security state as found)
```
git fetch origin feat/pq-hotstuff-2-snapshot-transfer-s1
git checkout 26872ce5110b2e8205c7e03bb9c87000b0c33b1b
git rev-parse HEAD
set -o pipefail
cargo test --release -p chain-forge-consensus --features pq-hotstuff --lib 2>&1 | tee s1-lib.log
cargo test --release -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine 2>&1 | tee s1-engine-doubles.log
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204 2>&1 | tee s1-engine-fips204.log
cargo test --release -p chain-forge-node --features pq-devnet --test pq_devnet_live --test pq_devnet_live_v3 -- --nocapture 2>&1 | tee s1-node-live.log
```
Expected: lib 101; each engine file 187 passed + 2 ignored; node live: v2 1 and v3 4 tests. Report `git rev-parse HEAD`, each exit status, and any antivirus/exception state as found (do not change it to get a pass).
