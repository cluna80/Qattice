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
  a crash matrix over every mutating operation from before the evidence write to the end of the install and over every post-crash disk state that the test model (`MemTreeFs::crash_outcomes`, a sample of 6 per crash point) represents - NOT every possible filesystem or power-loss outcome - checks that a published
  generation always has durable, matching, re-authenticating evidence and that the node's own files are untouched; evidence-ahead-of-application makes a driver refuse to start
  (`ExecutorBehindBase`) and the install can be redone;
* **local storage failure** (a chunk fsync fails; the generations directory cannot be made durable): the requester fails closed within 120 messages, blames nobody, the prior
  published generation is byte for byte intact, and after the disk recovers the install completes and the driver restarts with every floor where it was.
The crash matrix found a real defect in the first S-1 revision (a filesystem failure while staging was retried without end); it is fixed and the test fails without the fix.

## Mutation record
Campaign 1 (first S-1 commit): **9 of 12 mutants caught; 3 survived** - (1) no pump after a message, (2) per-peer capacity check removed, (3) chunk-for-another-snapshot
check removed. A message-driven test was then added for (1).
Rerun at `41be391`: (1) caught, (2) caught (by a new unit test that shares one peer's capacity across request kinds; the request table's own cap is per kind),
(3) **still survived**; a new mutant (storage failure retried without end) was caught by the crash matrix.
Targeted rerun at the frozen commit `26872ce` (these four mutants only; **not a fresh complete 12-mutant campaign at the final commit**): (1), (2), (3) and the storage-failure mutant are all **caught** - (3) by a unit test that calls the chunk logic directly with a chunk
naming another snapshot (the request table normally refuses such a response first, on the echoed selector, so (3) cannot be reached through the public API while the table is
correct).
These two checks are therefore **defence in depth behind the request table**; they were not shown equivalent to anything, they were killed by direct tests. Whether to keep them
is a design choice, not an unresolved test gap. Mutation is a spot check of 12 chosen mutants plus targeted reruns, not a proof; the other eight first-campaign mutants were last run at the first S-1 commit.

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
Node regressions at the same commit (Linux): v2 live 1/1, v3 live 4/4, node `pq_devnet` unit tests 5/5, all exit 0.
Expected: lib 101; each engine file 187 passed + 2 ignored; node live: v2 1 and v3 4 tests. Report `git rev-parse HEAD`, each exit status, and any antivirus/exception state as found (do not change it to get a pass).

## Windows confirmation RESULT (owner-run, MINGW64, 2026-11-10; pinned code commit)
`git rev-parse HEAD` printed `26872ce5110b2e8205c7e03bb9c87000b0c33b1b` (detached HEAD at that commit). Results as pasted:
| Check | Result |
|---|---|
| `chain-forge-consensus --features pq-hotstuff --lib` | 101 passed, 0 failed |
| `pq_hotstuff_engine` (test doubles) | 187 passed, 0 failed, 2 ignored (531.54 s) |
| `pq_hotstuff_engine_fips204` (real ML-DSA-65) | 187 passed, 0 failed, 2 ignored (193.34 s) |
| `pq_devnet_live` (v2 regression) | 1 passed (34.92 s) |
| `pq_devnet_live_v3` | 4 passed (193.13 s), agreement checks ok at every stage |
These match the expectations. **What the paste does not show (stated, not inferred):** (1) the exit statuses of the four commands were not printed (`set -o pipefail` was
set and every command printed an all-passed `test result`; no failure line appears); (2) **no antivirus/exception state was recorded for this run** - the antivirus query in the
same paste belongs to the earlier #145 run (`88c0685`, antivirus off per a read-only query) and must not be read as this run's state; (3) `git status --short` was not shown
for this checkout. The paste also contains that earlier #145 run again (169/169 per backend, v3 live 4, v2 live 1, all exit 0), already recorded in the recovery-stack review.
This is validation of the S-1 components on the stated platform; it is not a Qattice application-recovery result and not network installation.

## Windows confirmation, SECOND RUN with exit statuses (owner-run, 2026-11-10; same pinned commit `26872ce5110b2e8205c7e03bb9c87000b0c33b1b`)
`git rev-parse HEAD` printed the pinned commit. `git status --short`, run before the rerun, listed only the four untracked log files `s1-*.log` left by the first run (no modified
tracked file). Results: lib 101 passed (exit 0 0 0); `pq_hotstuff_engine` 187 passed, 2 ignored, 509.23 s (exit 0 0 0); `pq_hotstuff_engine_fips204` 187 passed, 2 ignored, 211.91 s
(exit 0 0 0); node live: v2 1 passed (34.43 s) and v3 4 passed (186.79 s) (exit 0 0 0). A read-only Defender query immediately afterwards printed `AntivirusEnabled : False`,
`RealTimeProtectionEnabled : False` (exclusions were not queried; no other scanner was checked). This closes the three gaps above **for this second run**; it describes this run's
state, not the first run's, which remains unrecorded. Both runs passed with identical counts.

## PROPOSED resource budgets for S-2 (owner review; derived from this code, not yet decided or implemented)
Derived quantities (n = 4; ML-DSA-65 signature envelope 3,323 B): QC <= 13.4 KB; TC <= 26.8 KB; largest legal header ~43.6 KB (typical, one 3-signature QC: ~14 KB).
| Bound | Proposal for the devnet | Basis |
|---|---|---|
| Frame buffer, per connection | `transport limit + 4` (8 MiB + 4), one frame at a time, drop on overrun | the locked 8 MiB envelope |
| Decoded objects in flight | `max_recovery_memory = 64 MiB` -> `outstanding_cap = 8` (`min(16, floor(64 MiB / 8 MiB))`); requester `max_outstanding` <= that cap, per peer 2 | existing `outstanding_cap`; each outstanding response may be decoded at up to L |
| Accumulated headers | **10,000 headers** (~140 MB typical, ~436 MB worst case); a chain longer than this is an UNSUPPORTED configuration, refused locally | evidence is O(chain) from genesis until anchored evidence exists; this is the binding limit, and 100,000 would need 1.4 GB+ |
| Staging disk | explicit budget = `retained snapshots (3) x max snapshot + one in staging`; devnet proposal 64 MiB per snapshot -> 256 MiB; a larger manifest is refused locally | interim state is tiny; the codec ceiling (64 GiB) is not a budget |
| Concurrent requests | total 4, per peer 2 (as in the S-1 tests), reserved per phase so headers cannot starve chunks | S-1 slot-accounting tests |
| Chunk size | 256 KiB (codec max 1 MiB) | memory per in-flight chunk response |
Open questions for the owner: whether 10,000 headers is acceptable for the devnet lifetime (at one block per second it is under three hours of chain), which makes the
O(chain) evidence limit the first thing S-2 must address (anchored evidence or segmented authentication), not a tuning knob; and whether the retention budget should be
configured per node or fixed.
