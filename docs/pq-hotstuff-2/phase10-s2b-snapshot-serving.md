# PQ-HotStuff-2 - S-2b: snapshot capture and serving in the driver and an opt-in node flag (DRAFT; provider side only; installation over the network and pruning stay disabled)

Scope: `phase10-automated-snapshot-transfer-scope.md` (owner decisions 2026-11-09 and 2026-11-10). Stacked on S-2a (#149). **Frozen code commit: `9be9c1854a49a951e5fe196f310c73e75d21b856`**
(the only change since `5f7b54f` is one test assertion; later commits, if any, are docs only). v3 stays off by default. Retention is a devnet CACHE policy, not a pruning-safety guarantee.

## Two gates, both off by default
1. a BUILD feature: `pq-snapshot-transfer` (consensus and node crates);
2. a RUNTIME opt-in: `Driver::enable_snapshot_serving(...)` and, in the node, the explicit `--serve-snapshots` flag (with `--snapshot-count`, `--snapshot-budget-bytes`,
   `--snapshot-max-bytes`, `--snapshot-dir`, `--snapshot-min-spacing-ms`, `--snapshot-pin-idle-ms`). Invalid settings are refused locally at start. **A build without the feature REFUSES the flag
   (the node exits); it is never silently ignored.**
With either gate missing the driver is as before: recovery kinds 7 to 14 are unknown input (counted as malformed) and the node's status document has no snapshot field.

## What it does (the PROVIDER side)
* **Capture:** the driver keeps, as a bounded in-memory candidate, the application state at each checkpoint height it executes. When a block that carries a reference is FINALIZED and executed,
  the state is captured into the S-2a store only if this node's own executed block id and state root equal the reference (otherwise nothing is captured).
* **Serving:** header, manifest and chunk requests (kinds 7, 9, 11) are answered from the node's own chain and the snapshot store under the S-1 serve gate. Responses (8, 10, 12) are never answered.
  A reply goes only to the asker; a request from this node's own index or a non-existent peer is ignored.
* **Pins:** a snapshot a peer is reading is pinned. One pin per peer and a total cap; a peer over its share is told BUSY. A transfer that fetched every chunk releases its pin at once; a quiet one is released by
  the idle timeout (node default 60 s). Pinned snapshots are never evicted (S-2a).
* **Flood control:** the minimum request spacing (node default 20 ms) is what throttles a flood of SMALL requests; the byte buckets refund what a small reply did not use.
* **Not done here:** nothing installs, nothing prunes, no provider signing state is imported (the recipient restarts on its OWN safety store), no automatic trigger, no requester inside a running driver.
  The recipient side is the operator-initiated install-then-restart path (S-1 requester plus the existing installer); its operator command and a process-level transfer over TCP belong to the next slice.

## Evidence at the frozen commit (Linux, release, REAL FIPS 204 ML-DSA-65; NOT milestone confirmation)
Required engine run: the named real-crypto binary only (the test-double file was not run; historical both-backend results stay as recorded).
| Run | Result |
|---|---|
| consensus `pq-hotstuff-fips204` (feature OFF): lib / engine / foundation / safety / safety-fips204 / wire | 101 / **194 passed, 2 ignored** / 30 / 76 / 11 / 24 (status 0) |
| consensus `pq-hotstuff-fips204,pq-snapshot-transfer` (feature ON) | 101 / **203 passed, 2 ignored** / 30 / 76 / 11 / 24 (status 0) |
| node, feature OFF: v2 live / v3 live | 1 passed / **5** passed (the 4 earlier plus the refused-flag test) (status 0) |
| node, feature ON: v2 live / v3 live / `pq_devnet` unit | 1 passed / **6** passed (the 4 earlier plus 2 serving tests) / 5 passed (status 0) |
The 9 new in-process tests (real drivers, the real encoded bytes): opt-in required; serving enabled changes no consensus behaviour when nothing asks (heights, rounds, counters, executed sequence identical off and on);
captured snapshots served and measured against the reference they are served for; an S-1 requester installing through live drivers with a non-serving peer and silent peers, then the recipient restarting with
its signing floors unchanged and every request slot released; malformed, truncated, oversize, unsolicited and out-of-range input changes nothing; pins (per-peer, total, protection against eviction, release by idle
timeout, resumable interrupted transfer); budget exhaustion defers capture without disturbing consensus and a flood is told BUSY; capture only of the state this node executed that a final reference attests;
serving configuration validated. The 3 new live-process tests (4 real processes): the flag refused without the feature; feature built but flag off behaves as before (no snapshot status, no cache directory,
agreement); serving on captures final snapshots, stays in agreement, and a restarted node re-verifies its cache.

## Mutation record (real crypto; a spot check of chosen mutants, not a proof)
Run at `5f7b54f` (11 mutants): **10 caught, 1 survived.** Caught: no pin recorded; per-peer pin cap ignored; total pin cap ignored; idle release removed; complete-transfer release removed;
candidate match check removed; driver skipping the final reference; driver without the peer range check; headers without the final QC; replies broadcast instead of sent to the asker.
Survivor: `responses-not-dropped-early` (it changed only the request counter). A test assertion that a response is never counted as a request was added (`9be9c18`) and **that one mutant was rerun and is caught**;
the other ten were not rerun at `9be9c18`. (A first attempt at this campaign was killed by a full disk and its results discarded; the campaign was rerun from scratch.)

## Defects found by the new tests while building this
The node never created the snapshot directory (a live test); the on-disk layout nests the store's own `snapshots/` inside the cache root (the cache root now has its own name); without a minimum request spacing a
flood of tiny requests was unthrottled (node default now 20 ms); a requester that spreads chunks over several providers never completes any one provider's transfer, so pins last until the idle timeout (default now 60 s).

## Limits of this evidence
Real signatures validate the cryptographic path these tests exercise; they do not establish mainnet readiness or production key-custody safety. The interim application is a hash chain of opaque payloads, not Qattice state.
The Linux sandbox is not Windows. No process-level test has a requester fetch from a serving node over TCP. Production keys and counter (#109), U5, draft QC/TC approval, PO-4, D2, the canonical state root, anchored evidence
(O(chain) evidence still caps recovery at the bounded devnet ceiling) and pruning remain open.

## Windows confirmation (owner-run; pin the commit; full logs and exit statuses; record security state as found, do not change it)
```
git fetch origin feat/pq-hotstuff-2-snapshot-transfer-s2b
git checkout 9be9c1854a49a951e5fe196f310c73e75d21b856
git rev-parse HEAD
git status --short
set -o pipefail
S="--lib --test pq_hotstuff_foundation --test pq_hotstuff_safety --test pq_hotstuff_safety_fips204 --test pq_hotstuff_wire --test pq_hotstuff_engine_fips204"
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 $S 2>&1 | tee s2b-consensus-off.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-snapshot-transfer $S 2>&1 | tee s2b-consensus-on.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
cargo test --release -p chain-forge-node --features pq-devnet --test pq_devnet_live --test pq_devnet_live_v3 -- --nocapture 2>&1 | tee s2b-node-off.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
cargo test --release -p chain-forge-node --features pq-snapshot-transfer --test pq_devnet_live --test pq_devnet_live_v3 -- --nocapture 2>&1 | tee s2b-node-on.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
powershell -NoProfile -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | Format-List"
```
Expected, consensus OFF: lib 101; engine 194 passed + 2 ignored; foundation 30; safety 76; safety-fips204 11; wire 24. Consensus ON: the same with engine **203** passed + 2 ignored. Node OFF: v2 1 and v3 **5**.
Node ON: v2 1 and v3 **6**. (Windows needs no `--test pq_hotstuff_engine`; the test-double engine file is not part of routine validation.)
