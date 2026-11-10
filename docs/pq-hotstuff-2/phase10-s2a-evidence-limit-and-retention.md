# PQ-HotStuff-2 - S-2a: EvidenceLimitExceeded and bounded snapshot retention (DRAFT; isolated; not wired; installation over the network and pruning stay disabled)

Scope: `phase10-automated-snapshot-transfer-scope.md` (owner decisions 2026-11-09 and 2026-11-10). **Frozen code commit: `5bffc05ea0a35148f6a68b911b5e3981f1604769`** (stacked on S-1, #148).
S-2b (provider serving from the store and node wiring, behind the disabled flag) is NOT started. v3 stays off by default. Retention is a devnet CACHE policy, not a pruning-safety guarantee.

## What it adds
* **`EvidenceLimitExceeded`** (`transfer.rs`): the requester bounds accumulated evidence by encoded BYTES as well as header count (`max_accumulated_bytes`). A chain beyond either bound ends in
  `Phase::EvidenceLimitExceeded { headers, bytes }`: nothing is installed or persisted, no snapshot is requested, **no peer is blamed**, local files and signing floors are untouched, and ordinary
  block sync (verified replay) is left available. Nothing newer is trusted and no evidence is discarded in favour of an unauthenticated anchor. (S-1 had blamed the provider at the count bound; that was wrong
  and is fixed.) The 10,000-header ceiling is a bounded devnet recovery limit, not a lifetime guarantee; anchored evidence remains separate work.
* **`SnapshotStore`** (`recovery/retention.rs`): per-node validated config (`max_snapshots` = 3 target, `disk_budget_bytes`, `max_snapshot_bytes`; the budget must hold one retained snapshot plus one capture of
  the largest size). Accounting covers retained snapshots, the temporary capture (at its peak) and bytes reserved by the installer (staging and generations, never evicted). Eviction is oldest-unpinned first;
  **pinned snapshots are never evicted** (a pin keeps the count above target); if the budget cannot hold a capture even after evicting every unpinned snapshot, **nothing is evicted** and the capture is deferred with
  `BudgetExhausted`. Capture writes to a temporary directory and publishes with one atomic rename; **every retained snapshot is re-verified from its files when the store opens** (id, manifest, each chunk's length and hash,
  no foreign files) and anything that fails is removed and never served.
* Not included: nothing captures automatically; no provider serves from the store; nothing is wired into the driver or node; no pruning exists.

## Evidence at the frozen commit (Linux, release mode; NOT milestone confirmation)
`chain-forge-consensus`, both feature sets, all binaries exit 0: lib 101; engine suite **194 passed, 2 ignored** in the test-double file and in the real-ML-DSA-65 file; foundation 30, safety 76, wire 24, safety-fips204 11.
New tests (shared by both backends): 1 evidence-limit test (exact at the boundary: a limit equal to the chain succeeds; one header or one byte short reports the new phase; no snapshot request, nobody blamed, local files untouched)
and 7 retention tests (config validation incl. checked arithmetic; newest three kept with accounting equal to the bytes on disk and the installer's files untouched; pinned snapshots never evicted and exhaustion defers with nothing
evicted; installer bytes counted against the budget; invalid, oversized, stale and duplicate captures; damaged snapshots removed on open and never served; a crash matrix over every mutating operation of a capture and
over the post-crash disk states the test model represents - not every possible filesystem or power-loss outcome - checking every retained snapshot verifies, temporaries are gone, the pinned oldest snapshot is never lost, and
accounting equals the disk). **The node regressions (v2 and v3 live) were NOT rerun on Linux at this commit**; this change touches no node path; the Windows commands below include them.

## Mutation record (10 mutants, run against the frozen commit; a spot check, not a proof)
All 10 **caught**: evict-pinned-for-budget, evict-pinned-for-count, installer-bytes-ignored, capture-temp-not-removed-on-open, open-skips-chunk-hash, publish-without-dir-sync, not-forward-allowed,
peak-ignores-the-capture, evidence-bytes-not-bounded, evidence-limit-blames-peer. (A first background run was killed after three mutants when the container was suspended; the remaining seven were rerun from a clean worktree.)

## Open
S-2b (serving, wiring); concrete numeric defaults (proposals in the S-1 record); the O(chain) evidence cost (anchored evidence is separate and needs an owner decision); U5, draft QC/TC approval, PO-4, D2, #109, canonical state root.

## Windows confirmation (owner-run; pin the commit; full logs and exit statuses; record security state as found, do not change it)
```
git fetch origin feat/pq-hotstuff-2-snapshot-transfer-s2
git checkout 5bffc05ea0a35148f6a68b911b5e3981f1604769
git rev-parse HEAD
git status --short
set -o pipefail
cargo test --release -p chain-forge-consensus --features pq-hotstuff --lib 2>&1 | tee s2a-lib.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
cargo test --release -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine 2>&1 | tee s2a-engine-doubles.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204 2>&1 | tee s2a-engine-fips204.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
cargo test --release -p chain-forge-node --features pq-devnet --test pq_devnet_live --test pq_devnet_live_v3 -- --nocapture 2>&1 | tee s2a-node-live.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
powershell -NoProfile -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | Format-List"
```
Expected: lib 101; each engine file 194 passed + 2 ignored; node live v2 1 and v3 4.
