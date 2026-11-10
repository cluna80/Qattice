# PQ-HotStuff-2 - AN-1: the local anchor record and its crash-safe two-generation ring (DRAFT; STORAGE ONLY; off by default)

Scope: `phase11-anchored-evidence-scope.md` (PR #152; section 6A and the owner decisions of 2026-11-10). Stacked on S-2b (#151). **Frozen code commit: `e0d29c847d3848fa8eee880368304460dce9fab5`** (later commits, if any, are docs only).
Feature `pq-anchored-evidence`, OFF by default. **Nothing verifies an anchor's proof, creates an anchor from verification, audits, or lets a node START from an anchor.** No node, driver or network code changed. v3 stays off by default; dynamic membership stays disabled; pruning is not implemented.

## What it adds (`chain-forge-consensus/src/pq_hotstuff/anchor_record.rs`)
* `AnchorRecord`: a LOCAL record (a checksum detects accidents and authenticates nothing). Versioned, strictly decoded: wrong tag, version, checksum, length, trailing bytes, more headers or bytes than the configured limits, or fields that contradict each other
  (audited height above the anchor, a reference above the anchor, a provenance generation that is not older, an empty proof) are errors. Allocation is bounded by the input.
* `AnchorBinding::of(&EngineConfig)`: the binding is RECOMPUTED from the node's own configuration (effective genesis hash, profile, chain id, validator-set hash, checkpoint interval and max age); the record's copy is only compared with it. A profile-v2 configuration has no checkpoint parameters and is refused.
* `AnchorLimits` and `supports()`: a proof spans from the checkpoint block to a final carrier of its reference, at most `max_age + 3` headers; a genesis whose `max_age` cannot fit the configured header and byte limits makes anchored start UNSUPPORTED (refused locally, with checked arithmetic).
* `AnchorRing`: two generations, newest first. Forward-only; a new generation is written to a temporary name, flushed, published with ONE atomic rename and directory syncs, and the older generation is removed only after the new one is durable. On open: leftover temporaries are removed;
  every record is re-decoded and must carry the node's own binding and a generation equal to its file name, otherwise it is discarded (never trusted, never "repaired"); more than two generations (a crash between publish and cleanup) are trimmed to the newest two.
* Audit progress (`set_audited`): a separate small checksummed file, forward-only, never above the anchor, replaced atomically; on open it only ever RAISES the audited height of the generation it names, and a damaged file is ignored.
* The ring never touches application state, signing state or the application pointer (checked by test).

## Evidence at the frozen commit (Linux, release, REAL FIPS 204 ML-DSA-65; NOT milestone confirmation)
Required engine run: the named real-crypto binary only. All statuses 0.
| Configuration | lib | engine | foundation | safety | safety-fips204 | wire |
|---|---|---|---|---|---|---|
| `pq-hotstuff-fips204` (feature OFF) | 101 | **194** passed, 2 ignored | 30 | 76 | 11 | 24 |
| `pq-hotstuff-fips204,pq-anchored-evidence` | 101 | **202** passed, 2 ignored | 30 | 76 | 11 | 24 |
| `pq-hotstuff-fips204,pq-snapshot-transfer,pq-anchored-evidence` | 101 | **211** passed, 2 ignored | 30 | 76 | 11 | 24 |
The feature-off engine count is unchanged. The node tests were NOT rerun on Linux at this commit (no node, driver or network code changed); the Windows commands include them.
The 8 new tests (real headers and certificates from a real driver network): the binding is recomputed and differs for other parameters, another interval, another genesis hash and a v2 configuration; the record round-trips and the decoder is strict about everything, including
inconsistent fields that carry a valid checksum; unsupported freshness bounds are refused; the ring is forward-only, keeps two generations and refuses a foreign binding and over-limit proofs before anything is written; damaged, foreign-bound, misnamed and leftover files are never trusted on open;
audit progress is forward-only, bounded by the anchor, durable, and ignored when damaged; a stale progress file can never lower the audited height; and a crash matrix over EVERY mutating operation of a publish and of an audit-progress update and over the post-crash disk states the test model represents
(NOT every possible filesystem or power-loss outcome) shows the old or the new state, never a lost previous generation, and that application state, safety files and the application pointer are never touched.

## Mutation record (real crypto; a spot check of chosen mutants, not a proof)
First run at the AN-1 commit `9772313`: **11 of 12 caught; 1 survived** (`progress-can-lower-the-audit`: a valid progress file naming a height below the record's own was untested). A test for exactly that (and for a higher value being applied and a value above the anchor being ignored) was added, and **that one mutant
was rerun at `e0d29c8` and is caught; the other eleven were not rerun there.** Caught: binding not compared on open; generation not matched to the name; only one generation kept; temporaries not cleaned on open; progress above the anchor allowed; decoder skipping the checksum;
decoder allowing an audited height above the anchor; publish not forward-only; publish without the file sync; `supports()` ignoring the byte limit; provenance generation not required to be older.

## Limits of this evidence
Real signatures validate the cryptographic path these tests exercise, not mainnet readiness or key-custody safety. This slice is storage: it makes no claim that an anchor is authentic, that a node may sign on one, or that recovery is faster. The anchor audit, the proof re-verification, the signing-disabled modes
(`off` default and `audit_first`), forward verification for ring fallback, header extension from a persisted anchor and segmented verification are the next slices (AN-2 and AN-3) and are NOT implemented. The signing-floor assumptions are the SafetyStore's own (a trusted monotonic counter outside the file's reach; the devnet counter is a file; production keys and counter are blocked on #109).
Open: U5, draft QC/TC approval, PO-4, D2, the canonical state root, header pruning's bootstrap decision, pruning (not implemented).

## Windows confirmation (owner-run; pin the commit; full logs and exit statuses; record security state as found, do not change it)
```
git fetch origin feat/pq-hotstuff-2-anchored-evidence-an1
git checkout e0d29c847d3848fa8eee880368304460dce9fab5
git rev-parse HEAD
git status --short
set -o pipefail
S="--lib --test pq_hotstuff_foundation --test pq_hotstuff_safety --test pq_hotstuff_safety_fips204 --test pq_hotstuff_wire --test pq_hotstuff_engine_fips204"
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 $S 2>&1 | tee an1-consensus-off.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-anchored-evidence $S 2>&1 | tee an1-consensus-on.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204,pq-snapshot-transfer,pq-anchored-evidence $S 2>&1 | tee an1-consensus-all.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
cargo test --release -p chain-forge-node --features pq-devnet --test pq_devnet_live --test pq_devnet_live_v3 -- --nocapture 2>&1 | tee an1-node-off.log | grep -E "test result|FAILED"; echo "exit: ${PIPESTATUS[*]}"
powershell -NoProfile -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | Format-List"
```
Expected: lib 101; engine **194** (feature off), **202** (anchored), **211** (anchored plus snapshot); each +2 ignored; foundation 30; safety 76; safety-fips204 11; wire 24; node v2 1 and v3 5.

## Windows confirmation RESULT (owner-run, MINGW64, 2026-11-10; pinned code commit)
`git rev-parse HEAD` printed `e0d29c847d3848fa8eee880368304460dce9fab5` (detached HEAD). `git status --short`, run after the checkout, listed only untracked log files from earlier runs
(`s1-*`, `s2a-*`, `s2b-*`; no modified tracked file). Results as pasted:
| Check | Result | Exit statuses |
|---|---|---|
| consensus `pq-hotstuff-fips204` (feature OFF): lib / engine / foundation / safety / safety-fips204 / wire | 101 / **194** passed + 2 ignored (190.51 s) / 30 / 76 / 11 / 24 | 0 0 0 |
| consensus `pq-hotstuff-fips204,pq-anchored-evidence` | 101 / **202** passed + 2 ignored (182.29 s) / 30 / 76 / 11 / 24 | 0 0 0 |
| consensus `pq-hotstuff-fips204,pq-snapshot-transfer,pq-anchored-evidence` | 101 / **211** passed + 2 ignored (182.49 s) / 30 / 76 / 11 / 24 | 0 0 0 |
| node (default features): v2 live / v3 live | 1 passed (34.67 s) / **5** passed (197.66 s) | 0 0 0 |
These match the expectations. A read-only Defender query immediately afterwards printed `AntivirusEnabled : False`, `RealTimeProtectionEnabled : False` (exclusions not queried; no other scanner checked; the
query ran after the tests). This validates the AN-1 storage components and the unchanged node paths on the stated platform, on the real FIPS 204 path these tests exercise. It says nothing about anchor authenticity, anchored start, recovery
speed, pruning, mainnet readiness or key-custody safety: none of those exist in this slice.
