# Real FIPS 204 ML-DSA-65 engine validation

The engine, the certificate verifier and the crash-safe safety store now run together with REAL ML-DSA-65 signatures (existing `Fips204Signer` /
`Fips204Verifier` adapter over the `fips204` backend). This is a REQUIRED validation suite, in addition to the fast test-double suite.

## How
* `tests/common/pq_engine_suite.rs` holds the single test body. It is `include!`d by two test crates that differ only in the signature scheme:
  `tests/pq_hotstuff_engine.rs` (fast non-cryptographic doubles) and `tests/pq_hotstuff_engine_fips204.rs` (real ML-DSA-65). Every assertion is identical.
* Keys: each test validator's 32-byte seed comes from the operating-system RNG once per process, lives in memory only, and is never written, committed or
  printed. Signing is hedged, so signature bytes differ on every run. Storage and counter are the same (untrusted) test doubles as the safety tests.
* New authentication tests (run under BOTH schemes): a block signed with another validator's key; wrong-context signatures (vote/timeout/proposal contexts
  swapped) for proposals, votes, timeouts, QCs and TCs; a certificate signature from the wrong validator's key; messages, certificates and the genesis
  certificate from another chain (isolated so that only the chain id differs). Existing tests cover altered fields, restart re-send byte for byte, forged QC/TC.

## Required commands (release mode: ML-DSA and SHA3 are slow in debug)
    cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204
    cargo test --release -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine
    PQHS_SEEDS=60 cargo test --release -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_engine_fips204   # soak

## Linux results (sandbox)
| Run | Result |
|---|---|
| real ML-DSA-65 engine suite, 10 seeds per campaign | 36 passed, 1 ignored (diagnostic), 12.2 s |
| fast doubles engine suite, 10 seeds per campaign | 36 passed, 1 ignored, 30.4 s |
| real ML-DSA-65 soak, 60 seeds per campaign (honest, silent, equivocator, crash/restart, restart plus equivocator) | 36 passed, 68.4 s; no agreement, double-signing or commit-conflict violation, progress after GST in every run |
| regression: foundation / safety / safety_fips204 / wire / default consensus lib / core lib | 30 / 76 / 11 / 24 / 98 / 74 passed |
| mutation check against the real-crypto suite | 25 of 26 caught, 1 justified (docs/pq-hotstuff-2/phase2-real-crypto-mutation-results.txt) |

Simulation seeds are 1..=N per campaign (the scheduler is deterministic per seed); the keys are random per process, so a failing run is reproduced by its
seed and scenario, not by its keys.

## Not covered
Network faults beyond the simulator's random delay/drop/reorder; Byzantine behaviour beyond one silent or equivocating node; block sync, pacemaker backoff,
persistent block store, node wiring, real key storage and the production counter; Windows confirmation of THIS commit (pending).
