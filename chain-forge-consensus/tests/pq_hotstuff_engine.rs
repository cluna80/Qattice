//! PQ-HotStuff-2 certificates and engine: DRAFT canonical encodings (spec 3.4), validity (3.5.2), the fixed-validator-set state
//! machine, and a seeded deterministic simulation (agreement, no honest double signing, crash/restart, progress after GST).
//!
//! The signer/verifier here are the NON-CRYPTOGRAPHIC doubles of tests/common (unforgeable by assumption inside the test); the
//! real FIPS 204 adapter is exercised by its own tests. Run: cargo test -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine
#![cfg(feature = "pq-hotstuff")]

#[path = "common/pq_safety_doubles.rs"]
mod doubles;

// The tests live in tests/common/pq_engine_suite.rs so that the same assertions also run against real FIPS 204 signatures
// (tests/pq_hotstuff_engine_fips204.rs).
const DEFAULT_SEEDS: u64 = 10;
include!("common/pq_engine_suite.rs");
