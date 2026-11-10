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
/// Whether the test keys are deterministic (the test doubles): golden byte values are only asserted when they are.
const DETERMINISTIC_KEYS: bool = true;
include!("common/pq_engine_suite.rs");
#[path = "common/pq_tree_doubles.rs"]
mod tree_doubles;
include!("common/pq_recovery_suite.rs");
include!("common/pq_checkpoint_suite.rs");
include!("common/pq_seed_suite.rs");
include!("common/pq_seed_persist_suite.rs");
include!("common/pq_transfer_suite.rs");
include!("common/pq_retention_suite.rs");
#[cfg(feature = "pq-snapshot-transfer")]
include!("common/pq_serving_suite.rs");
#[cfg(feature = "pq-anchored-evidence")]
include!("common/pq_anchor_record_suite.rs");
#[cfg(feature = "pq-anchored-evidence")]
include!("common/pq_anchor_verify_suite.rs");
