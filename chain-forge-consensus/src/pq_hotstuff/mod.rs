//! PQ-HotStuff-2 consensus engine (docs/pq-hotstuff-001-spec.md).
//!
//! Phase 0 step 1: the canonical byte layouts of section 3.2 (`wire`). Phase 1 step 1: the crash-safe safety-state
//! persistence of section 7 (`safety`). CF-C1: the native `PqHotStuffEngine` implementing `ConsensusEngine` (`engine`).
pub mod wire;
pub mod safety;
pub mod engine;
pub mod signing;
