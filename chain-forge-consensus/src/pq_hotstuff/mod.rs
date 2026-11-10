//! PQ-HotStuff-2 consensus engine (docs/pq-hotstuff-001-spec.md).
//!
//! Phase 0 step 1: the canonical byte layouts of section 3.2 (`wire`). Phase 1 step 1: the crash-safe safety-state
//! persistence of section 7 (`safety`). No engine, no network activation.
pub mod wire;
pub mod safety;
// Engine foundation (feature `pq-hotstuff`, off by default; no network activates it): validator sets, limits, leader
// selection and the section 5/6 safety rules. Dynamic membership stays disabled (PO-4).
#[cfg(feature = "pq-hotstuff")]
pub mod types;
#[cfg(feature = "pq-hotstuff")]
pub mod limits;
#[cfg(feature = "pq-hotstuff")]
pub mod leader;
#[cfg(feature = "pq-hotstuff")]
pub mod rules;
#[cfg(feature = "pq-hotstuff")]
pub mod certs;
#[cfg(feature = "pq-hotstuff")]
pub mod engine;
#[cfg(feature = "pq-hotstuff")]
pub mod sync;
#[cfg(feature = "pq-hotstuff")]
pub mod pacemaker;
#[cfg(feature = "pq-hotstuff")]
pub mod netmsg;
#[cfg(feature = "pq-hotstuff")]
pub mod blockstore;
#[cfg(feature = "pq-hotstuff")]
pub mod exec;
#[cfg(feature = "pq-hotstuff")]
pub mod driver;
#[cfg(feature = "pq-hotstuff")]
pub mod header;
#[cfg(feature = "pq-hotstuff")]
pub mod seed;
#[cfg(feature = "pq-hotstuff")]
pub mod recovery;
#[cfg(feature = "pq-hotstuff")]
pub mod checkpoint;

#[cfg(feature = "pq-snapshot-transfer")]
pub mod serving;

#[cfg(feature = "pq-anchored-evidence")]
pub mod anchor_record;

#[cfg(feature = "pq-anchored-evidence")]
pub mod anchor_verify;

#[cfg(feature = "pq-anchored-evidence")]
pub mod anchor_restart;
