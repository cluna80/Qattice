# PQ-HotStuff-2 engine core (PR 2): what exists, what is simulated

Stacked on the foundation PR (genesis variant, validator sets, limits, leader, section 5/6 rules). Feature `pq-hotstuff`, off by default. Fixed
validator set, epoch 0 only. Dynamic membership is disabled (PO-4 unresolved). Not wired into the node; no network activates it.

* `certs.rs`: QC v1 / TC v1 / genesis certificate with the DRAFT canonical encodings of spec 3.4 (unapproved), strict decoding, the validity checks of
  3.5.2 (cheap and power checks before any signature), `validator_set_hash`, `block_id` over the opaque `devnet-interim` payload.
* `engine.rs`: sans-IO state machine: proposal validation, voting through the section 5 rules and the crash-safe SafetyStore, vote aggregation to QC,
  timeout aggregation to TC (broadcast when formed), two-chain commit, round advance, byte-for-byte re-send of the stored vote after a restart.
* `tests/pq_hotstuff_engine.rs`: encoding, validity, block identity, engine behaviour and a seeded deterministic simulation (4 validators): all honest;
  one silent; one equivocating (double proposal and double vote); crash/restart; restart plus equivocator. Properties: agreement, no honest double
  voting or timing out, no conflicting commit, progress after GST. Run the simulation in release mode (the SHA3-based test doubles are slow in debug):
  `cargo test --release -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_engine` (`PQHS_SEEDS=60` for a longer soak).

## Not covered (explicit)
* Signatures in the simulation use the non-cryptographic test doubles; the real FIPS 204 adapter has its own tests and is not exercised here.
* Block sync is a simulator stand-in (the engine has no sync protocol; a restarted engine has an empty block tree and the committed ledger is assumed
  durable in the execution layer). The pacemaker is a fixed timeout in the simulator.
* Network faults are random delay, drop before GST and reordering; there is no scripted partition or adversarial scheduler.
* Byzantine behaviour is one equivocator (double proposal to half the nodes, votes for every proposal it sees) and one silent node; no other attack.
* No equivocation evidence (spec section 9), no payload validation, no execution, no p2p, no persistent block store, no real keys or counter.
