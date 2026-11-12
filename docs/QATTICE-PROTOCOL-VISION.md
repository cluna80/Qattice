# The Qattice Protocol: Technical Vision and Target Architecture

**Note on Implementation Status:** This document describes Qattice's intended architecture.
Components are at different stages of implementation, validation, and research. Early
milestones—including payload-free header verification, multi-node devnets, and isolated
snapshot structures—have been cross-platform verified, while dynamic networking, canonical
execution, and live pruning subsystems remain active development workstreams.

---

## Abstract

Traditional distributed ledger designs suffer from systemic vulnerabilities driven by
long-term state bloat, capital-weighted consensus captures (Proof-of-Stake), and legacy
cryptographic exposures. We present Qattice, a novel, sovereign Layer-1 blockchain
architecture designed to unify three core pillars: Post-Quantum Cryptography (PQC)
utilizing stateless lattice-based FIPS 204 ML-DSA-65 signatures, an identity-gated
Proof-of-Personhood (PoP) verification layer, and a highly optimized PQ-HotStuff-2
consensus engine [1] featuring a Defensive Pruning Watermark framework.

By separating consensus-critical retention from long-term historical payload storage
through a checkpoint-attested snapshot recovery path, Qattice aims to dramatically reduce
the validator storage footprint. This lightweight profile is intended to democratize
network validation, allowing secure, quantum-resistant consensus participation directly on
consumer hardware and mobile devices, with mobile validator feasibility subject to resource
and performance validation.

---

## 1. Executive Summary & Design Objectives

The Qattice architecture rejects the industry paradigm that high performance inherently
requires enterprise-class data centers or massive, unbounded state accumulation. Instead,
the protocol is engineered around a central design objective: maximizing decentralization
by minimizing the hardware barriers to full ledger verification.

To achieve this, the target architecture synthesizes three core innovations into an
internally consistent state machine:

---

### 🛡️ Pillar 1: Post-Quantum Cryptographic Readiness

Legacy blockchains rely on elliptic curve cryptography (ECDSA) and classical BLS
primitives, both of which are fundamentally vulnerable to discrete logarithm calculation
attacks by future quantum adversaries. Qattice integrates FIPS 204 ML-DSA-65 signatures
natively at the foundation of the state machine.

While lattice-based cryptography introduces a structural data penalty—with each individual
signature requiring approximately 3.3 KB [2]—the network transport architecture enforces a
configurable, bounded transport envelope, currently 8 MiB for the devnet profile, governed
by strict, checked arithmetic to mitigate memory-amplification and Denial-of-Service (DoS)
vectors.

---

### 👥 Pillar 2: Personhood-Bounded Sybil Resistance

Rather than weighting voting influence by computational hashing power (Proof-of-Work) or
financial concentration (Proof-of-Stake), Qattice aims to anchor consensus eligibility
directly to unique human identities. This is designed around a target hardware-bonded,
non-biometric Digital Identity Stone (DIS) protocol.

Users perform a local, privacy-preserving cryptographic authorization using their
smartphone's local protected wallet. Wallet authorization establishes control of
credentials, while the underlying personhood process must establish human uniqueness. The
system cleanly separates user identity authorization from high-frequency consensus signing:
the phone wallet authorizes the node's validity, while validator nodes utilize independent,
optimized consensus keys through a crash-safe system to process pipelined blocks. This
architecture is designed to mitigate Sybil or bot armies from hijacking consensus while
preserving user anonymity.

---

### ⏳ Pillar 3: HotStuff-2 Core with Defensive Pruning Watermarks

Consensus is driven by an advanced, leader-based HotStuff-2 protocol, which targets
low-latency finality using a two-chain commit rule, subject to network and execution
conditions.

To mitigate the state-bloat crisis, Qattice designs an innovative Defensive Pruning
Watermark. The engine moves through six methodical, deterministic recovery boundaries:

```
[1. Two-Chain Finality] ──> [2. Authenticated Snapshot] ──> [3. Durable Publication]
                                                                     │
                                                                     ▼
[6. Eligible Payload Deletion] <── [5. Watermark Advance] <── [4. Dependency & Availability]
```

1. **Finality under Stated Assumptions:** Block identity (`block_id`) commits
   mathematically to the `SHA3-256` hash of its payload, allowing the raw transaction text
   to be stripped while preserving unforgeable proposer signatures.

2. **Authenticated Snapshot:** At a configurable target interval, provisionally 1,000
   blocks, eligible proposals may include a 72-byte checkpoint reference (`CheckpointRef`
   comprising height, block_id, and state_root). Later blocks carry this forward as a
   periodic commitment to an application state root.

3. **Durable Publication:** Local state database snapshots are compiled and written
   durably into shadow storage before publishing, designed for crash-consistent recovery,
   subject to filesystem and storage durability guarantees.

4. **Dependency and Availability Checks:** Checkpoint validation, execution-root checks,
   and finality verification ensure validators retain or dynamically recompute the necessary
   historical roots required to fulfill validation requests.

5. **Watermark Advancement:** Once an authenticated snapshot is durably committed and
   verified against consensus history, the monotonic watermark file atomically advances
   forward, enforcing a strict safety margin buffer.

6. **Eligible Payload Deletion:** Raw transaction payloads below the safety watermark are
   candidate for deletion, leaving behind the payload-free headers and required certificates
   to keep storage footprint bounded.

---

## 2. Target Competitive Profile: Why the Vision Scales

While pruning optimizes payload storage, it does not by itself bound all storage or
verification costs, nor does it dictate block execution throughput. However, the
combination of a managed ledger profile, post-quantum armor, and human-centric validation
positions Qattice uniquely against legacy networks:

- **Sovereign Accessibility:** By keeping payload storage requirements low, validation
  power is intended to remain accessible to ordinary human operators running on
  consumer-grade hardware, directly counteracting the data-center centralization trends of
  modern networks.

- **Mitigating Security Debt:** Ethereum and other legacy networks face significant
  "security debt" regarding post-quantum migrations and retroactive history pruning (such
  as EIP-4444). Qattice builds these boundaries into its target architecture from the
  ground up.

- **Personhood-Bounded Sybil Resistance:** Unlike stake-weighted networks where validation
  power can be consolidated via capital accumulation, Qattice's personhood layer bounds
  actual consensus voting influence directly to verified human individuals.

---

## References

[1] PQ-HotStuff-2 engine specification: `docs/pq-hotstuff-001-spec.md`

[2] ML-DSA-65 signature size: FIPS 204, Table 1. Each ML-DSA-65 signature is 3,309 bytes;
    public keys are 1,952 bytes.
