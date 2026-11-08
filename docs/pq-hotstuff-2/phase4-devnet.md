# PQ-HotStuff-2 four-node devnet and node driver (PR 4)

**DEVNET ONLY. NOT FOR PRODUCTION. No merge, no production activation.** Feature `pq-devnet` of `chain-forge-node` (off by default); nothing in the
default build changes, and the Tendermint node path is untouched.

## What exists
* `pq_hotstuff::driver::Driver`: sans-IO node driver around the engine. Durable-state ordering, block sync with parked messages, pacemaker backoff,
  execution handoff, restart recovery, startup validation of the configuration.
* `chain-forge-node/src/pq_devnet.rs` and `src/bin/pq-devnet-node.rs`: configuration, devnet-only key loader, NON-PRODUCTION file counter, bounded
  local TCP transport, the node binary (`keygen`, `assemble`, `run`).
* `tests/pq_devnet_live.rs`: four OS processes, real FIPS 204 ML-DSA-65 keys generated on the machine running the test.

## Restrictions that stay visible
| Item | State |
|---|---|
| U5 canonical payload codec | OPEN. Payloads are opaque `devnet-interim` bytes (`devnet-interim:<node>:<round>`); the application is a hash chain. |
| Draft QC/TC layouts (spec 3.4) | DRAFT, owner approval pending. Behind `pq-hotstuff`/`pq-devnet`. |
| PO-4 epoch-change safety | OPEN (unproved). Dynamic membership is disabled: the validator set is fixed for the run; the config has no epoch field. |
| Production key storage | BLOCKED on review of #109. Keys are a 32-byte seed file generated locally, owner-only on Unix, never committed (`*.seed` is git-ignored), never printed. |
| Monotonic counter | NON-PRODUCTION. `DevnetFileCounter` is an ordinary file; the safety-store contract says a file is not a valid counter (its owner can roll it back). It exists only to run the real safety store end to end. |
| Transport | Local TCP, unauthenticated, unencrypted. Safety does not rely on it (messages are signed, sync responses validated, the frame's sender index is only a reply address). It is not the libp2p path. |
| 1,000-validator target | OPEN. 8 MiB does not fit a 1,000-validator proposal carrying a QC and a TC (about 9.96 MB with an empty payload); the driver rejects that configuration at startup. No committee was introduced to fit the envelope. Certificate sizing is a separate measured design decision (D2). |
| Pruning | Disabled and unimplemented. Finalized payloads are retained. |
| Core genesis | The devnet uses its own small JSON config (genesis hash = SHA3-256 of the file bytes), not the repository's core genesis format; wiring `BftVariant::PqHotStuff` startup is a later step. |

## Startup validation
`validate_config` derives, with checked arithmetic, the worst-case vote, timeout, TC, proposal and sync response for the configured validator count,
payload limit, chain id and sync size, and requires every one to fit `max_message_bytes` (which must be set). It rejects: an unset limit, a limit
below the derived minimum (for example 1,000 validators under 8 MiB), a sync size that does not fit, a bad pacemaker, and zero-sized driver parameters.
The node also refuses to start if its key is not in the set, if the counter file exists without safety state (it will not reset signing safety), if
safety state exists without its counter, or if the data directory is locked by another process.

## Run it
```
cargo build --release -p chain-forge-node --features pq-devnet --bin pq-devnet-node
B=target/release/pq-devnet-node; R=$(mktemp -d)
for i in 0 1 2 3; do $B keygen --dir $R/n$i; done
$B assemble --out $R/pq-devnet.json --chain-id qattice-pqhs2-devnet --base-port 24000 --dirs $R/n0,$R/n1,$R/n2,$R/n3
for i in 0 1 2 3; do $B run --config $R/pq-devnet.json --dir $R/n$i & done
cat $R/n0/status.json          # heights, block ids, application state digests
echo 3 > $R/n0/partition.txt   # cut node 0 off from node 3 (both directions); empty the file to heal
```
Automated: `cargo test --release -p chain-forge-node --features pq-devnet --test pq_devnet_live -- --nocapture`
