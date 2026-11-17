# Devnet files

The supported devnet is the **ML-DSA devnet on PQ-HotStuff-2**. Every genesis file here uses `"signature_scheme": "pqc-native"`, `"validator_scheme": "ml-dsa-65"`, `"bft_variant": "pq-hotstuff"` and `environment.mode = "devnet"`, with validator keys in `keys/mldsa/`. Tendermint and the Ed25519 devnet are retired from Qattice (owner, 2026-11-15/16); Tendermint remains available as a Chain Forge option in `chain-forge-frontend`.

| File | Used by |
|---|---|
| `genesis-4node-mldsa.json` | `run_4node_devnet.sh`, `run_machine1.sh`, `run_machine2.sh`, `test7`–`test9`, `watch_testnet.sh`, `scripts/start-devnet-local.sh`, `scripts/start-testnet.ps1`, `devnet_4node` (`*_mldsa_*`), `mldsa_only_accounts_live`, `bootstrap_order_live`, `h0_8_genesis_peer_verification_live` |
| `genesis-4node.json` | `devnet_4node` (other tests), `attestation_live`, `dis_auth_live`, `personhood_live`, `vca_pq_live`, `adversarial_gossip`, `scripts/start-machine1.sh` |
| `genesis-4node-pqhs2*.json` | the `pqhs2_4node_*` live tests |
| `genesis-val-jail.json`, `genesis-val-jail-5node.json`, `genesis-val-delay.json`, `genesis-val-evict.json`, `genesis-auto-suspend.json` | the H0-11 validator lifecycle live tests |
| `genesis-mldsa.json`, `genesis-val002.json` | the live tests that name them |

The legacy pilot devnet (repo-root `genesis-4node.json`, `qcb-testnet-4node`, Tendermint + Ed25519) is no longer on this branch; it runs from branch `devnet-legacy-2026-10`, which `scripts/start-carol.sh` and `devnet/restart-machine*.sh` belong to.

All keys in this folder are **public test keys**. Never use them on a network anyone relies on.

The scripts read JSON with `json.sh` (grep/sed), not Python, so they run in Git Bash on Windows.

Ports used by the supported devnet scripts: API 19080–19083, P2P 28000–28003. They stay clear of the legacy devnet's 18080–18083 / 27000–27003.
