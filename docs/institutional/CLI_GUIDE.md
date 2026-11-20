# CLI Guide — chain-forge-institutional-cli

## Installation

Build from the workspace root:

```bash
cargo build -p chain-forge-institutional --release
```

The binary is at `target/release/chain-forge-institutional-cli`.

---

## Subcommands

### `create`

Generate a new institutional blockchain.

```
chain-forge-institutional-cli create [OPTIONS]
```

**Required flags:**

| Flag | Values |
|---|---|
| `--template` | `healthcare` \| `corrections` \| `education` \| `enterprise` |
| `--name` | Chain name (converted to lowercase chain ID, spaces → hyphens) |

**Optional flags:**

| Flag | Default | Description |
|---|---|---|
| `--validators <n>` | `4` | Number of validators (minimum 4 for BFT quorum) |
| `--consensus` | `tendermint` | `tendermint` \| `pq-hotstuff` |
| `--crypto` | `ml-dsa-65` | `ml-dsa-65` \| `ed25519` \| `hybrid` |
| `--timestamp <unix-secs>` | current time | Fix genesis timestamp for reproducibility |
| `--out-dir <path>` | `./<chain-id>` | Output directory (created if absent) |

---

## Examples

### Healthcare network, 7 validators

```bash
chain-forge-institutional-cli create \
  --template healthcare \
  --name hospital-network \
  --validators 7 \
  --out-dir ./hospital-network
```

Output:
```
chain_id:          hospital-network
genesis_hash:      a3f8...  (time-dependent without --timestamp)
domain_separator:  7c2d...
validators:        7 (f=2, quorum=5)
output:            hospital-network/
```

### Corrections, reproducible hash

```bash
chain-forge-institutional-cli create \
  --template corrections \
  --name state-corrections \
  --validators 10 \
  --timestamp 1700000000 \
  --out-dir ./state-corrections
```

Running this command twice with the same `--timestamp` produces the same
`genesis_hash`. Omit `--timestamp` for a time-stamped genesis.

### Enterprise with PQ-HotStuff consensus

```bash
chain-forge-institutional-cli create \
  --template enterprise \
  --name corp-chain \
  --validators 4 \
  --consensus pq-hotstuff \
  --crypto ml-dsa-65 \
  --out-dir ./corp-chain
```

---

## Output Files

All four files are written to `--out-dir`:

### `genesis.json`

Full genesis document compatible with `chain-forge-core`'s `GenesisConfig`.
Contains consensus config, cryptography config, validator accounts, network
settings, governance, and institutional extension fields.

### `validator-enrollment.json`

```json
{
  "chain_id": "hospital-network",
  "quorum": { "n": 7, "f": 2, "quorum": 5 },
  "validators": [
    {
      "validator_id": "hospital-network-validator-0",
      "public_key_type": "ml-dsa-65",
      "public_key_hex_prefix": "0101010101010101",
      "voting_weight": 1,
      "note": "PLACEHOLDER KEY — replace before production deployment"
    }
  ]
}
```

### `deployment-manifest.json`

```json
{
  "chain_id": "hospital-network",
  "chain_name": "hospital-network",
  "template": "healthcare",
  "consensus": "tendermint",
  "crypto": "ml-dsa-65",
  "validator_count": 7,
  "genesis_hash": "a3f8...",
  "domain_separator": "7c2d...",
  "quorum": { "n": 7, "f": 2, "quorum": 5 },
  "deployment_status": "DEVELOPMENT — NOT PRODUCTION READY",
  "note": "Replace placeholder validator keys before any production or testnet deployment."
}
```

### `validation-report.json`

```json
{
  "chain_id": "hospital-network",
  "validation": "passed",
  "fields_validated": [
    "chain_id format",
    "validator_count >= 4 (BFT quorum)",
    "consensus/crypto compatibility",
    "governance threshold (1-100%)",
    "block_time_ms > 0"
  ],
  "warnings": [
    "Validator keys are test-vector placeholders (not real ML-DSA-65 keys).",
    "No --timestamp provided; genesis hash is time-dependent and not reproducible."
  ],
  "genesis_hash": "a3f8..."
}
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success — all four artifact files written |
| `1` | Validation error or I/O failure (message on stderr) |

---

## Production Key Replacement

The generated artifacts use **test-vector placeholder public keys** (repeating
byte patterns). These are safe for development and local devnet testing.

Before any production, testnet, or external deployment:

1. Generate real ML-DSA-65 key pairs using `chain-forge-crypto` or a compatible
   FIPS 204 implementation.
2. Replace each `public_key_hex` in `genesis.json` with the corresponding
   validator's real 1952-byte public key (hex-encoded).
3. Update `validator-enrollment.json` accordingly.
4. Recompute the genesis hash from the updated genesis document.
5. Distribute the updated genesis to all validators and verify the hash matches.

**Never commit private signing keys to source control or include them in genesis files.**
