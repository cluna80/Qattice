# Institutional Builder HTTP API

All endpoints are served by `chain-forge-service` on `127.0.0.1:7700`.
Only the wizard origin (`http://localhost:5173`) or no-origin (curl) may call them.

---

## GET /api/institutional/templates

Returns the four built-in institutional templates with defaults.

**Response 200**
```json
[
  {
    "id": "healthcare-l1",
    "name": "Healthcare L1",
    "description": "...",
    "default_validator_count": 4,
    "default_crypto": "ml_dsa_65",
    "default_consensus": "tendermint_bft",
    "modules": ["bank", "identity", "governance"]
  },
  ...
]
```

---

## POST /api/institutional/validate

Validates a `ChainSpec` without writing any files.

**Request body**: a `ChainSpec` JSON object (see below).

**Response 200**
```json
{ "valid": true, "chain_id": "my-hospital-1", "template": "healthcare-l1",
  "validator_count": 4, "domain_separator": "aabbcc..." }
```
or
```json
{ "valid": false, "error": "minimum 4 validators required" }
```

---

## POST /api/institutional/generate

Validates spec, generates genesis artifacts, writes them to disk, and returns metadata.
No private keys are generated.

**Request body**: a `ChainSpec` JSON object.

**Response 200**
```json
{
  "chain_id": "my-hospital-1",
  "template": "healthcare-l1",
  "domain_separator": "aabbcc...",
  "genesis_hash": "ddeeff...",
  "artifacts_dir": "/home/user/.chain-forge/my-hospital-1/institutional",
  "artifacts": ["genesis.json", "manifest.json"]
}
```

**Response 400**: invalid spec or chain_id.
**Response 500**: file system error or genesis build failure.

---

## GET /api/institutional/artifacts/{chain_id}/{filename}

Returns a generated artifact as JSON. `filename` must be `genesis.json` or `manifest.json`.

**Response 200**: the artifact JSON.
**Response 400**: invalid chain_id.
**Response 404**: artifact not found (chain not generated yet, or bad filename).

---

## ChainSpec schema

```json
{
  "template": {
    "type": "healthcare",
    "fhir_integration": true,
    "emergency_access_policy": "break_glass",
    "audit_policy": "full",
    "hipaa_compliant_audit": true
  },
  "chain_id": "my-hospital-1",
  "chain_name": "My Hospital Network",
  "validator_count": 4,
  "consensus": "tendermint_bft",
  "crypto": "ml_dsa_65",
  "governance": {
    "approval_threshold_pct": 67,
    "execution_delay_blocks": 100,
    "constitutional_governance": true
  },
  "network": {
    "p2p_port": 27000,
    "rpc_port": 8080,
    "max_peers": 50,
    "discovery": "bootstrap"
  },
  "block_time_ms": 3000
}
```

Template `type` values: `healthcare`, `corrections`, `education`, `enterprise`.
Consensus values: `tendermint_bft`, `pq_hot_stuff2`.
Crypto values: `ml_dsa_65`, `hybrid`, `ed25519`.
