//! Typed epoch-change payload codec for PQ-HotStuff-2 (devnet use only).
//!
//! A proposer at the configured epoch-change height encodes the new validator
//! set into `tx_data` using a fixed magic prefix + JSON body. Receivers decode
//! it before passing `new_validator_set` to `on_commit`. The decoder is
//! fail-closed: a magic prefix followed by malformed content returns `Err`
//! rather than silently dropping the transition.

#[cfg(feature = "pq-hotstuff")]
mod inner {
    use crate::{ValidatorId, ValidatorInfo, ValidatorSet};

    /// Magic prefix. Chosen so it cannot appear as the start of a valid
    /// `BlockPayload::encode()` JSON output (which always starts with `{"`).
    pub const EPOCH_CHANGE_MAGIC: &[u8] = b"PQHS-EC1:";

    /// Encode an epoch-change payload: magic prefix + JSON body.
    pub fn encode_epoch_change_payload(new_epoch: u64, validators: &ValidatorSet) -> Vec<u8> {
        let vs_json: Vec<serde_json::Value> = validators
            .validators
            .iter()
            .map(|v| {
                serde_json::json!({
                    "id": v.id.0,
                    "voting_power": v.voting_power,
                    "public_key": hex::encode(&v.public_key),
                })
            })
            .collect();
        let payload = serde_json::json!({
            "type": "epoch_change",
            "epoch": new_epoch,
            "validators": vs_json,
        });
        let mut out = EPOCH_CHANGE_MAGIC.to_vec();
        out.extend_from_slice(payload.to_string().as_bytes());
        out
    }

    /// Decode an epoch-change payload.
    ///
    /// - `Ok(None)` — `data` does not start with the magic (ordinary block).
    /// - `Err(msg)` — magic present but payload is malformed; caller must NOT
    ///   proceed with the commit (fails closed).
    /// - `Ok(Some(vs))` — well-formed; `vs` is the new validator set.
    pub fn decode_epoch_change_payload(data: &[u8]) -> Result<Option<ValidatorSet>, String> {
        if !data.starts_with(EPOCH_CHANGE_MAGIC) {
            return Ok(None);
        }
        let json_bytes = &data[EPOCH_CHANGE_MAGIC.len()..];
        let v: serde_json::Value = serde_json::from_slice(json_bytes)
            .map_err(|e| format!("epoch_change payload: invalid JSON: {e}"))?;
        if v.get("type").and_then(|t| t.as_str()) != Some("epoch_change") {
            return Err("epoch_change payload: missing or wrong 'type' field".to_string());
        }
        let _new_epoch = v
            .get("epoch")
            .and_then(|e| e.as_u64())
            .ok_or_else(|| "epoch_change payload: missing 'epoch' field".to_string())?;
        let validators_json = v
            .get("validators")
            .and_then(|vs| vs.as_array())
            .ok_or_else(|| "epoch_change payload: missing 'validators' array".to_string())?;
        let mut validators = Vec::with_capacity(validators_json.len());
        for (i, entry) in validators_json.iter().enumerate() {
            let id = entry
                .get("id")
                .and_then(|s| s.as_str())
                .ok_or_else(|| format!("epoch_change payload: validators[{i}] missing 'id'"))?;
            let voting_power = entry
                .get("voting_power")
                .and_then(|p| p.as_u64())
                .ok_or_else(|| {
                    format!("epoch_change payload: validators[{i}] missing 'voting_power'")
                })?;
            let pk_hex = entry
                .get("public_key")
                .and_then(|s| s.as_str())
                .ok_or_else(|| {
                    format!("epoch_change payload: validators[{i}] missing 'public_key'")
                })?;
            let public_key = hex::decode(pk_hex).map_err(|e| {
                format!("epoch_change payload: validators[{i}] bad 'public_key' hex: {e}")
            })?;
            validators.push(ValidatorInfo {
                id: ValidatorId(id.to_string()),
                voting_power,
                pop_verified: true,
                public_key,
            });
        }
        Ok(Some(ValidatorSet {
            height: 0,
            validators,
        }))
    }
}

#[cfg(feature = "pq-hotstuff")]
pub use inner::{decode_epoch_change_payload, encode_epoch_change_payload, EPOCH_CHANGE_MAGIC};
