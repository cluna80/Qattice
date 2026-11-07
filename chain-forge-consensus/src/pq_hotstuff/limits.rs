//! Configurable validator, certificate and message limits (spec sections 3.4.3, 3.4.3a). All size arithmetic is checked `u64`
//! (never `usize` multiplication), so a hostile count cannot wrap a bound. The repository defines no PQ-HotStuff-2 message
//! limit: `max_message_bytes` is therefore optional here and must be supplied before the engine runs
//! ([`PqLimits::require_message_limit`]); it is never invented.

/// Decoder-protection ceiling on a certificate's validator count, applied before the epoch is known.
pub const MAX_CERT_VALIDATORS: usize = 1024;
/// One ML-DSA-65 signature envelope: `alg_id` u16 + length u32 + 3309 bytes.
pub const SIG_ENVELOPE_BYTES: u64 = 3315;
/// Fixed header allowance of a proposal (epoch, round, height, parent id, proposer, length prefixes).
pub const PROPOSAL_HEADER_ALLOWANCE: u64 = 512;

fn bitmap_bytes(n: u64) -> u64 { n / 8 + u64::from(n % 8 != 0) }

/// Largest encoded QC v1 for `n` validators, all signing: `140 + ceil(n/8) + 3315*n`.
pub fn qc_max_bytes(n: usize) -> Option<u64> {
    let n = u64::try_from(n).ok()?;
    140u64.checked_add(bitmap_bytes(n))?.checked_add(SIG_ENVELOPE_BYTES.checked_mul(n)?)
}

/// Largest encoded TC v1 for `n` validators with a nested QC of an earlier epoch of `n_h` validators:
/// `72 + ceil(n/8) + 3323*n + qc_max(n_h)`.
pub fn tc_max_bytes(n: usize, n_h: usize) -> Option<u64> {
    let nn = u64::try_from(n).ok()?;
    72u64.checked_add(bitmap_bytes(nn))?.checked_add(3323u64.checked_mul(nn)?)?.checked_add(qc_max_bytes(n_h)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LimitsError {
    #[error("max_validators is zero")]
    NoValidators,
    #[error("max_cert_validators exceeds the decoder ceiling {MAX_CERT_VALIDATORS}")]
    CertificateCeilingTooHigh,
    #[error("max_validators exceeds max_cert_validators")]
    ValidatorsAboveCertificateCeiling,
    #[error("a size computation overflowed")]
    Overflow,
    #[error("max_message_bytes {limit} is below the largest legal proposal {needed}")]
    MessageLimitBelowEnvelope { limit: u64, needed: u64 },
    #[error("max_message_bytes is not set; the repository defines no PQ-HotStuff-2 message limit")]
    MessageLimitUnset,
    #[error("a validator set of {n} exceeds the profile limit {max}")]
    SetTooLarge { n: usize, max: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqLimits {
    /// The profile's validator limit (`V_profile`).
    pub max_validators: usize,
    /// Decoder ceiling for a certificate's bitmap before the epoch is known.
    pub max_cert_validators: usize,
    /// Payload limit (genesis `limits.max_block_bytes`); certificates are not charged against it.
    pub max_block_payload_bytes: u64,
    /// Network message limit for consensus messages. `None` until the owner sets one.
    pub max_message_bytes: Option<u64>,
}

impl PqLimits {
    /// Largest proposal as transmitted: payload + QC + TC (nested QC of an equally large set) + proposer envelope + header.
    pub fn proposal_envelope_max(&self, n: usize) -> Option<u64> {
        self.max_block_payload_bytes
            .checked_add(qc_max_bytes(n)?)?
            .checked_add(tc_max_bytes(n, n)?)?
            .checked_add(SIG_ENVELOPE_BYTES)?
            .checked_add(PROPOSAL_HEADER_ALLOWANCE)
    }

    pub fn validate(&self) -> Result<(), LimitsError> {
        if self.max_validators == 0 {
            return Err(LimitsError::NoValidators);
        }
        if self.max_cert_validators > MAX_CERT_VALIDATORS {
            return Err(LimitsError::CertificateCeilingTooHigh);
        }
        if self.max_validators > self.max_cert_validators {
            return Err(LimitsError::ValidatorsAboveCertificateCeiling);
        }
        let needed = self.proposal_envelope_max(self.max_validators).ok_or(LimitsError::Overflow)?;
        if let Some(limit) = self.max_message_bytes {
            if limit < needed {
                return Err(LimitsError::MessageLimitBelowEnvelope { limit, needed });
            }
        }
        Ok(())
    }

    pub fn require_message_limit(&self) -> Result<u64, LimitsError> {
        self.max_message_bytes.ok_or(LimitsError::MessageLimitUnset)
    }

    pub fn check_set_size(&self, n: usize) -> Result<(), LimitsError> {
        if n > self.max_validators { Err(LimitsError::SetTooLarge { n, max: self.max_validators }) } else { Ok(()) }
    }
}
