//! Validator sets for PQ-HotStuff-2 (spec section 3.4.1): canonical order, uniqueness, and quorum arithmetic.
//!
//! Dynamic membership is disabled (spec section 3.7 is an open proof obligation, PO-4): only epoch 0 can be built.
//! Powers and thresholds use `u128`, so no sum or `2T` can wrap.
use super::wire::{MAX_NAME_LEN, MLDSA65_PUBLIC_KEY_LEN};

pub type Round = u64;
pub type Epoch = u64;

/// One validator of an epoch: its registered address (byte for byte), its ML-DSA-65 consensus key and its power.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorEntry {
    pub address: String,
    pub public_key: Vec<u8>,
    pub power: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SetError {
    #[error("the validator set is empty")]
    Empty,
    #[error("two validators share an address")]
    DuplicateAddress,
    #[error("two validators share a public key")]
    DuplicateKey,
    #[error("a validator address must be 1 to 255 bytes with no NUL")]
    BadAddress,
    #[error("a consensus key must be exactly {MLDSA65_PUBLIC_KEY_LEN} bytes (got {0})")]
    BadKeyLength(usize),
    #[error("no validator has power")]
    NoPower,
    #[error("a signer index is outside the validator set")]
    IndexOutOfRange,
    #[error("a signer appears twice")]
    DuplicateSigner,
    #[error("a zero-power validator cannot sign")]
    ZeroPowerSigner,
    #[error("epoch changes are disabled: only epoch 0 can be built (PO-4 is unresolved)")]
    EpochChangeDisabled,
}

/// The validators of one epoch in canonical order: ascending bytewise comparison of the UTF-8 address. Every registered
/// validator occupies an index, including one with power 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochSet {
    epoch: Epoch,
    entries: Vec<ValidatorEntry>,
    total: u128,
}

impl EpochSet {
    pub fn new(epoch: Epoch, mut entries: Vec<ValidatorEntry>) -> Result<Self, SetError> {
        if epoch != 0 {
            return Err(SetError::EpochChangeDisabled);
        }
        if entries.is_empty() {
            return Err(SetError::Empty);
        }
        for e in &entries {
            if e.address.is_empty() || e.address.len() > MAX_NAME_LEN || e.address.as_bytes().contains(&0) {
                return Err(SetError::BadAddress);
            }
            if e.public_key.len() != MLDSA65_PUBLIC_KEY_LEN {
                return Err(SetError::BadKeyLength(e.public_key.len()));
            }
        }
        entries.sort_by(|a, b| a.address.as_bytes().cmp(b.address.as_bytes()));
        if entries.windows(2).any(|w| w[0].address == w[1].address) {
            return Err(SetError::DuplicateAddress);
        }
        let mut keys: Vec<&[u8]> = entries.iter().map(|e| e.public_key.as_slice()).collect();
        keys.sort_unstable();
        if keys.windows(2).any(|w| w[0] == w[1]) {
            return Err(SetError::DuplicateKey);
        }
        let total: u128 = entries.iter().map(|e| u128::from(e.power)).sum();
        if total == 0 {
            return Err(SetError::NoPower);
        }
        Ok(Self { epoch, entries, total })
    }

    pub fn epoch(&self) -> Epoch { self.epoch }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn entries(&self) -> &[ValidatorEntry] { &self.entries }
    pub fn index_of(&self, address: &str) -> Option<usize> {
        self.entries.binary_search_by(|e| e.address.as_bytes().cmp(address.as_bytes())).ok()
    }
    pub fn total_power(&self) -> u128 { self.total }
    /// `q = floor(2T/3) + 1` (spec section 3.5.2 step 4).
    pub fn quorum_threshold(&self) -> u128 { 2 * self.total / 3 + 1 }
    pub fn is_quorum(&self, power: u128) -> bool { power >= self.quorum_threshold() }

    /// Total power of a signer list given as ascending-or-not indices. Duplicate, out-of-range and zero-power signers are
    /// errors, not skipped: a certificate that names one is invalid.
    pub fn signer_power(&self, signers: &[usize]) -> Result<u128, SetError> {
        let mut seen = vec![false; self.entries.len()];
        let mut sum = 0u128;
        for &i in signers {
            let e = self.entries.get(i).ok_or(SetError::IndexOutOfRange)?;
            if std::mem::replace(&mut seen[i], true) {
                return Err(SetError::DuplicateSigner);
            }
            if e.power == 0 {
                return Err(SetError::ZeroPowerSigner);
            }
            sum += u128::from(e.power);
        }
        Ok(sum)
    }
}
