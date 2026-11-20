use thiserror::Error;

#[derive(Debug, Error)]
pub enum InstError {
    #[error("invalid chain ID: {0}")]
    InvalidChainId(String),

    #[error("invalid validator count {count}: {reason}")]
    InvalidValidatorCount { count: u32, reason: String },

    #[error("incompatible consensus/crypto combination: {consensus} requires post-quantum crypto, but {crypto} was specified")]
    IncompatibleCryptoConsensus { consensus: String, crypto: String },

    #[error("invalid governance configuration: {0}")]
    InvalidGovernanceConfig(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("genesis build error: {0}")]
    GenesisBuildError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

pub type InstResult<T> = Result<T, InstError>;
