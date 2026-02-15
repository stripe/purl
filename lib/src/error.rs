//! Error types for the purl library.

use thiserror::Error;

/// Result type alias for purl operations.
pub type Result<T> = std::result::Result<T, PurlError>;

#[derive(Error, Debug)]
pub enum PurlError {
    #[error("Network '{0}' is not supported. Run `purl networks list` to see available networks.")]
    ProviderNotFound(String),

    #[error("No wallet configured. Run `purl wallet create` to create a new wallet, or `purl wallet import` to import an existing one.")]
    NoPaymentMethods,

    #[error("This payment requires a wallet for {networks:?}, but you don't have one configured. Run `purl wallet create` to add one.")]
    NoCompatibleMethod { networks: Vec<String> },

    #[error("Payment amount {required} exceeds your limit of {max}. Increase your limit with `--max-amount` or decline this payment.")]
    AmountExceedsMax { required: u128, max: u128 },

    #[error("Invalid amount '{0}'. Expected a numeric value.")]
    InvalidAmount(String),

    #[error("The server's payment request is missing required field: {0}")]
    MissingRequirement(String),

    #[error("{0}")]
    ConfigMissing(String),

    #[error("{0}")]
    InvalidConfig(String),

    #[error("{0}")]
    InvalidKey(String),

    #[error("Incorrect wallet password. Please try again.")]
    InvalidPassword,

    #[error("Could not find config directory. Set the PURL_CONFIG_DIR environment variable or ensure your home directory is accessible.")]
    NoConfigDir,

    #[error("Unknown network '{0}'. Run `purl networks list` to see supported networks.")]
    UnknownNetwork(String),

    #[error("Token '{asset}' is not supported on {network}. Run `purl networks info {network}` to see supported tokens.")]
    TokenConfigNotFound { asset: String, network: String },

    #[error("{0}")]
    UnsupportedToken(String),

    #[error("Could not check balance: {0}")]
    BalanceQuery(String),

    // ==================== HTTP Errors ====================
    #[error("{0}")]
    Http(String),

    #[error("HTTP method '{0}' is not supported. Use GET or POST.")]
    UnsupportedHttpMethod(String),

    #[error("{0}")]
    Signing(String),

    #[error("{0}")]
    InvalidAddress(String),

    #[error("{0}")]
    Solana(String),

    #[error("Invalid JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid config file format: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("Failed to save config: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("Invalid hex encoding: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Invalid base64 encoding: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Invalid base58 encoding: {0}")]
    Base58Decode(#[from] bs58::decode::Error),

    #[error("Serialization error: {0}")]
    Bincode(#[from] bincode::Error),

    // ==================== External Library Errors ====================
    #[error("File operation failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network request failed: {0}")]
    Curl(#[from] curl::Error),

    #[error("Server returned invalid text encoding. The response may be corrupted.")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("System clock error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
}

impl PurlError {
    /// Create a signing error
    pub fn signing(msg: impl Into<String>) -> Self {
        Self::Signing(msg.into())
    }

    /// Create an invalid address error
    pub fn invalid_address(msg: impl Into<String>) -> Self {
        Self::InvalidAddress(msg.into())
    }

    /// Create a Solana-specific error
    pub fn solana(msg: impl Into<String>) -> Self {
        Self::Solana(msg.into())
    }

    /// Create a config missing error
    pub fn config_missing(msg: impl Into<String>) -> Self {
        Self::ConfigMissing(msg.into())
    }
}
