//! Error types for the purl library.

use thiserror::Error;

/// Result type alias for purl operations.
pub type Result<T> = std::result::Result<T, PurlError>;

#[derive(Error, Debug)]
pub enum PurlError {
    #[error("Payment provider not found for network: {0}")]
    ProviderNotFound(String),

    /// No payment methods are configured
    #[error("No payment methods configured")]
    NoPaymentMethods,

    /// No compatible payment method for the server's requirements
    #[error("No compatible payment method found. Available networks: {networks:?}")]
    NoCompatibleMethod { networks: Vec<String> },

    /// Required amount exceeds user's maximum allowed
    #[error("Required amount ({required}) exceeds maximum allowed ({max})")]
    AmountExceedsMax { required: u128, max: u128 },

    /// Insufficient balance to complete payment
    #[error("Insufficient balance to complete payment")]
    InsufficientBalance { message: String },

    /// Invalid payment amount format
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Missing required payment field
    #[error("Missing payment requirement: {0}")]
    MissingRequirement(String),

    /// Configuration file or value is missing
    #[error("Configuration missing: {0}")]
    ConfigMissing(String),

    /// Configuration is invalid
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Invalid private key format
    #[error("Invalid private key: {0}")]
    InvalidKey(String),

    /// Invalid password for keystore decryption
    #[error("Invalid password")]
    InvalidPassword,

    /// Failed to determine config directory
    #[error("Failed to determine config directory")]
    NoConfigDir,

    /// Unknown network identifier
    #[error("Unknown network: {0}")]
    UnknownNetwork(String),

    /// Token not configured for network
    #[error("Token configuration not found for asset {asset} on network {network}")]
    TokenConfigNotFound { asset: String, network: String },

    /// Unsupported token type
    #[error("Unsupported token: {0}")]
    UnsupportedToken(String),

    /// Balance query failed
    #[error("Balance query failed: {0}")]
    BalanceQuery(String),

    // ==================== HTTP Errors ====================
    /// HTTP request/response error
    #[error("HTTP error: {0}")]
    Http(String),

    /// Unsupported HTTP method
    #[error("Unsupported HTTP method: {0}")]
    UnsupportedHttpMethod(String),

    /// EVM/Alloy signing error
    #[error("Signing error: {0}")]
    Signing(String),

    /// Address parsing error (EVM or Solana)
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Solana-specific error
    #[error("Solana error: {0}")]
    Solana(String),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// TOML parsing error
    #[error("TOML parsing error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// TOML serialization error
    #[error("TOML serialization error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    /// Hex decoding error
    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Base64 decoding error
    #[error("Base64 decoding error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// Base58 decoding error
    #[error("Base58 decoding error: {0}")]
    Base58Decode(#[from] bs58::decode::Error),

    /// Bincode serialization error
    #[error("Bincode error: {0}")]
    Bincode(#[from] bincode::Error),

    // ==================== External Library Errors ====================
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Curl error
    #[error("Curl error: {0}")]
    Curl(#[from] curl::Error),

    /// Invalid UTF-8 in response
    #[error("Invalid UTF-8 in response body")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    /// System time error
    #[error("System time error: {0}")]
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
