//! Configuration management for purl.

use crate::error::{PurlError, Result};
use crate::network::ChainType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// Trait for chain-specific wallet configuration.
///
/// This provides a common interface for validating and accessing wallet
/// information regardless of the underlying blockchain.
pub trait WalletConfig {
    /// The type of address/public key this wallet produces
    type Address: fmt::Display;

    /// Check if this config has a wallet source configured
    fn has_wallet(&self) -> bool;

    /// Validate the wallet configuration
    fn validate(&self) -> Result<()>;

    /// Get the wallet address/public key
    fn get_address(&self) -> Result<Self::Address>;

    /// Get the chain name for error messages
    fn chain_name(&self) -> &'static str;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub evm: Option<EvmConfig>,
    #[serde(default)]
    pub solana: Option<SolanaConfig>,
    /// RPC URL overrides for built-in networks
    #[serde(default)]
    pub rpc: HashMap<String, String>,
    /// Custom network definitions
    #[serde(default)]
    pub networks: Vec<CustomNetwork>,
    /// Custom token definitions
    #[serde(default)]
    pub tokens: Vec<CustomToken>,
    /// Runtime-only password for keystore decryption (from CLI/env var)
    /// This is not persisted to the config file
    #[serde(skip)]
    pub password: Option<String>,
}

/// Custom network definition for extending built-in networks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomNetwork {
    /// Network identifier (e.g., "my-custom-chain")
    pub id: String,
    /// Chain type (evm or solana)
    pub chain_type: ChainType,
    /// Chain ID for EVM networks (None for Solana)
    #[serde(default)]
    pub chain_id: Option<u64>,
    /// Whether this is a mainnet or testnet
    #[serde(default)]
    pub mainnet: bool,
    /// Human-readable display name
    pub display_name: String,
    /// RPC endpoint URL
    pub rpc_url: String,
}

/// Custom token definition for extending built-in tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomToken {
    /// Network ID this token belongs to
    pub network: String,
    /// Token contract address
    pub address: String,
    /// Token symbol (e.g., "USDC")
    pub symbol: String,
    /// Token full name (e.g., "USD Coin")
    pub name: String,
    /// Number of decimal places
    pub decimals: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmConfig {
    /// Path to encrypted keystore file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keystore: Option<PathBuf>,
}

impl EvmConfig {
    fn address_from_keystore(path: &Path) -> Result<String> {
        use crate::keystore::Keystore;

        let keystore = Keystore::load(path)?;
        keystore
            .formatted_address()
            .ok_or_else(|| PurlError::ConfigMissing("Keystore missing address field".to_string()))
    }
}

impl WalletConfig for EvmConfig {
    type Address = String;

    fn has_wallet(&self) -> bool {
        self.keystore.is_some()
    }

    fn validate(&self) -> Result<()> {
        if let Some(keystore_path) = &self.keystore {
            if !keystore_path.exists() {
                return Err(PurlError::ConfigMissing(format!(
                    "EVM keystore file not found: {}",
                    keystore_path.display()
                )));
            }
        }
        Ok(())
    }

    fn get_address(&self) -> Result<String> {
        let keystore_path = self
            .keystore
            .as_ref()
            .ok_or_else(|| PurlError::ConfigMissing("No EVM keystore configured".to_string()))?;

        Self::address_from_keystore(keystore_path)
    }

    fn chain_name(&self) -> &'static str {
        "EVM"
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolanaConfig {
    /// Path to encrypted keystore file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keystore: Option<PathBuf>,
}

impl WalletConfig for SolanaConfig {
    type Address = String;

    fn has_wallet(&self) -> bool {
        self.keystore.is_some()
    }

    fn validate(&self) -> Result<()> {
        if let Some(keystore_path) = &self.keystore {
            if !keystore_path.exists() {
                return Err(PurlError::ConfigMissing(format!(
                    "Solana keystore file not found: {}",
                    keystore_path.display()
                )));
            }
        }
        Ok(())
    }

    fn get_address(&self) -> Result<String> {
        let keystore_path = self
            .keystore
            .as_ref()
            .ok_or_else(|| PurlError::ConfigMissing("No Solana keystore configured".to_string()))?;

        crate::keystore::get_solana_pubkey_from_keystore(keystore_path)
    }

    fn chain_name(&self) -> &'static str {
        "Solana"
    }
}

/// Macro to reduce builder pattern boilerplate
macro_rules! builder_method {
    ($name:ident, $field:ident, $config_type:ident, $inner_field:ident, $value_type:ty) => {
        #[allow(clippy::needless_update)]
        pub fn $name(mut self, value: impl Into<$value_type>) -> Self {
            self.$field = Some($config_type {
                $inner_field: Some(value.into()),
                ..Default::default()
            });
            self
        }
    };
}

/// Builder for creating Config instances
///
/// # Examples
///
/// ```no_run
/// use purl_lib::config::{Config, ConfigBuilder};
/// use std::path::PathBuf;
///
/// // Build a config with EVM keystore
/// let config = Config::builder()
///     .with_evm_keystore("/path/to/keystore.json")
///     .build()
///     .unwrap();
///
/// // Build a config with both EVM and Solana keystores
/// let config = ConfigBuilder::new()
///     .with_evm_keystore("/path/to/evm-keystore.json")
///     .with_solana_keystore("/path/to/solana-keystore.json")
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    evm: Option<EvmConfig>,
    solana: Option<SolanaConfig>,
    rpc: HashMap<String, String>,
    networks: Vec<CustomNetwork>,
    tokens: Vec<CustomToken>,
}

impl ConfigBuilder {
    /// Create a new config builder
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // Use macro to generate builder methods
    builder_method!(with_evm_keystore, evm, EvmConfig, keystore, PathBuf);
    builder_method!(
        with_solana_keystore,
        solana,
        SolanaConfig,
        keystore,
        PathBuf
    );

    /// Add an RPC URL override for a network
    pub fn with_rpc_override(
        mut self,
        network: impl Into<String>,
        rpc_url: impl Into<String>,
    ) -> Self {
        self.rpc.insert(network.into(), rpc_url.into());
        self
    }

    /// Add a custom network
    pub fn with_network(mut self, network: CustomNetwork) -> Self {
        self.networks.push(network);
        self
    }

    /// Add a custom token
    pub fn with_token(mut self, token: CustomToken) -> Self {
        self.tokens.push(token);
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<Config> {
        let config = Config {
            evm: self.evm,
            solana: self.solana,
            rpc: self.rpc,
            networks: self.networks,
            tokens: self.tokens,
            password: None,
        };

        // Validate the configuration
        config.validate()?;
        Ok(config)
    }
}

impl Config {
    /// Create a new config builder
    #[must_use]
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }

    /// Load config from the specified path or default location (~/.purl/config.toml)
    pub fn load_from(config_path: Option<impl AsRef<Path>>) -> Result<Self> {
        let config_path = if let Some(path) = config_path {
            PathBuf::from(path.as_ref())
        } else {
            Self::default_config_path()?
        };

        if !config_path.exists() {
            return Err(PurlError::ConfigMissing(format!(
                "Config file not found at {}. Run 'purl wallet add' to create one.",
                config_path.display()
            )));
        }

        let content = std::fs::read_to_string(&config_path).map_err(|e| {
            PurlError::ConfigMissing(format!(
                "Failed to read config file at {}: {}",
                config_path.display(),
                e
            ))
        })?;

        let config: Config = toml::from_str(&content).map_err(|e| {
            PurlError::ConfigMissing(format!(
                "Failed to parse config file at {}: {}",
                config_path.display(),
                e
            ))
        })?;

        // Validate configuration immediately after loading
        config.validate().map_err(|e| {
            PurlError::ConfigMissing(format!(
                "Invalid configuration in {}: {}",
                config_path.display(),
                e
            ))
        })?;

        Ok(config)
    }

    /// Load config from the default location (~/.purl/config.toml)
    pub fn load() -> Result<Self> {
        Self::load_from(None::<&str>)
    }

    /// Load config without validation.
    ///
    /// This is useful during initialization or when you want to inspect
    /// a potentially invalid config file. Use `load_from` for normal usage.
    pub fn load_unchecked(config_path: Option<impl AsRef<Path>>) -> Result<Self> {
        let config_path = if let Some(path) = config_path {
            PathBuf::from(path.as_ref())
        } else {
            Self::default_config_path()?
        };

        if !config_path.exists() {
            return Err(PurlError::ConfigMissing(format!(
                "Config file not found at {}. Run 'purl wallet add' to create one.",
                config_path.display()
            )));
        }

        let content = std::fs::read_to_string(&config_path).map_err(|e| {
            PurlError::ConfigMissing(format!(
                "Failed to read config file at {}: {}",
                config_path.display(),
                e
            ))
        })?;

        toml::from_str(&content).map_err(|e| {
            PurlError::ConfigMissing(format!(
                "Failed to parse config file at {}: {}",
                config_path.display(),
                e
            ))
        })
    }

    /// Load config, returning default if file doesn't exist.
    ///
    /// Unlike `load_unchecked().unwrap_or_default()`, this propagates errors
    /// for invalid or unreadable config files instead of silently discarding them.
    pub fn load_or_default(config_path: Option<impl AsRef<Path>>) -> Result<Self> {
        let config_path = if let Some(path) = config_path {
            PathBuf::from(path.as_ref())
        } else {
            Self::default_config_path()?
        };

        if !config_path.exists() {
            return Ok(Self::default());
        }

        // File exists - any error here should be propagated
        let content = std::fs::read_to_string(&config_path).map_err(|e| {
            PurlError::InvalidConfig(format!(
                "Failed to read config file at {}: {}",
                config_path.display(),
                e
            ))
        })?;

        toml::from_str(&content).map_err(|e| {
            PurlError::InvalidConfig(format!(
                "Failed to parse config file at {}: {}",
                config_path.display(),
                e
            ))
        })
    }

    /// Get the default config file path (~/.purl/config.toml)
    pub fn default_config_path() -> Result<PathBuf> {
        crate::constants::default_config_path().ok_or(PurlError::NoConfigDir)
    }

    /// Save config to the default location with validation
    pub fn save(&self) -> Result<()> {
        // Validate the configuration before saving
        self.validate()?;

        let config_path = Self::default_config_path()?;

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
            // Set secure permissions on the config directory
            crate::permissions::set_secure_dir_permissions(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        std::fs::write(&config_path, &content)?;

        // Set secure permissions on the config file (0600)
        crate::permissions::set_secure_file_permissions(&config_path)?;

        Ok(())
    }

    /// Detect which payment method is available based on config
    pub fn available_payment_methods(&self) -> Vec<PaymentMethod> {
        let mut methods = Vec::new();
        if self.evm.is_some() {
            methods.push(PaymentMethod::Evm);
        }
        if self.solana.is_some() {
            methods.push(PaymentMethod::Solana);
        }
        methods
    }

    /// Validate the configuration by checking all configured wallet sources.
    ///
    /// This validates that configured wallets have valid key material.
    pub fn validate(&self) -> Result<()> {
        if let Some(evm) = &self.evm {
            evm.validate()
                .map_err(|e| PurlError::ConfigMissing(format!("EVM configuration invalid: {e}")))?;
        }
        if let Some(solana) = &self.solana {
            solana.validate().map_err(|e| {
                PurlError::ConfigMissing(format!("Solana configuration invalid: {e}"))
            })?;
        }
        Ok(())
    }

    /// Get EVM configuration, returning an error if not configured.
    ///
    /// This is a convenience method to avoid repeated error handling boilerplate.
    pub fn require_evm(&self) -> Result<&EvmConfig> {
        self.evm.as_ref().ok_or_else(|| {
            PurlError::ConfigMissing(
                "EVM configuration not found. Run 'purl wallet add' to configure.".to_string(),
            )
        })
    }

    /// Get Solana configuration, returning an error if not configured.
    ///
    /// This is a convenience method to avoid repeated error handling boilerplate.
    pub fn require_solana(&self) -> Result<&SolanaConfig> {
        self.solana.as_ref().ok_or_else(|| {
            PurlError::ConfigMissing(
                "Solana configuration not found. Run 'purl wallet add' to configure.".to_string(),
            )
        })
    }
}

/// Payment method types supported by the library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentMethod {
    /// Ethereum Virtual Machine compatible chains (Ethereum, Base, Polygon, etc.)
    Evm,
    /// Solana blockchain
    Solana,
}

impl PaymentMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            PaymentMethod::Evm => "evm",
            PaymentMethod::Solana => "solana",
        }
    }

    /// Get a human-readable display name
    pub fn display_name(&self) -> &'static str {
        match self {
            PaymentMethod::Evm => "EVM",
            PaymentMethod::Solana => "Solana",
        }
    }
}

impl fmt::Display for PaymentMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config_with_both_keystores() {
        let toml = r#"
            [evm]
            keystore = "/path/to/evm.json"

            [solana]
            keystore = "/path/to/solana.json"
        "#;

        let config: Config = toml::from_str(toml).expect("should parse");
        assert!(config.evm.is_some());
        assert!(config.solana.is_some());
        let evm = config.evm.as_ref().unwrap();
        let solana = config.solana.as_ref().unwrap();
        assert_eq!(
            evm.keystore.as_ref().unwrap().to_str().unwrap(),
            "/path/to/evm.json"
        );
        assert_eq!(
            solana.keystore.as_ref().unwrap().to_str().unwrap(),
            "/path/to/solana.json"
        );
    }

    #[test]
    fn test_parse_config_evm_only() {
        let toml = r#"
            [evm]
            keystore = "/path/to/evm.json"
        "#;

        let config: Config = toml::from_str(toml).expect("should parse");
        assert!(config.evm.is_some());
        assert!(config.solana.is_none());
    }

    #[test]
    fn test_parse_config_solana_only() {
        let toml = r#"
            [solana]
            keystore = "/path/to/solana.json"
        "#;

        let config: Config = toml::from_str(toml).expect("should parse");
        assert!(config.evm.is_none());
        assert!(config.solana.is_some());
    }

    #[test]
    fn test_parse_config_rejects_unknown_fields() {
        let toml = r#"
            [evm]
            private_key = "abcdef1234567890"
        "#;

        let result: std::result::Result<Config, _> = toml::from_str(toml);
        assert!(result.is_err(), "Should reject unknown field 'private_key'");
    }

    #[test]
    fn test_parse_config_with_keystores() {
        let toml = r#"
            [evm]
            keystore = "/path/to/evm.json"

            [solana]
            keystore = "/path/to/solana.json"
        "#;

        let config: Config = toml::from_str(toml).expect("should parse");
        assert!(config.evm.is_some());
        assert!(config.solana.is_some());
        let evm = config.evm.as_ref().unwrap();
        let solana = config.solana.as_ref().unwrap();
        assert_eq!(
            evm.keystore.as_ref().unwrap().to_str().unwrap(),
            "/path/to/evm.json"
        );
        assert_eq!(
            solana.keystore.as_ref().unwrap().to_str().unwrap(),
            "/path/to/solana.json"
        );
    }

    #[test]
    fn test_available_payment_methods() {
        let config = Config {
            evm: Some(EvmConfig {
                keystore: Some(PathBuf::from("/path/to/evm.json")),
            }),
            solana: Some(SolanaConfig {
                keystore: Some(PathBuf::from("/path/to/solana.json")),
            }),
            ..Default::default()
        };
        let methods = config.available_payment_methods();
        assert_eq!(methods.len(), 2);
        assert!(methods.contains(&PaymentMethod::Evm));
        assert!(methods.contains(&PaymentMethod::Solana));

        let config = Config {
            evm: None,
            solana: Some(SolanaConfig {
                keystore: Some(PathBuf::from("/path/to/solana.json")),
            }),
            ..Default::default()
        };
        let methods = config.available_payment_methods();
        assert_eq!(methods.len(), 1);
        assert!(methods.contains(&PaymentMethod::Solana));
    }
}
