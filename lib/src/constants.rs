//! Constants used throughout the purl library

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Application name for XDG directories
pub const APP_NAME: &str = "purl";

/// Config file name
pub const CONFIG_FILE: &str = "config.toml";

/// Keystores subdirectory name
pub const KEYSTORES_DIR: &str = "keystores";

/// x402 protocol version
pub const X402_VERSION: u32 = 1;

/// Default HTTP request timeout in seconds (30 seconds)
pub const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 30;

/// Size of an EVM private key in bytes
pub const EVM_PRIVATE_KEY_BYTES: usize = 32;

/// Size of a Solana keypair in bytes (32 bytes private + 32 bytes public)
pub const SOLANA_KEYPAIR_BYTES: usize = 64;

/// Size of a Solana public key in bytes
pub const SOLANA_PUBKEY_BYTES: usize = 32;

/// Default name for newly created keystores
pub const DEFAULT_KEYSTORE_NAME: &str = "default";

/// Default name for imported keystores
pub const IMPORTED_KEYSTORE_NAME: &str = "imported";

/// Default name for EVM keystores created during init
pub const DEFAULT_EVM_KEYSTORE_NAME: &str = "evm";

/// Keystore file extension
pub const KEYSTORE_EXTENSION: &str = "json";

/// Get the purl home directory (`~/.purl/`)
///
/// Returns the directory where purl stores all its files.
///
/// # Returns
///
/// - `Some(PathBuf)` if the home directory can be determined
/// - `None` if the home directory cannot be determined
///
/// # Examples
///
/// ```
/// use purl_lib::constants::purl_home_dir;
///
/// if let Some(path) = purl_home_dir() {
///     println!("Purl home dir: {}", path.display());
/// }
/// ```
pub fn purl_home_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".purl"))
}

/// Alias for purl_home_dir
pub fn purl_config_dir() -> Option<PathBuf> {
    purl_home_dir()
}

/// Alias for purl_home_dir
pub fn purl_data_dir() -> Option<PathBuf> {
    purl_home_dir()
}

/// Alias for purl_home_dir
pub fn purl_cache_dir() -> Option<PathBuf> {
    purl_home_dir()
}

/// Get the default config file path (`~/.purl/config.toml`)
///
/// Returns the path to the main purl configuration file.
///
/// # Returns
///
/// - `Some(PathBuf)` pointing to the config file location
/// - `None` if the config directory cannot be determined
pub fn default_config_path() -> Option<PathBuf> {
    purl_config_dir().map(|p| p.join(CONFIG_FILE))
}

/// Get the default keystores directory (`~/.purl/keystores/`)
///
/// Returns the path to the directory where encrypted keystores are stored.
///
/// # Returns
///
/// - `Some(PathBuf)` pointing to the keystores directory
/// - `None` if the home directory cannot be determined
pub fn default_keystores_dir() -> Option<PathBuf> {
    purl_data_dir().map(|p| p.join(KEYSTORES_DIR))
}

/// Built-in token definition (compile-time constant)
struct BuiltinToken {
    network: &'static str,
    address: &'static str,
    name: &'static str,
    symbol: &'static str,
    decimals: u8,
}

/// Default built-in tokens defined in code
const BUILTIN_TOKENS: &[BuiltinToken] = &[
    BuiltinToken {
        network: crate::network::networks::SOLANA,
        address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        name: "USD Coin",
        symbol: "USDC",
        decimals: 6,
    },
    BuiltinToken {
        network: crate::network::networks::SOLANA_DEVNET,
        address: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        name: "USD Coin",
        symbol: "USDC",
        decimals: 6,
    },
    BuiltinToken {
        network: crate::network::networks::BASE,
        address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        name: "USD Coin",
        symbol: "USDC",
        decimals: 6,
    },
    BuiltinToken {
        network: crate::network::networks::BASE_SEPOLIA,
        address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
        name: "USD Coin",
        symbol: "USDC",
        decimals: 6,
    },
    BuiltinToken {
        network: crate::network::networks::ETHEREUM,
        address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        name: "USD Coin",
        symbol: "USDC",
        decimals: 6,
    },
    BuiltinToken {
        network: crate::network::networks::ETHEREUM_SEPOLIA,
        address: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238",
        name: "USD Coin",
        symbol: "USDC",
        decimals: 6,
    },
];

/// Represents a token with its metadata
///
/// Contains information about a specific token contract including its
/// human-readable name, symbol, and decimal precision.
///
/// # Examples
///
/// ```
/// use purl_lib::constants::Token;
///
/// let usdc = Token {
///     name: "USD Coin".to_string(),
///     symbol: "USDC".to_string(),
///     decimals: 6,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Full name of the token (e.g., "USD Coin")
    pub name: String,
    /// Token symbol (e.g., "USDC")
    pub symbol: String,
    /// Number of decimal places for the token
    pub decimals: u8,
}

/// Registry for token configuration across all supported networks
///
/// Manages token metadata (name, symbol, decimals) for token contracts
/// across different blockchain networks. Tokens are organized first by
/// network, then by contract address.
///
/// The registry loads from:
/// 1. Built-in token definitions (defined in code)
/// 2. Custom tokens from `~/.purl/config.toml` `[[tokens]]` section
///
/// # Structure
///
/// The registry maps: `network -> contract_address -> Token`
///
/// For EVM networks, addresses are normalized to lowercase for
/// case-insensitive lookups.
///
/// # Custom Tokens
///
/// To add custom tokens, edit `~/.purl/config.toml`:
///
/// ```toml
/// [[tokens]]
/// network = "base"
/// address = "0x..."
/// symbol = "MYTOKEN"
/// name = "My Token"
/// decimals = 18
/// ```
pub struct TokenRegistry {
    tokens: HashMap<String, HashMap<String, Token>>,
}

impl TokenRegistry {
    /// Load token registry from built-in defaults and config.toml extensions.
    ///
    /// The loading order is:
    /// 1. Start with built-in token definitions (defined in code)
    /// 2. Merge custom tokens from config.toml `[[tokens]]` section
    fn load() -> Self {
        let mut tokens: HashMap<String, HashMap<String, Token>> = HashMap::new();

        // Load built-in tokens from code
        for builtin in BUILTIN_TOKENS {
            let token = Token {
                name: builtin.name.to_string(),
                symbol: builtin.symbol.to_string(),
                decimals: builtin.decimals,
            };

            // Addresses are already lowercase for EVM in the builtin definitions
            tokens
                .entry(builtin.network.to_string())
                .or_default()
                .insert(builtin.address.to_string(), token);
        }

        // Try to load config for custom tokens
        if let Ok(config) = crate::config::Config::load_unchecked(None::<&str>) {
            for custom in &config.tokens {
                let token = Token {
                    name: custom.name.clone(),
                    symbol: custom.symbol.clone(),
                    decimals: custom.decimals,
                };

                // Normalize address for EVM networks (lowercase)
                let address = if crate::network::is_evm_network(&custom.network) {
                    custom.address.to_lowercase()
                } else {
                    custom.address.clone()
                };

                tokens
                    .entry(custom.network.clone())
                    .or_default()
                    .insert(address, token);
            }
        }

        Self { tokens }
    }

    /// Look up a token by network and asset address
    ///
    /// Supports both v1 (e.g., "base") and v2 CAIP-2 (e.g., "eip155:8453") network formats
    fn get_token(&self, network: &str, asset: &str) -> Option<&Token> {
        // Resolve network aliases (v2 CAIP-2 format to v1 name)
        let canonical_network = crate::network::resolve_network_alias(network);

        let network_tokens = self.tokens.get(canonical_network)?;

        // Try exact match first (for case-sensitive addresses like Solana)
        if let Some(token) = network_tokens.get(asset) {
            return Some(token);
        }

        // For EVM networks, try case-insensitive lookup
        if crate::network::is_evm_network(canonical_network) {
            let asset_lower = asset.to_lowercase();
            if let Some(token) = network_tokens.get(&asset_lower) {
                return Some(token);
            }
        }

        None
    }

    /// Get token decimals for a network and asset address
    fn get_decimals(&self, network: &str, asset: &str) -> Result<u8, crate::error::PurlError> {
        self.get_token(network, asset)
            .map(|t| t.decimals)
            .ok_or_else(|| crate::error::PurlError::TokenConfigNotFound {
                asset: asset.to_string(),
                network: network.to_string(),
            })
    }

    /// Get token symbol for a network and asset address
    fn get_symbol(&self, network: &str, asset: &str) -> Option<&str> {
        self.get_token(network, asset).map(|t| t.symbol.as_str())
    }
}

/// Global token registry
pub static TOKEN_REGISTRY: Lazy<TokenRegistry> = Lazy::new(TokenRegistry::load);

/// Get token decimals for a network and asset address
///
/// This function checks both built-in tokens (defined in code) and
/// custom tokens (from ~/.purl/config.toml). Returns an error with helpful message if token is not found.
///
/// # Errors
/// Returns `PurlError::TokenConfigNotFound` if the token is not configured for the specified network.
/// To add custom tokens, add a `[[tokens]]` section to `~/.purl/config.toml`.
pub fn get_token_decimals(network: &str, asset: &str) -> Result<u8, crate::error::PurlError> {
    TOKEN_REGISTRY.get_decimals(network, asset)
}

/// Get token symbol for a network and asset address
///
/// This function checks both built-in tokens (defined in code) and
/// custom tokens (from ~/.purl/config.toml). Returns None if token is not found.
///
/// # Examples
///
/// ```
/// use purl_lib::constants::get_token_symbol;
///
/// // Look up USDC on Base
/// if let Some(symbol) = get_token_symbol("base", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913") {
///     assert_eq!(symbol, "USDC");
/// }
/// ```
pub fn get_token_symbol(network: &str, asset: &str) -> Option<&'static str> {
    TOKEN_REGISTRY.get_symbol(network, asset)
}
