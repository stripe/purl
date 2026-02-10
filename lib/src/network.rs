//! Network registry with support for both built-in and custom networks.

use crate::currency::Currency;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Network name constants for use in configuration and matching
pub mod networks {
    pub const ETHEREUM: &str = "ethereum";
    pub const ETHEREUM_SEPOLIA: &str = "ethereum-sepolia";
    pub const BASE: &str = "base";
    pub const BASE_SEPOLIA: &str = "base-sepolia";
    pub const AVALANCHE: &str = "avalanche";
    pub const AVALANCHE_FUJI: &str = "avalanche-fuji";
    pub const POLYGON: &str = "polygon";
    pub const ARBITRUM: &str = "arbitrum";
    pub const OPTIMISM: &str = "optimism";
    pub const SOLANA: &str = "solana";
    pub const SOLANA_DEVNET: &str = "solana-devnet";
}

/// Chain type (blockchain family)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    Evm,
    Solana,
}

/// Built-in network definition (compile-time constant)
struct BuiltinNetwork {
    id: &'static str,
    chain_type: ChainType,
    chain_id: Option<u64>,
    mainnet: bool,
    display_name: &'static str,
    rpc_url: &'static str,
    /// Alternative network identifiers (e.g., CAIP-2 formats for v2 x402)
    aliases: &'static [&'static str],
    /// Base URL for blockchain explorer (e.g., "https://basescan.org")
    explorer_url: Option<&'static str>,
}

/// Default built-in networks defined in code
const BUILTIN_NETWORKS: &[BuiltinNetwork] = &[
    BuiltinNetwork {
        id: networks::ETHEREUM,
        chain_type: ChainType::Evm,
        chain_id: Some(1),
        mainnet: true,
        display_name: "Ethereum",
        rpc_url: "https://eth.llamarpc.com",
        aliases: &["eip155:1"],
        explorer_url: Some("https://etherscan.io"),
    },
    BuiltinNetwork {
        id: networks::ETHEREUM_SEPOLIA,
        chain_type: ChainType::Evm,
        chain_id: Some(11155111),
        mainnet: false,
        display_name: "Ethereum Sepolia",
        rpc_url: "https://ethereum-sepolia-rpc.publicnode.com",
        aliases: &["eip155:11155111"],
        explorer_url: Some("https://sepolia.etherscan.io"),
    },
    BuiltinNetwork {
        id: networks::BASE,
        chain_type: ChainType::Evm,
        chain_id: Some(8453),
        mainnet: true,
        display_name: "Base",
        rpc_url: "https://mainnet.base.org",
        aliases: &["eip155:8453"],
        explorer_url: Some("https://basescan.org"),
    },
    BuiltinNetwork {
        id: networks::BASE_SEPOLIA,
        chain_type: ChainType::Evm,
        chain_id: Some(84532),
        mainnet: false,
        display_name: "Base Sepolia",
        rpc_url: "https://sepolia.base.org",
        aliases: &["eip155:84532"],
        explorer_url: Some("https://sepolia.basescan.org"),
    },
    BuiltinNetwork {
        id: networks::AVALANCHE,
        chain_type: ChainType::Evm,
        chain_id: Some(43114),
        mainnet: true,
        display_name: "Avalanche C-Chain",
        rpc_url: "https://api.avax.network/ext/bc/C/rpc",
        aliases: &["eip155:43114"],
        explorer_url: Some("https://snowtrace.io"),
    },
    BuiltinNetwork {
        id: networks::AVALANCHE_FUJI,
        chain_type: ChainType::Evm,
        chain_id: Some(43113),
        mainnet: false,
        display_name: "Avalanche Fuji",
        rpc_url: "https://api.avax-test.network/ext/bc/C/rpc",
        aliases: &["eip155:43113"],
        explorer_url: Some("https://testnet.snowtrace.io"),
    },
    BuiltinNetwork {
        id: networks::POLYGON,
        chain_type: ChainType::Evm,
        chain_id: Some(137),
        mainnet: true,
        display_name: "Polygon",
        rpc_url: "https://polygon-rpc.com",
        aliases: &["eip155:137"],
        explorer_url: Some("https://polygonscan.com"),
    },
    BuiltinNetwork {
        id: networks::ARBITRUM,
        chain_type: ChainType::Evm,
        chain_id: Some(42161),
        mainnet: true,
        display_name: "Arbitrum One",
        rpc_url: "https://arb1.arbitrum.io/rpc",
        aliases: &["eip155:42161"],
        explorer_url: Some("https://arbiscan.io"),
    },
    BuiltinNetwork {
        id: networks::OPTIMISM,
        chain_type: ChainType::Evm,
        chain_id: Some(10),
        mainnet: true,
        display_name: "Optimism",
        rpc_url: "https://mainnet.optimism.io",
        aliases: &["eip155:10"],
        explorer_url: Some("https://optimistic.etherscan.io"),
    },
    BuiltinNetwork {
        id: networks::SOLANA,
        chain_type: ChainType::Solana,
        chain_id: None,
        mainnet: true,
        display_name: "Solana Mainnet",
        rpc_url: "https://api.mainnet-beta.solana.com",
        aliases: &["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"],
        explorer_url: Some("https://solscan.io"),
    },
    BuiltinNetwork {
        id: networks::SOLANA_DEVNET,
        chain_type: ChainType::Solana,
        chain_id: None,
        mainnet: false,
        display_name: "Solana Devnet",
        rpc_url: "https://api.devnet.solana.com",
        aliases: &["solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"],
        explorer_url: Some("https://solscan.io?cluster=devnet"),
    },
];

/// Runtime network information
///
/// Contains metadata about a blockchain network including its type,
/// chain ID (for EVM networks), mainnet/testnet status, display name,
/// and RPC endpoint URL.
///
/// # Examples
///
/// ```
/// use purl_lib::network::get_network;
///
/// let base = get_network("base").expect("base network exists");
/// assert!(base.mainnet);
/// assert!(!base.is_testnet());
/// ```
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    /// The blockchain family (EVM or Solana)
    pub chain_type: ChainType,
    /// Chain ID for EVM networks (None for Solana)
    pub chain_id: Option<u64>,
    /// True if this is a mainnet, false for testnets
    pub mainnet: bool,
    /// Human-readable display name
    pub display_name: String,
    /// RPC endpoint URL for blockchain interactions
    pub rpc_url: String,
    /// Base URL for blockchain explorer (e.g., "https://basescan.org")
    pub explorer_url: Option<String>,
}

impl NetworkInfo {
    pub fn is_testnet(&self) -> bool {
        !self.mainnet
    }

    /// Get the explorer URL for a transaction hash
    pub fn tx_url(&self, tx_hash: &str) -> Option<String> {
        self.explorer_url.as_ref().map(|base| {
            if self.chain_type == ChainType::Solana {
                format!("{}/tx/{}", base.trim_end_matches('?'), tx_hash)
            } else {
                format!("{}/tx/{}", base, tx_hash)
            }
        })
    }

    /// Get the explorer URL for an address
    pub fn address_url(&self, address: &str) -> Option<String> {
        self.explorer_url.as_ref().map(|base| {
            if self.chain_type == ChainType::Solana {
                format!("{}/account/{}", base.trim_end_matches('?'), address)
            } else {
                format!("{}/address/{}", base, address)
            }
        })
    }
}

/// Registry for managing network configurations
///
/// Loads network definitions from built-in defaults and config.toml overrides.
/// Custom networks and RPC overrides can be configured in `~/.purl/config.toml`.
///
/// The registry provides lookup and filtering capabilities for all configured networks.
///
/// # Structure
///
/// Maps network ID (e.g., "base", "ethereum") to [`NetworkInfo`]
///
/// # Custom Networks
///
/// To add custom networks or override RPC URLs, edit `~/.purl/config.toml`:
///
/// ```toml
/// # Override RPC URLs for built-in networks
/// [rpc]
/// base = "https://my-custom-rpc.com"
///
/// # Add custom networks
/// [[networks]]
/// id = "custom-evm"
/// chain_type = "evm"
/// chain_id = 12345
/// mainnet = false
/// display_name = "Custom EVM Chain"
/// rpc_url = "https://rpc.custom.com"
/// ```
pub struct NetworkRegistry {
    networks: HashMap<String, NetworkInfo>,
    /// Maps network aliases (e.g., CAIP-2 formats) to canonical network IDs
    aliases: HashMap<String, String>,
}

impl NetworkRegistry {
    /// Load network registry from built-in defaults and config.toml overrides.
    ///
    /// The loading order is:
    /// 1. Start with built-in network definitions (defined in code)
    /// 2. Apply RPC URL overrides from config.toml `[rpc]` section
    /// 3. Merge custom networks from config.toml `[[networks]]` section
    fn load() -> Self {
        // Start with built-in defaults from code
        let mut networks = HashMap::new();
        let mut aliases = HashMap::new();

        for builtin in BUILTIN_NETWORKS {
            let info = NetworkInfo {
                chain_type: builtin.chain_type,
                chain_id: builtin.chain_id,
                mainnet: builtin.mainnet,
                display_name: builtin.display_name.to_string(),
                rpc_url: builtin.rpc_url.to_string(),
                explorer_url: builtin.explorer_url.map(|s| s.to_string()),
            };
            networks.insert(builtin.id.to_string(), info);

            // Register all aliases for this network
            for alias in builtin.aliases {
                aliases.insert(alias.to_string(), builtin.id.to_string());
            }
        }

        // Try to load config for overrides
        if let Ok(config) = crate::config::Config::load_unchecked(None::<&str>) {
            // Apply RPC URL overrides
            for (network_id, rpc_url) in &config.rpc {
                if let Some(info) = networks.get_mut(network_id) {
                    info.rpc_url = rpc_url.clone();
                }
            }

            // Merge custom networks from config
            for custom in &config.networks {
                let info = NetworkInfo {
                    chain_type: custom.chain_type,
                    chain_id: custom.chain_id,
                    mainnet: custom.mainnet,
                    display_name: custom.display_name.clone(),
                    rpc_url: custom.rpc_url.clone(),
                    explorer_url: None, // Custom networks don't have explorer URLs yet
                };
                networks.insert(custom.id.clone(), info);
            }
        }

        Self { networks, aliases }
    }

    /// Get network info by ID
    pub fn get(&self, id: &str) -> Option<&NetworkInfo> {
        self.networks.get(id)
    }

    /// Resolve a network alias to its canonical ID
    ///
    /// Supports both v1 names (returned as-is) and v2 CAIP-2 formats (resolved to v1 names).
    /// Returns the input unchanged if it's already a canonical ID or if no alias exists.
    pub fn resolve_alias<'a>(&'a self, network: &'a str) -> &'a str {
        self.aliases
            .get(network)
            .map(|s| s.as_str())
            .unwrap_or(network)
    }

    /// Get all network IDs
    pub fn all_ids(&self) -> impl Iterator<Item = &String> {
        self.networks.keys()
    }

    /// Get all networks of a specific chain type
    pub fn by_chain_type(
        &self,
        chain_type: ChainType,
    ) -> impl Iterator<Item = (&String, &NetworkInfo)> {
        self.networks
            .iter()
            .filter(move |(_, info)| info.chain_type == chain_type)
    }

    /// Check if a network ID is an EVM network
    pub fn is_evm(&self, id: &str) -> bool {
        self.get(id)
            .map(|n| n.chain_type == ChainType::Evm)
            .unwrap_or(false)
    }

    /// Check if a network ID is a Solana network
    pub fn is_solana(&self, id: &str) -> bool {
        self.get(id)
            .map(|n| n.chain_type == ChainType::Solana)
            .unwrap_or(false)
    }

    /// Get the number of registered networks
    pub fn len(&self) -> usize {
        self.networks.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }
}

/// Global network registry
pub static NETWORK_REGISTRY: Lazy<NetworkRegistry> = Lazy::new(NetworkRegistry::load);

/// Type-safe network identifier with FromStr parsing.
///
/// This enum provides compile-time guarantees for well-known network names.
/// For dynamic/custom networks, use the NetworkRegistry directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Ethereum,
    EthereumSepolia,
    Base,
    BaseSepolia,
    Avalanche,
    AvalancheFuji,
    Polygon,
    Arbitrum,
    Optimism,
    Solana,
    SolanaDevnet,
}

impl Network {
    /// Get the string identifier for this network.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Network::Ethereum => networks::ETHEREUM,
            Network::EthereumSepolia => networks::ETHEREUM_SEPOLIA,
            Network::Base => networks::BASE,
            Network::BaseSepolia => networks::BASE_SEPOLIA,
            Network::Avalanche => networks::AVALANCHE,
            Network::AvalancheFuji => networks::AVALANCHE_FUJI,
            Network::Polygon => networks::POLYGON,
            Network::Arbitrum => networks::ARBITRUM,
            Network::Optimism => networks::OPTIMISM,
            Network::Solana => networks::SOLANA,
            Network::SolanaDevnet => networks::SOLANA_DEVNET,
        }
    }

    /// Get the NetworkInfo for this network from the registry.
    pub fn info(&self) -> NetworkInfo {
        // These should always exist since they're built-in
        NETWORK_REGISTRY
            .get(self.as_str())
            .cloned()
            .expect("Built-in network missing from registry")
    }

    /// Get all network variants as a const array.
    pub const fn all() -> [Network; 11] {
        [
            Network::Ethereum,
            Network::EthereumSepolia,
            Network::Base,
            Network::BaseSepolia,
            Network::Avalanche,
            Network::AvalancheFuji,
            Network::Polygon,
            Network::Arbitrum,
            Network::Optimism,
            Network::Solana,
            Network::SolanaDevnet,
        ]
    }

    /// Get the chain type for this network.
    pub fn chain_type(&self) -> ChainType {
        self.info().chain_type
    }

    /// Check if this is a mainnet network.
    pub fn is_mainnet(&self) -> bool {
        self.info().mainnet
    }

    /// Check if this is a testnet network.
    pub fn is_testnet(&self) -> bool {
        !self.is_mainnet()
    }

    /// Get all networks of a specific chain type, optionally filtered by name.
    /// Only returns networks that have USDC support configured.
    pub fn by_chain_type(chain_type: ChainType, name_filter: Option<&str>) -> Vec<Network> {
        Network::all()
            .into_iter()
            .filter(|n| n.chain_type() == chain_type)
            .filter(|n| n.usdc_config().is_some())
            .filter(|n| name_filter.is_none_or(|f| n.as_str() == f))
            .collect()
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            networks::ETHEREUM => Ok(Network::Ethereum),
            networks::ETHEREUM_SEPOLIA => Ok(Network::EthereumSepolia),
            networks::BASE => Ok(Network::Base),
            networks::BASE_SEPOLIA => Ok(Network::BaseSepolia),
            networks::AVALANCHE => Ok(Network::Avalanche),
            networks::AVALANCHE_FUJI => Ok(Network::AvalancheFuji),
            networks::POLYGON => Ok(Network::Polygon),
            networks::ARBITRUM => Ok(Network::Arbitrum),
            networks::OPTIMISM => Ok(Network::Optimism),
            networks::SOLANA => Ok(Network::Solana),
            networks::SOLANA_DEVNET => Ok(Network::SolanaDevnet),
            _ => Err(format!("Unknown network: {s}")),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Token configuration for a specific token on a network
///
/// Contains the currency metadata (symbol, decimals) and the token's
/// on-chain address (contract address for EVM, mint address for Solana).
///
/// # Examples
///
/// ```
/// use purl_lib::network::Network;
///
/// let base = Network::Base;
/// let usdc_config = base.usdc_config().expect("Base has USDC");
/// assert_eq!(usdc_config.currency.symbol, "USDC");
/// assert_eq!(usdc_config.currency.decimals, 6);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TokenConfig {
    /// Currency information (symbol, decimals, etc.)
    pub currency: Currency,
    /// Token address - contract address for EVM chains (ERC20), mint address for Solana (SPL)
    pub address: &'static str,
}

impl Network {
    /// Get token configuration for a specific currency on this network
    /// Currently only supports USDC
    pub const fn token_config(&self, _currency: &str) -> Option<TokenConfig> {
        // For now, only USDC is supported
        self.usdc_config()
    }

    /// Get USDC configuration for this network
    pub const fn usdc_config(&self) -> Option<TokenConfig> {
        use crate::currency::currencies;

        match self {
            Network::Ethereum => Some(TokenConfig {
                currency: currencies::USDC,
                address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            }),
            Network::EthereumSepolia => Some(TokenConfig {
                currency: currencies::USDC,
                address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
            }),
            Network::Base => Some(TokenConfig {
                currency: currencies::USDC,
                address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            }),
            Network::BaseSepolia => Some(TokenConfig {
                currency: currencies::USDC,
                address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            }),
            Network::Solana => Some(TokenConfig {
                currency: currencies::USDC,
                address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            }),
            Network::SolanaDevnet => Some(TokenConfig {
                currency: currencies::USDC,
                address: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            }),
            // Other networks don't have USDC support yet
            _ => None,
        }
    }
}

// ==================== Convenience Functions ====================

/// Look up network info by name.
///
/// Supports both v1 names and v2 CAIP-2 formats (e.g., "eip155:8453").
#[must_use]
pub fn get_network(name: &str) -> Option<NetworkInfo> {
    let canonical = NETWORK_REGISTRY.resolve_alias(name);
    NETWORK_REGISTRY.get(canonical).cloned()
}

/// Check if a network name refers to an EVM network.
///
/// Supports both v1 names and v2 CAIP-2 formats (e.g., "eip155:8453").
#[must_use]
pub fn is_evm_network(name: &str) -> bool {
    let canonical = NETWORK_REGISTRY.resolve_alias(name);
    NETWORK_REGISTRY.is_evm(canonical)
}

/// Check if a network name refers to a Solana network.
///
/// Supports both v1 names and v2 CAIP-2 formats.
#[must_use]
pub fn is_solana_network(name: &str) -> bool {
    let canonical = NETWORK_REGISTRY.resolve_alias(name);
    NETWORK_REGISTRY.is_solana(canonical)
}

/// Get the EVM chain ID for a network by name.
///
/// Supports both v1 names and v2 CAIP-2 formats (e.g., "eip155:8453").
#[must_use]
pub fn get_evm_chain_id(name: &str) -> Option<u64> {
    let canonical = NETWORK_REGISTRY.resolve_alias(name);
    NETWORK_REGISTRY.get(canonical).and_then(|n| n.chain_id)
}

/// Resolve network alias to canonical network name
///
/// Supports both v1 names (returned as-is) and v2 CAIP-2 formats (resolved to v1 names).
/// Uses the network registry's alias mappings defined in built-in network definitions.
///
/// # Examples
///
/// ```
/// use purl_lib::network::resolve_network_alias;
///
/// assert_eq!(resolve_network_alias("base"), "base");
/// assert_eq!(resolve_network_alias("eip155:8453"), "base");
/// ```
pub fn resolve_network_alias(network: &str) -> &str {
    NETWORK_REGISTRY.resolve_alias(network)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_lookup() {
        let base = get_network("base").expect("base network should exist");
        assert_eq!(base.chain_type, ChainType::Evm);
        assert_eq!(base.chain_id, Some(8453));
        assert!(base.mainnet);

        let solana = get_network("solana-devnet").expect("solana-devnet should exist");
        assert_eq!(solana.chain_type, ChainType::Solana);
        assert_eq!(solana.chain_id, None);
        assert!(!solana.mainnet);
    }

    #[test]
    fn test_is_evm_network() {
        assert!(is_evm_network("base"));
        assert!(is_evm_network("ethereum"));
        assert!(!is_evm_network("solana"));
        assert!(!is_evm_network("unknown"));
    }

    #[test]
    fn test_is_solana_network() {
        assert!(is_solana_network("solana"));
        assert!(is_solana_network("solana-devnet"));
        assert!(!is_solana_network("base"));
        assert!(!is_solana_network("unknown"));
    }

    #[test]
    fn test_get_evm_chain_id() {
        assert_eq!(get_evm_chain_id("base"), Some(8453));
        assert_eq!(get_evm_chain_id("ethereum"), Some(1));
        assert_eq!(get_evm_chain_id("base-sepolia"), Some(84532));
        assert_eq!(get_evm_chain_id("unknown"), None);
    }

    #[test]
    fn test_network_enum_from_str() {
        assert_eq!("base".parse::<Network>().unwrap(), Network::Base);
        assert_eq!(
            "ethereum-sepolia".parse::<Network>().unwrap(),
            Network::EthereumSepolia
        );
        assert_eq!("solana".parse::<Network>().unwrap(), Network::Solana);
        assert!("unknown-network".parse::<Network>().is_err());
    }

    #[test]
    fn test_network_enum_to_str() {
        assert_eq!(Network::Base.as_str(), "base");
        assert_eq!(Network::EthereumSepolia.as_str(), "ethereum-sepolia");
        assert_eq!(Network::Solana.as_str(), "solana");
        assert_eq!(Network::Base.to_string(), "base");
    }

    #[test]
    fn test_network_enum_info() {
        let base = Network::Base;
        assert_eq!(base.chain_type(), ChainType::Evm);
        assert!(base.is_mainnet());
        assert!(!base.is_testnet());

        let sepolia = Network::EthereumSepolia;
        assert_eq!(sepolia.chain_type(), ChainType::Evm);
        assert!(!sepolia.is_mainnet());
        assert!(sepolia.is_testnet());

        let solana_devnet = Network::SolanaDevnet;
        assert_eq!(solana_devnet.chain_type(), ChainType::Solana);
        assert!(!solana_devnet.is_mainnet());
        assert!(solana_devnet.is_testnet());
    }

    #[test]
    fn test_network_enum_roundtrip() {
        for network_str in &[
            "ethereum",
            "ethereum-sepolia",
            "base",
            "base-sepolia",
            "avalanche",
            "avalanche-fuji",
            "polygon",
            "arbitrum",
            "optimism",
            "solana",
            "solana-devnet",
        ] {
            let network: Network = network_str.parse().expect("should parse");
            assert_eq!(network.as_str(), *network_str);
            assert_eq!(network.to_string(), *network_str);
        }
    }

    #[test]
    fn test_registry_has_all_networks() {
        for network in Network::all() {
            assert!(
                NETWORK_REGISTRY.get(network.as_str()).is_some(),
                "Registry missing network: {}",
                network.as_str()
            );
        }
    }

    #[test]
    fn test_resolve_network_alias() {
        // EVM networks - v2 CAIP-2 format should resolve to v1 names
        assert_eq!(resolve_network_alias("eip155:8453"), "base");
        assert_eq!(resolve_network_alias("eip155:84532"), "base-sepolia");
        assert_eq!(resolve_network_alias("eip155:1"), "ethereum");

        // Solana networks
        assert_eq!(
            resolve_network_alias("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
            "solana"
        );
        assert_eq!(
            resolve_network_alias("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"),
            "solana-devnet"
        );

        // Already v1 format - should return unchanged
        assert_eq!(resolve_network_alias("base"), "base");
        assert_eq!(resolve_network_alias("solana"), "solana");

        // Unknown network - should return unchanged
        assert_eq!(resolve_network_alias("eip155:999999"), "eip155:999999");
    }

    #[test]
    fn test_v2_format_with_convenience_functions() {
        // Test that convenience functions work with v2 CAIP-2 formats

        // get_network
        let base_v1 = get_network("base").expect("base should exist");
        let base_v2 = get_network("eip155:8453").expect("eip155:8453 should resolve to base");
        assert_eq!(base_v1.chain_id, base_v2.chain_id);
        assert_eq!(base_v1.chain_id, Some(8453));

        // is_evm_network
        assert!(is_evm_network("base"));
        assert!(is_evm_network("eip155:8453"));

        // is_solana_network
        assert!(is_solana_network("solana"));
        assert!(is_solana_network("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"));

        // get_evm_chain_id
        assert_eq!(get_evm_chain_id("base"), Some(8453));
        assert_eq!(get_evm_chain_id("eip155:8453"), Some(8453));
        assert_eq!(get_evm_chain_id("eip155:84532"), Some(84532));
    }
}
