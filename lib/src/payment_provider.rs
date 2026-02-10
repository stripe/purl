//! Payment provider abstraction and registry.
//!
//! This module defines the trait for payment providers (blockchain-specific
//! payment implementations) and a registry for looking up providers by network.

use crate::config::Config;
use crate::currency::Currency;
use crate::error::Result;
use crate::network::Network;
use crate::x402::{PaymentPayload, PaymentRequirements};
use async_trait::async_trait;
use once_cell::sync::Lazy;

/// Balance information for a single network
#[derive(Debug, Clone)]
pub struct NetworkBalance {
    pub network: String,
    pub balance_atomic: String,
    pub balance_human: String,
    pub asset: String,
}

impl std::fmt::Display for NetworkBalance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} on {}",
            self.balance_human, self.asset, self.network
        )
    }
}

/// Information about what a dry-run payment would do
#[derive(Debug, Clone)]
pub struct DryRunInfo {
    pub provider: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    pub from: String,
    pub to: String,
    pub estimated_fee: Option<String>,
}

/// Trait for payment providers (chains/networks).
///
/// This trait defines the interface that all payment providers must implement.
/// The built-in EVM and Solana providers are optimized using enum dispatch,
/// but custom providers can implement this trait directly.
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// Check if this provider supports the given network
    fn supports_network(&self, network: &str) -> bool;

    /// Create a payment payload for the given requirements
    async fn create_payment(
        &self,
        requirements: &PaymentRequirements,
        config: &Config,
    ) -> Result<PaymentPayload>;

    /// Get the name of this provider
    fn name(&self) -> &str;

    /// Check if a dry run shows this payment would succeed
    fn dry_run(&self, requirements: &PaymentRequirements, config: &Config) -> Result<DryRunInfo>;

    /// Get the wallet address for this provider from config
    fn get_address(&self, config: &Config) -> Result<String>;

    /// Get token balance for an address on a specific network
    async fn get_balance(
        &self,
        address: &str,
        network: Network,
        currency: Currency,
    ) -> Result<NetworkBalance>;
}

macro_rules! dispatch_provider {
    ($self:expr, $method:ident ( $($arg:expr),* )) => {
        match $self {
            #[cfg(feature = "evm")]
            BuiltinProvider::Evm => Self::evm().$method($($arg),*),
            #[cfg(feature = "solana")]
            BuiltinProvider::Solana => Self::solana().$method($($arg),*),
        }
    };
}

/// Enum wrapper for built-in providers.
///
/// This provides compile-time dispatch for the standard providers,
/// avoiding the overhead of dynamic dispatch for common operations.
///
/// The variants are conditionally compiled based on enabled features.
#[derive(Debug, Clone, Copy)]
pub enum BuiltinProvider {
    #[cfg(feature = "evm")]
    Evm,
    #[cfg(feature = "solana")]
    Solana,
}

impl Default for BuiltinProvider {
    fn default() -> Self {
        #[cfg(feature = "evm")]
        return BuiltinProvider::Evm;
        #[cfg(all(not(feature = "evm"), feature = "solana"))]
        return BuiltinProvider::Solana;
        #[cfg(all(not(feature = "evm"), not(feature = "solana")))]
        compile_error!("At least one provider feature (evm or solana) must be enabled");
    }
}

impl BuiltinProvider {
    /// Get the EVM provider instance
    #[cfg(feature = "evm")]
    fn evm() -> &'static crate::providers::evm::EvmProvider {
        static EVM: crate::providers::evm::EvmProvider = crate::providers::evm::EvmProvider;
        &EVM
    }

    /// Get the Solana provider instance
    #[cfg(feature = "solana")]
    fn solana() -> &'static crate::providers::solana::SolanaProvider {
        static SOLANA: crate::providers::solana::SolanaProvider =
            crate::providers::solana::SolanaProvider;
        &SOLANA
    }

    /// Get the appropriate provider for a network
    pub fn for_network(network: &str) -> Option<Self> {
        #[cfg(feature = "evm")]
        if Self::evm().supports_network(network) {
            return Some(BuiltinProvider::Evm);
        }
        #[cfg(feature = "solana")]
        if Self::solana().supports_network(network) {
            return Some(BuiltinProvider::Solana);
        }
        None
    }

    /// Get all built-in providers
    pub fn all() -> Vec<BuiltinProvider> {
        vec![
            #[cfg(feature = "evm")]
            BuiltinProvider::Evm,
            #[cfg(feature = "solana")]
            BuiltinProvider::Solana,
        ]
    }
}

#[async_trait]
impl PaymentProvider for BuiltinProvider {
    fn supports_network(&self, network: &str) -> bool {
        dispatch_provider!(self, supports_network(network))
    }

    async fn create_payment(
        &self,
        requirements: &PaymentRequirements,
        config: &Config,
    ) -> Result<PaymentPayload> {
        match self {
            #[cfg(feature = "evm")]
            BuiltinProvider::Evm => Self::evm().create_payment(requirements, config).await,
            #[cfg(feature = "solana")]
            BuiltinProvider::Solana => Self::solana().create_payment(requirements, config).await,
        }
    }

    fn name(&self) -> &str {
        dispatch_provider!(self, name())
    }

    fn dry_run(&self, requirements: &PaymentRequirements, config: &Config) -> Result<DryRunInfo> {
        dispatch_provider!(self, dry_run(requirements, config))
    }

    fn get_address(&self, config: &Config) -> Result<String> {
        dispatch_provider!(self, get_address(config))
    }

    async fn get_balance(
        &self,
        address: &str,
        network: Network,
        currency: Currency,
    ) -> Result<NetworkBalance> {
        match self {
            #[cfg(feature = "evm")]
            BuiltinProvider::Evm => Self::evm().get_balance(address, network, currency).await,
            #[cfg(feature = "solana")]
            BuiltinProvider::Solana => Self::solana().get_balance(address, network, currency).await,
        }
    }
}

/// Registry of payment providers.
///
/// The registry uses built-in providers by default (with enum dispatch),
/// but also supports custom providers via trait objects.
pub struct PaymentProviderRegistry {
    builtin_providers: Vec<BuiltinProvider>,
    custom_providers: Vec<Box<dyn PaymentProvider>>,
}

impl Default for PaymentProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PaymentProviderRegistry {
    /// Create a new registry with built-in providers
    pub fn new() -> Self {
        Self {
            builtin_providers: BuiltinProvider::all().to_vec(),
            custom_providers: Vec::new(),
        }
    }

    /// Register a custom payment provider
    pub fn register_custom(&mut self, provider: Box<dyn PaymentProvider>) {
        self.custom_providers.push(provider);
    }

    /// Find a provider that supports the given network
    ///
    /// Supports both v1 (e.g., "base") and v2 CAIP-2 (e.g., "eip155:8453") network formats
    #[must_use]
    pub fn find_provider(&self, network: &str) -> Option<&dyn PaymentProvider> {
        // Resolve network aliases (v2 CAIP-2 to v1 name)
        let canonical_network = crate::network::resolve_network_alias(network);

        // Check built-in providers first
        for provider in &self.builtin_providers {
            if provider.supports_network(canonical_network) {
                return Some(provider);
            }
        }

        // Fall back to custom providers
        for provider in &self.custom_providers {
            if provider.supports_network(canonical_network) {
                return Some(provider.as_ref());
            }
        }

        None
    }

    /// Get a builtin provider directly (for performance-critical paths)
    #[must_use]
    pub fn find_builtin_provider(&self, network: &str) -> Option<BuiltinProvider> {
        BuiltinProvider::for_network(network)
    }

    /// Iterate over all providers
    pub fn iter(&self) -> impl Iterator<Item = &dyn PaymentProvider> {
        self.builtin_providers
            .iter()
            .map(|p| p as &dyn PaymentProvider)
            .chain(self.custom_providers.iter().map(|p| p.as_ref()))
    }
}

/// Global static registry of payment providers
pub static PROVIDER_REGISTRY: Lazy<PaymentProviderRegistry> =
    Lazy::new(PaymentProviderRegistry::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_finds_evm_provider() {
        let registry = &*PROVIDER_REGISTRY;

        let provider = registry.find_provider("base");
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "EVM");

        let provider = registry.find_provider("ethereum-sepolia");
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "EVM");
    }

    #[test]
    fn test_registry_finds_solana_provider() {
        let registry = &*PROVIDER_REGISTRY;

        let provider = registry.find_provider("solana");
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "Solana");

        let provider = registry.find_provider("solana-devnet");
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "Solana");
    }

    #[test]
    fn test_registry_no_provider_for_unknown_network() {
        let registry = &*PROVIDER_REGISTRY;

        let provider = registry.find_provider("unknown-network");
        assert!(provider.is_none());
    }

    #[test]
    fn test_builtin_provider_for_network() {
        assert!(matches!(
            BuiltinProvider::for_network("base"),
            Some(BuiltinProvider::Evm)
        ));
        assert!(matches!(
            BuiltinProvider::for_network("solana"),
            Some(BuiltinProvider::Solana)
        ));
        assert!(BuiltinProvider::for_network("unknown").is_none());
    }

    #[test]
    fn test_builtin_provider_names() {
        let evm = BuiltinProvider::Evm;
        let solana = BuiltinProvider::Solana;

        assert_eq!(evm.name(), "EVM");
        assert_eq!(solana.name(), "Solana");
    }
}
