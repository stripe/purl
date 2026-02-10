//! Payment provider implementations for different blockchain networks.

#[cfg(feature = "evm")]
pub mod evm;

#[cfg(feature = "solana")]
pub mod solana;

// Re-export providers when available
#[cfg(feature = "evm")]
pub use evm::EvmProvider;

#[cfg(feature = "solana")]
pub use solana::SolanaProvider;

use crate::payment_provider::PaymentProvider;

/// Get all available payment providers as boxed trait objects.
#[allow(clippy::vec_init_then_push)]
pub fn all_providers() -> Vec<Box<dyn PaymentProvider>> {
    let mut providers = Vec::new();

    #[cfg(feature = "evm")]
    providers.push(Box::new(EvmProvider::new()) as Box<dyn PaymentProvider>);

    #[cfg(feature = "solana")]
    providers.push(Box::new(SolanaProvider::new()) as Box<dyn PaymentProvider>);

    providers
}

/// Get provider names for debugging/display purposes.
#[allow(clippy::vec_init_then_push)]
pub fn provider_names() -> Vec<&'static str> {
    let mut names = Vec::new();

    #[cfg(feature = "evm")]
    names.push("EVM");

    #[cfg(feature = "solana")]
    names.push("Solana");

    names
}

/// Check if any providers are available.
#[must_use]
pub fn has_providers() -> bool {
    #[cfg(any(feature = "evm", feature = "solana"))]
    return true;

    #[cfg(not(any(feature = "evm", feature = "solana")))]
    return false;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_providers() {
        // At least one provider should be enabled in tests
        assert!(has_providers());
    }

    #[test]
    fn test_all_providers_returns_expected_count() {
        let providers = all_providers();

        let expected_count = {
            let mut count = 0;
            #[cfg(feature = "evm")]
            {
                count += 1;
            }
            #[cfg(feature = "solana")]
            {
                count += 1;
            }
            count
        };

        assert_eq!(providers.len(), expected_count);
    }

    #[test]
    fn test_provider_names_matches_providers() {
        let names = provider_names();
        let providers = all_providers();

        assert_eq!(names.len(), providers.len());
    }
}
