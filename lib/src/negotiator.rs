//! Payment requirement negotiation logic.

use crate::config::{Config, PaymentMethod};
use crate::error::{CompatibilityReason, PurlError, Result};
use crate::x402::{Amount, PaymentRequirements, PaymentRequirementsResponse};

/// Service to handle 402 Payment Required negotiation.
///
/// Selects the best payment requirement from a server's response based on:
/// - Available payment methods in the config
/// - Allowed networks filter
/// - Maximum amount constraint
/// - Token support
///
/// # Example
///
/// ```no_run
/// use purl_lib::negotiator::PaymentNegotiator;
/// use purl_lib::Config;
///
/// let config = Config::load().unwrap();
/// let negotiator = PaymentNegotiator::new(&config)
///     .with_max_amount(Some("1000000"));
///
/// let response_body = r#"{"x402Version": 1, "error": "Payment Required", "accepts": []}"#;
/// let requirement = negotiator.select_requirement(response_body);
/// ```
pub struct PaymentNegotiator<'a> {
    config: &'a Config,
    allowed_networks: Vec<String>,
    max_amount: Option<&'a str>,
}

impl<'a> PaymentNegotiator<'a> {
    /// Create a new payment negotiator with the given configuration.
    #[must_use]
    pub fn new(config: &'a Config) -> Self {
        Self {
            config,
            allowed_networks: Vec::new(),
            max_amount: None,
        }
    }

    /// Filter to only allow specific networks.
    ///
    /// If networks is empty, all networks are allowed.
    #[must_use]
    pub fn with_allowed_networks(mut self, networks: &[String]) -> Self {
        self.allowed_networks = networks
            .iter()
            .map(|network| crate::network::resolve_network_alias(network).to_string())
            .collect();
        self
    }

    /// Set maximum amount willing to pay (in atomic units).
    #[must_use]
    pub fn with_max_amount(mut self, amount: Option<&'a str>) -> Self {
        self.max_amount = amount;
        self
    }

    /// Parse response body and select the best payment requirement.
    ///
    /// This is a convenience method that parses JSON and then selects.
    pub fn select_requirement(&self, response_body: &str) -> Result<PaymentRequirements> {
        let requirements: PaymentRequirementsResponse = serde_json::from_str(response_body)?;
        self.select_from_requirements(&requirements)
    }

    /// Select the best payment requirement from a parsed response.
    ///
    /// This is useful when you've already parsed the response (e.g., for inspection).
    pub fn select_from_requirements(
        &self,
        requirements: &PaymentRequirementsResponse,
    ) -> Result<PaymentRequirements> {
        let selected = self.find_compatible_requirement(requirements)?;

        // Check constraints (like max amount)
        self.validate_constraints(&selected)?;

        Ok(selected)
    }

    /// Find the first compatible payment requirement using a single-pass filter.
    fn find_compatible_requirement(
        &self,
        requirements: &PaymentRequirementsResponse,
    ) -> Result<PaymentRequirements> {
        let available_methods = self.config.available_payment_methods();

        if available_methods.is_empty() {
            return Err(PurlError::NoPaymentMethods);
        }

        // Single-pass find while preserving the first rejection reason category.
        let accepts = requirements.accepts();
        let mut networks = Vec::with_capacity(accepts.len());
        let mut network_filtered = false;
        let mut unsupported_token: Option<(String, String)> = None;
        let mut missing_chains: Vec<String> = Vec::new();

        for requirement in accepts {
            networks.push(requirement.network().to_string());

            if !self.matches_network_filter(&requirement) {
                network_filtered = true;
                continue;
            }

            if let Err(err) = self.validate_token_support(&requirement) {
                if let PurlError::TokenConfigNotFound { network, asset } = err {
                    unsupported_token.get_or_insert((network, asset));
                }
                continue;
            }

            if !self.has_compatible_method(&requirement, &available_methods) {
                let chain = if requirement.is_evm() {
                    "evm"
                } else if requirement.is_solana() {
                    "solana"
                } else {
                    "unknown"
                };

                if !missing_chains.iter().any(|existing| existing == chain) {
                    missing_chains.push(chain.to_string());
                }
                continue;
            }

            return Ok(requirement);
        }

        let reason = if !missing_chains.is_empty() {
            Some(CompatibilityReason::MissingWallet {
                required_chains: missing_chains,
            })
        } else if let Some((network, asset)) = unsupported_token {
            Some(CompatibilityReason::UnsupportedToken { network, asset })
        } else if network_filtered && !self.allowed_networks.is_empty() {
            Some(CompatibilityReason::NetworkFiltered {
                allowed_networks: self.allowed_networks.clone(),
            })
        } else {
            None
        };

        Err(PurlError::NoCompatibleMethod { networks, reason })
    }

    /// Check if the requirement's network passes the filter.
    #[inline]
    fn matches_network_filter(&self, requirement: &PaymentRequirements) -> bool {
        if self.allowed_networks.is_empty() {
            return true;
        }

        let requirement_network = crate::network::resolve_network_alias(requirement.network());

        self.allowed_networks
            .iter()
            .any(|network| network == requirement_network)
    }

    /// Validate token support (token must have decimals configured).
    #[inline]
    fn validate_token_support(&self, requirement: &PaymentRequirements) -> Result<()> {
        crate::constants::get_token_decimals(requirement.network(), requirement.asset()).map(|_| ())
    }

    /// Check if we have a compatible payment method for this requirement.
    #[inline]
    fn has_compatible_method(
        &self,
        requirement: &PaymentRequirements,
        available_methods: &[PaymentMethod],
    ) -> bool {
        (requirement.is_evm() && available_methods.contains(&PaymentMethod::Evm))
            || (requirement.is_solana() && available_methods.contains(&PaymentMethod::Solana))
    }

    /// Validate amount constraints.
    fn validate_constraints(&self, requirement: &PaymentRequirements) -> Result<()> {
        if let Some(max) = self.max_amount {
            let required = requirement
                .parse_max_amount()
                .map_err(|e| PurlError::InvalidAmount(format!("required amount: {e}")))?;
            let max_val: Amount = max
                .parse()
                .map_err(|e| PurlError::InvalidAmount(format!("max amount: {e}")))?;

            if required > max_val {
                return Err(PurlError::AmountExceedsMax {
                    required: required.as_atomic_units(),
                    max: max_val.as_atomic_units(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, EvmConfig, SolanaConfig};
    use crate::error::CompatibilityReason;
    use crate::x402::v2;

    fn make_test_config() -> Config {
        Config {
            evm: Some(EvmConfig {
                keystore: Some(std::path::PathBuf::from("/path/to/evm.json")),
            }),
            solana: None,
            ..Default::default()
        }
    }

    fn make_test_solana_config() -> Config {
        Config {
            evm: None,
            solana: Some(SolanaConfig {
                keystore: Some(std::path::PathBuf::from("/path/to/solana.json")),
            }),
            ..Default::default()
        }
    }

    fn make_test_requirements() -> PaymentRequirementsResponse {
        use crate::x402::v1;

        PaymentRequirementsResponse::V1(v1::PaymentRequirementsResponse {
            x402_version: 1,
            error: "Payment Required".to_string(),
            accepts: vec![v1::PaymentRequirements {
                scheme: "eip3009".to_string(),
                network: "base-sepolia".to_string(),
                max_amount_required: "1000".to_string(),
                asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_string(),
                pay_to: "0x1234".to_string(),
                resource: "/test".to_string(),
                description: "Test".to_string(),
                mime_type: "application/json".to_string(),
                output_schema: None,
                max_timeout_seconds: 300,
                extra: Some(serde_json::json!({"name": "USDC", "version": "1"})),
            }],
        })
    }

    fn make_test_v2_requirements() -> PaymentRequirementsResponse {
        PaymentRequirementsResponse::V2(v2::PaymentRequired {
            x402_version: 2,
            error: None,
            accepts: vec![
                v2::PaymentRequirements {
                    scheme: "exact".to_string(),
                    network: "eip155:8453".to_string(),
                    amount: "10000".to_string(),
                    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".to_string(),
                    pay_to: "0x1234".to_string(),
                    max_timeout_seconds: 60,
                    extra: Some(serde_json::json!({"name": "USD Coin", "version": "2"})),
                },
                v2::PaymentRequirements {
                    scheme: "exact".to_string(),
                    network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
                    amount: "10000".to_string(),
                    asset: "11111111111111111111111111111111".to_string(),
                    pay_to: "11111111111111111111111111111111".to_string(),
                    max_timeout_seconds: 60,
                    extra: Some(serde_json::json!({"name": "USD Coin", "version": "2"})),
                },
            ],
            resource: v2::ResourceInfo {
                url: "https://example.com/paid".to_string(),
                description: Some("Test endpoint".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            extensions: None,
        })
    }

    fn make_test_solana_known_token_requirement() -> PaymentRequirementsResponse {
        PaymentRequirementsResponse::V2(v2::PaymentRequired {
            x402_version: 2,
            error: None,
            accepts: vec![v2::PaymentRequirements {
                scheme: "exact".to_string(),
                network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
                amount: "10000".to_string(),
                asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
                pay_to: "11111111111111111111111111111111".to_string(),
                max_timeout_seconds: 60,
                extra: None,
            }],
            resource: v2::ResourceInfo {
                url: "https://example.com/paid".to_string(),
                description: None,
                mime_type: None,
            },
            extensions: None,
        })
    }

    fn make_test_solana_unknown_token_requirement() -> PaymentRequirementsResponse {
        PaymentRequirementsResponse::V2(v2::PaymentRequired {
            x402_version: 2,
            error: None,
            accepts: vec![v2::PaymentRequirements {
                scheme: "exact".to_string(),
                network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
                amount: "10000".to_string(),
                asset: "11111111111111111111111111111111".to_string(),
                pay_to: "11111111111111111111111111111111".to_string(),
                max_timeout_seconds: 60,
                extra: None,
            }],
            resource: v2::ResourceInfo {
                url: "https://example.com/paid".to_string(),
                description: None,
                mime_type: None,
            },
            extensions: None,
        })
    }

    #[test]
    fn test_negotiator_selects_compatible_requirement() {
        let config = make_test_config();
        let requirements = make_test_requirements();

        let negotiator = PaymentNegotiator::new(&config);
        let result = negotiator.select_from_requirements(&requirements);

        assert!(result.is_ok(), "Expected Ok, got: {result:?}");
        let selected = result.unwrap();
        assert_eq!(selected.network(), "base-sepolia");
    }

    #[test]
    fn test_negotiator_respects_max_amount() {
        let config = make_test_config();
        let requirements = make_test_requirements();

        let negotiator = PaymentNegotiator::new(&config).with_max_amount(Some("500"));
        let result = negotiator.select_from_requirements(&requirements);

        assert!(result.is_err());
        match result {
            Err(PurlError::AmountExceedsMax { required, max }) => {
                assert_eq!(required, 1000);
                assert_eq!(max, 500);
            }
            _ => panic!("Expected AmountExceedsMax error"),
        }
    }

    #[test]
    fn test_negotiator_respects_network_filter() {
        let config = make_test_config();
        let requirements = make_test_requirements();

        let negotiator =
            PaymentNegotiator::new(&config).with_allowed_networks(&["ethereum".to_string()]);
        let result = negotiator.select_from_requirements(&requirements);

        assert!(matches!(
            result,
            Err(PurlError::NoCompatibleMethod {
                reason: Some(CompatibilityReason::NetworkFiltered { .. }),
                ..
            })
        ));
    }

    #[test]
    fn test_negotiator_no_payment_methods() {
        let config = Config {
            evm: None,
            solana: None,
            ..Default::default()
        };
        let requirements = make_test_requirements();

        let negotiator = PaymentNegotiator::new(&config);
        let result = negotiator.select_from_requirements(&requirements);

        assert!(matches!(result, Err(PurlError::NoPaymentMethods)));
    }

    #[test]
    fn test_negotiator_network_filter_matches_caip2_aliases() {
        let config = make_test_config();
        let requirements = make_test_v2_requirements();

        let negotiator = PaymentNegotiator::new(&config)
            .with_allowed_networks(&["base".to_string(), "base-sepolia".to_string()]);
        let result = negotiator.select_from_requirements(&requirements);

        assert!(result.is_ok(), "Expected Ok, got: {result:?}");
        let selected = result.unwrap();
        assert_eq!(selected.network(), "eip155:8453");
    }

    #[test]
    fn test_negotiator_network_filter_accepts_mixed_alias_inputs() {
        let config = make_test_config();
        let requirements = make_test_v2_requirements();

        let negotiator =
            PaymentNegotiator::new(&config).with_allowed_networks(&["eip155:8453".to_string()]);
        let result = negotiator.select_from_requirements(&requirements);

        assert!(result.is_ok(), "Expected Ok, got: {result:?}");
        let selected = result.unwrap();
        assert_eq!(selected.network(), "eip155:8453");
    }

    #[test]
    fn test_negotiator_selects_requirement_with_private_key_override() {
        let config = Config {
            evm: None,
            solana: None,
            evm_private_key: Some(
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            ),
            ..Default::default()
        };
        let requirements = make_test_v2_requirements();

        let negotiator = PaymentNegotiator::new(&config);
        let result = negotiator.select_from_requirements(&requirements);

        assert!(result.is_ok(), "Expected Ok, got: {result:?}");
        let selected = result.unwrap();
        assert!(selected.is_evm());
        assert_eq!(selected.network(), "eip155:8453");
    }

    #[test]
    fn test_negotiator_reports_missing_wallet_reason() {
        let config = make_test_config();
        let requirements = make_test_solana_known_token_requirement();

        let negotiator = PaymentNegotiator::new(&config);
        let result = negotiator.select_from_requirements(&requirements);

        assert!(matches!(
            result,
            Err(PurlError::NoCompatibleMethod {
                reason: Some(CompatibilityReason::MissingWallet { .. }),
                ..
            })
        ));
    }

    #[test]
    fn test_negotiator_reports_unsupported_token_reason() {
        let config = make_test_solana_config();
        let requirements = make_test_solana_unknown_token_requirement();

        let negotiator = PaymentNegotiator::new(&config);
        let result = negotiator.select_from_requirements(&requirements);

        assert!(matches!(
            result,
            Err(PurlError::NoCompatibleMethod {
                reason: Some(CompatibilityReason::UnsupportedToken { .. }),
                ..
            })
        ));
    }
}
