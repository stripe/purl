//! Payment requirement negotiation logic.

use crate::config::{Config, PaymentMethod};
use crate::error::{PurlError, Result};
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
        self.allowed_networks = networks.to_vec();
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

        // Single-pass find with all conditions
        let accepts = requirements.accepts();
        accepts
            .into_iter()
            .find(|req| self.is_compatible(req, &available_methods))
            .ok_or_else(|| {
                let accepts = requirements.accepts();
                let networks: Vec<String> =
                    accepts.iter().map(|r| r.network().to_string()).collect();
                PurlError::NoCompatibleMethod { networks }
            })
    }

    /// Check if a requirement is compatible with current configuration.
    fn is_compatible(
        &self,
        requirement: &PaymentRequirements,
        available_methods: &[PaymentMethod],
    ) -> bool {
        // Check network filter
        if !self.matches_network_filter(requirement) {
            return false;
        }

        // Check token support (has decimals configured)
        if !self.has_token_support(requirement) {
            return false;
        }

        // Check if we have a compatible payment method
        self.has_compatible_method(requirement, available_methods)
    }

    /// Check if the requirement's network passes the filter.
    #[inline]
    fn matches_network_filter(&self, requirement: &PaymentRequirements) -> bool {
        self.allowed_networks.is_empty()
            || self
                .allowed_networks
                .iter()
                .any(|n| n == requirement.network())
    }

    /// Check if the token is supported (has decimals configured).
    #[inline]
    fn has_token_support(&self, requirement: &PaymentRequirements) -> bool {
        crate::constants::get_token_decimals(requirement.network(), requirement.asset()).is_ok()
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
    use crate::config::{Config, EvmConfig};

    fn make_test_config() -> Config {
        Config {
            evm: Some(EvmConfig {
                keystore: Some(std::path::PathBuf::from("/path/to/evm.json")),
            }),
            solana: None,
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

        assert!(result.is_err());
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
}
