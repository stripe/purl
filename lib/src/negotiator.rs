//! Payment requirement negotiation logic.

use crate::config::{Config, PaymentMethod};
use crate::error::{PurlError, Result};
use crate::protocol::PaymentChallenge;
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

    /// Select the best payment challenge from protocol-agnostic challenges.
    ///
    /// This is the preferred method for selecting challenges from the new
    /// `parse_challenges()` protocol interface.
    ///
    /// When multiple protocols provide compatible challenges, prefers direct
    /// wallet matches (e.g. EVM challenge + EVM wallet) over compatibility
    /// matches (e.g. Tempo challenge + EVM wallet via fallback).
    pub fn select_challenge<'c>(
        &self,
        challenges: &'c [Box<dyn PaymentChallenge>],
    ) -> Result<&'c dyn PaymentChallenge> {
        let available_methods = self.config.available_payment_methods();

        if available_methods.is_empty() {
            return Err(PurlError::NoPaymentMethods);
        }

        // Only native Tempo MPP challenges can be paid through the MPP provider.
        // Other Payment-auth challenges should not block a valid x402 offer.
        let is_payable_challenge = |challenge: &dyn PaymentChallenge| {
            challenge.protocol_name() != crate::mpp::protocol::PROTOCOL_NAME || challenge.is_tempo()
        };

        let selected = challenges
            .iter()
            .filter(|c| is_payable_challenge(c.as_ref()))
            .find(|c| self.is_challenge_direct_match(c.as_ref(), &available_methods))
            .or_else(|| {
                challenges
                    .iter()
                    .filter(|c| is_payable_challenge(c.as_ref()))
                    .find(|c| self.is_challenge_compatible(c.as_ref(), &available_methods))
            })
            .ok_or_else(|| {
                let networks: Vec<String> =
                    challenges.iter().map(|c| c.network().to_string()).collect();
                PurlError::NoCompatibleMethod { networks }
            })?;

        // Validate constraints
        self.validate_challenge_constraints(selected.as_ref())?;

        Ok(selected.as_ref())
    }

    /// Check if a challenge is compatible with current configuration.
    fn is_challenge_compatible(
        &self,
        challenge: &dyn PaymentChallenge,
        available_methods: &[PaymentMethod],
    ) -> bool {
        // Check network filter
        if !self.allowed_networks.is_empty()
            && !self
                .allowed_networks
                .iter()
                .any(|n| n == challenge.network())
        {
            return false;
        }

        // Check token support (has decimals configured)
        // For Tempo/MPP, we accept any token since the server determines valid tokens
        if !challenge.is_tempo()
            && crate::constants::get_token_decimals(challenge.network(), challenge.asset()).is_err()
        {
            return false;
        }

        // Check if we have a compatible payment method
        // Tempo challenges work with both Tempo and EVM wallets (EVM-compatible addresses)
        (challenge.is_evm() && available_methods.contains(&PaymentMethod::Evm))
            || (challenge.is_solana() && available_methods.contains(&PaymentMethod::Solana))
            || (challenge.is_tempo()
                && (available_methods.contains(&PaymentMethod::Tempo)
                    || available_methods.contains(&PaymentMethod::Evm)))
    }

    /// Check if a challenge is a direct wallet match (not a compatibility fallback).
    ///
    /// Direct matches: EVM challenge + EVM wallet, Solana challenge + Solana wallet,
    /// Tempo challenge + Tempo wallet. This excludes Tempo challenges matched only
    /// via EVM wallet compatibility, which is a fallback path.
    fn is_challenge_direct_match(
        &self,
        challenge: &dyn PaymentChallenge,
        available_methods: &[PaymentMethod],
    ) -> bool {
        // Must pass the same network/token filters as compatibility check
        if !self.allowed_networks.is_empty()
            && !self
                .allowed_networks
                .iter()
                .any(|n| n == challenge.network())
        {
            return false;
        }

        if !challenge.is_tempo()
            && crate::constants::get_token_decimals(challenge.network(), challenge.asset()).is_err()
        {
            return false;
        }

        // Only direct wallet matches — no EVM-as-Tempo fallback.
        // Tempo challenges report is_evm() == true (EVM-compatible addresses),
        // so we must exclude them from the EVM direct-match path.
        (challenge.is_evm()
            && !challenge.is_tempo()
            && available_methods.contains(&PaymentMethod::Evm))
            || (challenge.is_solana() && available_methods.contains(&PaymentMethod::Solana))
            || (challenge.is_tempo() && available_methods.contains(&PaymentMethod::Tempo))
    }

    /// Validate amount constraints for a challenge.
    fn validate_challenge_constraints(&self, challenge: &dyn PaymentChallenge) -> Result<()> {
        if let Some(max) = self.max_amount {
            let required: Amount = challenge
                .amount()
                .parse()
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

    /// Parse response body and select the best payment requirement.
    ///
    /// This is a convenience method that parses JSON and then selects.
    /// Consider using `select_challenge()` with protocol's `parse_challenges()` instead.
    pub fn select_requirement(&self, response_body: &str) -> Result<PaymentRequirements> {
        let requirements: PaymentRequirementsResponse = serde_json::from_str(response_body)?;
        self.select_from_requirements(&requirements)
    }

    /// Select the best payment requirement from a parsed response.
    ///
    /// This is useful when you've already parsed the response (e.g., for inspection).
    /// Consider using `select_challenge()` with protocol's `parse_challenges()` instead.
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
        if self.allowed_networks.is_empty() {
            return true;
        }

        let requirement_network = crate::network::resolve_network_alias(requirement.network());

        self.allowed_networks
            .iter()
            .any(|network| network == requirement_network)
    }

    /// Check if the token is supported (has decimals configured).
    #[inline]
    fn has_token_support(&self, requirement: &PaymentRequirements) -> bool {
        // For Tempo/MPP, we accept any token since the server determines valid tokens
        if requirement.is_tempo() {
            return true;
        }
        crate::constants::get_token_decimals(requirement.network(), requirement.asset()).is_ok()
    }

    /// Check if we have a compatible payment method for this requirement.
    #[inline]
    fn has_compatible_method(
        &self,
        requirement: &PaymentRequirements,
        available_methods: &[PaymentMethod],
    ) -> bool {
        // Tempo challenges work with both Tempo and EVM wallets (EVM-compatible addresses)
        (requirement.is_evm() && available_methods.contains(&PaymentMethod::Evm))
            || (requirement.is_solana() && available_methods.contains(&PaymentMethod::Solana))
            || (requirement.is_tempo()
                && (available_methods.contains(&PaymentMethod::Tempo)
                    || available_methods.contains(&PaymentMethod::Evm)))
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
    fn test_select_challenge_with_trait_objects() {
        use crate::x402::v1;

        let config = make_test_config();

        // Create challenges as trait objects
        let req = PaymentRequirements::V1(v1::PaymentRequirements {
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
        });

        let challenges: Vec<Box<dyn PaymentChallenge>> = vec![Box::new(req)];

        let negotiator = PaymentNegotiator::new(&config);
        let result = negotiator.select_challenge(&challenges);

        assert!(result.is_ok(), "Expected Ok, got: {result:?}");
        let selected = result.unwrap();
        assert_eq!(selected.network(), "base-sepolia");
        assert_eq!(selected.amount(), "1000");
    }

    #[test]
    fn test_select_challenge_respects_max_amount() {
        use crate::x402::v1;

        let config = make_test_config();

        let req = PaymentRequirements::V1(v1::PaymentRequirements {
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
        });

        let challenges: Vec<Box<dyn PaymentChallenge>> = vec![Box::new(req)];

        let negotiator = PaymentNegotiator::new(&config).with_max_amount(Some("500"));
        let result = negotiator.select_challenge(&challenges);

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
    fn test_select_challenge_with_mpp_tempo() {
        use crate::mpp::MppChallenge;
        use mpp::protocol::core::Base64UrlJson;

        let config = make_test_config();

        let request_json = serde_json::json!({
            "amount": "1000",
            "currency": "pathUSD",
            "recipient": "0x1234",
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let inner = mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            "tempo",
            "charge",
            request,
        );
        let mpp_challenge = MppChallenge::from_mpp_challenge(inner).unwrap();

        let challenges: Vec<Box<dyn PaymentChallenge>> = vec![Box::new(mpp_challenge)];

        let negotiator = PaymentNegotiator::new(&config);
        let result = negotiator.select_challenge(&challenges);

        assert!(
            result.is_ok(),
            "Tempo challenge should be selected with EVM config: {result:?}"
        );
        let selected = result.unwrap();
        assert!(selected.is_tempo());
        assert_eq!(selected.scheme(), "mpp");
        assert_eq!(selected.amount(), "1000");
    }

    #[test]
    fn test_select_challenge_mpp_respects_max_amount() {
        use crate::mpp::MppChallenge;
        use mpp::protocol::core::Base64UrlJson;

        let config = make_test_config();

        let request_json = serde_json::json!({
            "amount": "5000",
            "currency": "pathUSD",
            "recipient": "0x1234",
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let inner = mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            "tempo",
            "charge",
            request,
        );
        let mpp_challenge = MppChallenge::from_mpp_challenge(inner).unwrap();

        let challenges: Vec<Box<dyn PaymentChallenge>> = vec![Box::new(mpp_challenge)];

        let negotiator = PaymentNegotiator::new(&config).with_max_amount(Some("1000"));
        let result = negotiator.select_challenge(&challenges);

        assert!(result.is_err());
        assert!(matches!(result, Err(PurlError::AmountExceedsMax { .. })));
    }

    #[test]
    fn test_select_challenge_mpp_respects_network_filter() {
        use crate::mpp::MppChallenge;
        use mpp::protocol::core::Base64UrlJson;

        let config = make_test_config();

        let request_json = serde_json::json!({
            "amount": "1000",
            "currency": "pathUSD",
            "recipient": "0x1234",
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let inner = mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            "tempo",
            "charge",
            request,
        );
        let mpp_challenge = MppChallenge::from_mpp_challenge(inner).unwrap();

        let challenges: Vec<Box<dyn PaymentChallenge>> = vec![Box::new(mpp_challenge)];

        // Filter to only allow base-sepolia - should reject tempo
        let negotiator =
            PaymentNegotiator::new(&config).with_allowed_networks(&["base-sepolia".to_string()]);
        let result = negotiator.select_challenge(&challenges);

        assert!(result.is_err());
        assert!(matches!(result, Err(PurlError::NoCompatibleMethod { .. })));
    }

    #[test]
    fn test_select_challenge_prefers_direct_match_over_tempo_fallback() {
        use crate::mpp::MppChallenge;
        use crate::x402::v1;
        use mpp::protocol::core::Base64UrlJson;

        let config = make_test_config(); // EVM wallet only

        // MPP/Tempo challenge (compatible via EVM fallback)
        let request_json = serde_json::json!({
            "amount": "1000",
            "currency": "pathUSD",
            "recipient": "0x1234",
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let inner = mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            "tempo",
            "charge",
            request,
        );
        let mpp_challenge = MppChallenge::from_mpp_challenge(inner).unwrap();

        // x402 EVM challenge (direct match)
        let x402_challenge = PaymentRequirements::V1(v1::PaymentRequirements {
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
        });

        // MPP first in list (mimics registration order), x402 second
        let challenges: Vec<Box<dyn PaymentChallenge>> =
            vec![Box::new(mpp_challenge), Box::new(x402_challenge)];

        let negotiator = PaymentNegotiator::new(&config);
        let result = negotiator.select_challenge(&challenges);

        assert!(result.is_ok(), "Expected Ok, got: {result:?}");
        let selected = result.unwrap();
        // Should pick x402 (direct EVM match) over MPP (EVM fallback)
        assert_eq!(selected.protocol_name(), "x402");
        assert_eq!(selected.network(), "base-sepolia");
    }

    #[test]
    fn test_select_challenge_skips_non_tempo_mpp_before_x402() {
        use crate::mpp::MppChallenge;
        use mpp::protocol::core::Base64UrlJson;

        let config = make_test_config();

        let request_json = serde_json::json!({
            "amount": "10000",
            "currency": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "methodDetails": {
                "chainId": 84532,
                "credentialTypes": ["authorization"],
                "decimals": 6
            },
            "recipient": "0x1234",
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let inner = mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            "evm",
            "charge",
            request,
        );
        let mpp_challenge = MppChallenge::from_mpp_challenge(inner).unwrap();

        let x402_challenge = PaymentRequirements::V2 {
            requirements: v2::PaymentRequirements {
                scheme: "exact".to_string(),
                network: "eip155:84532".to_string(),
                amount: "10000".to_string(),
                asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_string(),
                pay_to: "0x1234".to_string(),
                max_timeout_seconds: 300,
                extra: Some(serde_json::json!({"name": "USDC", "version": "2"})),
            },
            resource_info: v2::ResourceInfo {
                url: "https://example.com/api".to_string(),
                description: None,
                mime_type: None,
            },
        };

        let challenges: Vec<Box<dyn PaymentChallenge>> =
            vec![Box::new(mpp_challenge), Box::new(x402_challenge)];

        let negotiator = PaymentNegotiator::new(&config);
        let result = negotiator.select_challenge(&challenges);

        assert!(result.is_ok(), "Expected Ok, got: {result:?}");
        let selected = result.unwrap();
        assert_eq!(selected.protocol_name(), "x402");
        assert_eq!(selected.scheme(), "exact");
        assert_eq!(selected.network(), "eip155:84532");
    }

    #[test]
    fn test_select_challenge_falls_back_to_tempo_when_no_direct_match() {
        use crate::mpp::MppChallenge;
        use mpp::protocol::core::Base64UrlJson;

        // EVM wallet only, no Tempo wallet
        let config = make_test_config();

        // Only MPP/Tempo challenge available (no x402)
        let request_json = serde_json::json!({
            "amount": "1000",
            "currency": "pathUSD",
            "recipient": "0x1234",
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let inner = mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            "tempo",
            "charge",
            request,
        );
        let mpp_challenge = MppChallenge::from_mpp_challenge(inner).unwrap();

        let challenges: Vec<Box<dyn PaymentChallenge>> = vec![Box::new(mpp_challenge)];

        let negotiator = PaymentNegotiator::new(&config);
        let result = negotiator.select_challenge(&challenges);

        // Should still select MPP via EVM fallback when it's the only option
        assert!(result.is_ok(), "Expected Ok, got: {result:?}");
        let selected = result.unwrap();
        assert_eq!(selected.protocol_name(), "mpp");
        assert!(selected.is_tempo());
    }

    #[test]
    fn test_select_challenge_no_wallet_rejects_mpp() {
        use crate::mpp::MppChallenge;
        use mpp::protocol::core::Base64UrlJson;

        // Config with no wallets
        let config = Config {
            evm: None,
            solana: None,
            ..Default::default()
        };

        let request_json = serde_json::json!({
            "amount": "1000",
            "currency": "pathUSD",
            "recipient": "0x1234",
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let inner = mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            "tempo",
            "charge",
            request,
        );
        let mpp_challenge = MppChallenge::from_mpp_challenge(inner).unwrap();

        let challenges: Vec<Box<dyn PaymentChallenge>> = vec![Box::new(mpp_challenge)];

        let negotiator = PaymentNegotiator::new(&config);
        let result = negotiator.select_challenge(&challenges);

        assert!(matches!(result, Err(PurlError::NoPaymentMethods)));
    }
}
