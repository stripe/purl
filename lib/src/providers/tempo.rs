//! Tempo payment provider.
//!
//! This module provides integration with the Tempo blockchain using MPP (Machine Payments Protocol).
//! It wraps `mpp::client::TempoProvider` and implements purl's `PaymentProvider` trait.

use crate::config::{Config, WalletConfig};
use crate::currency::Currency;
use crate::error::{PurlError, Result};
use crate::mpp::MppChallenge;
use crate::network::{get_network, ChainType, Network};
use crate::payment_provider::{DryRunInfo, NetworkBalance, PaymentProvider};
use crate::protocol::PaymentChallenge;
use crate::PaymentPayload;
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use alloy::sol;
use async_trait::async_trait;
use std::str::FromStr;

const PROVIDER_NAME: &str = "Tempo";

/// Tempo payment provider using MPP protocol.
///
/// This provider handles payments on the Tempo blockchain, using TIP-20 stablecoins.
/// It reuses EVM keystores since Tempo uses EVM-compatible addresses.
#[derive(Default)]
pub struct TempoProvider;

impl TempoProvider {
    pub fn new() -> Self {
        Self
    }

    /// Load EVM signer from config (reused for Tempo since it uses EVM addresses)
    fn load_signer(config: &Config) -> Result<alloy_signer_local::PrivateKeySigner> {
        use crate::signer::WalletSource;
        let evm_config = config.require_evm()?;
        evm_config.load_signer(config.password.as_deref())
    }

    /// Require a native MPP challenge and reject semantics purl cannot safely show.
    ///
    /// `MppChallenge` contains snapshots taken when the challenge was parsed, but the
    /// signer pays from `inner` — mpp-rs re-decodes the request itself. Comparing the
    /// security-sensitive fields here makes "what purl displayed is what purl signs" an
    /// enforced invariant rather than a coincidence of both sides reading the same data.
    fn validate_challenge(challenge: &dyn PaymentChallenge) -> Result<(&MppChallenge, u64)> {
        let mpp_challenge = challenge
            .as_any()
            .downcast_ref::<MppChallenge>()
            .ok_or_else(|| {
                PurlError::InvalidConfig("Tempo provider requires an MppChallenge".to_string())
            })?;

        let request = crate::mpp::policy::decode_and_validate(&mpp_challenge.inner)?;
        let signed_recipient = crate::mpp::policy::require_recipient(&request)?;
        let signed_amount = crate::mpp::policy::require_amount(&request)?;
        let signed_chain_id = crate::mpp::policy::tempo_chain_id(&request)?;

        if signed_recipient != mpp_challenge.recipient {
            return Err(PurlError::invalid_address(format!(
                "MPP challenge recipient mismatch: purl would display {} but the challenge pays {}",
                mpp_challenge.recipient, signed_recipient
            )));
        }

        if signed_amount != mpp_challenge.amount {
            return Err(PurlError::InvalidAmount(format!(
                "MPP challenge amount mismatch: purl would display {} but the challenge pays {}",
                mpp_challenge.amount, signed_amount
            )));
        }

        let signed_network = format!("eip155:{signed_chain_id}");
        if signed_network != mpp_challenge.network {
            return Err(PurlError::InvalidConfig(format!(
                "MPP challenge network mismatch: purl would display {} but the challenge pays {}",
                mpp_challenge.network, signed_network
            )));
        }

        Ok((mpp_challenge, signed_chain_id))
    }
}

#[async_trait]
impl PaymentProvider for TempoProvider {
    fn supports_network(&self, network: &str) -> bool {
        get_network(network)
            .map(|n| n.chain_type == ChainType::Tempo)
            .unwrap_or(false)
    }

    async fn create_payment(
        &self,
        challenge: &dyn PaymentChallenge,
        config: &Config,
    ) -> Result<PaymentPayload> {
        // Require and validate the native challenge before loading a wallet or signing.
        // MppChallenge fields are public, so callers can construct one without using
        // the protocol parser that normally performs this validation.
        let (mpp_challenge, expected_chain_id) = Self::validate_challenge(challenge)?;

        // Resolve RPC URL from network registry based on the challenge's network
        let rpc_url = get_network(challenge.network())
            .map(|n| n.rpc_url.clone())
            .unwrap_or_else(|| "https://rpc.tempo.xyz".to_string());

        let signer = Self::load_signer(config)?;

        // Create mpp-rs TempoProvider
        let mpp_provider = mpp::client::TempoProvider::new(signer.clone(), &rpc_url)
            .map_err(|e| {
                PurlError::InvalidConfig(format!("Failed to create Tempo provider: {}", e))
            })?
            .with_expected_chain_id(expected_chain_id);

        // Execute payment using native MPP challenge
        use mpp::client::PaymentProvider as MppPaymentProvider;
        let credential = mpp_provider
            .pay(&mpp_challenge.inner)
            .await
            .map_err(|e| PurlError::Signing(format!("Tempo payment failed: {}", e)))?;

        // Format as Authorization header value
        let auth_header = mpp::format_authorization(&credential)
            .map_err(|e| PurlError::Signing(format!("Failed to format credential: {}", e)))?;

        // Create a purl PaymentPayload that carries the MPP credential
        // We store the full Authorization header value so it can be used directly
        let payload_json = serde_json::json!({
            "mpp_authorization": auth_header,
            "source": credential.source,
        });

        let payment_payload = PaymentPayload::new_v1(
            challenge.scheme().to_string(),
            challenge.network().to_string(),
            payload_json,
        );

        Ok(payment_payload)
    }

    fn name(&self) -> &str {
        PROVIDER_NAME
    }

    fn dry_run(&self, challenge: &dyn PaymentChallenge, config: &Config) -> Result<DryRunInfo> {
        Self::validate_challenge(challenge)?;
        let evm_config = config.require_evm()?;

        // Validate amount is a parseable number
        let _: u128 = challenge.amount().parse().map_err(|_| {
            PurlError::InvalidAmount("The server provided an invalid payment amount.".to_string())
        })?;

        Ok(DryRunInfo {
            provider: PROVIDER_NAME.to_owned(),
            network: challenge.network().to_string(),
            amount: challenge.amount().to_string(),
            asset: challenge.asset().to_string(),
            from: evm_config.get_address()?,
            to: challenge.recipient().to_string(),
            estimated_fee: Some("0".to_string()), // Server pays gas on Tempo
        })
    }

    fn get_address(&self, config: &Config) -> Result<String> {
        // Reuse EVM address since Tempo uses EVM-compatible addresses
        config.require_evm()?.get_address()
    }

    async fn get_balance(
        &self,
        address: &str,
        network: Network,
        currency: Currency,
    ) -> Result<NetworkBalance> {
        // TIP-20 is ERC20-compatible, so we can use the standard balanceOf interface
        sol! {
            #[sol(rpc)]
            interface IERC20 {
                function balanceOf(address account) external view returns (uint256);
            }
        }

        // Get the token configuration for this network (pathUSD for Tempo Moderato)
        let token_config = network.default_token_config().ok_or_else(|| {
            PurlError::UnsupportedToken(format!(
                "{} is not supported on {}",
                currency.symbol, network
            ))
        })?;

        let network_info = network.info();
        let provider =
            ProviderBuilder::new().connect_http(network_info.rpc_url.parse().map_err(|_| {
                PurlError::InvalidConfig(format!(
                    "Invalid network configuration for {}. This is an internal error.",
                    network
                ))
            })?);

        let wallet_address = Address::from_str(address)
            .map_err(|_| PurlError::invalid_address(format!("Invalid address: {}", address)))?;
        let token_address = Address::from_str(token_config.address).map_err(|_| {
            PurlError::invalid_address(format!(
                "Invalid {} token configuration for {}. This is an internal error.",
                token_config.currency.symbol, network
            ))
        })?;

        let contract = IERC20::new(token_address, &provider);

        let balance = contract
            .balanceOf(wallet_address)
            .call()
            .await
            .map_err(|e| {
                PurlError::BalanceQuery(format!(
                    "Could not fetch balance from {}. The network may be unavailable: {}",
                    network, e
                ))
            })?;

        let balance_atomic: u128 = balance.to_string().parse().unwrap_or(0);
        let balance_human = token_config.currency.format_atomic(balance_atomic);

        Ok(NetworkBalance {
            network: network.to_string(),
            balance_atomic: balance.to_string(),
            balance_human,
            asset: token_config.currency.symbol.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpp::protocol::core::Base64UrlJson;

    /// Build an `MppChallenge` directly, bypassing the protocol parser, with an
    /// arbitrary `recipient` snapshot so display/signing divergence can be tested.
    fn hand_built_challenge(
        request_json: serde_json::Value,
        displayed_recipient: &str,
    ) -> MppChallenge {
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let inner = mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            "tempo",
            "charge",
            request,
        );
        MppChallenge {
            inner,
            network: "eip155:42431".to_string(),
            amount: "1000000".to_string(),
            asset: "0x20c0000000000000000000000000000000000000".to_string(),
            recipient: displayed_recipient.to_string(),
            resource: "https://example.com/api".to_string(),
            description: String::new(),
        }
    }

    /// Assert both signing entry points reject a challenge for the expected reason.
    async fn assert_both_paths_reject(challenge: &MppChallenge, expected: &str) {
        let create_error = TempoProvider::new()
            .create_payment(challenge, &Config::default())
            .await
            .unwrap_err();
        let dry_run_error = TempoProvider::new()
            .dry_run(challenge, &Config::default())
            .unwrap_err();

        for error in [create_error, dry_run_error] {
            assert!(
                error.to_string().contains(expected),
                "expected {expected:?}, got: {error}"
            );
        }
    }

    #[tokio::test]
    async fn test_create_payment_rejects_manually_constructed_split_challenge() {
        let challenge = hand_built_challenge(
            serde_json::json!({
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x1111111111111111111111111111111111111111",
                "methodDetails": {
                    "chainId": 42431,
                    "feePayer": true,
                    "splits": [{
                        "amount": "999999",
                        "recipient": "0x2222222222222222222222222222222222222222"
                    }]
                }
            }),
            "0x1111111111111111111111111111111111111111",
        );

        assert_both_paths_reject(&challenge, "split-payment challenges").await;
    }

    #[tokio::test]
    async fn test_rejects_challenge_whose_displayed_recipient_is_not_the_signed_one() {
        // The snapshot purl would display points at 0x1111..., but the request the
        // signer actually consumes pays 0x2222....
        let challenge = hand_built_challenge(
            serde_json::json!({
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x2222222222222222222222222222222222222222",
                "methodDetails": { "chainId": 42431 }
            }),
            "0x1111111111111111111111111111111111111111",
        );

        assert_both_paths_reject(&challenge, "recipient mismatch").await;
    }

    #[tokio::test]
    async fn test_rejects_challenge_whose_displayed_amount_is_not_the_signed_one() {
        let mut challenge = hand_built_challenge(
            serde_json::json!({
                "amount": "1000000000",
                "currency": "pathUSD",
                "recipient": "0x1111111111111111111111111111111111111111",
                "methodDetails": { "chainId": 42431 }
            }),
            "0x1111111111111111111111111111111111111111",
        );
        challenge.amount = "0".to_string();

        assert_both_paths_reject(&challenge, "amount mismatch").await;
    }

    #[tokio::test]
    async fn test_rejects_challenge_whose_displayed_network_is_not_the_signed_one() {
        let mut challenge = hand_built_challenge(
            serde_json::json!({
                "amount": "1000000",
                "currency": "pathUSD",
                "recipient": "0x1111111111111111111111111111111111111111",
                "methodDetails": { "chainId": 4217 }
            }),
            "0x1111111111111111111111111111111111111111",
        );
        challenge.network = "eip155:42431".to_string();

        assert_both_paths_reject(&challenge, "network mismatch").await;
    }

    #[tokio::test]
    async fn test_rejects_hex_amount_before_loading_a_wallet_or_signing() {
        let challenge = hand_built_challenge(
            serde_json::json!({
                "amount": "0x3B9ACA00",
                "currency": "pathUSD",
                "recipient": "0x1111111111111111111111111111111111111111",
                "methodDetails": { "chainId": 42431, "feePayer": true }
            }),
            "0x1111111111111111111111111111111111111111",
        );

        assert_both_paths_reject(&challenge, "Invalid amount").await;
    }

    #[tokio::test]
    async fn test_rejects_challenge_with_no_recipient() {
        let challenge = hand_built_challenge(
            serde_json::json!({
                "amount": "1000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "methodDetails": { "chainId": 42431 }
            }),
            "",
        );

        assert_both_paths_reject(&challenge, "did not provide a recipient").await;
    }
}
