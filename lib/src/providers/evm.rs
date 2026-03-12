use crate::config::Config;
use crate::currency::Currency;
use crate::error::{PurlError, Result};
use crate::network::{get_evm_chain_id, get_network, ChainType, Network};
use crate::payment_provider::{DryRunInfo, NetworkBalance, PaymentProvider};
use crate::x402::{PaymentPayload, PaymentRequirements};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::{local::PrivateKeySigner, SignerSync};
use alloy::sol;
use alloy::sol_types::{eip712_domain, SolStruct};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

const PROVIDER_NAME: &str = "EVM";

sol! {
    #[derive(Debug, Serialize, Deserialize)]
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmPayload {
    pub signature: String,
    pub authorization: Authorization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    pub from: String,
    pub nonce: String,
    pub to: String,
    pub valid_after: String,
    pub valid_before: String,
    pub value: String,
}

#[derive(Default)]
pub struct EvmProvider;

impl EvmProvider {
    pub fn new() -> Self {
        Self
    }

    fn load_signer(config: &Config) -> Result<PrivateKeySigner> {
        config.load_evm_signer()
    }
}

#[async_trait]
impl PaymentProvider for EvmProvider {
    fn supports_network(&self, network: &str) -> bool {
        get_network(network)
            .map(|n| n.chain_type == ChainType::Evm)
            .unwrap_or(false)
    }

    async fn create_payment(
        &self,
        requirements: &PaymentRequirements,
        config: &Config,
    ) -> Result<PaymentPayload> {
        let signer = Self::load_signer(config)?;

        let nonce_bytes = rand::random::<[u8; 32]>();
        let nonce = B256::from(nonce_bytes);

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Set validAfter to 10 minutes ago to account for clock skew and match
        // the official EVM client:
        // https://github.com/coinbase/x402/blob/c23d94eabec89de92b0229d7006d82097eec8b34/typescript/packages/mechanisms/evm/src/exact/client/scheme.ts#L40
        let valid_after = U256::from(now.saturating_sub(600));
        let valid_before = U256::from(now + requirements.max_timeout_seconds());

        let amount = requirements.parse_max_amount().map_err(|_| {
            PurlError::InvalidAmount("The server provided an invalid payment amount.".to_string())
        })?;
        let value = U256::from(amount.as_atomic_units());

        let from = signer.address();
        let to = Address::from_str(requirements.pay_to()).map_err(|_| {
            PurlError::invalid_address(
                "The server provided an invalid recipient address.".to_string(),
            )
        })?;

        let _ = crate::constants::get_token_decimals(requirements.network(), requirements.asset())?;

        let (token_name, token_version) = requirements.evm_token_metadata().ok_or_else(|| {
            PurlError::MissingRequirement("token metadata (name and version)".to_string())
        })?;

        let verifying_contract = Address::from_str(requirements.asset()).map_err(|_| {
            PurlError::invalid_address("The server provided an invalid token address.".to_string())
        })?;

        let chain_id = get_evm_chain_id(requirements.network())
            .ok_or_else(|| PurlError::UnknownNetwork(requirements.network().to_string()))?;

        let authorization = TransferWithAuthorization {
            from,
            to,
            value,
            validAfter: valid_after,
            validBefore: valid_before,
            nonce,
        };

        let domain = eip712_domain! {
            name: token_name,
            version: token_version,
            chain_id: chain_id,
            verifying_contract: verifying_contract,
        };

        let signing_hash = authorization.eip712_signing_hash(&domain);

        let signature = signer.sign_hash_sync(&signing_hash).map_err(|_| {
            PurlError::signing("Could not sign the payment with your wallet.".to_string())
        })?;

        let evm_payload = EvmPayload {
            signature: signature.to_string(),
            authorization: Authorization {
                from: from.to_checksum(None),
                nonce: format!("{nonce:#x}"),
                to: to.to_checksum(None),
                valid_after: valid_after.to_string(),
                valid_before: valid_before.to_string(),
                value: value.to_string(),
            },
        };

        // Create version-appropriate payload based on requirements version
        let payment_payload = match requirements {
            PaymentRequirements::V1(_) => PaymentPayload::new_v1(
                requirements.scheme().to_string(),
                requirements.network().to_string(),
                serde_json::to_value(evm_payload)?,
            ),
            PaymentRequirements::V2 {
                requirements: req,
                resource_info,
            } => PaymentPayload::new_v2(
                Some(resource_info.clone()),
                req.clone(),
                serde_json::to_value(evm_payload)?,
                None,
            ),
        };

        Ok(payment_payload)
    }

    fn name(&self) -> &str {
        PROVIDER_NAME
    }

    fn dry_run(&self, requirements: &PaymentRequirements, config: &Config) -> Result<DryRunInfo> {
        let amount = requirements.parse_max_amount().map_err(|_| {
            PurlError::InvalidAmount("The server provided an invalid payment amount.".to_string())
        })?;

        Ok(DryRunInfo {
            provider: PROVIDER_NAME.to_owned(),
            network: requirements.network().to_string(),
            amount: amount.to_string(),
            asset: requirements.asset().to_string(),
            from: config.evm_address()?,
            to: requirements.pay_to().to_string(),
            estimated_fee: Some("0".to_string()), // EIP-3009 has no gas cost for sender
        })
    }

    fn get_address(&self, config: &Config) -> Result<String> {
        config.evm_address()
    }

    async fn get_balance(
        &self,
        address: &str,
        network: Network,
        currency: Currency,
    ) -> Result<NetworkBalance> {
        sol! {
            #[sol(rpc)]
            interface IERC20 {
                function balanceOf(address account) external view returns (uint256);
            }
        }

        let token_config = network.usdc_config().ok_or_else(|| {
            PurlError::UnsupportedToken(format!(
                "{} is not supported on {}. Run `purl networks info {}` to see supported tokens.",
                currency.symbol, network, network
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

        let user_addr = Address::from_str(address).map_err(|_| {
            PurlError::invalid_address(format!("Invalid Ethereum address: {}", address))
        })?;
        let token_addr = Address::from_str(token_config.address).map_err(|_| {
            PurlError::invalid_address(format!(
                "Invalid {} token configuration for {}. This is an internal error.",
                token_config.currency.symbol, network
            ))
        })?;

        let contract = IERC20::new(token_addr, &provider);

        let balance = contract.balanceOf(user_addr).call().await.map_err(|e| {
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
    use crate::payment_provider::PaymentProvider;
    use crate::x402::{v2, PaymentRequirements as UnifiedRequirements};
    use serial_test::serial;

    const TEST_EVM_KEY: &str = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    fn make_test_requirements() -> UnifiedRequirements {
        let req = v2::PaymentRequirements {
            scheme: "exact".to_string(),
            network: "eip155:84532".to_string(),
            amount: "10000".to_string(),
            asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_string(),
            pay_to: "0x1111111111111111111111111111111111111111".to_string(),
            max_timeout_seconds: 60,
            extra: Some(serde_json::json!({"name": "USD Coin", "version": "2"})),
        };
        let resource = v2::ResourceInfo {
            url: "https://example.com/paid".to_string(),
            description: Some("Test endpoint".to_string()),
            mime_type: Some("application/json".to_string()),
        };
        UnifiedRequirements::V2 {
            requirements: req,
            resource_info: resource,
        }
    }

    #[test]
    fn test_dry_run_with_private_key_override() {
        let config = Config {
            evm: None,
            evm_private_key: Some(TEST_EVM_KEY.to_string()),
            ..Default::default()
        };
        let requirements = make_test_requirements();
        let provider = EvmProvider::new();

        let info = provider
            .dry_run(&requirements, &config)
            .expect("dry_run should succeed");

        assert_eq!(info.provider, "EVM");
        assert_eq!(info.network, "eip155:84532");
        assert_eq!(info.amount, "10000");
        assert_eq!(info.to, "0x1111111111111111111111111111111111111111");
        assert!(info.from.starts_with("0x"));
        assert_eq!(info.from.len(), 42);
    }

    #[test]
    #[serial(home_env)]
    fn test_dry_run_with_keystore_override() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");

        // Point HOME at temp so create_keystore writes there
        std::env::set_var("HOME", temp_dir.path());
        let keystore_path =
            crate::keystore::create_keystore(TEST_EVM_KEY, "test-password", "override-wallet")
                .expect("create keystore");

        let config = Config {
            evm: Some(crate::config::EvmConfig {
                keystore: Some(keystore_path),
            }),
            password: Some("test-password".to_string()),
            ..Default::default()
        };
        let requirements = make_test_requirements();
        let provider = EvmProvider::new();

        let info = provider
            .dry_run(&requirements, &config)
            .expect("dry_run should succeed");

        assert_eq!(info.provider, "EVM");
        assert_eq!(info.network, "eip155:84532");
        assert_eq!(info.amount, "10000");
        assert!(info.from.starts_with("0x"));
        assert_eq!(info.from.len(), 42);
    }
}
