use crate::config::{Config, WalletConfig};
use crate::currency::Currency;
use crate::error::{PurlError, Result};
use crate::network::{get_network, ChainType, Network};
use crate::payment_provider::{DryRunInfo, NetworkBalance, PaymentProvider};
use crate::x402::{PaymentPayload, PaymentRequirements};
use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
#[cfg(not(test))]
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    hash::Hash,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaPayload {
    pub transaction: String,
}

const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const SPL_TOKEN_2022_NAME: &str = "Token-2022";
const SPL_TOKEN_NAME: &str = "SPL Token";

#[derive(Default)]
pub struct SolanaProvider;

impl SolanaProvider {
    pub fn new() -> Self {
        Self
    }

    fn get_rpc_url(network: &str) -> String {
        network
            .parse::<Network>()
            .ok()
            .map(|n| n.info().rpc_url)
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string())
    }

    fn get_recent_blockhash(network: &str) -> Result<Hash> {
        Self::get_recent_blockhash_impl(network)
    }

    #[cfg(not(test))]
    fn get_recent_blockhash_impl(network: &str) -> Result<Hash> {
        let rpc_url = Self::get_rpc_url(network);
        let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

        client
            .get_latest_blockhash()
            .map_err(|e| PurlError::solana(format!("Failed to fetch recent blockhash: {e}")))
    }

    #[cfg(test)]
    fn get_recent_blockhash_impl(_network: &str) -> Result<Hash> {
        use solana_sdk::hash::hash;
        Ok(hash(b"mock_blockhash_for_testing"))
    }

    /// Load and parse the Solana keypair from configuration
    fn load_keypair(config: &Config) -> Result<Keypair> {
        let solana_config = config.require_solana()?;

        let keystore_path = solana_config.keystore.as_ref().ok_or_else(|| {
            PurlError::ConfigMissing(
                "No Solana keystore configured. Run 'purl wallet add' to set up.".to_string(),
            )
        })?;

        let password = config.password.as_deref();
        let keypair_bytes = crate::keystore::decrypt_solana_keystore(keystore_path, password)?;

        Keypair::try_from(&keypair_bytes[..])
            .map_err(|e| PurlError::solana(format!("Failed to create keypair: {e}")))
    }
}

#[async_trait]
impl PaymentProvider for SolanaProvider {
    fn supports_network(&self, network: &str) -> bool {
        get_network(network)
            .map(|n| n.chain_type == ChainType::Solana)
            .unwrap_or(false)
    }

    async fn create_payment(
        &self,
        requirements: &PaymentRequirements,
        config: &Config,
    ) -> Result<PaymentPayload> {
        let keypair = Self::load_keypair(config)?;

        let source_pubkey = keypair.pubkey();
        let destination_pubkey = Pubkey::from_str(requirements.pay_to()).map_err(|e| {
            PurlError::invalid_address(format!("Failed to parse payTo address: {e}"))
        })?;
        let mint_pubkey = Pubkey::from_str(requirements.asset()).map_err(|e| {
            PurlError::invalid_address(format!("Failed to parse asset address: {e}"))
        })?;
        let fee_payer = requirements.solana_fee_payer().ok_or_else(|| {
            PurlError::MissingRequirement("feePayer in payment requirements".to_string())
        })?;
        let fee_payer_pubkey = Pubkey::from_str(&fee_payer).map_err(|e| {
            PurlError::invalid_address(format!("Failed to parse feePayer address: {e}"))
        })?;

        let amount_parsed = requirements.parse_max_amount().map_err(|e| {
            PurlError::InvalidAmount(format!("Failed to parse maxAmountRequired: {e}"))
        })?;
        let amount: u64 = amount_parsed
            .try_as_u64()
            .map_err(|e| PurlError::InvalidAmount(e.to_string()))?;

        let token_program_id = if let Some(program_str) = requirements.solana_token_program() {
            Pubkey::from_str(&program_str).map_err(|e| {
                PurlError::invalid_address(format!("Failed to parse token program: {e}"))
            })?
        } else {
            spl_token::id()
        };

        let is_token_2022 = token_program_id == spl_token_2022::id();

        let source_ata = spl_associated_token_account::get_associated_token_address_with_program_id(
            &source_pubkey,
            &mint_pubkey,
            &token_program_id,
        );
        let destination_ata =
            spl_associated_token_account::get_associated_token_address_with_program_id(
                &destination_pubkey,
                &mint_pubkey,
                &token_program_id,
            );

        let compute_limit_ix = ComputeBudgetInstruction::set_compute_unit_limit(200_000);
        let compute_price_ix = ComputeBudgetInstruction::set_compute_unit_price(1);

        let decimals =
            crate::constants::get_token_decimals(requirements.network(), requirements.asset())?;

        let transfer_ix = if is_token_2022 {
            spl_token_2022::instruction::transfer_checked(
                &token_program_id,
                &source_ata,
                &mint_pubkey,
                &destination_ata,
                &source_pubkey,
                &[],
                amount,
                decimals,
            )
            .map_err(|e| {
                PurlError::solana(format!(
                    "Failed to create Token-2022 transfer_checked instruction: {e:?}"
                ))
            })?
        } else {
            spl_token::instruction::transfer_checked(
                &token_program_id,
                &source_ata,
                &mint_pubkey,
                &destination_ata,
                &source_pubkey,
                &[],
                amount,
                decimals,
            )
            .map_err(|e| {
                PurlError::solana(format!(
                    "Failed to create transfer_checked instruction: {e:?}"
                ))
            })?
        };

        let instructions = vec![compute_limit_ix, compute_price_ix, transfer_ix];
        let recent_blockhash = Self::get_recent_blockhash(requirements.network())?;

        let message =
            Message::new_with_blockhash(&instructions, Some(&fee_payer_pubkey), &recent_blockhash);

        let mut transaction = Transaction::new_unsigned(message);

        transaction
            .try_partial_sign(&[&keypair], recent_blockhash)
            .map_err(|e| {
                PurlError::signing(format!("Failed to partially sign transaction: {e}"))
            })?;

        let serialized = bincode::serialize(&transaction)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&serialized);

        let solana_payload = SolanaPayload {
            transaction: encoded,
        };

        // Create version-appropriate payload based on requirements version
        let payment_payload = match requirements {
            PaymentRequirements::V1(_) => PaymentPayload::new_v1(
                requirements.scheme().to_string(),
                requirements.network().to_string(),
                serde_json::to_value(solana_payload)?,
            ),
            PaymentRequirements::V2 {
                requirements: req,
                resource_info,
            } => PaymentPayload::new_v2(
                Some(resource_info.clone()),
                req.clone(),
                serde_json::to_value(solana_payload)?,
                None,
            ),
        };

        Ok(payment_payload)
    }

    fn name(&self) -> &str {
        "Solana"
    }

    fn dry_run(&self, requirements: &PaymentRequirements, config: &Config) -> Result<DryRunInfo> {
        let solana_config = config.require_solana()?;

        let token_program = if requirements.solana_token_program().is_some() {
            SPL_TOKEN_2022_NAME
        } else {
            SPL_TOKEN_NAME
        };

        let amount = requirements
            .parse_max_amount()
            .map_err(|e| PurlError::InvalidAmount(format!("Failed to parse max amount: {e}")))?;

        Ok(DryRunInfo {
            provider: format!("Solana ({token_program})"),
            network: requirements.network().to_string(),
            amount: amount.to_string(),
            asset: requirements.asset().to_string(),
            from: solana_config.get_address()?,
            to: requirements.pay_to().to_string(),
            estimated_fee: Some("5000".to_string()), // ~5000 lamports for transaction
        })
    }

    fn get_address(&self, config: &Config) -> Result<String> {
        config.require_solana()?.get_address()
    }

    async fn get_balance(
        &self,
        address: &str,
        network: Network,
        currency: Currency,
    ) -> Result<NetworkBalance> {
        let token_config = network.usdc_config().ok_or_else(|| {
            PurlError::UnsupportedToken(format!(
                "Network {} does not support {}",
                network, currency.symbol
            ))
        })?;

        let network_info = network.info();
        let client = RpcClient::new(network_info.rpc_url);

        let owner_pubkey = Pubkey::from_str(address)
            .map_err(|e| PurlError::invalid_address(format!("Invalid Solana public key: {e}")))?;
        let token_mint = Pubkey::from_str(token_config.address).map_err(|e| {
            PurlError::invalid_address(format!(
                "Invalid {} mint address for {}: {}",
                token_config.currency.symbol, network, e
            ))
        })?;

        let associated_token_address =
            spl_associated_token_account::get_associated_token_address(&owner_pubkey, &token_mint);

        let balance = match client.get_token_account_balance(&associated_token_address) {
            Ok(token_balance) => token_balance.ui_amount.unwrap_or(0.0),
            Err(_) => 0.0,
        };

        let balance_atomic = (balance * token_config.currency.divisor as f64) as u64;
        let balance_human = token_config.currency.format_atomic(balance_atomic as u128);

        Ok(NetworkBalance {
            network: network.to_string(),
            balance_atomic: balance_atomic.to_string(),
            balance_human,
            asset: token_config.currency.symbol.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_rpc_url_mainnet() {
        // Uses Network enum names from network.rs
        assert_eq!(
            SolanaProvider::get_rpc_url("solana"),
            "https://api.mainnet-beta.solana.com"
        );
    }

    #[test]
    fn test_get_rpc_url_devnet() {
        assert_eq!(
            SolanaProvider::get_rpc_url("solana-devnet"),
            "https://api.devnet.solana.com"
        );
    }

    #[test]
    fn test_get_rpc_url_unknown_defaults_to_mainnet() {
        assert_eq!(
            SolanaProvider::get_rpc_url("unknown-network"),
            "https://api.mainnet-beta.solana.com"
        );
        assert_eq!(
            SolanaProvider::get_rpc_url(""),
            "https://api.mainnet-beta.solana.com"
        );
    }

    #[test]
    fn test_get_recent_blockhash_devnet() {
        let result = SolanaProvider::get_recent_blockhash("solana-devnet");
        assert!(result.is_ok(), "Should successfully get blockhash");

        let blockhash = result.unwrap();
        assert_ne!(
            blockhash,
            Hash::default(),
            "Blockhash must not be default (all zeros)"
        );
    }

    #[test]
    fn test_get_recent_blockhash_mainnet() {
        let result = SolanaProvider::get_recent_blockhash("solana");
        assert!(result.is_ok(), "Should successfully get blockhash");

        let blockhash = result.unwrap();
        assert_ne!(
            blockhash,
            Hash::default(),
            "Blockhash must not be default (all zeros)"
        );
    }

    #[test]
    fn test_blockhash_deterministic_in_tests() {
        let hash1 = SolanaProvider::get_recent_blockhash("solana-devnet").unwrap();
        let hash2 = SolanaProvider::get_recent_blockhash("solana").unwrap();

        assert_eq!(
            hash1, hash2,
            "Mock blockhash should be deterministic in tests"
        );
    }

    #[test]
    fn test_supports_network() {
        let provider = SolanaProvider::new();

        assert!(provider.supports_network("solana"));
        assert!(provider.supports_network("solana-devnet"));

        assert!(!provider.supports_network("base"));
        assert!(!provider.supports_network("base-sepolia"));
        assert!(!provider.supports_network("ethereum"));
        assert!(!provider.supports_network("devnet"));
        assert!(!provider.supports_network("unknown"));
    }

    #[test]
    fn test_provider_name() {
        let provider = SolanaProvider::new();
        assert_eq!(provider.name(), "Solana");
    }
}
