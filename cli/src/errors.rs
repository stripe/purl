//! Error display helpers with actionable suggestions.
//!
//! Provides user-friendly error messages that include suggestions
//! for how to fix common problems.

use crate::colors::Colors;
use purl_lib::PurlError;

/// Get a suggestion for how to fix an error, if available.
pub fn get_suggestion(err: &anyhow::Error) -> Option<String> {
    // Try to downcast to PurlError
    if let Some(purl_err) = err.downcast_ref::<PurlError>() {
        return get_purl_error_suggestion(purl_err);
    }

    // Check error message for common patterns
    let msg = err.to_string().to_lowercase();

    if msg.contains("no such file") || msg.contains("not found") {
        if msg.contains("config") {
            return Some("Run 'purl wallet add' to create a wallet.".into());
        }
        if msg.contains("keystore") || msg.contains("wallet") {
            return Some("Run 'purl wallet new <name> --generate' to create a new wallet.".into());
        }
    }

    if msg.contains("permission denied") {
        return Some("Check file permissions or run with appropriate privileges.".into());
    }

    if msg.contains("connection refused") || msg.contains("connect error") {
        return Some("Check your internet connection and try again.".into());
    }

    if msg.contains("timeout") {
        return Some(
            "The request timed out. Try again or increase the timeout with --max-time.".into(),
        );
    }

    None
}

/// Get suggestion for a specific PurlError variant.
fn get_purl_error_suggestion(err: &PurlError) -> Option<String> {
    match err {
        PurlError::NoPaymentMethods => Some(
            "To configure payment methods:\n  \
             • Run 'purl wallet add' to create a wallet"
                .into(),
        ),

        PurlError::ConfigMissing(_) => Some("Run 'purl wallet add' to create a wallet.".into()),

        PurlError::NoConfigDir => {
            Some("Could not determine home directory. Set the HOME environment variable.".into())
        }

        PurlError::InvalidConfig(msg) => {
            if msg.contains("keystore") || msg.contains("wallet") {
                Some("Check that your wallet file exists and is valid JSON.".into())
            } else if msg.contains("private_key") {
                Some("Private key should be 64 hex characters (with optional 0x prefix).".into())
            } else {
                Some("Run 'purl config' to view your current configuration.".into())
            }
        }

        PurlError::InvalidKey(_) => Some(
            "EVM private keys should be 64 hex characters (with optional 0x prefix).\n\
             Solana keys should be base58-encoded keypairs."
                .into(),
        ),

        PurlError::InvalidPassword => Some("Check your keystore password and try again.".into()),

        PurlError::NoCompatibleMethod { networks } => {
            let networks_str = networks.join(", ");
            Some(format!(
                "Server accepts: {networks_str}\n\
                 Configure a wallet for one of these networks with 'purl wallet add'."
            ))
        }

        PurlError::AmountExceedsMax { required, max } => Some(format!(
            "The server requires {required} but your max is {max}.\n\
             Increase with --max-amount or remove the limit."
        )),

        PurlError::InsufficientBalance {
            message: _,
            required,
            balance,
            asset,
            network,
        } => {
            // Build the main error message with token and network info
            let mut msg = match (asset.as_deref(), network.as_deref()) {
                (Some(token), Some(net)) => {
                    format!(
                        "The payment was rejected due to insufficient {} balance on {}.",
                        token, net
                    )
                }
                (Some(token), None) => {
                    format!(
                        "The payment was rejected due to insufficient {} balance.",
                        token
                    )
                }
                (None, Some(net)) => {
                    format!(
                        "The payment was rejected due to insufficient balance on {}.",
                        net
                    )
                }
                (None, None) => "The payment was rejected due to insufficient balance.".to_string(),
            };

            // Add details if available
            match (required, balance, asset.as_deref()) {
                (Some(req), Some(bal), Some(asset_sym)) => {
                    msg.push_str(&format!(
                        "\n\nRequired: {} {}\nYour balance: {} {}",
                        req, asset_sym, bal, asset_sym
                    ));
                }
                (Some(req), Some(bal), None) => {
                    // Have both amounts but no asset symbol - use generic "tokens"
                    msg.push_str(&format!(
                        "\n\nRequired: {} tokens\nYour balance: {} tokens",
                        req, bal
                    ));
                }
                (Some(req), None, Some(asset_sym)) => {
                    // Have required amount but couldn't fetch balance
                    msg.push_str(&format!("\n\nRequired: {} {}", req, asset_sym));
                }
                (Some(req), None, None) => {
                    // Have required amount but no asset symbol
                    msg.push_str(&format!("\n\nRequired: {} tokens", req));
                }
                (None, Some(bal), Some(asset_sym)) => {
                    // Have balance but no required amount
                    msg.push_str(&format!("\n\nYour balance: {} {}", bal, asset_sym));
                }
                (None, Some(bal), None) => {
                    // Have balance but no asset symbol
                    msg.push_str(&format!("\n\nYour balance: {} tokens", bal));
                }
                _ => {
                    // Not enough info to show details
                }
            }

            msg.push_str(
                "\n\nCheck your balance with 'purl balance' and add funds to your wallet.",
            );
            Some(msg)
        }

        PurlError::UnknownNetwork(network) => Some(format!(
            "Network '{network}' is not recognized.\n\
             Run 'purl networks list' to see available networks.\n\
             Or add a custom network in ~/.purl/config.toml"
        )),

        PurlError::TokenConfigNotFound { asset, network } => Some(format!(
            "Token {asset} not configured for {network}.\n\
             Add it to ~/.purl/config.toml under [[tokens]]."
        )),

        PurlError::ProviderNotFound(network) => Some(format!(
            "No payment provider for network '{network}'.\n\
             Run 'purl networks list' to see supported networks."
        )),

        PurlError::Http(msg) => {
            if msg.contains("402") {
                Some("The server requires payment. Ensure you have configured a wallet.".into())
            } else if msg.contains("401") || msg.contains("403") {
                Some("Authentication failed. Check your credentials.".into())
            } else if msg.contains("404") {
                Some("The requested resource was not found. Check the URL.".into())
            } else if msg.contains("5") {
                Some("Server error. Try again later.".into())
            } else {
                None
            }
        }

        PurlError::Signing(_) => Some(
            "Failed to sign the transaction. Check your wallet configuration:\n  \
             • Verify your wallet password is correct\n  \
             • Ensure your private key is valid"
                .into(),
        ),

        PurlError::BalanceQuery(_) => {
            Some("Could not query balance. Check your network connection and RPC endpoint.".into())
        }

        _ => None,
    }
}

/// Format an error with its suggestion for display.
pub fn format_error_with_suggestion(err: &anyhow::Error) -> String {
    let mut output = format!("{} {err:#}", Colors::error("Error:"));

    if let Some(suggestion) = get_suggestion(err) {
        output.push_str(&format!("\n\n{}:\n", Colors::info("Suggestion")));
        output.push_str(&suggestion);
    }

    // Add related commands if available
    if let Some(related) = get_related_commands(err) {
        output.push_str(&format!("\n\n{}:\n", Colors::info("Related commands")));
        for cmd in related {
            output.push_str(&format!("  {}\n", cmd));
        }
    }

    output
}

/// Get related commands that might help fix an error.
fn get_related_commands(err: &anyhow::Error) -> Option<Vec<&'static str>> {
    if let Some(purl_err) = err.downcast_ref::<PurlError>() {
        match purl_err {
            PurlError::NoPaymentMethods | PurlError::ConfigMissing(_) => Some(vec![
                "purl wallet add        # Create a wallet",
                "purl wallet list       # List available wallets",
                "purl config            # View current configuration",
            ]),
            PurlError::NoCompatibleMethod { .. } => Some(vec![
                "purl networks list     # See supported networks",
                "purl wallet new        # Create a new wallet",
                "purl inspect <url>     # Check payment requirements",
            ]),
            PurlError::AmountExceedsMax { .. } => Some(vec![
                "purl inspect <url>     # Check payment requirements",
                "purl balance           # Check your balance",
            ]),
            PurlError::InsufficientBalance { .. } => Some(vec![
                "purl balance           # Check your wallet balance",
                "purl inspect <url>     # View payment requirements",
                "purl wallet list       # List configured wallets",
            ]),
            PurlError::UnknownNetwork(_) => {
                Some(vec!["purl networks list     # See available networks"])
            }
            PurlError::BalanceQuery(_) => Some(vec![
                "purl networks list     # Check network configuration",
                "purl balance           # Retry balance check",
            ]),
            _ => None,
        }
    } else {
        // Check error message for common patterns
        let msg = err.to_string().to_lowercase();

        if msg.contains("config") {
            return Some(vec![
                "purl wallet add        # Create a wallet",
                "purl config            # View configuration",
            ]);
        }

        if msg.contains("keystore") || msg.contains("wallet") {
            return Some(vec![
                "purl wallet list       # List wallets",
                "purl wallet new        # Create new wallet",
            ]);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_payment_methods_suggestion() {
        let err = PurlError::NoPaymentMethods;
        let suggestion = get_purl_error_suggestion(&err);
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().contains("purl wallet add"));
    }

    #[test]
    fn test_config_missing_suggestion() {
        let err = PurlError::ConfigMissing("test".into());
        let suggestion = get_purl_error_suggestion(&err);
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().contains("purl wallet add"));
    }

    #[test]
    fn test_unknown_network_suggestion() {
        let err = PurlError::UnknownNetwork("testnet".into());
        let suggestion = get_purl_error_suggestion(&err);
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().contains("purl networks list"));
    }
}
