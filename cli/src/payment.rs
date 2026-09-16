//! Payment handling for the CLI

use anyhow::{Context, Result};
use dialoguer::Confirm;
use purl_lib::protocol::{PaymentChallenge, PaymentProtocol};
use purl_lib::x402::PaymentPayload;
use purl_lib::{
    Config, HttpResponse, SettlementResponse, WalletConfig, PROTOCOL_REGISTRY, PROVIDER_REGISTRY,
};

use crate::cli::Cli;
use crate::exit_codes::ExitCode;
use crate::request::RequestContext;

/// Handle payment required (402) response
pub async fn handle_payment_request(
    config: &Config,
    request_ctx: &RequestContext,
    url: &str,
    challenges: Vec<Box<dyn PaymentChallenge>>,
) -> Result<HttpResponse> {
    if request_ctx.cli.is_verbose() && request_ctx.cli.should_show_output() {
        eprintln!();
        eprintln!("Payment Required (402)");
        eprintln!("Available payment options: {}", challenges.len());

        // Show details for each challenge
        for (i, challenge) in challenges.iter().enumerate() {
            eprintln!();
            eprintln!("  Option {}:", i + 1);
            eprintln!("    Protocol:    {}", challenge.protocol_name());
            eprintln!("    Scheme:      {}", challenge.scheme());
            eprintln!("    Network:     {}", challenge.network());

            // Format amount with human-readable display
            let (amount_display, asset_symbol) = format_challenge_amount(challenge.as_ref());
            eprintln!("    Amount:      {}", amount_display);
            eprintln!("    Asset:       {} ({})", asset_symbol, challenge.asset());
            eprintln!("    Recipient:   {}", challenge.recipient());

            if !challenge.description().is_empty() {
                eprintln!("    Description: {}", challenge.description());
            }
            if !challenge.resource().is_empty() {
                eprintln!("    Resource:    {}", challenge.resource());
            }

            // Show MPP-specific details if available
            if challenge.scheme() == "mpp" {
                if let Some(mpp_challenge) = challenge
                    .as_any()
                    .downcast_ref::<purl_lib::mpp::MppChallenge>()
                {
                    eprintln!("    Challenge ID: {}", mpp_challenge.inner.id);
                    eprintln!("    Method:      {}", mpp_challenge.inner.method.as_str());
                }
            }
        }
        eprintln!();
    }

    let selected = select_challenge(config, &challenges, &request_ctx.cli)?;

    // Resolve the protocol from the selected challenge
    let protocol = PROTOCOL_REGISTRY
        .get(selected.protocol_name())
        .with_context(|| format!("Unknown protocol: {}", selected.protocol_name()))?;

    if request_ctx.cli.is_verbose() && request_ctx.cli.should_show_output() {
        let (amount_display, _) = format_challenge_amount(selected);
        eprintln!(
            "Selected: {} on {} for {} (protocol: {})",
            selected.scheme(),
            selected.network(),
            amount_display,
            protocol.name()
        );
    }

    if request_ctx.cli.dry_run {
        return handle_dry_run(config, selected);
    }

    if request_ctx.cli.confirm {
        confirm_payment(config, selected)?;
    }

    let payment_payload = create_payment_payload(config, selected).await?;

    if request_ctx.cli.is_verbose() && request_ctx.cli.should_show_output() {
        eprintln!("Created payment credential");
        // Show protocol-specific debug info
        if protocol.name() == "mpp" {
            // For MPP, show the Authorization header that will be sent
            let payload_json = serde_json::to_string(&payment_payload).ok();
            let encoded = payload_json
                .as_ref()
                .map(|j| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, j));
            if let Some(enc) = encoded {
                let credential = purl_lib::protocol::CredentialPayload {
                    data: enc,
                    version: 1,
                };
                let (header_name, header_value) = protocol.create_credential_header(&credential);
                eprintln!(
                    "{header_name} header: {}",
                    truncate_for_display(&header_value, 80)
                );
            }
        } else {
            // For x402, show the decoded payload
            eprintln!(
                "{} header (decoded):",
                payment_payload.payment_header_name()
            );
            if let Ok(pretty_json) = serde_json::to_string_pretty(&payment_payload) {
                eprintln!("{pretty_json}");
            }
        }
        eprintln!("Making payment request...");
    }

    let response = request_ctx
        .execute_with_payment(url, protocol, &payment_payload)
        .await?;

    // Show detailed response info in verbose mode
    if request_ctx.cli.is_verbose() && request_ctx.cli.should_show_output() {
        eprintln!();
        eprintln!("Response Status: {}", response.status_code);

        // If payment was rejected (still 402) or other error, show details
        if response.status_code >= 400 {
            eprintln!("Payment rejected by server");

            // Show relevant headers
            for (key, value) in &response.headers {
                let key_lower = key.to_lowercase();
                if key_lower.contains("error")
                    || key_lower.contains("payment")
                    || key_lower.contains("x-")
                    || key_lower == "www-authenticate"
                {
                    eprintln!("  {}: {}", key, value);
                }
            }

            // Show response body (truncated if too long)
            if !response.body.is_empty() {
                if let Ok(body_str) = std::str::from_utf8(&response.body) {
                    // Try to pretty-print JSON
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
                        if let Ok(pretty) = serde_json::to_string_pretty(&json) {
                            eprintln!("Response body:");
                            // Limit output to first 2000 chars
                            if pretty.len() > 2000 {
                                eprintln!("{}...", &pretty[..2000]);
                            } else {
                                eprintln!("{}", pretty);
                            }
                        }
                    } else {
                        // Not JSON, show as-is (truncated)
                        eprintln!("Response body:");
                        if body_str.len() > 500 {
                            eprintln!("{}...", &body_str[..500]);
                        } else {
                            eprintln!("{}", body_str);
                        }
                    }
                }
            }
            eprintln!();
        }
    }

    display_settlement_info(&request_ctx.cli, protocol, &response, payment_payload.x402_version)?;

    Ok(response)
}

/// Handle dry-run mode
fn handle_dry_run(config: &Config, challenge: &dyn PaymentChallenge) -> Result<HttpResponse> {
    use crate::hyperlink::address_link;

    let registry = &*PROVIDER_REGISTRY;
    if let Some(provider) = registry.find_provider(challenge.network()) {
        let dry_run_info = provider.dry_run(challenge, config)?;

        let from_display = address_link(&dry_run_info.from, &dry_run_info.network);
        let to_display = address_link(&dry_run_info.to, &dry_run_info.network);

        // Try to get human-readable asset symbol
        let (amount_display, asset_display) = format_dry_run_amount(
            &dry_run_info.network,
            &dry_run_info.asset,
            &dry_run_info.amount,
        );

        println!("[DRY RUN] Payment would be made:");
        println!("Provider: {}", dry_run_info.provider);
        println!("Network: {}", dry_run_info.network);
        println!("Amount: {} {}", amount_display, asset_display);
        println!("From: {}", from_display);
        println!("To: {}", to_display);
        if let Some(fee) = dry_run_info.estimated_fee {
            println!("Estimated Fee: {fee}");
        }

        anyhow::bail!("Dry run completed");
    } else {
        anyhow::bail!("No provider found for network: {}", challenge.network());
    }
}

/// Format a challenge's amount for verbose display
fn format_challenge_amount(challenge: &dyn PaymentChallenge) -> (String, String) {
    let network = challenge.network();
    let asset = challenge.asset();
    let amount = challenge.amount();

    // Try to get token info from registry
    if let Ok(decimals) = purl_lib::constants::get_token_decimals(network, asset) {
        let symbol = purl_lib::constants::get_token_symbol(network, asset).unwrap_or(asset);
        let amount_u128: u128 = amount.parse().unwrap_or(0);
        let divisor = 10u128.pow(decimals as u32);
        let whole = amount_u128 / divisor;
        let frac = amount_u128 % divisor;

        let amount_str = if frac == 0 {
            format!("{} {}", whole, symbol)
        } else {
            // Trim trailing zeros from fractional part
            let frac_str = format!("{frac:0>width$}", width = decimals as usize);
            let trimmed = frac_str.trim_end_matches('0');
            format!("{}.{} {}", whole, trimmed, symbol)
        };

        (amount_str, symbol.to_string())
    } else {
        // Fallback to raw values
        (format!("{} (atomic)", amount), asset.to_string())
    }
}

/// Format amount and asset for dry run display
fn format_dry_run_amount(network: &str, asset: &str, amount: &str) -> (String, String) {
    // Try to get token info from registry
    if let Ok(decimals) = purl_lib::constants::get_token_decimals(network, asset) {
        let symbol = purl_lib::constants::get_token_symbol(network, asset).unwrap_or(asset);
        let amount_u128: u128 = amount.parse().unwrap_or(0);
        let divisor = 10u128.pow(decimals as u32);
        let whole = amount_u128 / divisor;
        let frac = amount_u128 % divisor;

        let amount_str = if frac == 0 {
            whole.to_string()
        } else {
            // Trim trailing zeros from fractional part
            let frac_str = format!("{frac:0>width$}", width = decimals as usize);
            let trimmed = frac_str.trim_end_matches('0');
            format!("{whole}.{trimmed}")
        };

        (amount_str, symbol.to_string())
    } else {
        // Fallback to raw values
        (format!("{} (atomic)", amount), asset.to_string())
    }
}

/// Confirm payment with user
fn confirm_payment(config: &Config, challenge: &dyn PaymentChallenge) -> Result<()> {
    use crate::hyperlink::address_link;
    use std::io::IsTerminal;

    // Check if we're in an interactive terminal
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "Cannot confirm payment: not running in an interactive terminal.\n\
             Remove --confirm flag or run in an interactive terminal."
        );
    }

    // Format the amount for display
    let (amount_display, asset_symbol) = format_payment_amount(challenge);

    // Get sender address if available
    let from_address = get_sender_address(config, challenge);

    // Format addresses with hyperlinks
    let to_truncated = truncate_address(challenge.recipient(), 45);
    let to_display = address_link(&to_truncated, challenge.network());

    // Print payment details
    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────┐");
    eprintln!("│                     Payment Details                         │");
    eprintln!("├─────────────────────────────────────────────────────────────┤");
    eprintln!("│  Amount:    {:<47} │", amount_display);
    eprintln!("│  Asset:     {:<47} │", asset_symbol);
    eprintln!("│  Network:   {:<47} │", challenge.network());
    eprintln!("│  To:        {:<47} │", to_display);
    if let Some(ref from) = from_address {
        let from_truncated = truncate_address(from, 45);
        let from_display = address_link(&from_truncated, challenge.network());
        eprintln!("│  From:      {:<47} │", from_display);
    }
    eprintln!("└─────────────────────────────────────────────────────────────┘");
    eprintln!();

    let confirm = Confirm::new()
        .with_prompt("Proceed with this payment?")
        .default(false) // Default to no for safety
        .interact()?;

    if !confirm {
        ExitCode::UserCancelled.exit();
    }
    Ok(())
}

/// Format the payment amount for display
fn format_payment_amount(challenge: &dyn PaymentChallenge) -> (String, String) {
    let amount_str_raw = challenge.amount();
    let asset = challenge.asset();
    let network = challenge.network();

    // Try to get decimals for the asset from the centralized token registry
    if let Ok(decimals) = purl_lib::constants::get_token_decimals(network, asset) {
        let amount_u128: u128 = amount_str_raw.parse().unwrap_or(0);
        let divisor = 10u128.pow(decimals as u32);
        let whole = amount_u128 / divisor;
        let frac = amount_u128 % divisor;

        // Get token symbol from centralized registry
        let symbol = purl_lib::constants::get_token_symbol(network, asset).unwrap_or("tokens");

        let amount_str = if frac == 0 {
            format!("{whole} {symbol}")
        } else {
            let frac_str = format!("{frac:0>width$}", width = decimals as usize);
            let trimmed = frac_str.trim_end_matches('0');
            format!("{whole}.{trimmed} {symbol}")
        };

        (amount_str, symbol.to_string())
    } else {
        // Fallback to raw amount
        let amount_str = format!("{} (atomic units)", amount_str_raw);
        (amount_str, truncate_address(asset, 20))
    }
}

/// Get the sender address from config
fn get_sender_address(config: &Config, challenge: &dyn PaymentChallenge) -> Option<String> {
    // Determine chain type from network/challenge type
    if challenge.is_evm() || challenge.is_tempo() {
        config.evm_address().ok()
    } else if challenge.is_solana() {
        config
            .solana
            .as_ref()
            .and_then(|sol| sol.get_address().ok())
    } else {
        None
    }
}

/// Truncate an address for display
fn truncate_address(addr: &str, max_len: usize) -> String {
    if addr.len() <= max_len {
        addr.to_string()
    } else {
        let prefix = &addr[..6];
        let suffix = &addr[addr.len() - 4..];
        format!("{prefix}...{suffix}")
    }
}

/// Truncate a string for display with ellipsis
fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Display settlement information from response
fn display_settlement_info(
    cli: &Cli,
    protocol: &dyn PaymentProtocol,
    response: &HttpResponse,
    version: u32,
) -> Result<()> {
    use crate::hyperlink::{address_link, tx_link};

    // Use protocol to get the receipt header name and parse the receipt
    if let Some(receipt_json) = protocol.parse_receipt_json(response, version).ok().flatten() {
        let settlement: SettlementResponse =
            serde_json::from_str(&receipt_json).context("Failed to parse settlement response")?;

        if cli.is_verbose() && cli.should_show_output() {
            eprintln!("Payment settled:");
            let tx_display = tx_link(settlement.transaction(), settlement.network());
            eprintln!("Transaction: {}", tx_display);
            eprintln!("Network: {}", settlement.network());
            eprintln!("Success: {}", settlement.is_success());
            if let Some(payer) = settlement.payer() {
                let payer_display = address_link(payer, settlement.network());
                eprintln!("Payer: {}", payer_display);
            }
            if let Some(reason) = settlement.error_reason() {
                eprintln!("Error: {reason}");
            }
        }
    }
    Ok(())
}

/// Select the best compatible payment challenge from protocol-agnostic challenges.
fn select_challenge<'a>(
    config: &Config,
    challenges: &'a [Box<dyn PaymentChallenge>],
    cli: &Cli,
) -> Result<&'a dyn PaymentChallenge> {
    use purl_lib::negotiator::PaymentNegotiator;

    let allowed_networks = cli.allowed_networks().unwrap_or_default();

    let negotiator = PaymentNegotiator::new(config)
        .with_allowed_networks(&allowed_networks)
        .with_max_amount(cli.max_amount.as_deref());

    negotiator
        .select_challenge(challenges)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Create a payment payload for the selected challenge
async fn create_payment_payload(
    config: &Config,
    challenge: &dyn PaymentChallenge,
) -> Result<PaymentPayload> {
    let registry = &*PROVIDER_REGISTRY;

    if let Some(provider) = registry.find_provider(challenge.network()) {
        Ok(provider.create_payment(challenge, config).await?)
    } else {
        anyhow::bail!("No provider found for network: {}", challenge.network());
    }
}
