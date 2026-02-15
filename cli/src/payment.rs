//! Payment handling for the CLI

use anyhow::{Context, Result};
use base64::Engine;
use dialoguer::Confirm;
use purl_lib::x402::{
    PaymentPayload, PaymentRequirements, PAYMENT_RESPONSE_HEADER, V1_X_PAYMENT_RESPONSE_HEADER,
};
use purl_lib::{
    Config, HttpResponse, PaymentRequirementsResponse, SettlementResponse, PROVIDER_REGISTRY,
};

use crate::cli::Cli;
use crate::exit_codes::ExitCode;
use crate::request::RequestContext;

/// Handle payment required (402) response
pub async fn handle_payment_request(
    config: &Config,
    request_ctx: &RequestContext,
    url: &str,
    requirements: PaymentRequirementsResponse,
) -> Result<HttpResponse> {
    if request_ctx.cli.is_verbose() && request_ctx.cli.should_show_output() {
        eprintln!("x402 version: {}", requirements.version());
        if let Some(error) = requirements.error() {
            eprintln!("Message: {}", error);
        }
        eprintln!(
            "Available payment methods: {}",
            requirements.accepts().len()
        );
    }

    let selected_requirement = select_payment_requirement(config, &requirements, &request_ctx.cli)?;

    if request_ctx.cli.is_verbose() && request_ctx.cli.should_show_output() {
        let amount = selected_requirement
            .parse_max_amount()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "invalid".to_string());
        eprintln!(
            "Selected payment method: {} on {} ({})",
            selected_requirement.scheme(),
            selected_requirement.network(),
            amount
        );
    }

    if request_ctx.cli.dry_run {
        return handle_dry_run(config, &selected_requirement);
    }

    if request_ctx.cli.confirm {
        confirm_payment(config, &selected_requirement)?;
    }

    let payment_payload = create_payment_payload(config, &selected_requirement).await?;

    if request_ctx.cli.is_verbose() && request_ctx.cli.should_show_output() {
        eprintln!("Created payment payload");
        eprintln!(
            "{} header (decoded):",
            payment_payload.payment_header_name()
        );
        if let Ok(pretty_json) = serde_json::to_string_pretty(&payment_payload) {
            eprintln!("{pretty_json}");
        }
        eprintln!("Making payment request...");
    }

    let response = request_ctx
        .execute_with_payment(url, &payment_payload)
        .await?;

    display_settlement_info(&request_ctx.cli, &response)?;

    Ok(response)
}

/// Handle dry-run mode
fn handle_dry_run(config: &Config, requirement: &PaymentRequirements) -> Result<HttpResponse> {
    use crate::hyperlink::address_link;

    let registry = &*PROVIDER_REGISTRY;
    if let Some(provider) = registry.find_provider(requirement.network()) {
        let dry_run_info = provider.dry_run(requirement, config)?;

        let from_display = address_link(&dry_run_info.from, &dry_run_info.network);
        let to_display = address_link(&dry_run_info.to, &dry_run_info.network);

        println!("[DRY RUN] Payment would be made:");
        println!("Provider: {}", dry_run_info.provider);
        println!("Network: {}", dry_run_info.network);
        println!("Amount: {} {}", dry_run_info.amount, dry_run_info.asset);
        println!("From: {}", from_display);
        println!("To: {}", to_display);
        if let Some(fee) = dry_run_info.estimated_fee {
            println!("Estimated Fee: {fee}");
        }

        anyhow::bail!("Dry run completed");
    } else {
        anyhow::bail!("No provider found for network: {}", requirement.network());
    }
}

/// Confirm payment with user
fn confirm_payment(config: &Config, requirement: &PaymentRequirements) -> Result<()> {
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
    let (amount_display, asset_symbol) = format_payment_amount(requirement);

    // Get sender address if available
    let from_address = get_sender_address(config, requirement);

    // Format addresses with hyperlinks
    let to_truncated = truncate_address(requirement.pay_to(), 45);
    let to_display = address_link(&to_truncated, requirement.network());

    // Print payment details
    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────┐");
    eprintln!("│                     Payment Details                         │");
    eprintln!("├─────────────────────────────────────────────────────────────┤");
    eprintln!("│  Amount:    {:<47} │", amount_display);
    eprintln!("│  Asset:     {:<47} │", asset_symbol);
    eprintln!("│  Network:   {:<47} │", requirement.network());
    eprintln!("│  To:        {:<47} │", to_display);
    if let Some(ref from) = from_address {
        let from_truncated = truncate_address(from, 45);
        let from_display = address_link(&from_truncated, requirement.network());
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
fn format_payment_amount(requirement: &PaymentRequirements) -> (String, String) {
    let amount_result = requirement.parse_max_amount();
    let asset = requirement.asset();
    let network = requirement.network();

    // Try to get decimals for the asset from the centralized token registry
    if let Ok(decimals) = purl_lib::constants::get_token_decimals(network, asset) {
        let amount_u128: u128 = amount_result.map(|a| a.as_atomic_units()).unwrap_or(0);
        let divisor = 10u128.pow(decimals as u32);
        let whole = amount_u128 / divisor;
        let frac = amount_u128 % divisor;

        // Get token symbol from centralized registry
        let symbol = purl_lib::constants::get_token_symbol(network, asset).unwrap_or("tokens");

        let amount_str = if frac == 0 {
            format!("{whole} {symbol}")
        } else {
            format!(
                "{whole}.{frac:0>width$} {symbol}",
                width = decimals as usize
            )
        };

        (amount_str, symbol.to_string())
    } else {
        // Fallback to raw amount
        let amount_str = amount_result
            .map(|a| format!("{} (atomic units)", a.as_atomic_units()))
            .unwrap_or_else(|_| "invalid amount".to_string());
        (amount_str, truncate_address(asset, 20))
    }
}

/// Get the sender address from config
fn get_sender_address(config: &Config, requirement: &PaymentRequirements) -> Option<String> {
    use purl_lib::WalletConfig;

    // Determine chain type from network
    if purl_lib::network::is_evm_network(requirement.network()) {
        config.evm.as_ref().and_then(|evm| evm.get_address().ok())
    } else if purl_lib::network::is_solana_network(requirement.network()) {
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

/// Display settlement information from response
fn display_settlement_info(cli: &Cli, response: &HttpResponse) -> Result<()> {
    use crate::hyperlink::{address_link, tx_link};

    // Check both v2 and v1 response headers
    let settlement_header = response
        .get_header(PAYMENT_RESPONSE_HEADER)
        .or_else(|| response.get_header(V1_X_PAYMENT_RESPONSE_HEADER));

    if let Some(settlement_header) = settlement_header {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(settlement_header)
            .context("Failed to decode payment response header")?;
        let settlement: SettlementResponse =
            serde_json::from_slice(&decoded).context("Failed to parse settlement response")?;

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

/// Select the best compatible payment requirement from server's response.
fn select_payment_requirement(
    config: &Config,
    requirements: &PaymentRequirementsResponse,
    cli: &Cli,
) -> Result<PaymentRequirements> {
    use purl_lib::negotiator::PaymentNegotiator;

    let allowed_networks = cli.allowed_networks().unwrap_or_default();

    let negotiator = PaymentNegotiator::new(config)
        .with_allowed_networks(&allowed_networks)
        .with_max_amount(cli.max_amount.as_deref());

    negotiator
        .select_from_requirements(requirements)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Create a payment payload for the selected requirement
async fn create_payment_payload(
    config: &Config,
    requirement: &PaymentRequirements,
) -> Result<PaymentPayload> {
    let registry = &*PROVIDER_REGISTRY;

    if let Some(provider) = registry.find_provider(requirement.network()) {
        Ok(provider.create_payment(requirement, config).await?)
    } else {
        anyhow::bail!("No provider found for network: {}", requirement.network());
    }
}
