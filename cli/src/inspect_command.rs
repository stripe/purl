//! Inspect command for viewing payment requirements without executing payment

use anyhow::{Context, Result};
use colored::Colorize;
use purl_lib::{HttpClientBuilder, HttpMethod, PaymentMethod, PaymentRequirementsResponse};
use serde::Serialize;

use crate::cli::{Cli, OutputFormat};
use crate::config_utils::load_config;

/// Output format for a single payment option
#[derive(Debug, Serialize)]
struct AcceptedPaymentOption {
    network: String,
    scheme: String,
    amount_atomic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount_human: Option<String>,
    asset: String,
    symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    decimals: Option<u8>,
    compatible: bool,
    pay_to: String,
    description: String,
}

/// Output format for the inspect command
#[derive(Debug, Serialize)]
struct InspectOutput {
    x402_version: u32,
    message: String,
    accepts: Vec<AcceptedPaymentOption>,
    configured_methods: Vec<String>,
}

/// Format atomic units to human-readable amounts
fn format_amount(atomic: &str, decimals: u8, symbol: &str) -> String {
    use purl_lib::currency::format_atomic_trimmed;
    format_atomic_trimmed(atomic, decimals, symbol)
}

/// Get token symbol for a requirement
fn get_token_symbol(requirement: &purl_lib::x402::PaymentRequirements) -> String {
    if let Some(extra) = requirement.extra() {
        if let Some(symbol) = extra.get("symbol").and_then(|s| s.as_str()) {
            return symbol.to_string();
        }
    }

    requirement.asset().to_string()
}

/// Get decimals for a token on a network
fn get_decimals(network: &str, asset: &str) -> Result<u8> {
    purl_lib::constants::get_token_decimals(network, asset).map_err(|e| {
        anyhow::anyhow!("Token decimals not configured: {e}. Add to ~/.purl/tokens.json if needed.")
    })
}

/// Inspect payment requirements for a URL
pub fn inspect_command(cli: &Cli, url: &str) -> Result<()> {
    let config = load_config(cli.config.as_ref())?;

    // Build HTTP client
    let mut builder = HttpClientBuilder::new()
        .verbose(cli.is_verbose())
        .follow_redirects(cli.follow_redirects);

    if let Some(timeout) = cli.get_timeout() {
        builder = builder.timeout(timeout);
    }

    if let Some(user_agent) = &cli.user_agent {
        builder = builder.user_agent(user_agent);
    }

    let mut client = builder.build()?;

    if cli.is_verbose() && cli.should_show_output() {
        eprintln!("Inspecting payment requirements for: {url}");
    }

    let response = client.request(HttpMethod::Get, url, None)?;

    if !response.is_payment_required() {
        anyhow::bail!(
            "No payment required (status: {}). URL does not require payment.",
            response.status_code
        );
    }

    let json = response.payment_requirements_json()?;
    let requirements: PaymentRequirementsResponse =
        serde_json::from_str(&json).context("Failed to parse payment requirements")?;

    let available_methods = config.available_payment_methods();
    let format = cli.output_format.resolve();

    match format {
        OutputFormat::Auto => unreachable!("Auto should be resolved"),
        OutputFormat::Json => {
            output_json(cli, &requirements, &available_methods)?;
        }
        OutputFormat::Yaml => {
            output_yaml(cli, &requirements, &available_methods)?;
        }
        OutputFormat::Text => {
            output_text(cli, &requirements, &available_methods)?;
        }
    }

    Ok(())
}

/// Build structured output from payment requirements
fn build_inspect_output(
    requirements: &PaymentRequirementsResponse,
    available_methods: &[PaymentMethod],
) -> InspectOutput {
    let accepts = requirements
        .accepts()
        .iter()
        .map(|req| {
            let symbol = get_token_symbol(req);
            let decimals = get_decimals(req.network(), req.asset()).ok();
            let amount_result = req.parse_max_amount();
            let amount_atomic = amount_result
                .as_ref()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "invalid".to_string());
            let amount_human = decimals.and_then(|dec| {
                amount_result
                    .ok()
                    .map(|amt| format_amount(&amt.to_string(), dec, &symbol))
            });

            AcceptedPaymentOption {
                network: req.network().to_string(),
                scheme: req.scheme().to_string(),
                amount_atomic,
                amount_human,
                asset: req.asset().to_string(),
                symbol,
                decimals,
                compatible: is_compatible_method(req, available_methods),
                pay_to: req.pay_to().to_string(),
                description: req.description().to_string(),
            }
        })
        .collect();

    InspectOutput {
        x402_version: requirements.version(),
        message: requirements
            .error()
            .map(|s| s.to_string())
            .unwrap_or_default(),
        accepts,
        configured_methods: available_methods
            .iter()
            .map(|m| m.as_str().to_string())
            .collect(),
    }
}

fn output_json(
    cli: &Cli,
    requirements: &PaymentRequirementsResponse,
    available_methods: &[PaymentMethod],
) -> Result<()> {
    let output = build_inspect_output(requirements, available_methods);
    let pretty_json = serde_json::to_string_pretty(&output)?;

    if let Some(output_file) = &cli.output {
        std::fs::write(output_file, &pretty_json)?;
        if cli.is_verbose() && cli.should_show_output() {
            eprintln!("Saved to: {output_file}");
        }
    } else {
        println!("{pretty_json}");
    }

    Ok(())
}

fn output_yaml(
    cli: &Cli,
    requirements: &PaymentRequirementsResponse,
    available_methods: &[PaymentMethod],
) -> Result<()> {
    let output = build_inspect_output(requirements, available_methods);
    let yaml_output = serde_yaml::to_string(&output)?;

    if let Some(output_file) = &cli.output {
        std::fs::write(output_file, &yaml_output)?;
        if cli.is_verbose() && cli.should_show_output() {
            eprintln!("Saved to: {output_file}");
        }
    } else {
        println!("{yaml_output}");
    }

    Ok(())
}

fn output_text(
    cli: &Cli,
    requirements: &PaymentRequirementsResponse,
    available_methods: &[PaymentMethod],
) -> Result<()> {
    let data = build_inspect_output(requirements, available_methods);

    // When writing to file, use plain text (no ANSI codes)
    if let Some(output_file) = &cli.output {
        let mut output = String::new();
        output.push_str("Payment Required (402)\n");
        output.push_str(&format!("Message: {}\n", data.message));
        output.push_str(&format!("x402 Version: {}\n", data.x402_version));
        output.push_str("\nAccepts:\n");

        for opt in &data.accepts {
            output.push_str(&format!("  - Network: {}\n", opt.network));
            output.push_str(&format!("    Scheme: {}\n", opt.scheme));
            if let Some(ref human) = opt.amount_human {
                output.push_str(&format!(
                    "    Amount: {} ({} atomic units)\n",
                    human, opt.amount_atomic
                ));
            } else {
                output.push_str(&format!(
                    "    Amount: {} atomic units (decimals unknown)\n",
                    opt.amount_atomic
                ));
            }
            output.push_str(&format!("    Asset: {}\n", opt.asset));
            output.push_str(&format!("    Pay To: {}\n", opt.pay_to));
            if !opt.description.is_empty() {
                output.push_str(&format!("    Description: {}\n", opt.description));
            }
            if opt.compatible {
                output.push_str("    Compatible: Yes (configured)\n");
            } else {
                output.push_str("    Compatible: No (not configured)\n");
            }
            output.push('\n');
        }

        output.push_str(&format!(
            "Configured payment methods: {}\n",
            if data.configured_methods.is_empty() {
                "None".to_string()
            } else {
                data.configured_methods.join(", ")
            }
        ));

        std::fs::write(output_file, &output)?;
        if cli.is_verbose() && cli.should_show_output() {
            eprintln!("Saved to: {output_file}");
        }
        return Ok(());
    }

    // Colored output for terminal
    println!("{}", "Payment Required (402)".yellow().bold());

    if !data.message.is_empty() {
        println!("{}: {}", "Message".bold(), data.message);
    }
    println!("{}: {}", "x402 Version".bold(), data.x402_version);
    println!();
    println!("{}", "Accepts:".green().bold());

    for opt in &data.accepts {
        println!("  {} {}", "•".cyan(), opt.network.cyan());
        println!("    {}: {}", "Scheme".dimmed(), opt.scheme);

        if let Some(ref human) = opt.amount_human {
            println!(
                "    {}: {} {}",
                "Amount".dimmed(),
                human.yellow(),
                format!("({} atomic)", opt.amount_atomic).dimmed()
            );
        } else {
            println!(
                "    {}: {} {}",
                "Amount".dimmed(),
                opt.amount_atomic.yellow(),
                "atomic (decimals unknown)".dimmed()
            );
        }

        println!("    {}: {}", "Asset".dimmed(), opt.asset);
        println!("    {}: {}", "Pay To".dimmed(), opt.pay_to.yellow());

        if !opt.description.is_empty() {
            println!("    {}: {}", "Description".dimmed(), opt.description);
        }

        if opt.compatible {
            println!(
                "    {}: {}",
                "Compatible".dimmed(),
                "Yes (configured)".green()
            );
        } else {
            println!(
                "    {}: {}",
                "Compatible".dimmed(),
                "No (not configured)".red()
            );
        }

        println!();
    }

    let methods_str = if data.configured_methods.is_empty() {
        "None".red().to_string()
    } else {
        data.configured_methods.join(", ")
    };
    println!("{}: {}", "Configured payment methods".bold(), methods_str);

    Ok(())
}

/// Check if a requirement is compatible with configured payment methods
fn is_compatible_method(
    req: &purl_lib::x402::PaymentRequirements,
    available_methods: &[PaymentMethod],
) -> bool {
    if req.is_evm() && available_methods.contains(&PaymentMethod::Evm) {
        return true;
    }
    if req.is_solana() && available_methods.contains(&PaymentMethod::Solana) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_amount_eth() {
        // 1 ETH = 1000000000000000000 wei
        assert_eq!(format_amount("1000000000000000000", 18, "ETH"), "1 ETH");
        assert_eq!(format_amount("100000000000000000", 18, "ETH"), "0.1 ETH");
        assert_eq!(format_amount("10000000000000000", 18, "ETH"), "0.01 ETH");
        assert_eq!(format_amount("1000000000000000", 18, "ETH"), "0.001 ETH");
    }

    #[test]
    fn test_format_amount_usdc() {
        // USDC has 6 decimals
        assert_eq!(format_amount("1000000", 6, "USDC"), "1 USDC");
        assert_eq!(format_amount("100000", 6, "USDC"), "0.1 USDC");
        assert_eq!(format_amount("10000", 6, "USDC"), "0.01 USDC");
        assert_eq!(format_amount("1000", 6, "USDC"), "0.001 USDC");
    }

    #[test]
    fn test_format_amount_sol() {
        // SOL has 9 decimals (lamports)
        assert_eq!(format_amount("1000000000", 9, "SOL"), "1 SOL");
        assert_eq!(format_amount("100000000", 9, "SOL"), "0.1 SOL");
        assert_eq!(format_amount("10000000", 9, "SOL"), "0.01 SOL");
        assert_eq!(format_amount("1000000", 9, "SOL"), "0.001 SOL");
    }

    #[test]
    fn test_format_amount_no_fraction() {
        assert_eq!(format_amount("5000000000000000000", 18, "ETH"), "5 ETH");
        assert_eq!(format_amount("5000000", 6, "USDC"), "5 USDC");
    }

    #[test]
    fn test_format_amount_zero() {
        assert_eq!(format_amount("0", 18, "ETH"), "0 ETH");
        assert_eq!(format_amount("0", 6, "USDC"), "0 USDC");
    }
}
