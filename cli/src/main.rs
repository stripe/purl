//! purl CLI - A curl-like tool for x402 payment-enabled HTTP requests

mod balance_command;
mod cli;
mod colors;
mod config_commands;
mod config_utils;
mod errors;
mod exit_codes;
mod help_topics;
mod hyperlink;
mod inspect_command;
mod network_commands;
mod output;
mod payment;
mod request;
mod table;
mod wallet_commands;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use clap_complete::{generate, shells};
use cli::{
    Cli, ColorMode, Commands, ConfigCommands, NetworkCommands, OutputFormat, Shell, WalletCommands,
};
use colored::control;
use exit_codes::ExitCode;
use purl_lib::{Config, PaymentRequirementsResponse, WalletConfig};
use std::path::PathBuf;
use std::str::FromStr;

use config_utils::load_config;
use output::{
    build_config_display, decrypt_keystores_upfront, handle_regular_response,
    print_payment_method_text, write_output,
};
use payment::handle_payment_request;
use request::RequestContext;

#[tokio::main]
async fn main() {
    // Set up low-level Ctrl+C handler that works during blocking calls (e.g., password prompts)
    ctrlc::set_handler(move || {
        eprintln!("Interrupted");
        std::process::exit(ExitCode::Interrupted.code());
    })
    .expect("Failed to set Ctrl+C handler");

    let result = run().await;

    if let Err(e) = result {
        eprintln!("{}", errors::format_error_with_suggestion(&e));
        ExitCode::from(&e).exit();
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Initialize color support based on user preference and NO_COLOR env var
    init_color_support(&cli);

    // Handle subcommands
    if let Some(ref command) = cli.command {
        return handle_command(&cli, command).await;
    }

    // No subcommand and no URL - show status and help
    if cli.url.is_none() {
        show_status_and_help().await;
        return Ok(());
    }

    // No subcommand - make an HTTP request
    make_request(cli).await
}

/// Handle CLI subcommands
async fn handle_command(cli: &Cli, command: &Commands) -> Result<()> {
    match command {
        Commands::Config {
            command,
            output_format,
            unsafe_show_private_keys,
        } => {
            if let Some(subcommand) = command {
                match subcommand {
                    ConfigCommands::Get { key, output_format } => {
                        config_commands::get_command(cli, key, *output_format)
                    }
                    ConfigCommands::Validate => config_commands::validate_command(cli),
                }
            } else {
                show_config(cli, *output_format, *unsafe_show_private_keys)
            }
        }

        Commands::Version => show_version(),

        Commands::Wallet { command } => match command {
            WalletCommands::List => wallet_commands::list_command(),
            WalletCommands::Add {
                name,
                wallet_type,
                private_key,
            } => wallet_commands::add_command(name.clone(), *wallet_type, private_key.clone()),
            WalletCommands::Show { name } => wallet_commands::show_command(name),
            WalletCommands::Verify { name } => wallet_commands::verify_command(name),
            WalletCommands::Use { name } => wallet_commands::use_command(name),
            WalletCommands::Remove { name } => wallet_commands::remove_command(name),
        },

        Commands::Completions { shell } => generate_completions(*shell),

        Commands::Balance { address, network } => {
            let config = load_config(cli.config.as_ref())?;
            balance_command::balance_command(&config, address.clone(), network.clone()).await
        }

        Commands::Networks {
            command,
            output_format,
        } => {
            if let Some(subcommand) = command {
                match subcommand {
                    NetworkCommands::List { output_format } => {
                        network_commands::list_networks(*output_format)
                            .context("Failed to list networks")
                    }
                    NetworkCommands::Info {
                        network,
                        output_format,
                    } => network_commands::show_network_info(network, *output_format)
                        .context("Failed to show network info"),
                }
            } else {
                network_commands::list_networks(*output_format).context("Failed to list networks")
            }
        }

        Commands::Inspect { url } => inspect_command::inspect_command(cli, url),

        Commands::Topics { topic } => {
            if let Some(topic_name) = topic {
                if let Some(content) = help_topics::get_topic(topic_name) {
                    println!("{content}");
                    Ok(())
                } else {
                    eprintln!("Unknown help topic: '{topic_name}'\n");
                    help_topics::list_topics();
                    std::process::exit(1);
                }
            } else {
                help_topics::list_topics();
                Ok(())
            }
        }
    }
}

/// Make an HTTP request (main flow)
async fn make_request(cli: Cli) -> Result<()> {
    let mut config = load_config(cli.config.as_ref())?;

    // Set runtime password from CLI/env var for keystore decryption
    config.password = cli.password.clone();

    let request_ctx = RequestContext::new(cli);

    let url = request_ctx
        .cli
        .url
        .as_ref()
        .context("URL is required. Run 'purl --help' for usage.")?;

    if request_ctx.cli.is_verbose() && request_ctx.cli.should_show_output() {
        eprintln!("Making {} request to: {url}", request_ctx.method);
    }

    let response = request_ctx.execute(url, None)?;

    if !response.is_payment_required() {
        handle_regular_response(&request_ctx.cli, response)?;
        return Ok(());
    }

    if request_ctx.cli.is_verbose() && request_ctx.cli.should_show_output() {
        eprintln!("402 status: payment required");
    }

    let json = response.payment_requirements_json()?;
    let requirements: PaymentRequirementsResponse =
        serde_json::from_str(&json).context("Failed to parse payment requirements")?;

    let response = handle_payment_request(&config, &request_ctx, url, requirements).await?;

    // If still 402 after payment attempt, check for specific error codes
    if response.is_payment_required() {
        if let Ok(json) = response.payment_requirements_json() {
            if let Ok(requirements) =
                serde_json::from_str::<purl_lib::PaymentRequirementsResponse>(&json)
            {
                if let Some(error_msg) = requirements.error() {
                    if error_msg == "insufficient_funds" {
                        let (required, balance, asset, network) = if let Some(req) = requirements.accepts().first()
                        {
                            let network_str = req.network().to_string();
                            let asset_str = req.asset().to_string();

                            let required_amount = if let Ok(amt) = req.parse_max_amount() {
                                Some(format_amount_human(amt.as_atomic_units(), &network_str, &asset_str))
                            } else {
                                Some("Unspecified amount".to_string())
                            };

                            let balance_str = get_user_balance(&config, &network_str, &asset_str).await;

                            let symbol = get_token_symbol(&network_str, &asset_str);

                            let canonical_network = purl_lib::network::resolve_network_alias(&network_str);
                            let network_display = if canonical_network.is_empty() {
                                network_str.clone()
                            } else {
                                canonical_network.to_string()
                            };

                            (
                                required_amount,
                                balance_str,
                                Some(symbol),
                                Some(network_display),
                            )
                        } else {
                            (None, None, None, None)
                        };

                        return Err(purl_lib::PurlError::InsufficientBalance {
                            message: error_msg.to_string(),
                            required,
                            balance,
                            asset,
                            network,
                        }
                        .into());
                    }
                }
            }
        }

        anyhow::bail!("Payment was not accepted by the server");
    }

    handle_regular_response(&request_ctx.cli, response)?;

    Ok(())
}

// ==================== Status and Help ====================

/// Show current status and abridged help when purl is run without arguments
async fn show_status_and_help() {
    use colored::Colorize;
    use purl_lib::currency::currencies;
    use purl_lib::network::Network;
    use purl_lib::PROVIDER_REGISTRY;
    use std::io::{IsTerminal, Write};

    let config = purl_lib::Config::load_unchecked(None::<&str>).ok();
    let is_tty = std::io::stdout().is_terminal();

    if let Some(ref config) = config {
        let mut wallet_info: Vec<(&str, String, String, String)> = Vec::new(); // (chain, address, short_addr, linked_short)

        if let Some(evm) = &config.evm {
            if let Ok(address) = evm.get_address() {
                let short_addr = if address.len() > 12 {
                    format!("{}...{}", &address[..6], &address[address.len() - 4..])
                } else {
                    address.clone()
                };
                // Create clickable link with short display text
                let linked_short = if let Some(url) =
                    purl_lib::network::get_network("base").and_then(|n| n.address_url(&address))
                {
                    hyperlink::hyperlink(&url, &short_addr)
                } else {
                    short_addr.clone()
                };
                wallet_info.push(("EVM", address, short_addr, linked_short));
            }
        }

        if let Some(solana) = &config.solana {
            if let Ok(pubkey) = solana.get_address() {
                let short_key = if pubkey.len() > 12 {
                    format!("{}...{}", &pubkey[..6], &pubkey[pubkey.len() - 4..])
                } else {
                    pubkey.clone()
                };
                // Create clickable link with short display text
                let linked_short = if let Some(url) =
                    purl_lib::network::get_network("solana").and_then(|n| n.address_url(&pubkey))
                {
                    hyperlink::hyperlink(&url, &short_key)
                } else {
                    short_key.clone()
                };
                wallet_info.push(("Solana", pubkey, short_key, linked_short));
            }
        }

        if !wallet_info.is_empty() {
            println!("{}", "Wallet".green().bold());

            // Print initial state with "fetching..." for balance
            for (chain, _addr, _short_addr, linked_short) in &wallet_info {
                if is_tty {
                    println!(
                        "  {} {} {}",
                        linked_short.yellow(),
                        format!("({})", chain).dimmed(),
                        "fetching...".dimmed()
                    );
                } else {
                    println!("  {} ({})", linked_short.yellow(), chain);
                }
            }

            // Fetch balances in parallel and update display
            if is_tty {
                let currency = currencies::USDC;
                let mut handles = Vec::new();

                for (idx, (chain, addr, _short, _linked)) in wallet_info.iter().enumerate() {
                    // Pick a representative network for this chain
                    let network = match *chain {
                        "EVM" => Network::Base,
                        "Solana" => Network::Solana,
                        _ => continue,
                    };

                    if let Some(provider) = PROVIDER_REGISTRY.find_provider(network.as_str()) {
                        let addr = addr.clone();
                        let handle = tokio::spawn(async move {
                            let result = provider.get_balance(&addr, network, currency).await;
                            (idx, result)
                        });
                        handles.push(handle);
                    }
                }

                // Update lines as results arrive
                let total_wallets = wallet_info.len();
                for handle in handles {
                    if let Ok((idx, result)) = handle.await {
                        let lines_from_bottom = total_wallets - idx;
                        let (chain, _, _short_addr, linked_short) = &wallet_info[idx];

                        let balance_str = match result {
                            Ok(b) => format!("{} {}", b.balance_human, b.asset)
                                .green()
                                .to_string(),
                            Err(_) => "".to_string(),
                        };

                        // Update the line
                        let mut stdout = std::io::stdout();
                        write!(
                            stdout,
                            "\x1B[{}A\r\x1B[K  {} {} {}\x1B[{}B\r",
                            lines_from_bottom,
                            linked_short.yellow(),
                            format!("({})", chain).dimmed(),
                            balance_str,
                            lines_from_bottom
                        )
                        .ok();
                        stdout.flush().ok();
                    }
                }
            }

            println!();
        }
    }

    // Print abridged help
    println!("{}", "Usage".green().bold());
    println!("  purl [OPTIONS] <URL>");
    println!("  purl <COMMAND>");
    println!();
    println!("{}", "Commands".green().bold());
    println!("  wallet       Manage wallets");
    println!("  config       Manage configuration");
    println!("  balance      Check wallet balance");
    println!("  inspect      Inspect payment requirements for a URL");
    println!("  networks     List supported networks");
    println!();
    println!("Run {} for more options", "purl help".cyan());
}

// ==================== Config Display ====================

fn show_config(cli: &Cli, output_format: OutputFormat, show_private_keys: bool) -> Result<()> {
    let config = load_config(cli.config.as_ref())?;
    let config_path = if let Some(ref path) = cli.config {
        PathBuf::from(path)
    } else {
        Config::default_config_path()?
    };

    let decrypted_keys = if show_private_keys {
        Some(decrypt_keystores_upfront(&config)?)
    } else {
        None
    };

    let format = output_format.resolve();

    match format {
        OutputFormat::Auto => unreachable!("Auto should be resolved"),
        OutputFormat::Json => {
            let display_data = build_config_display(
                &config,
                &config_path,
                show_private_keys,
                decrypted_keys.as_ref(),
            );
            let output = serde_json::to_string_pretty(&display_data)?;
            write_output(cli, output)?;
        }
        OutputFormat::Yaml => {
            let display_data = build_config_display(
                &config,
                &config_path,
                show_private_keys,
                decrypted_keys.as_ref(),
            );
            let output = serde_yaml::to_string(&display_data)?;
            write_output(cli, output)?;
        }
        OutputFormat::Text => {
            println!("Config file: {}", config_path.display());
            println!();

            if let Some(evm) = &config.evm {
                print_payment_method_text(
                    "evm",
                    evm.keystore.as_ref(),
                    evm.get_address().ok().as_deref(),
                    "address",
                    decrypted_keys
                        .as_ref()
                        .and_then(|k| k.evm_private_key.as_deref()),
                    show_private_keys,
                );
            }

            if let Some(solana) = &config.solana {
                print_payment_method_text(
                    "solana",
                    solana.keystore.as_ref(),
                    solana.get_address().ok().as_deref(),
                    "public_key",
                    decrypted_keys
                        .as_ref()
                        .and_then(|k| k.solana_private_key.as_deref()),
                    show_private_keys,
                );
            }

            if config.evm.is_none() && config.solana.is_none() {
                println!("No payment methods configured.");
                println!("Run 'purl wallet add' to create a wallet.");
            }
        }
    }

    Ok(())
}

// ==================== Simple Commands ====================

/// Show version information
fn show_version() -> Result<()> {
    const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

    println!("purl CLI: v{CLI_VERSION}");
    println!("purl-lib: v{}", purl_lib::VERSION);

    Ok(())
}

/// Generate shell completions
fn generate_completions(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();

    match shell {
        Shell::Bash => generate(shells::Bash, &mut cmd, bin_name, &mut std::io::stdout()),
        Shell::Zsh => generate(shells::Zsh, &mut cmd, bin_name, &mut std::io::stdout()),
        Shell::Fish => generate(shells::Fish, &mut cmd, bin_name, &mut std::io::stdout()),
        Shell::PowerShell => generate(
            shells::PowerShell,
            &mut cmd,
            bin_name,
            &mut std::io::stdout(),
        ),
    }

    Ok(())
}

/// Initialize color support based on user preference and NO_COLOR env var
fn init_color_support(cli: &Cli) {
    use std::io::IsTerminal;
    let no_color_env = std::env::var("NO_COLOR").is_ok();

    match cli.color {
        ColorMode::Always => control::set_override(true),
        ColorMode::Never => control::set_override(false),
        ColorMode::Auto => {
            if no_color_env || !std::io::stdout().is_terminal() {
                control::set_override(false);
            }
        }
    }
}

/// Format an amount in atomic units to human-readable format
///
/// Returns just the number without symbol.
fn format_amount_human(amount: u128, network: &str, asset: &str) -> String {
    use purl_lib::constants::get_token_decimals;

    if let Ok(decimals) = get_token_decimals(network, asset) {
        let divisor = 10u128.pow(decimals as u32);
        let whole = amount / divisor;
        let frac = amount % divisor;

        if frac == 0 {
            format!("{whole}")
        } else {
            format!("{whole}.{frac:0>width$}", width = decimals as usize)
        }
    } else {
        format!("{} (atomic units)", amount)
    }
}

/// Get the user's balance for a given network and asset
///
/// Note: Currently only supports USDC balance queries. Returns None if the asset
/// is not a recognized USDC token or if the balance query fails.
async fn get_user_balance(config: &Config, network: &str, asset: &str) -> Option<String> {
    use purl_lib::currency::currencies;
    use purl_lib::network::Network;
    use purl_lib::WalletConfig;
    use purl_lib::PROVIDER_REGISTRY;

    // Resolve CAIP-2 format (e.g., "eip155:84532") to canonical name (e.g., "base-sepolia")
    let canonical_network = purl_lib::network::resolve_network_alias(network);

    // Verify the network exists
    purl_lib::network::get_network(canonical_network)?;

    // Check if this asset is USDC - only query balance for known tokens
    let token_symbol = purl_lib::constants::get_token_symbol(canonical_network, asset);
    if token_symbol != Some("USDC") {
        return None;
    }

    let address = if purl_lib::network::is_evm_network(canonical_network) {
        config.evm.as_ref()?.get_address().ok()?
    } else if purl_lib::network::is_solana_network(canonical_network) {
        config.solana.as_ref()?.get_address().ok()?
    } else {
        return None;
    };

    let network_enum = Network::from_str(canonical_network).ok()?;
    let provider = PROVIDER_REGISTRY.find_provider(canonical_network)?;

    let balance = provider
        .get_balance(&address, network_enum, currencies::USDC)
        .await
        .ok()?;

    Some(balance.balance_human)
}

/// Get token symbol for display
fn get_token_symbol(network: &str, asset: &str) -> String {
    purl_lib::constants::get_token_symbol(network, asset)
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // Fallback to truncated address if symbol not found
            if asset.len() > 10 {
                format!("{}...{}", &asset[..6], &asset[asset.len() - 4..])
            } else {
                asset.to_string()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use purl_lib::Config;

    #[test]
    fn test_decrypt_keystores_upfront_with_no_keys() {
        let config = Config {
            evm: None,
            solana: None,
            ..Default::default()
        };

        let result = decrypt_keystores_upfront(&config);
        assert!(result.is_ok());

        let keys = result.unwrap();
        assert!(keys.evm_private_key.is_none());
        assert!(keys.solana_private_key.is_none());
    }

    #[test]
    fn test_build_config_display_no_wallets() {
        let config = Config {
            evm: None,
            solana: None,
            ..Default::default()
        };

        let config_path = PathBuf::from("/test/config.toml");
        let display = build_config_display(&config, &config_path, false, None);

        // No wallets configured, so evm and solana should be null
        assert!(display.get("evm").unwrap().is_null());
        assert!(display.get("solana").unwrap().is_null());
    }
}
