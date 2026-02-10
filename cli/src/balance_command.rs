//! Balance command for checking token wallet balances on configured networks

use crate::hyperlink::wallet_link;
use anyhow::{Context, Result};
use colored::Colorize;
use futures::stream::{FuturesUnordered, StreamExt};
use purl_lib::currency::currencies;
use purl_lib::network::{ChainType, Network};
use purl_lib::{Config, PaymentMethod, PurlError, WalletConfig, PROVIDER_REGISTRY};
use std::collections::HashSet;
use std::io::{IsTerminal, Write};
use std::sync::{Arc, Mutex};
use tokio::time::{interval, Duration};

/// Check token balances for configured networks
pub async fn balance_command(
    config: &Config,
    address: Option<String>,
    network_filter: Option<String>,
) -> Result<()> {
    let currency = currencies::USDC;
    let available_methods = config.available_payment_methods();

    if available_methods.is_empty() {
        anyhow::bail!("No payment methods configured. Run 'purl wallet add' to configure.");
    }

    // Show wallet info (only if not checking a specific address)
    if address.is_none() {
        let mut wallet_info: Vec<(&str, String, String)> = Vec::new(); // (chain, address, short_addr)

        if let Some(evm) = &config.evm {
            if let Ok(addr) = evm.get_address() {
                let short_addr = if addr.len() > 12 {
                    format!("{}...{}", &addr[..6], &addr[addr.len() - 4..])
                } else {
                    addr.clone()
                };
                wallet_info.push(("EVM", addr, short_addr));
            }
        }

        if let Some(solana) = &config.solana {
            if let Ok(pubkey) = solana.get_address() {
                let short_key = if pubkey.len() > 12 {
                    format!("{}...{}", &pubkey[..6], &pubkey[pubkey.len() - 4..])
                } else {
                    pubkey.clone()
                };
                wallet_info.push(("Solana", pubkey, short_key));
            }
        }

        if !wallet_info.is_empty() {
            println!("{}", "Wallet".green().bold());
            for (chain, addr, short_addr) in &wallet_info {
                let linked_addr = wallet_link(addr, chain);
                // Create display with short address as the visible text but full address in the link
                let display = if linked_addr != *addr {
                    // Has a link - create hyperlink with short display text
                    crate::hyperlink::hyperlink(
                        &purl_lib::network::get_network(match *chain {
                            "EVM" => "base",
                            "Solana" => "solana",
                            _ => "",
                        })
                        .and_then(|n| n.address_url(addr))
                        .unwrap_or_default(),
                        short_addr,
                    )
                } else {
                    short_addr.clone()
                };
                println!("  {} {}", display.yellow(), format!("({})", chain).dimmed());
            }
            println!();
        }
    }

    // First pass: collect all networks we'll check (for display ordering)
    let mut network_list: Vec<Network> = Vec::new();
    let mut network_addresses: Vec<(Network, String)> = Vec::new();

    for method in &available_methods {
        let chain_type = match method {
            PaymentMethod::Evm => ChainType::Evm,
            PaymentMethod::Solana => ChainType::Solana,
        };

        let networks = Network::by_chain_type(chain_type, network_filter.as_deref());
        if networks.is_empty() {
            continue;
        }

        // Get address once per chain type
        let check_address = match address.as_deref() {
            Some(addr) => addr.to_string(),
            None => {
                let first_provider = PROVIDER_REGISTRY
                    .find_provider(networks[0].as_str())
                    .context(format!("No provider found for network: {}", networks[0]))?;
                first_provider.get_address(config).context(format!(
                    "Failed to get address for {}",
                    first_provider.name()
                ))?
            }
        };

        for network in networks {
            network_list.push(network);
            network_addresses.push((network, check_address.clone()));
        }
    }

    if network_list.is_empty() {
        println!("No networks to check.");
        return Ok(());
    }

    let is_tty = std::io::stdout().is_terminal();
    let total_networks = network_list.len();

    // Calculate max network name width for alignment
    let max_network_width = network_list
        .iter()
        .map(|n| n.to_string().len())
        .max()
        .unwrap_or(15)
        .max(7); // At least "Network" width

    // Print header row (dimmed, like Table style)
    // Pad first, then apply color (ANSI codes interfere with width formatting)
    println!(
        "  {}  {}",
        format!("{:width$}", "Network", width = max_network_width).dimmed(),
        "Balance".dimmed(),
    );

    if is_tty {
        // Show all networks with initial shimmer state
        for network in &network_list {
            let shimmer_text = render_shimmer("fetching...", 0);
            let net_str = network.to_string();
            let padding = " ".repeat(max_network_width.saturating_sub(net_str.len()));
            println!("  {}{}  {}", net_str, padding, shimmer_text);
        }
    }

    // Track which lines are still loading (by index)
    let loading_lines: Arc<Mutex<HashSet<usize>>> =
        Arc::new(Mutex::new((0..total_networks).collect()));

    // Clone values needed for animation task
    let network_names: Vec<String> = network_list.iter().map(|n| n.to_string()).collect();
    let loading_lines_for_anim = Arc::clone(&loading_lines);

    // Spawn animation task for shimmer effect
    let animation_handle = if is_tty {
        Some(tokio::spawn(async move {
            let mut tick = interval(Duration::from_millis(60));
            let mut position: usize = 0;
            let shimmer_len = "fetching...".len();

            loop {
                tick.tick().await;
                position = (position + 1) % (shimmer_len + 4); // Extra frames for pause at edges

                let loading = loading_lines_for_anim.lock().unwrap();
                if loading.is_empty() {
                    break;
                }

                // Update each loading line with shimmer
                for &line_idx in loading.iter() {
                    let lines_from_bottom = network_names.len() - line_idx;
                    let shimmer_text = render_shimmer("fetching...", position);
                    let net_str = &network_names[line_idx];
                    let padding = " ".repeat(max_network_width.saturating_sub(net_str.len()));

                    let mut stdout = std::io::stdout();
                    write!(
                        stdout,
                        "\x1B[{}A\r\x1B[K  {}{}  {}\x1B[{}B\r",
                        lines_from_bottom, net_str, padding, shimmer_text, lines_from_bottom
                    )
                    .ok();
                    stdout.flush().ok();
                }
                drop(loading);
            }
        }))
    } else {
        None
    };

    // Spawn all balance check tasks
    let mut futures: FuturesUnordered<_> = network_addresses
        .into_iter()
        .map(|(network, addr)| {
            let provider = PROVIDER_REGISTRY.find_provider(network.as_str()).unwrap();
            tokio::spawn(async move {
                let result = provider.get_balance(&addr, network, currency).await;
                (network, result)
            })
        })
        .collect();

    // For non-TTY, collect results and display with Table at the end
    let mut results: Vec<(Network, String)> = Vec::new();

    // Process results as they arrive
    while let Some(join_result) = futures.next().await {
        match join_result {
            Ok((network, balance_result)) => {
                let line_index = network_list.iter().position(|n| n == &network).unwrap_or(0);
                let lines_from_bottom = total_networks - line_index;

                // Mark this line as done (stop shimmer for it)
                {
                    let mut loading = loading_lines.lock().unwrap();
                    loading.remove(&line_index);
                }

                match balance_result {
                    Ok(balance) => {
                        let output = format!("{} {}", balance.balance_human, balance.asset);
                        if is_tty {
                            update_line(
                                lines_from_bottom,
                                &network.to_string(),
                                &output.green().to_string(),
                                max_network_width,
                            );
                        } else {
                            results.push((network, output));
                        }
                    }
                    Err(e) => {
                        let error_msg = format_balance_error(&e);
                        if is_tty {
                            update_line(
                                lines_from_bottom,
                                &network.to_string(),
                                &error_msg.red().to_string(),
                                max_network_width,
                            );
                        } else {
                            results.push((network, error_msg));
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Task failed: {e}");
            }
        }
    }

    // Wait for animation to finish
    if let Some(handle) = animation_handle {
        handle.abort(); // Stop animation if still running
    }

    // For non-TTY, display collected results in order
    if !is_tty {
        // Sort results by network order
        results.sort_by_key(|(network, _)| {
            network_list
                .iter()
                .position(|n| n == network)
                .unwrap_or(usize::MAX)
        });
        for (network, balance) in results {
            let net_str = network.to_string();
            let padding = " ".repeat(max_network_width.saturating_sub(net_str.len()));
            println!("  {}{}  {}", net_str, padding, balance);
        }
    }

    println!();

    Ok(())
}

/// Update a specific line in-place using ANSI escape codes
fn update_line(lines_from_bottom: usize, network: &str, result: &str, width: usize) {
    let mut stdout = std::io::stdout();
    // Move cursor up N lines, go to start of line, clear line, print with 2-space indent, move back down
    write!(
        stdout,
        "\x1B[{lines_from_bottom}A\r\x1B[K  {network:width$}  {result}\x1B[{lines_from_bottom}B\r"
    )
    .ok();
    stdout.flush().ok();
}

/// Format balance errors concisely
fn format_balance_error(e: &PurlError) -> String {
    match e {
        PurlError::BalanceQuery(msg) => {
            // Extract just the key part of the error
            if msg.contains("HTTP error") {
                "RPC error".to_string()
            } else {
                "fetch failed".to_string()
            }
        }
        _ => "error".to_string(),
    }
}

/// Render text with a shimmer effect - a bright spot that moves across
fn render_shimmer(text: &str, position: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut result = String::new();

    for (i, ch) in chars.iter().enumerate() {
        // Calculate distance from the "bright spot"
        let distance = if position < len {
            (i as isize - position as isize).unsigned_abs()
        } else {
            // Position is past the text, fade out
            len
        };

        // Use ANSI 256-color grayscale (232=darkest, 255=brightest)
        // Create a gradient: bright at center, dimmer further away
        let color_code = match distance {
            0 => 255, // Brightest white
            1 => 252, // Very bright
            2 => 248, // Bright
            3 => 244, // Medium
            _ => 240, // Dim base color
        };

        result.push_str(&format!("\x1B[38;5;{}m{}\x1B[0m", color_code, ch));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_currency() {
        let usdc = currencies::USDC;
        assert_eq!(usdc.format_atomic(1_000_000), "1.000000");
        assert_eq!(usdc.format_atomic(500_000), "0.500000");
        assert_eq!(usdc.format_atomic(1), "0.000001");
        assert_eq!(usdc.format_atomic(0), "0.000000");
        assert_eq!(usdc.format_atomic(1_500_000), "1.500000");
    }

    #[test]
    fn test_by_chain_type() {
        let evm_networks = Network::by_chain_type(ChainType::Evm, None);
        assert!(!evm_networks.is_empty());
        assert!(evm_networks.contains(&Network::Base));
        assert!(evm_networks.contains(&Network::Ethereum));

        let solana_networks = Network::by_chain_type(ChainType::Solana, None);
        assert!(!solana_networks.is_empty());
        assert!(solana_networks.contains(&Network::Solana));
        assert!(solana_networks.contains(&Network::SolanaDevnet));
    }

    #[test]
    fn test_by_chain_type_with_filter() {
        let filtered = Network::by_chain_type(ChainType::Evm, Some("base"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], Network::Base);

        let filtered = Network::by_chain_type(ChainType::Solana, Some("solana-devnet"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], Network::SolanaDevnet);
    }

    #[test]
    fn test_usdc_config_presence() {
        // Networks with USDC support
        assert!(Network::Base.usdc_config().is_some());
        assert!(Network::BaseSepolia.usdc_config().is_some());
        assert!(Network::Ethereum.usdc_config().is_some());
        assert!(Network::EthereumSepolia.usdc_config().is_some());
        assert!(Network::Solana.usdc_config().is_some());
        assert!(Network::SolanaDevnet.usdc_config().is_some());

        // Networks without USDC support yet
        assert!(Network::Avalanche.usdc_config().is_none());
        assert!(Network::Polygon.usdc_config().is_none());
    }

    #[test]
    fn test_usdc_config_structure() {
        let base_config = Network::Base.usdc_config().unwrap();
        assert!(!base_config.address.is_empty());
        assert!(base_config.address.starts_with("0x"));
        assert_eq!(base_config.currency.symbol, "USDC");
        assert_eq!(base_config.currency.decimals, 6);

        let base_info = Network::Base.info();
        assert!(!base_info.rpc_url.is_empty());

        let solana_config = Network::Solana.usdc_config().unwrap();
        assert!(!solana_config.address.is_empty());
        assert!(!solana_config.address.starts_with("0x"));
        assert_eq!(solana_config.currency.symbol, "USDC");
        assert_eq!(solana_config.currency.decimals, 6);

        let solana_info = Network::Solana.info();
        assert!(!solana_info.rpc_url.is_empty());
    }
}
