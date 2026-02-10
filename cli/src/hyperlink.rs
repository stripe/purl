//! Terminal hyperlink utilities using OSC 8 escape sequences.
//!
//! Modern terminals support clickable hyperlinks via the OSC 8 standard.
//! Terminals that don't support it will simply show the visible text.

/// Format a clickable hyperlink for terminals that support OSC 8.
///
/// The format is: `\x1B]8;;URL\x07TEXT\x1B]8;;\x07`
/// Using BEL (\x07) as terminator for broader terminal compatibility.
///
/// Terminals that don't support this will just show TEXT.
pub fn hyperlink(url: &str, text: &str) -> String {
    format!("\x1B]8;;{}\x07{}\x1B]8;;\x07", url, text)
}

/// Format a transaction hash as a hyperlink if network supports it.
///
/// Returns plain text if the network is unknown or has no explorer configured.
pub fn tx_link(tx_hash: &str, network: &str) -> String {
    if let Some(info) = purl_lib::network::get_network(network) {
        if let Some(url) = info.tx_url(tx_hash) {
            return hyperlink(&url, tx_hash);
        }
    }
    tx_hash.to_string()
}

/// Format an address as a hyperlink if network supports it.
///
/// Returns plain text if the network is unknown or has no explorer configured.
pub fn address_link(address: &str, network: &str) -> String {
    if let Some(info) = purl_lib::network::get_network(network) {
        if let Some(url) = info.address_url(address) {
            return hyperlink(&url, address);
        }
    }
    address.to_string()
}

/// Format a wallet address as a clickable hyperlink using a default network for the chain type.
///
/// Uses Base for EVM wallets and Solana mainnet for Solana wallets.
pub fn wallet_link(address: &str, chain: &str) -> String {
    let network = match chain {
        "EVM" => "base",
        "Solana" => "solana",
        _ => return address.to_string(),
    };
    address_link(address, network)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hyperlink_format() {
        let link = hyperlink("https://example.com", "click me");
        assert!(link.contains("https://example.com"));
        assert!(link.contains("click me"));
        assert!(link.starts_with("\x1B]8;;"));
        assert!(link.ends_with("\x1B]8;;\x07"));
    }

    #[test]
    fn test_tx_link_known_network() {
        let link = tx_link("0x123abc", "base");
        assert!(link.contains("basescan.org"));
        assert!(link.contains("/tx/0x123abc"));
    }

    #[test]
    fn test_address_link_known_network() {
        let link = address_link("0xabcdef", "ethereum");
        assert!(link.contains("etherscan.io"));
        assert!(link.contains("/address/0xabcdef"));
    }

    #[test]
    fn test_tx_link_unknown_network() {
        let link = tx_link("0x123", "unknown-network");
        assert_eq!(link, "0x123");
    }

    #[test]
    fn test_solana_address_link() {
        let link = address_link("5xyzABC", "solana");
        assert!(link.contains("solscan.io"));
        assert!(link.contains("/account/5xyzABC"));
    }

    #[test]
    fn test_wallet_link_evm() {
        let link = wallet_link("0xabcdef123456", "EVM");
        assert!(link.contains("basescan.org"));
        assert!(link.contains("/address/0xabcdef123456"));
    }

    #[test]
    fn test_wallet_link_solana() {
        let link = wallet_link("5xyzABC", "Solana");
        assert!(link.contains("solscan.io"));
        assert!(link.contains("/account/5xyzABC"));
    }

    #[test]
    fn test_wallet_link_unknown_chain() {
        let link = wallet_link("0x123", "Unknown");
        assert_eq!(link, "0x123");
    }
}
