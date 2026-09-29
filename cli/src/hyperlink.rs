//! Terminal hyperlink utilities using OSC 8 escape sequences.
//!
//! Modern terminals support clickable hyperlinks via the OSC 8 standard.
//! Terminals that don't support it will simply show the visible text.

use colored::control::SHOULD_COLORIZE;
use std::io::IsTerminal;

/// Format a clickable hyperlink for terminals that support OSC 8.
///
/// The format is: `\x1B]8;;URL\x07TEXT\x1B]8;;\x07`
/// Using BEL (\x07) as terminator for broader terminal compatibility.
///
/// Terminals that don't support this will just show TEXT.
pub fn hyperlink(url: &str, text: &str) -> String {
    let safe_url = crate::terminal::sanitize(url);
    let safe_text = crate::terminal::sanitize(text);
    format!("\x1B]8;;{safe_url}\x07{safe_text}\x1B]8;;\x07")
}

/// Format a clickable hyperlink only when terminal decoration is appropriate.
///
/// Hyperlinks are suppressed for non-TTY output and when color/terminal decoration
/// has been disabled via the existing color control path.
pub fn supports_hyperlinks() -> bool {
    std::io::stdout().is_terminal() && SHOULD_COLORIZE.should_colorize()
}

/// Format a clickable hyperlink only when terminal decoration is appropriate.
///
/// Hyperlinks are suppressed for non-TTY output and when color/terminal decoration
/// has been disabled via the existing color control path.
pub fn terminal_hyperlink(url: &str, text: &str) -> String {
    if supports_hyperlinks() {
        hyperlink(url, text)
    } else {
        crate::terminal::sanitize(text)
    }
}

/// Format a transaction hash as a hyperlink if network supports it.
///
/// Returns plain text if the network is unknown or has no explorer configured.
pub fn tx_link(tx_hash: &str, network: &str) -> String {
    if let Some(info) = purl_lib::network::get_network(network) {
        if let Some(url) = info.tx_url(tx_hash) {
            return terminal_hyperlink(&url, tx_hash);
        }
    }
    crate::terminal::sanitize(tx_hash)
}

/// Format an address as a hyperlink if network supports it.
///
/// Returns plain text if the network is unknown or has no explorer configured.
pub fn address_link(address: &str, network: &str) -> String {
    if let Some(info) = purl_lib::network::get_network(network) {
        if let Some(url) = info.address_url(address) {
            return terminal_hyperlink(&url, address);
        }
    }
    crate::terminal::sanitize(address)
}

/// Format a wallet address as a clickable hyperlink using a default network for the chain type.
///
/// Uses Base for EVM wallets, Solana mainnet for Solana wallets, and Tempo Moderato for Tempo wallets.
pub fn wallet_link(address: &str, chain: &str) -> String {
    let network = match chain {
        "EVM" | "evm" => "base",
        "Solana" | "solana" => "solana",
        "Tempo" | "tempo" => "tempo",
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
    fn test_hyperlink_sanitizes_osc_injection() {
        let link = hyperlink(
            "https://example.com/\x07malicious",
            "safe\x1b]8;;https://evil.example\x07spoofed",
        );
        assert_eq!(
            link,
            "\x1B]8;;https://example.com/malicious\x07safe]8;;https://evil.examplespoofed\x1B]8;;\x07"
        );
    }

    #[test]
    fn test_terminal_hyperlink_plain_text_when_not_tty() {
        let link = terminal_hyperlink("https://example.com", "click me");
        assert_eq!(link, "click me");
    }

    #[test]
    fn test_supports_hyperlinks_false_when_not_tty() {
        assert!(!supports_hyperlinks());
    }

    #[test]
    fn test_tx_link_known_network_plain_text_when_not_tty() {
        let link = tx_link("0x123abc", "base");
        assert_eq!(link, "0x123abc");
    }

    #[test]
    fn test_tx_url_lookup_known_network() {
        let url = purl_lib::network::get_network("base")
            .and_then(|n| n.tx_url("0x123abc"))
            .expect("base tx url");
        assert!(url.contains("basescan.org"));
        assert!(url.contains("/tx/0x123abc"));
    }

    #[test]
    fn test_address_link_known_network_plain_text_when_not_tty() {
        let link = address_link("0xabcdef", "ethereum");
        assert_eq!(link, "0xabcdef");
    }

    #[test]
    fn test_address_url_lookup_known_network() {
        let url = purl_lib::network::get_network("ethereum")
            .and_then(|n| n.address_url("0xabcdef"))
            .expect("ethereum address url");
        assert!(url.contains("etherscan.io"));
        assert!(url.contains("/address/0xabcdef"));
    }

    #[test]
    fn test_tx_link_unknown_network() {
        let link = tx_link("0x123", "unknown-network");
        assert_eq!(link, "0x123");
    }

    #[test]
    fn test_unknown_network_link_sanitizes_text() {
        assert_eq!(
            address_link("safe\x1b[2Jaddress", "unknown"),
            "safe[2Jaddress"
        );
        assert_eq!(tx_link("hash\x07spoof", "unknown"), "hashspoof");
    }

    #[test]
    fn test_solana_address_link_plain_text_when_not_tty() {
        let link = address_link("5xyzABC", "solana");
        assert_eq!(link, "5xyzABC");
    }

    #[test]
    fn test_solana_address_url_lookup() {
        let url = purl_lib::network::get_network("solana")
            .and_then(|n| n.address_url("5xyzABC"))
            .expect("solana address url");
        assert!(url.contains("solscan.io"));
        assert!(url.contains("/account/5xyzABC"));
    }

    #[test]
    fn test_wallet_link_evm_plain_text_when_not_tty() {
        let link = wallet_link("0xabcdef123456", "EVM");
        assert_eq!(link, "0xabcdef123456");
    }

    #[test]
    fn test_wallet_link_evm_uses_base_url_lookup() {
        let url = purl_lib::network::get_network("base")
            .and_then(|n| n.address_url("0xabcdef123456"))
            .expect("base address url");
        assert!(url.contains("basescan.org"));
        assert!(url.contains("/address/0xabcdef123456"));
    }

    #[test]
    fn test_wallet_link_solana_plain_text_when_not_tty() {
        let link = wallet_link("5xyzABC", "Solana");
        assert_eq!(link, "5xyzABC");
    }

    #[test]
    fn test_wallet_link_solana_uses_solana_url_lookup() {
        let url = purl_lib::network::get_network("solana")
            .and_then(|n| n.address_url("5xyzABC"))
            .expect("solana wallet url");
        assert!(url.contains("solscan.io"));
        assert!(url.contains("/account/5xyzABC"));
    }

    #[test]
    fn test_wallet_link_unknown_chain() {
        let link = wallet_link("0x123", "Unknown");
        assert_eq!(link, "0x123");
    }

    #[test]
    fn test_wallet_link_tempo_plain_text_when_not_tty() {
        let link = wallet_link("0xa0d741ac1dc1a173c2f523f543b1b6325d4da8ca", "Tempo");
        assert_eq!(link, "0xa0d741ac1dc1a173c2f523f543b1b6325d4da8ca");
    }

    #[test]
    fn test_wallet_link_tempo_uses_tempo_url_lookup() {
        let url = purl_lib::network::get_network("tempo")
            .and_then(|n| n.address_url("0xa0d741ac1dc1a173c2f523f543b1b6325d4da8ca"))
            .expect("tempo address url");
        assert!(url.contains("explore.tempo.xyz"));
        assert!(url.contains("/address/0xa0d741ac1dc1a173c2f523f543b1b6325d4da8ca"));
    }

    #[test]
    fn test_tempo_address_link_plain_text_when_not_tty() {
        let link = address_link("0xa0d741ac1dc1a173c2f523f543b1b6325d4da8ca", "tempo");
        assert_eq!(link, "0xa0d741ac1dc1a173c2f523f543b1b6325d4da8ca");
    }

    #[test]
    fn test_tempo_address_url_lookup() {
        let url = purl_lib::network::get_network("tempo")
            .and_then(|n| n.address_url("0xa0d741ac1dc1a173c2f523f543b1b6325d4da8ca"))
            .expect("tempo address url");
        assert!(url.contains("explore.tempo.xyz"));
        assert!(url.contains("/address/0xa0d741ac1dc1a173c2f523f543b1b6325d4da8ca"));
    }

    #[test]
    fn test_tempo_tx_link_plain_text_when_not_tty() {
        let link = tx_link("0x123abc", "tempo");
        assert_eq!(link, "0x123abc");
    }

    #[test]
    fn test_tempo_tx_url_lookup() {
        let url = purl_lib::network::get_network("tempo")
            .and_then(|n| n.tx_url("0x123abc"))
            .expect("tempo tx url");
        assert!(url.contains("explore.tempo.xyz"));
        assert!(url.contains("/tx/0x123abc"));
    }
}
