//! Utility functions for purl library

/// Format an Ethereum address with 0x prefix
pub fn format_eth_address(addr: &str) -> String {
    if addr.starts_with("0x") || addr.starts_with("0X") {
        addr.to_string()
    } else {
        format!("0x{addr}")
    }
}

/// Strip 0x prefix from hex string if present
pub fn strip_0x_prefix(s: &str) -> &str {
    s.trim()
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_eth_address() {
        assert_eq!(format_eth_address("abc123"), "0xabc123");
        assert_eq!(format_eth_address("0xabc123"), "0xabc123");
        assert_eq!(format_eth_address("0Xabc123"), "0Xabc123");
    }

    #[test]
    fn test_strip_0x_prefix() {
        assert_eq!(strip_0x_prefix("0xabc123"), "abc123");
        assert_eq!(strip_0x_prefix("0Xabc123"), "abc123");
        assert_eq!(strip_0x_prefix("abc123"), "abc123");
        assert_eq!(strip_0x_prefix(" 0xabc123 "), "abc123");
    }
}
