//! Semantic color helpers for consistent CLI output.
//!
//! This module provides a consistent color scheme across all CLI output.
//! Colors are semantic - they convey meaning rather than just decoration.

use colored::{ColoredString, Colorize};

/// Semantic color helpers for consistent CLI output.
///
/// # Color Scheme
///
/// | Element | Color | Usage |
/// |---------|-------|-------|
/// | Success | Green | Successful operations, amounts |
/// | Error | Red | Error messages, failures |
/// | Warning | Yellow | Warnings, wallet addresses |
/// | Info | Cyan | Hints, commands to run |
/// | Network | Magenta | Network names |
/// | Path | Blue | File paths |
/// | Key | White+Bold | Labels, config keys |
/// | Dim | Dimmed | Secondary info, timestamps |
#[allow(dead_code)]
pub struct Colors;

#[allow(dead_code)]
impl Colors {
    // === Status Colors ===

    /// Green - for success messages and positive outcomes
    pub fn success(s: &str) -> ColoredString {
        s.green()
    }

    /// Red - for error messages and failures
    pub fn error(s: &str) -> ColoredString {
        s.red()
    }

    /// Yellow - for warnings and cautions
    pub fn warning(s: &str) -> ColoredString {
        s.yellow()
    }

    /// Cyan - for informational messages and hints
    pub fn info(s: &str) -> ColoredString {
        s.cyan()
    }

    // === Semantic Colors ===

    /// Cyan+Bold - for commands the user should run
    pub fn command(s: &str) -> ColoredString {
        s.cyan().bold()
    }

    /// Blue - for file and directory paths
    pub fn path(s: &str) -> ColoredString {
        s.blue()
    }

    /// Yellow - for wallet addresses (EVM, Solana)
    pub fn address(s: &str) -> ColoredString {
        s.yellow()
    }

    /// Green - for token/currency amounts
    pub fn amount(s: &str) -> ColoredString {
        s.green()
    }

    /// Magenta - for network names (base, ethereum, solana)
    pub fn network(s: &str) -> ColoredString {
        s.magenta()
    }

    /// White+Bold - for labels and config keys
    pub fn key(s: &str) -> ColoredString {
        s.white().bold()
    }

    /// White - for config values
    pub fn value(s: &str) -> ColoredString {
        s.white()
    }

    /// Dimmed - for less important/secondary information
    pub fn dim(s: &str) -> ColoredString {
        s.dimmed()
    }

    // === Status Markers ===

    /// Green [active] marker for active keystores/configs
    pub fn active_marker() -> ColoredString {
        "[active]".green()
    }

    /// Raw [active] string (for use with table formatters)
    pub fn active_marker_str() -> &'static str {
        "[active]"
    }

    /// Green [OK] marker for verification success
    pub fn ok_marker() -> ColoredString {
        "[OK]".green()
    }

    /// Red [FAIL] marker for verification failure
    pub fn fail_marker() -> ColoredString {
        "[FAIL]".red()
    }

    /// Yellow [WARN] marker for warnings
    pub fn warn_marker() -> ColoredString {
        "[WARN]".yellow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_markers() {
        // Just ensure these don't panic
        let _ = Colors::active_marker();
        let _ = Colors::ok_marker();
        let _ = Colors::fail_marker();
        let _ = Colors::warn_marker();
    }

    #[test]
    fn test_semantic_colors() {
        // Ensure color functions work without panic
        let _ = Colors::success("test");
        let _ = Colors::error("test");
        let _ = Colors::warning("test");
        let _ = Colors::info("test");
        let _ = Colors::command("purl wallet add");
        let _ = Colors::path("/home/user/.purl");
        let _ = Colors::address("0x1234");
        let _ = Colors::amount("10.50 USDC");
        let _ = Colors::network("base");
        let _ = Colors::key("Address:");
        let _ = Colors::value("some value");
        let _ = Colors::dim("secondary info");
    }
}
