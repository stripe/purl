use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Parser, Subcommand, ValueEnum};
use http::header::HeaderName;
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;

/// Custom styles for CLI help output - green headers like our abridged help
fn styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
        .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
        .literal(AnsiColor::Cyan.on_default())
        .placeholder(AnsiColor::Yellow.on_default())
}

/// Output format for CLI commands.
///
/// - `Auto`: Automatically detect based on terminal (text for TTY, JSON for pipes)
/// - `Text`: Human-readable text output
/// - `Json`: JSON output for scripting and agents
/// - `Yaml`: YAML output
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize, Default)]
pub enum OutputFormat {
    /// Auto-detect: JSON if piped, text if terminal
    #[default]
    Auto,
    /// Human-readable text output
    Text,
    /// JSON output for scripting
    Json,
    /// YAML output
    Yaml,
}

impl OutputFormat {
    /// Resolve `Auto` to a concrete format based on terminal detection.
    ///
    /// Returns `Text` if stdout is a terminal (interactive use),
    /// returns `Json` if stdout is not a terminal (piped/scripted use).
    pub fn resolve(self) -> Self {
        match self {
            OutputFormat::Auto => {
                if std::io::stdout().is_terminal() {
                    OutputFormat::Text
                } else {
                    OutputFormat::Json
                }
            }
            other => other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Parser, Debug)]
#[command(name = "purl")]
#[command(about = "A curl-like tool for HTTP-based payment requests", long_about = None)]
#[command(version)]
#[command(styles = styles())]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// URL to request
    #[arg(value_name = "URL")]
    pub url: Option<String>,

    /// Configuration file path
    #[arg(short = 'C', long = "config", value_name = "PATH", global = true)]
    pub config: Option<String>,

    // Payment Options
    /// Maximum amount willing to pay (in atomic units)
    #[arg(
        long,
        value_name = "AMOUNT",
        env = "PURL_MAX_AMOUNT",
        help_heading = "Payment Options"
    )]
    pub max_amount: Option<String>,

    /// Require confirmation before paying
    #[arg(long, env = "PURL_CONFIRM", help_heading = "Payment Options")]
    pub confirm: bool,

    /// Filter to specific networks (comma-separated, e.g. "base,base-sepolia")
    #[arg(
        long,
        value_name = "NETWORKS",
        env = "PURL_NETWORK",
        help_heading = "Payment Options"
    )]
    pub network: Option<String>,

    /// Dry run mode - show what would be paid without executing
    #[arg(long, help_heading = "Payment Options")]
    pub dry_run: bool,

    // Display Options
    /// Verbosity level (can be used multiple times: -v, -vv, -vvv)
    #[arg(short = 'v', long = "verbosity", action = clap::ArgAction::Count, global = true, help_heading = "Display Options")]
    pub verbosity: u8,

    /// Control color output
    #[arg(
        long,
        value_name = "MODE",
        default_value = "auto",
        global = true,
        help_heading = "Display Options"
    )]
    pub color: ColorMode,

    /// Do not print log messages (aliases: -s, --silent)
    #[arg(
        short = 'q',
        long = "quiet",
        visible_short_alias = 's',
        visible_alias = "silent",
        global = true,
        help_heading = "Display Options"
    )]
    pub quiet: bool,

    /// Include HTTP headers in output
    #[arg(short = 'i', long = "include", help_heading = "Display Options")]
    pub include_headers: bool,

    /// Show only HTTP headers
    #[arg(short = 'I', long = "head", help_heading = "Display Options")]
    pub head_only: bool,

    /// Output format for response (auto detects: text for terminal, json for pipes)
    #[arg(
        long,
        value_name = "FORMAT",
        default_value = "auto",
        help_heading = "Display Options"
    )]
    pub output_format: OutputFormat,

    /// Write output to file
    #[arg(
        short = 'o',
        long = "output",
        value_name = "FILE",
        help_heading = "Display Options"
    )]
    pub output: Option<String>,

    // HTTP Options
    /// Custom request method
    #[arg(
        short = 'X',
        long = "request",
        value_name = "METHOD",
        help_heading = "HTTP Options"
    )]
    pub method: Option<String>,

    /// Add custom header
    #[arg(
        short = 'H',
        long = "header",
        value_name = "HEADER",
        help_heading = "HTTP Options"
    )]
    pub headers: Vec<String>,

    /// Set user agent
    #[arg(
        short = 'A',
        long = "user-agent",
        value_name = "AGENT",
        help_heading = "HTTP Options"
    )]
    pub user_agent: Option<String>,

    /// Follow redirects
    #[arg(short = 'L', long = "location", help_heading = "HTTP Options")]
    pub follow_redirects: bool,

    /// Connection timeout in seconds
    #[arg(
        long = "connect-timeout",
        value_name = "SECONDS",
        help_heading = "HTTP Options"
    )]
    pub connect_timeout: Option<u64>,

    /// Maximum time for the request
    #[arg(
        short = 'm',
        long = "max-time",
        value_name = "SECONDS",
        help_heading = "HTTP Options"
    )]
    pub max_time: Option<u64>,

    /// POST data
    #[arg(
        short = 'd',
        long = "data",
        value_name = "DATA",
        help_heading = "HTTP Options"
    )]
    pub data: Option<String>,

    /// Send JSON data with Content-Type header
    #[arg(long = "json", value_name = "JSON", help_heading = "HTTP Options")]
    pub json: Option<String>,

    // Wallet Options
    /// Path to wallet file
    #[arg(
        long = "wallet",
        alias = "keystore",
        value_name = "PATH",
        env = "PURL_KEYSTORE",
        help_heading = "Wallet Options"
    )]
    pub wallet: Option<String>,

    /// Password for wallet decryption
    #[arg(
        long = "password",
        value_name = "PASSWORD",
        env = "PURL_PASSWORD",
        help_heading = "Wallet Options"
    )]
    pub password: Option<String>,

    /// Raw private key (hex, for EVM; use wallet for better security)
    #[arg(
        long = "private-key",
        value_name = "KEY",
        help_heading = "Wallet Options"
    )]
    pub private_key: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    // === Setup Commands ===
    /// Manage configuration
    #[command(
        alias = "c",
        args_conflicts_with_subcommands = true,
        after_help = "\
Examples:
  purl config                          # Show current config
  purl config get evm.address          # Get specific value
  purl config validate                 # Check config is valid
  purl config --output-format json     # Output as JSON"
    )]
    Config {
        #[command(subcommand)]
        command: Option<ConfigCommands>,

        /// Output format for config display (when no subcommand is given)
        #[arg(long, value_name = "FORMAT", default_value = "text")]
        output_format: OutputFormat,
        /// Show private keys (when no subcommand is given)
        #[arg(long)]
        unsafe_show_private_keys: bool,
    },

    /// Manage wallets (keystores)
    #[command(
        alias = "w",
        after_help = "\
Examples:
  purl wallet add                      # Interactive wallet creation
  purl wallet add --type evm           # Skip type selection
  purl wallet add --type solana -k KEY # Import existing key
  purl wallet list                     # List all wallets
  purl wallet use my-wallet            # Switch active wallet
  purl wallet verify my-wallet         # Check wallet integrity
  purl wallet remove my-wallet         # Remove a wallet"
    )]
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },

    // === Payment Commands ===
    /// Check wallet balance
    #[command(
        alias = "b",
        after_help = "\
Examples:
  purl balance                         # Check all balances
  purl balance --network base          # Check Base network only
  purl balance 0x1234...               # Check specific address"
    )]
    Balance {
        /// Check balance for specific address (defaults to configured addresses)
        address: Option<String>,
        /// Filter to specific network
        #[arg(long = "network", short = 'n')]
        network: Option<String>,
    },

    /// Inspect payment requirements without executing payment
    #[command(after_help = "\
Examples:
  purl inspect https://api.example.com/endpoint
  purl inspect https://api.example.com/endpoint --output-format json")]
    Inspect {
        /// URL to inspect
        url: String,
    },

    // === Info Commands ===
    /// Manage and inspect supported networks
    #[command(
        alias = "n",
        args_conflicts_with_subcommands = true,
        after_help = "\
Examples:
  purl networks                        # List all networks
  purl networks list                   # Same as above
  purl networks info base              # Show details for Base
  purl networks --output-format json   # Output as JSON"
    )]
    Networks {
        #[command(subcommand)]
        command: Option<NetworkCommands>,
        /// Output format (when no subcommand is given, same as 'networks list')
        #[arg(long, value_name = "FORMAT", default_value = "text")]
        output_format: OutputFormat,
    },

    /// Show version information
    #[command(alias = "v")]
    Version,

    /// Generate shell completions script
    #[command(
        alias = "com",
        after_help = "\
Examples:
  purl completions bash >> ~/.bashrc
  purl completions zsh >> ~/.zshrc
  purl completions fish > ~/.config/fish/completions/purl.fish"
    )]
    Completions {
        /// The shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Display help topics (exit-codes, formatting, examples, environment)
    #[command(
        alias = "topic",
        after_help = "\
Examples:
  purl topics                          # List all topics
  purl topics exit-codes               # View exit code docs
  purl topics examples                 # Common usage examples"
    )]
    Topics {
        /// Topic to display (exit-codes, formatting, examples, environment)
        topic: Option<String>,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

/// Wallet type for creation
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum WalletType {
    /// EVM-compatible wallet (Ethereum, Base, Polygon, etc.)
    Evm,
    /// Solana wallet
    Solana,
}

#[derive(Subcommand, Debug)]
pub enum WalletCommands {
    /// List available wallets
    List,
    /// Create a new wallet (interactive)
    #[command(alias = "create")]
    Add {
        /// Name for the wallet
        #[arg(short = 'n', long)]
        name: Option<String>,
        /// Wallet type (evm or solana)
        #[arg(short = 't', long, value_enum)]
        wallet_type: Option<WalletType>,
        /// Private key to import (hex for EVM, base58 for Solana)
        #[arg(short = 'k', long)]
        private_key: Option<String>,
    },
    /// Show wallet details
    Show {
        /// Name of the wallet (without .json extension)
        name: String,
    },
    /// Verify wallet integrity
    Verify {
        /// Name of the wallet (without .json extension)
        name: String,
    },
    /// Set a wallet as the active payment method
    Use {
        /// Name of the wallet (without .json extension)
        name: String,
    },
    /// Remove a wallet
    Remove {
        /// Name of the wallet (without .json extension)
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Get a specific configuration value
    Get {
        /// Configuration key (supports dot notation, e.g., "evm.address")
        key: String,
        /// Output format
        #[arg(long, value_name = "FORMAT", default_value = "text")]
        output_format: OutputFormat,
    },
    /// Validate configuration file
    Validate,
}

#[derive(Subcommand, Debug)]
pub enum NetworkCommands {
    /// List all supported networks
    List {
        /// Output format
        #[arg(long, value_name = "FORMAT", default_value = "text")]
        output_format: OutputFormat,
    },
    /// Show detailed information about a network
    Info {
        /// Network name (e.g., "base", "ethereum", "solana")
        network: String,
        /// Output format
        #[arg(long, value_name = "FORMAT", default_value = "text")]
        output_format: OutputFormat,
    },
}

/// Validate an HTTP header name.
/// Header names must conform to the HTTP specification (RFC 7230).
/// This includes characters from the 'tchar' set: alphanumerics and the following special characters:
/// ! # $ % & ' * + - . ^ _ ` | ~
fn validate_header_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Header name cannot be empty".to_string());
    }

    // Use the http crate's HeaderName parser which properly validates
    // according to the HTTP spec (RFC 7230)
    HeaderName::from_bytes(name.as_bytes())
        .map(|_| ())
        .map_err(|e| format!("Invalid header name '{}': {}", name, e))
}

/// Validate an HTTP header value.
/// Header values must not contain CR, LF, or NUL characters to prevent header injection.
fn validate_header_value(value: &str) -> Result<(), String> {
    for c in value.chars() {
        match c {
            '\r' => return Err("Header value cannot contain carriage return (\\r)".to_string()),
            '\n' => return Err("Header value cannot contain newline (\\n)".to_string()),
            '\0' => return Err("Header value cannot contain null character".to_string()),
            _ => {}
        }
    }
    Ok(())
}

impl Cli {
    /// Parse custom headers into (name, value) tuples with validation.
    ///
    /// # Errors
    /// Returns an error if any header name or value is invalid.
    pub fn parse_headers(&self) -> Result<Vec<(String, String)>, String> {
        let mut headers = Vec::new();
        for h in &self.headers {
            let (name, value) = h
                .split_once(':')
                .ok_or_else(|| format!("Invalid header format '{}'. Expected 'Name: Value'", h))?;

            let name = name.trim().to_string();
            let value = value.trim().to_string();

            validate_header_name(&name)?;
            validate_header_value(&value)?;

            headers.push((name, value));
        }
        Ok(headers)
    }

    /// Get the effective timeout
    pub fn get_timeout(&self) -> Option<u64> {
        self.max_time.or(self.connect_timeout)
    }

    /// Parse allowed networks from the --network flag
    pub fn allowed_networks(&self) -> Option<Vec<String>> {
        self.network
            .as_ref()
            .map(|nets| nets.split(',').map(|s| s.trim().to_string()).collect())
    }

    /// Check if verbose output is enabled
    pub fn is_verbose(&self) -> bool {
        self.verbosity >= 1
    }

    /// Check if output should be shown (not quiet)
    pub fn should_show_output(&self) -> bool {
        !self.quiet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_header_names() {
        assert!(validate_header_name("Content-Type").is_ok());
        assert!(validate_header_name("X-Custom-Header").is_ok());
        assert!(validate_header_name("Accept").is_ok());
        assert!(validate_header_name("X_Custom_123").is_ok());

        // Test additional tchar characters allowed by HTTP spec
        assert!(validate_header_name("X-Custom.Header").is_ok()); // dot
        assert!(validate_header_name("X+Custom+Header").is_ok()); // plus
        assert!(validate_header_name("X!Header").is_ok()); // exclamation
        assert!(validate_header_name("X#Header").is_ok()); // hash
        assert!(validate_header_name("X$Header").is_ok()); // dollar
        assert!(validate_header_name("X%Header").is_ok()); // percent
        assert!(validate_header_name("X&Header").is_ok()); // ampersand
        assert!(validate_header_name("X'Header").is_ok()); // apostrophe
        assert!(validate_header_name("X*Header").is_ok()); // asterisk
        assert!(validate_header_name("X^Header").is_ok()); // caret
        assert!(validate_header_name("X`Header").is_ok()); // backtick
        assert!(validate_header_name("X|Header").is_ok()); // pipe
        assert!(validate_header_name("X~Header").is_ok()); // tilde
    }

    #[test]
    fn test_invalid_header_names() {
        assert!(validate_header_name("").is_err());
        assert!(validate_header_name("Content Type").is_err()); // space
        assert!(validate_header_name("Header:Name").is_err()); // colon
        assert!(validate_header_name("Header\nName").is_err()); // newline
    }

    #[test]
    fn test_valid_header_values() {
        assert!(validate_header_value("application/json").is_ok());
        assert!(validate_header_value("Bearer token123").is_ok());
        assert!(validate_header_value("value with spaces").is_ok());
        assert!(validate_header_value("special chars: !@#$%").is_ok());
    }

    #[test]
    fn test_invalid_header_values() {
        assert!(validate_header_value("value\r\ninjected").is_err());
        assert!(validate_header_value("value\ninjected").is_err());
        assert!(validate_header_value("value\rinjected").is_err());
        assert!(validate_header_value("value\0null").is_err());
    }
}
