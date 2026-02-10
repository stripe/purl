//! Help topics for the purl CLI.
//!
//! Provides detailed documentation accessible via `purl help <topic>`.

use std::collections::HashMap;

/// Available help topics and their content.
pub fn get_topics() -> HashMap<&'static str, &'static str> {
    let mut topics = HashMap::new();

    topics.insert("exit-codes", EXIT_CODES_TOPIC);
    topics.insert("formatting", FORMATTING_TOPIC);
    topics.insert("examples", EXAMPLES_TOPIC);
    topics.insert("environment", ENVIRONMENT_TOPIC);

    topics
}

/// Get a specific help topic by name.
pub fn get_topic(name: &str) -> Option<&'static str> {
    get_topics().get(name).copied()
}

/// List all available help topics.
pub fn list_topics() {
    println!("Available help topics:\n");
    println!("  exit-codes    Exit codes used by purl");
    println!("  formatting    Output format options (JSON, YAML, text)");
    println!("  examples      Common usage examples");
    println!("  environment   Environment variables");
    println!();
    println!("Use 'purl help <topic>' to view a topic.");
}

const EXIT_CODES_TOPIC: &str = r#"
EXIT CODES

purl uses the following exit codes:

  0   Success
  1   General/unknown error
  2   Invalid usage (bad arguments, invalid flags)
  3   Configuration error (missing config, invalid config)
  4   Network/connection error
  5   Payment declined or failed
  6   Insufficient funds for payment
  7   User cancelled operation
  8   Authentication/signing error
  9   Resource not found (network, wallet, etc.)
  10  Operation timed out
  130 Interrupted by signal (Ctrl+C)

SCRIPTING EXAMPLES

Check exit code in shell:

  purl https://example.com/api || {
      case $? in
          3) echo "Config issue - run 'purl wallet add'" ;;
          6) echo "Need more funds" ;;
          *) echo "Request failed" ;;
      esac
  }

Conditional execution:

  if purl --dry-run https://example.com/api; then
      echo "Payment would succeed"
  fi
"#;

const FORMATTING_TOPIC: &str = r#"
OUTPUT FORMATS

purl supports multiple output formats for different use cases.

FORMAT OPTIONS

  --output-format auto    Auto-detect: JSON if piped, text if terminal (default)
  --output-format text    Human-readable text output
  --output-format json    JSON output for scripting
  --output-format yaml    YAML output

AUTO-DETECTION

When using --output-format auto (the default):
- Interactive terminal: Uses human-readable text format
- Piped to another command: Uses JSON format

Examples:
  purl networks list              # Text output (interactive)
  purl networks list | jq '.'     # JSON output (piped)

EXAMPLES

  # Get just the address from config
  purl config get evm.address --output-format json

  # List networks as JSON for scripting
  purl networks list --output-format json | jq '.[] | .name'

  # Get YAML output
  purl networks info base --output-format yaml
"#;

const EXAMPLES_TOPIC: &str = r#"
COMMON EXAMPLES

GETTING STARTED

  # Create a new wallet
  purl wallet add

  # Check your wallet balance
  purl balance

  # List supported networks
  purl networks list

MAKING REQUESTS

  # Simple GET request (payment handled automatically)
  purl https://api.example.com/paid-endpoint

  # POST request with JSON data
  purl https://api.example.com/data --json '{"key": "value"}'

  # Inspect payment requirements without paying
  purl inspect https://api.example.com/paid-endpoint

  # Dry run to see what would happen
  purl --dry-run https://api.example.com/paid-endpoint

  # Set maximum amount willing to pay
  purl --max-amount 1000000 https://api.example.com/endpoint

WALLET MANAGEMENT

  # Create or import a wallet interactively
  purl wallet add

  # List available wallets
  purl wallet list

  # Switch active wallet
  purl wallet use my-wallet

  # Show wallet details
  purl wallet show --name my-wallet

  # Verify wallet integrity
  purl wallet verify my-wallet

SCRIPTING

  # Check if endpoint requires payment
  purl inspect https://api.example.com/endpoint --output-format json

  # Get balance as JSON for scripts
  purl balance --output-format json

  # Filter to specific network
  purl --network base https://api.example.com/endpoint
"#;

const ENVIRONMENT_TOPIC: &str = r#"
ENVIRONMENT VARIABLES

purl respects the following environment variables:

CONFIGURATION

  PURL_KEYSTORE      Path to wallet file
  PURL_PASSWORD      Password for wallet decryption
  PURL_MAX_AMOUNT    Maximum amount willing to pay (atomic units)
  PURL_CONFIRM       Require confirmation before paying (set to any value)
  PURL_NETWORK       Filter to specific networks (comma-separated)

DISPLAY

  NO_COLOR           Disable color output when set (any value)
  TERM               Used to detect terminal capabilities

EXAMPLES

Set max amount for all requests:
  export PURL_MAX_AMOUNT=1000000
  purl https://api.example.com/endpoint

Use specific wallet:
  PURL_KEYSTORE=~/.purl/keystores/work.json purl https://api.example.com

Disable colors:
  NO_COLOR=1 purl balance
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_topics() {
        let topics = get_topics();
        assert!(topics.contains_key("exit-codes"));
        assert!(topics.contains_key("formatting"));
        assert!(topics.contains_key("examples"));
        assert!(topics.contains_key("environment"));
    }

    #[test]
    fn test_get_topic() {
        assert!(get_topic("exit-codes").is_some());
        assert!(get_topic("unknown").is_none());
    }

    #[test]
    fn test_topic_content() {
        let exit_codes = get_topic("exit-codes").unwrap();
        assert!(exit_codes.contains("130"));
        assert!(exit_codes.contains("Ctrl+C"));
    }
}
