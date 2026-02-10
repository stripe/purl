use crate::cli::{Cli, OutputFormat};
use crate::config_utils::load_config;
use anyhow::{Context, Result};
use purl_lib::{Config, WalletConfig};
use std::path::PathBuf;

/// Get a specific configuration value by key
pub fn get_command(cli: &Cli, key: &str, output_format: OutputFormat) -> Result<()> {
    let config = load_config(cli.config.as_ref())?;
    let config_path = if let Some(ref path) = cli.config {
        PathBuf::from(path)
    } else {
        Config::default_config_path()?
    };

    let output_value = match key {
        "evm.address" => {
            let addr = config
                .require_evm()
                .context("EVM configuration not found")?
                .get_address()
                .context("Failed to get EVM address")?;
            serde_json::Value::String(addr)
        }
        "solana.public_key" | "solana.pubkey" => {
            let pubkey = config
                .require_solana()
                .context("Solana configuration not found")?
                .get_address()
                .context("Failed to get Solana public key")?;
            serde_json::Value::String(pubkey)
        }
        _ => {
            // Read the raw TOML file to access nested keys
            let toml_content = std::fs::read_to_string(&config_path)
                .context("Failed to read configuration file")?;
            let toml_value: toml::Value =
                toml::from_str(&toml_content).context("Failed to parse TOML configuration")?;

            // Split the key by dots to navigate nested structure
            let parts: Vec<&str> = key.split('.').collect();
            let mut current_value = &toml_value;

            // Navigate through the nested structure
            for part in &parts {
                match current_value.get(part) {
                    Some(value) => current_value = value,
                    None => {
                        anyhow::bail!("Key '{key}' not found in configuration");
                    }
                }
            }

            toml_value_to_json(current_value)
        }
    };

    let format = output_format.resolve();

    match format {
        OutputFormat::Auto => unreachable!("Auto should be resolved"),
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&output_value)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&output_value)?);
        }
        OutputFormat::Text => {
            print_value_as_text(&output_value);
        }
    }

    Ok(())
}

/// Validate the configuration file
pub fn validate_command(cli: &Cli) -> Result<()> {
    let config_path = cli
        .config
        .as_ref()
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(Config::default_config_path)?;

    if !config_path.exists() {
        anyhow::bail!("Configuration file not found: {}", config_path.display());
    }

    let toml_content =
        std::fs::read_to_string(&config_path).context("Failed to read configuration file")?;
    let _: toml::Value = toml::from_str(&toml_content).context("Invalid TOML syntax")?;

    let config = load_config(cli.config.as_ref())?;

    if let Err(e) = config.validate() {
        println!("Configuration validation failed:");
        println!("  - {e}");
        anyhow::bail!("Configuration validation failed");
    }

    let available_methods = config.available_payment_methods();

    if available_methods.is_empty() {
        println!("No payment methods configured");
        anyhow::bail!("Configuration validation failed: no payment methods");
    }

    println!("Configuration is valid: {}", config_path.display());
    for method in &available_methods {
        let status = match method {
            purl_lib::PaymentMethod::Evm => config
                .evm
                .as_ref()
                .and_then(|evm| evm.get_address().ok())
                .map(|addr| format!("OK ({addr})"))
                .unwrap_or_else(|| "configured".to_string()),
            purl_lib::PaymentMethod::Solana => config
                .solana
                .as_ref()
                .and_then(|sol| sol.get_address().ok())
                .map(|addr| format!("OK ({addr})"))
                .unwrap_or_else(|| "configured".to_string()),
        };
        println!("{} configuration: {}", method.as_str(), status);
    }

    Ok(())
}

/// Convert TOML value to JSON value
fn toml_value_to_json(toml: &toml::Value) -> serde_json::Value {
    match toml {
        toml::Value::String(s) => serde_json::Value::String(s.clone()),
        toml::Value::Integer(i) => serde_json::Value::Number((*i).into()),
        toml::Value::Float(f) => serde_json::Value::Number(
            serde_json::Number::from_f64(*f).unwrap_or(serde_json::Number::from(0)),
        ),
        toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
        toml::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(toml_value_to_json).collect())
        }
        toml::Value::Table(table) => {
            let mut map = serde_json::Map::new();
            for (key, value) in table {
                map.insert(key.clone(), toml_value_to_json(value));
            }
            serde_json::Value::Object(map)
        }
        toml::Value::Datetime(dt) => serde_json::Value::String(dt.to_string()),
    }
}

/// Print a JSON value as plain text
fn print_value_as_text(value: &serde_json::Value) {
    match value {
        serde_json::Value::String(s) => println!("{s}"),
        serde_json::Value::Number(n) => println!("{n}"),
        serde_json::Value::Bool(b) => println!("{b}"),
        serde_json::Value::Null => println!("null"),
        serde_json::Value::Array(arr) => {
            for item in arr {
                print_value_as_text(item);
            }
        }
        serde_json::Value::Object(obj) => {
            for (key, val) in obj {
                match val {
                    serde_json::Value::String(s) => println!("{key} = \"{s}\""),
                    serde_json::Value::Number(n) => println!("{key} = {n}"),
                    serde_json::Value::Bool(b) => println!("{key} = {b}"),
                    _ => println!(
                        "{} = {}",
                        key,
                        serde_json::to_string_pretty(val).unwrap_or_default()
                    ),
                }
            }
        }
    }
}
