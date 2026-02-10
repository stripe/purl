//! Output formatting and display utilities for the CLI

use anyhow::{Context, Result};
use purl_lib::HttpResponse;
use serde_json::json;
use std::path::PathBuf;

use crate::cli::{Cli, OutputFormat};

/// Handle a regular (non-402) HTTP response
pub fn handle_regular_response(cli: &Cli, response: HttpResponse) -> Result<()> {
    let format = cli.output_format.resolve();

    match format {
        OutputFormat::Auto => unreachable!("Auto should be resolved"),
        OutputFormat::Json => {
            if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(&response.body) {
                let output = serde_json::to_string_pretty(&json_value)?;
                write_output(cli, output)?;
            } else {
                output_response_body(cli, &response.body)?;
            }
        }
        OutputFormat::Yaml => {
            if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(&response.body) {
                let output = serde_yaml::to_string(&json_value)?;
                write_output(cli, output)?;
            } else {
                output_response_body(cli, &response.body)?;
            }
        }
        OutputFormat::Text => {
            if cli.include_headers || cli.head_only {
                println!("HTTP {}", response.status_code);
                for (name, value) in &response.headers {
                    println!("{name}: {value}");
                }
                println!();
            }

            if !cli.head_only {
                output_response_body(cli, &response.body)?;
            }
        }
    }

    Ok(())
}

/// Write response body to file or stdout
pub fn output_response_body(cli: &Cli, body: &[u8]) -> Result<()> {
    if let Some(output_file) = &cli.output {
        std::fs::write(output_file, body).context("Failed to write output file")?;
        if cli.is_verbose() && cli.should_show_output() {
            eprintln!("Saved to: {output_file}");
        }
    } else {
        use std::io::Write;
        let mut stdout = std::io::stdout();
        stdout
            .write_all(body)
            .context("Failed to write response to stdout")?;
        stdout.write_all(b"\n").context("Failed to write newline")?;
    }
    Ok(())
}

/// Write string output to file or stdout based on CLI options
pub fn write_output(cli: &Cli, content: impl AsRef<str>) -> Result<()> {
    let content = content.as_ref();
    if let Some(output_file) = &cli.output {
        std::fs::write(output_file, content).context("Failed to write output file")?;
        if cli.is_verbose() && cli.should_show_output() {
            eprintln!("Saved to: {output_file}");
        }
    } else {
        println!("{content}");
    }
    Ok(())
}

// ==================== Config Display Helpers ====================

/// Decrypted private keys holder
pub struct DecryptedKeys {
    pub evm_private_key: Option<String>,
    pub solana_private_key: Option<String>,
}

/// Decrypt all keystores upfront before displaying
pub fn decrypt_keystores_upfront(config: &purl_lib::Config) -> Result<DecryptedKeys> {
    let mut evm_private_key = None;
    let mut solana_private_key = None;

    if let Some(evm) = &config.evm {
        if let Some(keystore) = &evm.keystore {
            if let Ok(private_key_bytes) = purl_lib::keystore::decrypt_keystore(keystore, None) {
                evm_private_key = Some(hex::encode(&private_key_bytes));
            }
        }
    }

    if let Some(solana) = &config.solana {
        if let Some(keystore) = &solana.keystore {
            if let Ok(keypair_bytes) = purl_lib::keystore::decrypt_solana_keystore(keystore, None) {
                solana_private_key = Some(bs58::encode(&keypair_bytes).into_string());
            }
        }
    }

    Ok(DecryptedKeys {
        evm_private_key,
        solana_private_key,
    })
}

/// Helper to build payment method display object
pub fn build_payment_method_display(
    keystore: Option<&PathBuf>,
    identifier: &str,
    identifier_key: &str,
    private_key: Option<&String>,
    show_private_keys: bool,
) -> serde_json::Map<String, serde_json::Value> {
    let mut obj = serde_json::Map::new();
    obj.insert(identifier_key.to_string(), json!(identifier));

    if let Some(keystore_path) = keystore {
        obj.insert(
            "keystore".to_string(),
            json!(keystore_path.display().to_string()),
        );
    }

    if show_private_keys {
        if let Some(key) = private_key {
            obj.insert("private_key".to_string(), json!(key));
        }
    }

    obj
}

/// Build configuration display data for all output formats
pub fn build_config_display(
    config: &purl_lib::Config,
    config_path: &std::path::Path,
    show_private_keys: bool,
    decrypted_keys: Option<&DecryptedKeys>,
) -> serde_json::Value {
    use purl_lib::WalletConfig;

    json!({
        "config_path": config_path.display().to_string(),
        "evm": config.evm.as_ref().and_then(|evm| {
            evm.get_address().ok().map(|address| {
                build_payment_method_display(
                    evm.keystore.as_ref(),
                    &address,
                    "address",
                    decrypted_keys.and_then(|k| k.evm_private_key.as_ref()),
                    show_private_keys,
                )
            })
        }),
        "solana": config.solana.as_ref().and_then(|solana| {
            solana.get_address().ok().map(|pubkey| {
                build_payment_method_display(
                    solana.keystore.as_ref(),
                    &pubkey,
                    "public_key",
                    decrypted_keys.and_then(|k| k.solana_private_key.as_ref()),
                    show_private_keys,
                )
            })
        })
    })
}

/// Helper to print payment method configuration in text format
pub fn print_payment_method_text(
    section_name: &str,
    keystore: Option<&PathBuf>,
    identifier: Option<&str>,
    identifier_key: &str,
    private_key: Option<&str>,
    show_private_keys: bool,
) {
    println!("[{section_name}]");

    if let Some(keystore_path) = keystore {
        println!("keystore = \"{}\"", keystore_path.display());
    }

    if let Some(id) = identifier {
        println!("{identifier_key} = \"{id}\"");
    }

    if show_private_keys {
        if let Some(key) = private_key {
            println!("private_key = \"{key}\"");
        }
    }

    println!();
}
