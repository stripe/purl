//! Wallet management commands for purl CLI

use crate::cli::WalletType;
use crate::colors::Colors;
use crate::hyperlink::{hyperlink, wallet_link};
use crate::table::Table;
use anyhow::{Context, Result};
use colored::Colorize;
use dialoguer::{Confirm, Input, Password, Select};
use purl_lib::keystore::{create_keystore, create_solana_keystore, list_keystores, Keystore};
use purl_lib::Config;
use solana_sdk::signature::{Keypair, Signer};
use std::path::PathBuf;

/// Create a clickable address link with shortened display text
fn short_address_link(address: &str, chain_type: &str) -> String {
    let short = if address.len() > 12 {
        format!("{}...{}", &address[..6], &address[address.len() - 4..])
    } else {
        address.to_string()
    };

    let network = match chain_type {
        "evm" | "EVM" => "base",
        "solana" | "Solana" => "solana",
        _ => return short,
    };

    if let Some(url) = purl_lib::network::get_network(network).and_then(|n| n.address_url(address))
    {
        hyperlink(&url, &short)
    } else {
        short
    }
}

/// List all available wallets in the wallets directory
///
/// Scans the default wallets directory (`~/.purl/keystores/`) and displays
/// all found wallet files along with their chain type, address/pubkey, and
/// whether they are currently active (configured in config.toml).
///
/// # Examples
///
/// ```text
/// $ purl wallet list
/// Wallets:
///
///   evm.json (evm: 0xabcd1234...)  [active]
///   test-wallet.json (evm: 0x5678efgh...)
///   solana.json (solana: 5xot9PVk...)  [active]
///
/// $ purl wallet list
/// No wallets found.
/// Create one with: purl wallet create
/// ```
///
/// # Errors
///
/// Returns an error if the wallets directory cannot be accessed.
pub fn list_command() -> Result<()> {
    let keystores = list_keystores()?;

    if keystores.is_empty() {
        println!("No wallets found.");
        println!("Create one with: purl wallet create");
        return Ok(());
    }

    // Load config to check which keystores are active
    let config = purl_lib::config::Config::load_unchecked(None::<&str>).ok();
    let active_evm_path = config
        .as_ref()
        .and_then(|c| c.evm.as_ref())
        .and_then(|e| e.keystore.as_ref())
        .and_then(|p| p.canonicalize().ok());
    let active_solana_path = config
        .as_ref()
        .and_then(|c| c.solana.as_ref())
        .and_then(|s| s.keystore.as_ref())
        .and_then(|p| p.canonicalize().ok());

    // Collect keystore info for table formatting
    struct KeystoreRow {
        filename: String,
        chain_type: String,
        display_identifier: String, // Shortened/linked version for display
        is_active: bool,
    }

    let mut rows: Vec<KeystoreRow> = Vec::new();

    for keystore_path in keystores {
        let filename = keystore_path
            .file_stem()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown")
            .to_string();

        let canonical_path = keystore_path.canonicalize().ok();

        // Try to read the keystore to get the address/pubkey and detect chain type
        if let Ok(content) = std::fs::read_to_string(&keystore_path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                // Detect chain type and get identifier
                let (chain_type, display_identifier) =
                    if let Some(address) = json["address"].as_str() {
                        let addr = if address.starts_with("0x") {
                            address.to_string()
                        } else {
                            format!("0x{address}")
                        };
                        let display = short_address_link(&addr, "evm");
                        ("evm".to_string(), display)
                    } else if let Some(pubkey) = json["public_key"].as_str() {
                        let display = short_address_link(pubkey, "solana");
                        ("solana".to_string(), display)
                    } else if json["keypair"].is_string() {
                        ("solana".to_string(), "keypair present".to_string())
                    } else {
                        ("unknown".to_string(), "no identifier".to_string())
                    };

                // Determine if this keystore is active
                let is_active = match chain_type.as_str() {
                    "evm" => canonical_path
                        .as_ref()
                        .map(|p| active_evm_path.as_ref() == Some(p))
                        .unwrap_or(false),
                    "solana" => canonical_path
                        .as_ref()
                        .map(|p| active_solana_path.as_ref() == Some(p))
                        .unwrap_or(false),
                    _ => false,
                };

                rows.push(KeystoreRow {
                    filename,
                    chain_type,
                    display_identifier,
                    is_active,
                });
            } else {
                rows.push(KeystoreRow {
                    filename,
                    chain_type: "?".to_string(),
                    display_identifier: "invalid format".to_string(),
                    is_active: false,
                });
            }
        } else {
            rows.push(KeystoreRow {
                filename,
                chain_type: "?".to_string(),
                display_identifier: "unreadable".to_string(),
                is_active: false,
            });
        }
    }

    // Build table
    println!("Wallets:");
    println!();

    let mut table = Table::new(&["Name", "Type", "Address", ""]);
    for row in &rows {
        let active_str = if row.is_active {
            Colors::active_marker_str()
        } else {
            ""
        };
        table.row(&[
            &row.filename,
            &row.chain_type,
            &row.display_identifier,
            active_str,
        ]);
    }

    table.print_with(|col, cell| match col {
        2 => cell.yellow(), // Address column
        3 => cell.green(),  // Active marker
        _ => cell.normal(),
    });

    Ok(())
}

/// Create or import a wallet interactively
///
/// This is the single entry point for wallet creation. It supports:
/// - Interactive type selection (EVM or Solana)
/// - Generating new keys or importing existing ones
/// - Setting the wallet as active
///
/// # Arguments
///
/// * `name` - Optional name for the wallet file. If None, user is prompted.
/// * `wallet_type` - Optional wallet type. If None, shows interactive picker.
/// * `private_key` - Optional private key to import. If None, asks generate vs import.
///
/// # Examples
///
/// ```text
/// $ purl wallet add
/// ? Wallet type:
///   > EVM (Ethereum, Base, Polygon, ...)
///     Solana
///
/// ? Create new or import existing?
///   > Generate new key
///     Import existing key
///
/// Enter password: ****
/// Confirm password: ****
///
/// Wallet name [evm]:
///
/// ✓ Wallet created: ~/.purl/keystores/evm.json
///   Address: 0x1234...5678
///
/// Set as active wallet? [Y/n]
/// ```
pub fn add_command(
    name: Option<String>,
    wallet_type: Option<WalletType>,
    private_key: Option<String>,
) -> Result<()> {
    // Step 1: Select wallet type
    let wallet_type = if let Some(t) = wallet_type {
        t
    } else {
        let options = vec![
            format!(
                "{} {}",
                "EVM".cyan(),
                "(Ethereum, Base, Polygon, ...)".dimmed()
            ),
            format!("{}", "Solana".cyan()),
        ];

        let selection = Select::new()
            .with_prompt("Wallet type")
            .items(&options)
            .default(0)
            .interact()?;

        match selection {
            0 => WalletType::Evm,
            _ => WalletType::Solana,
        }
    };

    // Step 2: Generate or import?
    let (is_generate, key_to_import) = if let Some(key) = private_key {
        (false, Some(key))
    } else {
        let options = vec!["Generate new key", "Import existing key"];

        let selection = Select::new()
            .with_prompt("Create new or import existing?")
            .items(&options)
            .default(0)
            .interact()?;

        if selection == 1 {
            // Import: prompt for key with validation, retry on error
            let prompt = match wallet_type {
                WalletType::Evm => "Enter private key (hex, with or without 0x prefix)",
                WalletType::Solana => "Enter private key (base58 encoded)",
            };

            let key = loop {
                let key: String = Password::new().with_prompt(prompt).interact()?;
                let key = key.trim().to_string();

                // Validate key format immediately
                let result = match wallet_type {
                    WalletType::Evm => purl_lib::crypto::validate_evm_key(&key),
                    WalletType::Solana => purl_lib::crypto::validate_solana_keypair(&key),
                };

                match result {
                    Ok(()) => break key,
                    Err(e) => {
                        eprintln!("{}", format!("Error: {e}").red());
                    }
                }
            };

            (false, Some(key))
        } else {
            (true, None)
        }
    };

    // Step 3: Generate key if needed
    let (private_key_value, display_info) = match wallet_type {
        WalletType::Evm => {
            let key = if is_generate {
                use alloy_signer_local::PrivateKeySigner;
                use rand::Rng;

                let mut rng = rand::rng();
                let key_bytes: [u8; 32] = rng.random();
                let key_hex = hex::encode(key_bytes);

                // Derive address from private key
                let address = key_hex
                    .parse::<PrivateKeySigner>()
                    .map(|s| format!("{:#x}", s.address()))
                    .unwrap_or_else(|_| "unknown".to_string());

                println!();
                println!(
                    "{} {}",
                    "Generated private key:".dimmed(),
                    format!("0x{key_hex}").green()
                );
                println!("{} {}", "Address:".dimmed(), address);
                println!(
                    "{}",
                    "Save this securely! You'll need it to recover your wallet.".yellow()
                );
                println!();

                key_hex
            } else {
                key_to_import.unwrap()
            };
            (key, "EVM")
        }
        WalletType::Solana => {
            let keypair_b58 = if is_generate {
                let (keypair_b58, pubkey_b58) = purl_lib::crypto::generate_solana_keypair();

                println!();
                println!(
                    "{} {}",
                    "Generated private key:".dimmed(),
                    keypair_b58.green()
                );
                println!("{} {}", "Address:".dimmed(), pubkey_b58);
                println!(
                    "{}",
                    "Save this securely! You'll need it to recover your wallet.".yellow()
                );
                println!();

                keypair_b58
            } else {
                key_to_import.unwrap()
            };
            (keypair_b58, "Solana")
        }
    };

    // Step 4: Password
    let password = Password::new()
        .with_prompt("Create password")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;

    // Step 5: Wallet name
    let default_name = match wallet_type {
        WalletType::Evm => "evm",
        WalletType::Solana => "solana",
    };

    let wallet_name = if let Some(n) = name {
        n
    } else {
        Input::new()
            .with_prompt("Wallet name")
            .default(default_name.to_string())
            .interact_text()?
    };

    // Step 6: Create keystore
    let keystore_path = match wallet_type {
        WalletType::Evm => create_keystore(&private_key_value, &password, &wallet_name)
            .context("Failed to create EVM wallet")?,
        WalletType::Solana => create_solana_keystore(&private_key_value, &password, &wallet_name)
            .context("Failed to create Solana wallet")?,
    };

    // Step 7: Create config file if it doesn't exist
    let config_path = Config::default_config_path()?;
    let mut config = Config::load_or_default(None::<&str>)?;

    // Display success
    println!();
    println!(
        "{} Wallet created: {}",
        "✓".green(),
        keystore_path.display().to_string().dimmed()
    );

    // Show address
    if let Ok(content) = std::fs::read_to_string(&keystore_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            let address = match wallet_type {
                WalletType::Evm => json["address"].as_str().map(|a| {
                    if a.starts_with("0x") {
                        a.to_string()
                    } else {
                        format!("0x{a}")
                    }
                }),
                WalletType::Solana => json["public_key"].as_str().map(|s| s.to_string()),
            };

            if let Some(addr) = address {
                let linked = wallet_link(&addr, display_info);
                println!("  Address: {}", linked.yellow());
            }
        }
    }

    println!();

    // Step 8: Ask to set as active
    let set_active = Confirm::new()
        .with_prompt("Set as active wallet?")
        .default(true)
        .interact()?;

    if set_active {
        match wallet_type {
            WalletType::Evm => {
                let evm_config = config.evm.get_or_insert_with(Default::default);
                evm_config.keystore = Some(keystore_path.clone());
            }
            WalletType::Solana => {
                let solana_config = config.solana.get_or_insert_with(Default::default);
                solana_config.keystore = Some(keystore_path.clone());
            }
        }

        config.save().context("Failed to save configuration")?;

        println!(
            "{} Set as active {} wallet",
            "✓".green(),
            display_info.cyan()
        );

        // Only mention config creation if it didn't exist before
        if !config_path.exists() {
            println!(
                "  Config saved to: {}",
                config_path.display().to_string().dimmed()
            );
        }
    }

    Ok(())
}

/// Helper function to find a wallet by name
fn find_keystore_by_name(name: &str) -> Result<PathBuf> {
    let keystores = list_keystores()?;

    // Try exact match with .json extension
    let name_with_json = format!("{name}.json");

    for keystore_path in keystores {
        if let Some(filename) = keystore_path.file_name().and_then(|f| f.to_str()) {
            if filename == name_with_json || filename == name {
                return Ok(keystore_path);
            }
        }
    }

    anyhow::bail!("Wallet '{name}' not found. Use 'purl wallet list' to see available wallets.")
}

/// Display wallet details without revealing the private key
///
/// Shows metadata about a wallet file including its address, creation date,
/// file size, and encryption details. This command does NOT require a password
/// and does NOT decrypt or display the private key.
///
/// # Arguments
///
/// * `name` - Name of the wallet to show (with or without .json extension)
///
/// # Examples
///
/// ```text
/// $ purl wallet show --name my-wallet
/// Wallet Details:
///
/// Name: my-wallet
/// Path: /home/user/.purl/keystores/my-wallet.json
/// Address: 0xabcd1234...
///   Created: SystemTime { ... }
///   Modified: SystemTime { ... }
///   Size: 491 bytes
/// Encryption: Standard Ethereum keystore format
/// Cipher: aes-128-ctr
/// KDF: scrypt
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The wallet with the given name is not found
/// - The wallet file cannot be read
/// - The wallet format is invalid
pub fn show_command(name: &str) -> Result<()> {
    let keystore_path = find_keystore_by_name(name)?;
    let keystore = Keystore::load(&keystore_path)?;

    println!("Wallet Details:");
    println!();
    println!("Name: {name}");
    println!("Path: {}", keystore_path.display());

    // Detect chain type from keystore content
    let chain_type = if keystore.content.get("address").is_some() {
        "EVM"
    } else if keystore.content.get("public_key").is_some()
        || keystore.content.get("keypair").is_some()
    {
        "Solana"
    } else {
        "unknown"
    };

    if let Some(address) = keystore.formatted_address() {
        let linked = wallet_link(&address, chain_type);
        println!("Address: {}", linked.yellow());
    } else {
        println!("Address: (not available)");
    }

    if let Ok(metadata) = std::fs::metadata(&keystore_path) {
        if let Ok(created) = metadata.created() {
            if let Ok(datetime) = created.duration_since(std::time::UNIX_EPOCH) {
                let secs = datetime.as_secs();
                // Simple date formatting (YYYY-MM-DD HH:MM:SS)
                use std::time::SystemTime;
                let system_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs);
                println!("  Created: {system_time:?}");
            }
        }

        if let Ok(modified) = metadata.modified() {
            if let Ok(datetime) = modified.duration_since(std::time::UNIX_EPOCH) {
                let secs = datetime.as_secs();
                use std::time::SystemTime;
                let system_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs);
                println!("  Modified: {system_time:?}");
            }
        }

        println!("  Size: {} bytes", metadata.len());
    }

    if keystore.content.get("crypto").is_some() {
        println!("Encryption: Standard Ethereum keystore format");

        if let Some(cipher) = keystore.content["crypto"]["cipher"].as_str() {
            println!("Cipher: {cipher}");
        }

        if let Some(kdf) = keystore.content["crypto"]["kdf"].as_str() {
            println!("KDF: {kdf}");
        }
    } else if keystore.content.get("Crypto").is_some() {
        println!("Encryption: Standard Ethereum keystore format (uppercase)");
    } else {
        println!("Encryption: Unknown format");
    }

    println!();

    Ok(())
}

/// Verify wallet integrity and password correctness
///
/// Performs a comprehensive verification of a wallet file by:
/// 1. Validating the wallet format and structure
/// 2. Checking that the address field is present
/// 3. Attempting to decrypt the wallet with the provided password
/// 4. Deriving the address from the decrypted private key
/// 5. Verifying that the derived address matches the stored address
///
/// This command requires the wallet password and will fail if the password
/// is incorrect or if the wallet is corrupted.
///
/// # Arguments
///
/// * `name` - Name of the wallet to verify (with or without .json extension)
///
/// # Examples
///
/// ```text
/// $ purl wallet verify --name my-wallet
/// Verifying wallet: my-wallet
///
/// [OK] Wallet format is valid
/// [OK] Address field present
/// Enter password to verify wallet integrity: ****
/// [OK] Successfully decrypted wallet
/// [OK] Address derivation matches
/// Verification successful!
/// Address: 0xabcd1234...
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The wallet with the given name is not found
/// - The wallet format is invalid
/// - The password is incorrect
/// - The stored address doesn't match the derived address (indicating corruption)
pub fn verify_command(name: &str) -> Result<()> {
    let keystore_path = find_keystore_by_name(name)?;
    let keystore = Keystore::load(&keystore_path)?;

    println!("Verifying wallet: {name}");
    println!();

    match keystore.content.get("chain").and_then(|v| v.as_str()) {
        Some("solana") => verify_solana_wallet(&keystore, &keystore_path),
        _ => verify_evm_wallet(&keystore),
    }
}

/// Verify a Solana wallet
fn verify_solana_wallet(keystore: &Keystore, keystore_path: &std::path::Path) -> Result<()> {
    // Validate format - Solana keystores should have crypto field
    if keystore.content.get("crypto").is_some() {
        println!("{} Wallet format is valid", "[OK]".green());
    } else {
        println!(
            "{} Wallet format is invalid: missing crypto field",
            "[FAIL]".red()
        );
        anyhow::bail!("Invalid Solana keystore format");
    }

    // Check for public key
    let stored_pubkey = keystore.content.get("public_key").and_then(|v| v.as_str());
    if stored_pubkey.is_some() {
        println!("{} Public key field present", "[OK]".green());
    } else {
        println!("{} Public key field missing", "[WARN]".yellow());
    }

    let password = Password::new()
        .with_prompt("Enter password to verify wallet integrity")
        .allow_empty_password(false)
        .interact()?;

    // Use Solana-specific decryption
    match purl_lib::keystore::decrypt_solana_keystore(keystore_path, Some(&password)) {
        Ok(keypair_bytes) => {
            println!("{} Successfully decrypted wallet", "[OK]".green());

            // Validate keypair length (should be 64 bytes)
            if keypair_bytes.len() != 64 {
                println!(
                    "{} Invalid keypair length: expected 64 bytes, got {}",
                    "[FAIL]".red(),
                    keypair_bytes.len()
                );
                anyhow::bail!("Invalid Solana keypair");
            }

            // Construct Keypair from the 64 bytes and derive public key from secret key
            let keypair = Keypair::try_from(&keypair_bytes[..])
                .context("Failed to construct Keypair from decrypted bytes")?;
            let derived_pubkey = keypair.pubkey().to_string();

            if let Some(stored) = stored_pubkey {
                if stored == derived_pubkey {
                    println!("{} Public key derivation matches", "[OK]".green());
                    println!("{}", "Verification successful!".green());
                    let linked = wallet_link(stored, "Solana");
                    println!("Address: {}", linked.yellow());
                } else {
                    println!("{} Public key mismatch!", "[FAIL]".red());
                    let stored_linked = wallet_link(stored, "Solana");
                    let derived_linked = wallet_link(&derived_pubkey, "Solana");
                    println!("Stored:  {}", stored_linked.yellow());
                    println!("Derived: {}", derived_linked.yellow());
                    anyhow::bail!("Public key derivation does not match stored public key");
                }
            } else {
                println!("{}", "Verification successful!".green());
                let linked = wallet_link(&derived_pubkey, "Solana");
                println!("Address: {}", linked.yellow());
            }
        }
        Err(e) => {
            println!("{} Failed to decrypt wallet: {e}", "[FAIL]".red());
            anyhow::bail!("Wallet decryption failed");
        }
    }

    Ok(())
}

/// Verify an EVM wallet
fn verify_evm_wallet(keystore: &Keystore) -> Result<()> {
    match keystore.validate() {
        Ok(()) => {
            println!("{} Wallet format is valid", "[OK]".green());
        }
        Err(e) => {
            println!("{} Wallet format is invalid: {e}", "[FAIL]".red());
            return Err(e.into());
        }
    }

    if keystore.address().is_some() {
        println!("{} Address field present", "[OK]".green());
    } else {
        println!("{} Address field missing", "[WARN]".yellow());
    }

    let password = Password::new()
        .with_prompt("Enter password to verify wallet integrity")
        .allow_empty_password(false)
        .interact()?;

    match keystore.decrypt(&password) {
        Ok(private_key_bytes) => {
            println!("{} Successfully decrypted wallet", "[OK]".green());

            if let Some(stored_address) = keystore.address() {
                use alloy_signer_local::PrivateKeySigner;
                let key_hex = hex::encode(&private_key_bytes);

                match key_hex.parse::<PrivateKeySigner>() {
                    Ok(signer) => {
                        let derived_address = format!("{:#x}", signer.address());
                        let derived_no_prefix = &derived_address[2..];

                        if stored_address.to_lowercase() == derived_no_prefix.to_lowercase() {
                            println!("{} Address derivation matches", "[OK]".green());
                            println!("{}", "Verification successful!".green());
                            let full_addr = format!("0x{stored_address}");
                            let linked = wallet_link(&full_addr, "EVM");
                            println!("Address: {}", linked.yellow());
                        } else {
                            println!("{} Address mismatch!", "[FAIL]".red());
                            let stored_full = format!("0x{stored_address}");
                            let stored_linked = wallet_link(&stored_full, "EVM");
                            let derived_linked = wallet_link(&derived_address, "EVM");
                            println!("Stored:  {}", stored_linked.yellow());
                            println!("Derived: {}", derived_linked.yellow());
                            anyhow::bail!("Address derivation does not match stored address");
                        }
                    }
                    Err(e) => {
                        println!(
                            "{} Could not derive address from private key: {e}",
                            "[WARN]".yellow()
                        );
                        let full_addr = format!("0x{stored_address}");
                        let linked = wallet_link(&full_addr, "EVM");
                        println!("Address: {}", linked.yellow());
                    }
                }
            } else {
                println!(
                    "{} No address stored in keystore to verify against",
                    "[WARN]".yellow()
                );
            }
        }
        Err(e) => {
            println!("{} Failed to decrypt wallet: {e}", "[FAIL]".red());
            anyhow::bail!("Wallet decryption failed");
        }
    }

    Ok(())
}

/// Set a wallet as the active payment method
///
/// Updates the configuration file to use the specified wallet for payments.
/// The chain type (EVM or Solana) is automatically detected from the wallet
/// content based on the presence of `address` (EVM) or `public_key`/`keypair`
/// (Solana) fields.
///
/// # Arguments
///
/// * `name` - Name of the wallet to activate (with or without .json extension)
///
/// # Examples
///
/// ```text
/// $ purl wallet use my-wallet
/// Detected EVM wallet
/// Activated EVM wallet: /home/user/.purl/keystores/my-wallet.json
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The wallet with the given name is not found
/// - The wallet format cannot be detected (no address or public_key field)
/// - The configuration file cannot be read or written
pub fn use_command(name: &str) -> Result<()> {
    let keystore_path = find_keystore_by_name(name)?;

    // Read wallet to detect chain type
    let content = std::fs::read_to_string(&keystore_path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    // Detect chain type
    let chain_type = if json["address"].is_string() {
        "evm"
    } else if json["public_key"].is_string() || json["keypair"].is_string() {
        "solana"
    } else {
        anyhow::bail!(
            "Cannot detect wallet type. Wallet must have 'address' (EVM) or 'public_key'/'keypair' (Solana) field."
        );
    };

    println!("Detected {chain_type} wallet");

    // Load existing config or create new one
    let mut config = purl_lib::config::Config::load_or_default(None::<&str>)?;

    // Update the appropriate config section
    match chain_type {
        "evm" => {
            let evm_config = config.evm.get_or_insert_with(Default::default);
            evm_config.keystore = Some(keystore_path.clone());
        }
        "solana" => {
            let solana_config = config.solana.get_or_insert_with(Default::default);
            solana_config.keystore = Some(keystore_path.clone());
        }
        _ => unreachable!(),
    }

    // Save the config
    config.save()?;

    println!(
        "Activated {} wallet: {}",
        chain_type.to_uppercase(),
        keystore_path.display()
    );

    Ok(())
}

/// Remove a wallet from the wallets directory
///
/// Deletes the wallet file from the filesystem. If the wallet is currently
/// configured as active in the config, the config reference will be cleared.
///
/// # Arguments
///
/// * `name` - Name of the wallet to remove (with or without .json extension)
///
/// # Examples
///
/// ```text
/// $ purl wallet remove my-wallet
/// Removed wallet: /home/user/.purl/keystores/my-wallet.json
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The wallet with the given name is not found
/// - The file cannot be deleted
pub fn remove_command(name: &str) -> Result<()> {
    let keystore_path = find_keystore_by_name(name)?;
    let canonical_path = keystore_path.canonicalize().ok();

    // Check if this wallet is currently active and clear the config if so
    let mut config = purl_lib::config::Config::load_unchecked(None::<&str>).ok();
    let mut config_modified = false;

    if let Some(ref mut cfg) = config {
        // Check EVM keystore
        if let Some(ref evm) = cfg.evm {
            if let Some(ref evm_keystore) = &evm.keystore {
                if evm_keystore.canonicalize().ok() == canonical_path {
                    // Remove the entire EVM config section since keystore is the only wallet source
                    cfg.evm = None;
                    config_modified = true;
                    println!("Cleared active EVM wallet from config");
                }
            }
        }

        // Check Solana keystore
        if let Some(ref solana) = cfg.solana {
            if let Some(ref solana_keystore) = &solana.keystore {
                if solana_keystore.canonicalize().ok() == canonical_path {
                    // Remove the entire Solana config section since keystore is the only wallet source
                    cfg.solana = None;
                    config_modified = true;
                    println!("Cleared active Solana wallet from config");
                }
            }
        }

        if config_modified {
            cfg.save()?;
        }
    }

    // Delete the wallet file
    std::fs::remove_file(&keystore_path)?;

    println!("Removed wallet: {}", keystore_path.display());

    Ok(())
}
