//! Common test utilities for purl CLI tests

#![allow(dead_code)]

use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// Builder for creating test configurations
pub struct TestConfigBuilder {
    temp_dir: TempDir,
    evm_keystore: Option<(String, String)>, // (name, private_key)
    solana_keystore: Option<(String, String)>, // (name, public_key)
}

impl TestConfigBuilder {
    /// Create a new test config builder
    pub fn new() -> Self {
        Self {
            temp_dir: TempDir::new().expect("Failed to create temp directory"),
            evm_keystore: None,
            solana_keystore: None,
        }
    }

    /// Add an EVM keystore
    pub fn with_evm_keystore(mut self, name: &str, private_key: &str) -> Self {
        self.evm_keystore = Some((name.to_string(), private_key.to_string()));
        self
    }

    /// Add a Solana keystore
    pub fn with_solana_keystore(mut self, name: &str, public_key: &str) -> Self {
        self.solana_keystore = Some((name.to_string(), public_key.to_string()));
        self
    }

    /// Add default EVM keystore (uses TEST_EVM_KEY)
    pub fn with_default_evm(self) -> Self {
        self.with_evm_keystore("evm-wallet", TEST_EVM_KEY)
    }

    /// Add default Solana keystore (uses TEST_SOLANA_PUBKEY)
    pub fn with_default_solana(self) -> Self {
        self.with_solana_keystore("solana-wallet", TEST_SOLANA_PUBKEY)
    }

    /// Add both default EVM and Solana keystores
    pub fn with_defaults(self) -> Self {
        self.with_default_evm().with_default_solana()
    }

    /// Build the test configuration
    pub fn build(self) -> TempDir {
        // Use ~/.purl/ for all platforms
        let purl_dir = self.temp_dir.path().join(".purl");

        fs::create_dir_all(&purl_dir).expect("Failed to create purl directory");

        let mut config = String::new();

        // Add EVM config with keystore
        if let Some((name, private_key)) = &self.evm_keystore {
            config.push_str("[evm]\n");
            let keystore_path = purl_dir.join("keystores").join(format!("{name}.json"));
            fs::create_dir_all(keystore_path.parent().unwrap()).ok();
            // Create a dummy keystore with a valid address derived from the private key
            let address = derive_evm_address(private_key);
            let keystore_content = format!(r#"{{"address":"{address}","crypto":{{}}}}"#);
            fs::write(&keystore_path, keystore_content).ok();
            config.push_str(&format!("keystore = \"{}\"\n", keystore_path.display()));
            config.push('\n');
        }

        // Add Solana config with keystore
        if let Some((name, public_key)) = &self.solana_keystore {
            config.push_str("[solana]\n");
            let keystore_path = purl_dir.join("keystores").join(format!("{name}.json"));
            fs::create_dir_all(keystore_path.parent().unwrap()).ok();
            // Create a dummy Solana keystore with public key
            let keystore_content =
                format!(r#"{{"chain":"solana","public_key":"{public_key}","crypto":{{}}}}"#);
            fs::write(&keystore_path, keystore_content).ok();
            config.push_str(&format!("keystore = \"{}\"\n", keystore_path.display()));
        }

        fs::write(purl_dir.join("config.toml"), config).expect("Failed to write config");
        self.temp_dir
    }
}

/// Derive EVM address from private key (hex string without 0x prefix)
fn derive_evm_address(private_key: &str) -> String {
    use sha3::{Digest, Keccak256};

    // Decode private key
    let key_bytes = hex::decode(private_key).expect("Invalid hex private key");

    // Derive public key using secp256k1
    let secp = secp256k1::Secp256k1::new();
    let secret_key =
        secp256k1::SecretKey::from_slice(&key_bytes).expect("Invalid private key bytes");
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    // Get uncompressed public key bytes (skip first byte which is 0x04)
    let public_key_bytes = &public_key.serialize_uncompressed()[1..];

    // Hash with Keccak256 and take last 20 bytes
    let hash = Keccak256::digest(public_key_bytes);
    let address_bytes = &hash[12..];

    hex::encode(address_bytes)
}

/// Set up a test configuration with optional EVM and Solana keystores
pub fn setup_test_config(evm_key: Option<&str>, solana_pubkey: Option<&str>) -> TempDir {
    let mut builder = TestConfigBuilder::new();

    if let Some(key) = evm_key {
        builder = builder.with_evm_keystore("evm-wallet", key);
    }
    if let Some(pubkey) = solana_pubkey {
        builder = builder.with_solana_keystore("solana-wallet", pubkey);
    }

    builder.build()
}

/// Common test EVM private key
pub const TEST_EVM_KEY: &str = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

/// Common test Solana public key (base58 encoded)
pub const TEST_SOLANA_PUBKEY: &str = "3Z7cXSyeFR8wNGMVXUE1TwtKn5D5Vu7FzEv69dokLv7K";

/// Get the keystores directory path for a test temp directory
pub fn get_test_keystores_dir(temp_dir: &TempDir) -> std::path::PathBuf {
    temp_dir.path().join(".purl/keystores")
}

/// Create a real encrypted keystore file for testing
pub fn create_test_keystore(
    temp_dir: &TempDir,
    name: &str,
    private_key: &str,
    password: &str,
) -> std::path::PathBuf {
    let keystores_dir = temp_dir.path().join(".purl/keystores");

    std::fs::create_dir_all(&keystores_dir).expect("Failed to create keystores directory");

    // Set HOME temporarily for this operation using a thread-local approach
    std::env::set_var("HOME", temp_dir.path());
    let result = purl_lib::keystore::create_keystore(private_key, password, name);

    result.expect("Failed to create test keystore")
}

/// Create a test command with proper environment variables set
///
/// This helper ensures HOME is set so purl uses ~/.purl/ within the temp directory.
pub fn test_command(temp_dir: &TempDir) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("purl"));

    // Set HOME so purl uses $HOME/.purl/
    cmd.env("HOME", temp_dir.path());

    cmd
}
