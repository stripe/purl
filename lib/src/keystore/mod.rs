//! Keystore management for encrypted wallet storage
//!
//! This module provides functionality for creating, storing, and managing
//! encrypted keystores for EVM wallets.
//!
//! # Module Structure
//!
//! - `store` - Keystore and KeystoreInfo types
//! - `encrypt` - Keystore creation and decryption
//!
//! # Example
//!
//! ```no_run
//! use purl_lib::keystore::{create_keystore, decrypt_keystore, list_keystores, Keystore};
//!
//! // Create a new keystore
//! let private_key = "0x1234567890123456789012345678901234567890123456789012345678901234";
//! let keystore_path = create_keystore(private_key, "password", "my-wallet").unwrap();
//!
//! // List all keystores
//! let keystores = list_keystores().unwrap();
//!
//! // Load and inspect a keystore
//! let keystore = Keystore::load(&keystores[0]).unwrap();
//! println!("Address: {:?}", keystore.formatted_address());
//!
//! // Decrypt a keystore
//! let private_key_bytes = decrypt_keystore(&keystore_path, Some("password")).unwrap();
//! ```

mod encrypt;
mod store;

use crate::error::{PurlError, Result};
use std::path::Path;

// Re-export public items
pub use encrypt::{
    create_keystore, create_solana_keystore, decrypt_keystore, decrypt_solana_keystore,
    default_keystore_dir, list_keystores,
};
pub use store::{Keystore, KeystoreInfo};

/// Extract EVM address from keystore without decrypting it
pub fn get_evm_address_from_keystore(keystore_path: &Path) -> Result<String> {
    let keystore = Keystore::load(keystore_path)?;
    keystore
        .formatted_address()
        .ok_or_else(|| PurlError::config_missing("Keystore missing address field"))
}

/// Extract Solana public key from keystore without decrypting it
///
/// Attempts to extract the Solana public key using the following methods (in order):
/// 1. Reads from `public_key` metadata field if present
/// 2. Derives from unencrypted `keypair` field if present (base58-encoded)
/// 3. Returns an error requiring decryption if neither is available
///
/// # Security Note
///
/// Full encrypted keystore support for Solana is planned. Currently, this
/// function expects either a `public_key` metadata field or an unencrypted
/// `keypair` field in the keystore JSON.
///
/// # Arguments
///
/// * `keystore_path` - Path to the Solana keystore file
///
/// # Returns
///
/// The base58-encoded Solana public key
///
/// # Errors
///
/// Returns an error if:
/// - The keystore file cannot be read
/// - Neither `public_key` nor `keypair` fields are present
/// - The keypair format is invalid
///
/// # Examples
///
/// ```no_run
/// use purl_lib::keystore::get_solana_pubkey_from_keystore;
/// use std::path::Path;
///
/// let path = Path::new("/path/to/solana-keystore.json");
/// let pubkey = get_solana_pubkey_from_keystore(path).unwrap();
/// println!("Public key: {}", pubkey);
/// ```
pub fn get_solana_pubkey_from_keystore(keystore_path: &Path) -> Result<String> {
    let keystore = Keystore::load(keystore_path)?;

    // Method 1: Try to get public key from metadata (preferred for encrypted keystores)
    if let Some(pubkey) = keystore.content.get("public_key").and_then(|v| v.as_str()) {
        return Ok(pubkey.to_string());
    }

    // Method 2: Try to extract from unencrypted keypair field (backwards compatibility)
    if let Some(keypair_b58) = keystore.content.get("keypair").and_then(|v| v.as_str()) {
        return extract_pubkey_from_solana_keypair(keypair_b58);
    }

    // If neither method works, decryption would be required
    Err(PurlError::config_missing(
        "Keystore does not contain public_key metadata or unencrypted keypair field. \
        Cannot perform dry-run without decrypting. Full Solana keystore encryption is planned.",
    ))
}

/// Extract the public key from a base58-encoded Solana keypair
///
/// A Solana keypair is 64 bytes: 32 bytes secret key + 32 bytes public key.
/// This function extracts the public key portion (last 32 bytes).
///
/// # Arguments
///
/// * `keypair_b58` - Base58-encoded Solana keypair (64 bytes)
///
/// # Returns
///
/// The base58-encoded public key (32 bytes)
///
/// # Errors
///
/// Returns an error if the keypair is not valid base58 or is not 64 bytes
fn extract_pubkey_from_solana_keypair(keypair_b58: &str) -> Result<String> {
    use crate::constants::SOLANA_KEYPAIR_BYTES;

    let keypair_bytes = bs58::decode(keypair_b58)
        .into_vec()
        .map_err(|e| PurlError::InvalidKey(format!("Invalid base58 keypair: {e}")))?;

    if keypair_bytes.len() != SOLANA_KEYPAIR_BYTES {
        return Err(PurlError::InvalidKey(format!(
            "Solana keypair must be {} bytes, got {}",
            SOLANA_KEYPAIR_BYTES,
            keypair_bytes.len()
        )));
    }

    // Public key is the last 32 bytes of the keypair
    let pubkey_bytes = &keypair_bytes[32..];
    Ok(bs58::encode(pubkey_bytes).into_string())
}

#[cfg(test)]
mod keystore_utils_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_get_evm_address_with_0x_prefix() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"{{"address": "0x1234567890abcdef1234567890abcdef12345678"}}"#
        )
        .unwrap();

        let addr = get_evm_address_from_keystore(temp.path()).unwrap();
        assert_eq!(addr, "0x1234567890abcdef1234567890abcdef12345678");
    }

    #[test]
    fn test_get_evm_address_without_0x_prefix() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"{{"address": "1234567890abcdef1234567890abcdef12345678"}}"#
        )
        .unwrap();

        let addr = get_evm_address_from_keystore(temp.path()).unwrap();
        assert_eq!(addr, "0x1234567890abcdef1234567890abcdef12345678");
    }

    #[test]
    fn test_get_evm_address_missing_field() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(temp, r#"{{"other_field": "value"}}"#).unwrap();

        let result = get_evm_address_from_keystore(temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_get_evm_address_invalid_json() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(temp, "not valid json").unwrap();

        let result = get_evm_address_from_keystore(temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_get_solana_pubkey_with_metadata() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"{{"public_key": "5xot9PVkphiX2adznghwrAuxGs2zeWisNSxMW6hU6Hkj"}}"#
        )
        .unwrap();

        let pubkey = get_solana_pubkey_from_keystore(temp.path()).unwrap();
        assert_eq!(pubkey, "5xot9PVkphiX2adznghwrAuxGs2zeWisNSxMW6hU6Hkj");
    }

    #[test]
    fn test_get_solana_pubkey_from_keypair_field() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"{{"keypair": "3Z7qW9HTzDNxTWPYHp5Q2FqZEK3Z3Z7qW9HTzDNxTWPYHp5Q2FqZEK3Z3Z7qW9HTzDNxTWPYHp5Q2FqZEK3Z5xot9PVkphiX2adznghwrAuxGs2zeWisNSxMW6hU6Hkj"}}"#
        )
        .unwrap();

        let result = get_solana_pubkey_from_keystore(temp.path());
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_get_solana_pubkey_prefers_metadata_over_keypair() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"{{"public_key": "5xot9PVkphiX2adznghwrAuxGs2zeWisNSxMW6hU6Hkj", "keypair": "invalid"}}"#
        )
        .unwrap();

        let pubkey = get_solana_pubkey_from_keystore(temp.path()).unwrap();
        assert_eq!(pubkey, "5xot9PVkphiX2adznghwrAuxGs2zeWisNSxMW6hU6Hkj");
    }

    #[test]
    fn test_get_solana_pubkey_without_metadata_or_keypair() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(temp, r#"{{"other_field": "value"}}"#).unwrap();

        let result = get_solana_pubkey_from_keystore(temp.path());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("public_key metadata or unencrypted keypair field"));
    }

    #[test]
    fn test_extract_pubkey_from_valid_keypair() {
        // Generate valid
        use solana_sdk::signature::{Keypair, Signer};

        let keypair = Keypair::new();
        let keypair_bytes = keypair.to_bytes();
        let keypair_b58 = bs58::encode(keypair_bytes).into_string();

        let extracted_pubkey = extract_pubkey_from_solana_keypair(&keypair_b58).unwrap();
        let expected_pubkey = keypair.pubkey().to_string();

        assert_eq!(extracted_pubkey, expected_pubkey);
    }

    #[test]
    fn test_extract_pubkey_from_invalid_keypair() {
        let result = extract_pubkey_from_solana_keypair("not-valid-base58!");
        assert!(result.is_err());

        let short_bytes = vec![0u8; 32]; // Only 32 bytes instead of 64
        let short_b58 = bs58::encode(short_bytes).into_string();
        let result = extract_pubkey_from_solana_keypair(&short_b58);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be 64 bytes"));
    }
}
