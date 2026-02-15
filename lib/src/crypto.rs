//! Cryptographic utilities for key generation

use crate::constants::{EVM_PRIVATE_KEY_BYTES, SOLANA_KEYPAIR_BYTES};
use crate::error::{PurlError, Result};

/// Trait for wallet key generation
///
/// # Examples
///
/// ```
/// use purl_lib::crypto::{KeyGenerator, EvmKeyGenerator, SolanaKeyGenerator};
///
/// // Generate an EVM key
/// let (private_key, address) = EvmKeyGenerator::generate().unwrap();
/// assert_eq!(private_key.len(), 64); // 32 bytes as hex
/// assert!(address.starts_with("0x"));
///
/// // Generate a Solana keypair
/// let (private_key, public_key) = SolanaKeyGenerator::generate().unwrap();
/// assert!(!private_key.is_empty());
/// assert!(!public_key.is_empty());
///
/// // Check key formats
/// assert_eq!(EvmKeyGenerator::key_format(), "hex");
/// assert_eq!(SolanaKeyGenerator::key_format(), "base58");
/// ```
pub trait KeyGenerator {
    /// Generate a new key pair
    /// Returns (private_key, public_key_or_address)
    fn generate() -> Result<(String, String)>;

    /// Validate a private key
    fn validate_key(key: &str) -> Result<()>;

    /// Get the key format name
    fn key_format() -> &'static str;
}

/// EVM (Ethereum Virtual Machine) key generator
///
/// Generates secp256k1 private keys and derives Ethereum-compatible addresses.
/// Private keys are returned as 64-character hexadecimal strings (32 bytes).
///
/// # Examples
///
/// ```
/// use purl_lib::crypto::{KeyGenerator, EvmKeyGenerator};
///
/// let (private_key, address) = EvmKeyGenerator::generate().unwrap();
/// assert_eq!(private_key.len(), 64);
/// assert!(address.starts_with("0x"));
/// ```
pub struct EvmKeyGenerator;

impl KeyGenerator for EvmKeyGenerator {
    fn generate() -> Result<(String, String)> {
        generate_evm_key()
    }

    fn validate_key(key: &str) -> Result<()> {
        validate_evm_key(key)
    }

    fn key_format() -> &'static str {
        "hex"
    }
}

/// Solana key generator
///
/// Generates Ed25519 keypairs for use on the Solana blockchain.
/// Private keys are returned as base58-encoded strings (64 bytes encoded).
///
/// # Examples
///
/// ```
/// use purl_lib::crypto::{KeyGenerator, SolanaKeyGenerator};
///
/// let (private_key, public_key) = SolanaKeyGenerator::generate().unwrap();
/// assert!(!private_key.is_empty());
/// assert!(!public_key.is_empty());
/// ```
pub struct SolanaKeyGenerator;

impl KeyGenerator for SolanaKeyGenerator {
    fn generate() -> Result<(String, String)> {
        Ok(generate_solana_keypair())
    }

    fn validate_key(key: &str) -> Result<()> {
        validate_solana_keypair(key)
    }

    fn key_format() -> &'static str {
        "base58"
    }
}

/// Generate a new EVM private key
/// Returns (private_key_hex, address)
pub fn generate_evm_key() -> Result<(String, String)> {
    use alloy_signer_local::PrivateKeySigner;
    use rand::Rng;

    let mut rng = rand::rng();
    let key_bytes: [u8; EVM_PRIVATE_KEY_BYTES] = rng.random();
    let key_hex = hex::encode(key_bytes);

    // Parse to get the address
    let signer: PrivateKeySigner = key_hex
        .parse()
        .map_err(|e| PurlError::InvalidKey(format!("Failed to parse generated key: {e}")))?;

    let address = format!("{:#x}", signer.address());

    Ok((key_hex, address))
}

/// Generate a new Solana keypair
/// Returns (private_key_base58, public_key_base58)
pub fn generate_solana_keypair() -> (String, String) {
    use solana_sdk::signature::{Keypair, Signer};

    let keypair = Keypair::new();
    let keypair_bytes = keypair.to_bytes();
    let keypair_b58 = bs58::encode(keypair_bytes).into_string();
    let pubkey_b58 = keypair.pubkey().to_string();

    (keypair_b58, pubkey_b58)
}

/// Validate an EVM private key hex string
///
/// Checks:
/// 1. Valid hex encoding (with optional 0x prefix)
/// 2. Exactly 32 bytes (64 hex characters)
/// 3. Valid secp256k1 scalar (non-zero and less than curve order)
pub fn validate_evm_key(key: &str) -> Result<()> {
    use alloy_signer_local::PrivateKeySigner;

    let key = crate::utils::strip_0x_prefix(key);
    let key_bytes = hex::decode(key).map_err(|_| {
        PurlError::InvalidKey(
            "Invalid Ethereum private key format. Expected a 64-character hex string.".to_string(),
        )
    })?;

    if key_bytes.len() != EVM_PRIVATE_KEY_BYTES {
        return Err(PurlError::InvalidKey(format!(
            "Invalid Ethereum private key. Expected 64 hex characters (32 bytes), got {}.",
            key_bytes.len() * 2
        )));
    }

    // Verify it's a valid key
    PrivateKeySigner::from_slice(&key_bytes).map_err(|_| {
        PurlError::InvalidKey(
            "Invalid Ethereum private key. The key value is not valid for this network."
                .to_string(),
        )
    })?;

    Ok(())
}

/// Validate a Solana keypair
///
/// Checks:
/// 1. Valid base58 encoding
/// 2. Exactly 64 bytes (32-byte secret + 32-byte public key)
/// 3. The public key (bytes 32-64) matches the public key derived from the secret (bytes 0-32)
pub fn validate_solana_keypair(keypair_b58: &str) -> Result<()> {
    use solana_sdk::signature::Keypair;

    let keypair_bytes = bs58::decode(keypair_b58).into_vec().map_err(|_| {
        PurlError::InvalidKey(
            "Invalid Solana private key format. Expected a base58-encoded string.".to_string(),
        )
    })?;

    if keypair_bytes.len() != SOLANA_KEYPAIR_BYTES {
        return Err(PurlError::InvalidKey(
            "Invalid Solana private key. The key length is incorrect. Make sure you copied the full key.".to_string()
        ));
    }

    // Verify the keypair is valid
    Keypair::try_from(&keypair_bytes[..]).map_err(|_| {
        PurlError::InvalidKey(
            "Invalid Solana private key. The key data is corrupted or invalid.".to_string(),
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_evm_key() {
        let result = generate_evm_key();
        assert!(result.is_ok());

        let (key, address) = result.unwrap();
        assert_eq!(key.len(), 64); // 32 bytes as hex
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42); // 0x + 40 hex chars
    }

    #[test]
    fn test_generate_solana_keypair() {
        let (private_key, public_key) = generate_solana_keypair();

        assert!(validate_solana_keypair(&private_key).is_ok());
        assert!(!public_key.is_empty());
    }

    #[test]
    fn test_validate_evm_key() {
        // Valid key with 0x prefix
        let valid_key = "0x1234567890123456789012345678901234567890123456789012345678901234";
        assert!(validate_evm_key(valid_key).is_ok());

        // Valid key without prefix
        let valid_key_no_prefix =
            "1234567890123456789012345678901234567890123456789012345678901234";
        assert!(validate_evm_key(valid_key_no_prefix).is_ok());

        // Invalid: too short (odd number of hex chars fails hex decode)
        let too_short = "0x12345";
        let err = validate_evm_key(too_short).unwrap_err();
        assert!(err.to_string().contains("Invalid Ethereum private key"));

        // Invalid: even length but wrong byte count
        let wrong_length = "0x12345678";
        let err = validate_evm_key(wrong_length).unwrap_err();
        assert!(err.to_string().contains("Expected 64 hex characters"));

        // Invalid: non-hex characters
        let invalid_hex = "0xGGGG567890123456789012345678901234567890123456789012345678901234";
        let err = validate_evm_key(invalid_hex).unwrap_err();
        assert!(err.to_string().contains("Invalid Ethereum private key"));

        // Invalid: zero key (not a valid scalar)
        let zero_key = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let err = validate_evm_key(zero_key).unwrap_err();
        assert!(err.to_string().contains("not valid for this network"));

        // Invalid: key >= curve order
        let too_large = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE";
        let err = validate_evm_key(too_large).unwrap_err();
        assert!(err.to_string().contains("not valid for this network"));
    }

    #[test]
    fn test_validate_solana_keypair() {
        // Generate a valid keypair and test it
        let (valid_keypair, _) = generate_solana_keypair();
        assert!(validate_solana_keypair(&valid_keypair).is_ok());

        // Invalid: non-base58 characters (0, O, I, l are not in base58)
        let invalid_base58 = "0OIl567890123456789012345678901234567890123456789012345678901234";
        let err = validate_solana_keypair(invalid_base58).unwrap_err();
        assert!(err.to_string().contains("Invalid Solana private key"));

        // Invalid: too short
        let too_short = "abcd1234";
        let err = validate_solana_keypair(too_short).unwrap_err();
        assert!(err.to_string().contains("key length is incorrect"));

        // Invalid: wrong length (valid base58 but not 64 bytes)
        // This is 32 bytes base58-encoded (a valid Solana pubkey, not a keypair)
        let pubkey_only = "3Z7cXSyeFR8wNGMVXUE1TwtKn5D5Vu7FzEv69dokLv7K";
        let err = validate_solana_keypair(pubkey_only).unwrap_err();
        assert!(err.to_string().contains("key length is incorrect"));
    }

    #[test]
    fn test_validate_solana_keypair_mismatched_pubkey() {
        // Create a 64-byte array with a valid secret key but wrong public key
        use solana_sdk::signature::Keypair;

        let keypair = Keypair::new();
        let mut bad_bytes = keypair.to_bytes();
        // Corrupt the public key portion (last 32 bytes)
        bad_bytes[32] ^= 0xFF;
        bad_bytes[33] ^= 0xFF;

        let bad_keypair_b58 = bs58::encode(&bad_bytes).into_string();
        let err = validate_solana_keypair(&bad_keypair_b58).unwrap_err();
        assert!(err.to_string().contains("corrupted or invalid"));
    }
}
