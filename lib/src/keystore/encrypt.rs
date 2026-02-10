//! Keystore encryption and decryption functionality

use crate::constants::{default_keystores_dir, EVM_PRIVATE_KEY_BYTES, KEYSTORE_EXTENSION};
use crate::error::{PurlError, Result};
use std::path::{Path, PathBuf};

/// Sanitize a string for safe display in terminal prompts.
/// Removes control characters (ASCII 0-31, 127) to prevent terminal manipulation attacks.
fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .filter(|c| {
            let code = *c as u32;
            // Keep printable ASCII (32-126) and valid Unicode above 127
            (32..127).contains(&code) || code > 127
        })
        .collect()
}

/// Get the default keystore directory (~/.purl/keystores)
pub fn default_keystore_dir() -> Result<PathBuf> {
    default_keystores_dir().ok_or(PurlError::NoConfigDir)
}

/// Create an encrypted keystore file from a private key
///
/// # Examples
///
/// ```no_run
/// use purl_lib::keystore::create_keystore;
///
/// // Create a keystore with a private key
/// let private_key = "0x1234567890123456789012345678901234567890123456789012345678901234";
/// let password = "secure_password";
/// let name = "my-wallet";
///
/// let keystore_path = create_keystore(private_key, password, name).unwrap();
/// println!("Keystore created at: {}", keystore_path.display());
/// ```
pub fn create_keystore(private_key: &str, password: &str, name: &str) -> Result<PathBuf> {
    let key_hex = crate::utils::strip_0x_prefix(private_key);
    let key_bytes = hex::decode(key_hex)
        .map_err(|e| PurlError::InvalidKey(format!("Invalid private key hex: {e}")))?;

    if key_bytes.len() != EVM_PRIVATE_KEY_BYTES {
        return Err(PurlError::InvalidKey(format!(
            "Private key must be {EVM_PRIVATE_KEY_BYTES} bytes"
        )));
    }

    use alloy_signer_local::PrivateKeySigner;
    let signer = PrivateKeySigner::from_slice(&key_bytes)
        .map_err(|e| PurlError::InvalidKey(format!("Invalid private key: {e}")))?;
    let address_no_prefix = format!("{:x}", signer.address());

    let keystore_dir = default_keystore_dir()?;

    std::fs::create_dir_all(&keystore_dir).map_err(|e| {
        PurlError::ConfigMissing(format!(
            "Failed to create keystore directory {}: {}",
            keystore_dir.display(),
            e
        ))
    })?;

    // Set secure permissions on the keystore directory (0700)
    crate::permissions::set_secure_dir_permissions(&keystore_dir)?;

    if !keystore_dir.exists() {
        return Err(PurlError::ConfigMissing(format!(
            "Keystore directory does not exist after creation: {}",
            keystore_dir.display()
        )));
    }

    let mut rng = rand_core::OsRng;
    let filename_with_ext = format!("{name}.{KEYSTORE_EXTENSION}");

    eth_keystore::encrypt_key(
        &keystore_dir,
        &mut rng,
        &key_bytes,
        password,
        Some(&filename_with_ext),
    )
    .map_err(|e| PurlError::ConfigMissing(format!("Failed to encrypt keystore: {e}")))?;

    let keystore_path = keystore_dir.join(&filename_with_ext);

    let keystore_content = std::fs::read_to_string(&keystore_path)
        .map_err(|e| PurlError::ConfigMissing(format!("Failed to read keystore: {e}")))?;

    let mut keystore_json: serde_json::Value = serde_json::from_str(&keystore_content)
        .map_err(|e| PurlError::ConfigMissing(format!("Failed to parse keystore: {e}")))?;

    keystore_json["address"] = serde_json::Value::String(address_no_prefix);

    let updated_keystore = serde_json::to_string_pretty(&keystore_json)
        .map_err(|e| PurlError::ConfigMissing(format!("Failed to serialize keystore: {e}")))?;

    std::fs::write(&keystore_path, updated_keystore)
        .map_err(|e| PurlError::ConfigMissing(format!("Failed to write keystore: {e}")))?;

    // Set secure permissions on the keystore file (0600)
    crate::permissions::set_secure_file_permissions(&keystore_path)?;

    Ok(keystore_path)
}

/// List all keystore files in the default directory
pub fn list_keystores() -> Result<Vec<PathBuf>> {
    let keystore_dir = default_keystore_dir()?;

    if !keystore_dir.exists() {
        return Ok(Vec::new());
    }

    let mut keystores = Vec::new();
    for entry in std::fs::read_dir(keystore_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some(KEYSTORE_EXTENSION) {
            keystores.push(path);
        }
    }

    Ok(keystores)
}

/// Decrypt a keystore file
///
/// # Arguments
///
/// * `keystore_path` - Path to the keystore file
/// * `password` - Optional password. If None, prompts the user with retry on failure.
pub fn decrypt_keystore(keystore_path: &Path, password: Option<&str>) -> Result<Vec<u8>> {
    if !keystore_path.exists() {
        return Err(PurlError::ConfigMissing(format!(
            "Keystore file not found: {}",
            keystore_path.display()
        )));
    }

    // If password provided explicitly, try once without retry
    if let Some(p) = password {
        return eth_keystore::decrypt_key(keystore_path, p).map_err(|e| match e {
            eth_keystore::KeystoreError::MacMismatch => PurlError::InvalidPassword,
            other => PurlError::ConfigMissing(format!("Failed to decrypt keystore: {other}")),
        });
    }

    // Interactive mode: prompt with retry on failure
    let keystore_name = keystore_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("keystore");
    let safe_keystore_name = sanitize_for_terminal(keystore_name);

    loop {
        print!("Enter {} password: ", safe_keystore_name);
        std::io::Write::flush(&mut std::io::stdout())
            .map_err(|e| PurlError::ConfigMissing(format!("Failed to flush stdout: {e}")))?;
        let password = rpassword::read_password()
            .map_err(|e| PurlError::ConfigMissing(format!("Failed to read password: {e}")))?;

        match eth_keystore::decrypt_key(keystore_path, &password) {
            Ok(private_key) => return Ok(private_key),
            Err(_) => {
                eprintln!("Error: Invalid password");
            }
        }
    }
}

/// Create an encrypted Solana keystore file from a base58-encoded keypair.
///
/// Uses the same encryption scheme as EVM keystores (scrypt + AES-128-CTR)
/// but stores the full 64-byte Solana keypair.
pub fn create_solana_keystore(keypair_b58: &str, password: &str, name: &str) -> Result<PathBuf> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;
    use rand::RngCore;
    use scrypt::{scrypt, Params};
    use sha3::{Digest, Keccak256};

    // Decode and validate the keypair
    let keypair_bytes = bs58::decode(keypair_b58)
        .into_vec()
        .map_err(|e| PurlError::InvalidKey(format!("Invalid base58 keypair: {e}")))?;

    if keypair_bytes.len() != crate::constants::SOLANA_KEYPAIR_BYTES {
        return Err(PurlError::InvalidKey(format!(
            "Solana keypair must be {} bytes, got {}",
            crate::constants::SOLANA_KEYPAIR_BYTES,
            keypair_bytes.len()
        )));
    }

    // Extract public key (last 32 bytes) for metadata
    let pubkey_bytes = &keypair_bytes[32..];
    let pubkey_b58 = bs58::encode(pubkey_bytes).into_string();

    // Generate encryption parameters
    let mut rng = rand::rng();
    let mut salt = [0u8; 32];
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    // Derive key using scrypt (matching eth_keystore parameters)
    // n=262144 (2^18), r=8, p=1, dklen=32
    let params = Params::new(18, 8, 1, 32)
        .map_err(|e| PurlError::ConfigMissing(format!("Invalid scrypt params: {e}")))?;
    let mut derived_key = [0u8; 32];
    scrypt(password.as_bytes(), &salt, &params, &mut derived_key)
        .map_err(|e| PurlError::ConfigMissing(format!("Scrypt key derivation failed: {e}")))?;

    // Encrypt keypair with AES-128-CTR using first 16 bytes of derived key
    let mut ciphertext = keypair_bytes.clone();
    let mut cipher = Ctr128BE::<aes::Aes128>::new(derived_key[..16].into(), iv.as_slice().into());
    cipher.apply_keystream(&mut ciphertext);

    // Create MAC using Keccak256 over (derived_key[16..32] || ciphertext)
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&derived_key[16..]);
    mac_input.extend_from_slice(&ciphertext);
    let mac = Keccak256::digest(&mac_input);

    // Build keystore JSON (similar to eth_keystore format)
    let keystore_json = serde_json::json!({
        "version": 3,
        "chain": "solana",
        "public_key": pubkey_b58,
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": hex::encode(iv)
            },
            "ciphertext": hex::encode(&ciphertext),
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "n": 262144,
                "p": 1,
                "r": 8,
                "salt": hex::encode(salt)
            },
            "mac": hex::encode(mac)
        }
    });

    // Write to file
    let keystore_dir = default_keystore_dir()?;
    std::fs::create_dir_all(&keystore_dir)?;
    crate::permissions::set_secure_dir_permissions(&keystore_dir)?;

    let filename = format!("{name}.{KEYSTORE_EXTENSION}");
    let keystore_path = keystore_dir.join(&filename);

    let content = serde_json::to_string_pretty(&keystore_json)
        .map_err(|e| PurlError::ConfigMissing(format!("Failed to serialize keystore: {e}")))?;
    std::fs::write(&keystore_path, content)?;

    // Set secure permissions on the keystore file (0600)
    crate::permissions::set_secure_file_permissions(&keystore_path)?;

    Ok(keystore_path)
}

/// Decrypt a Solana keystore file and return the keypair bytes.
///
/// # Arguments
///
/// * `keystore_path` - Path to the Solana keystore file
/// * `password` - Optional password. If None, prompts the user with retry on failure.
pub fn decrypt_solana_keystore(keystore_path: &Path, password: Option<&str>) -> Result<Vec<u8>> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;
    use scrypt::{scrypt, Params};
    use sha3::{Digest, Keccak256};

    if !keystore_path.exists() {
        return Err(PurlError::ConfigMissing(format!(
            "Keystore file not found: {}",
            keystore_path.display()
        )));
    }

    let content = std::fs::read_to_string(keystore_path)
        .map_err(|e| PurlError::ConfigMissing(format!("Failed to read keystore: {e}")))?;
    let keystore: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| PurlError::ConfigMissing(format!("Failed to parse keystore: {e}")))?;

    // Verify this is a Solana keystore
    if keystore["chain"].as_str() != Some("solana") {
        return Err(PurlError::InvalidKey(
            "Not a Solana keystore (missing or wrong 'chain' field)".to_string(),
        ));
    }

    // Extract crypto parameters upfront (before password prompt)
    let crypto = &keystore["crypto"];
    let salt = hex::decode(
        crypto["kdfparams"]["salt"]
            .as_str()
            .ok_or_else(|| PurlError::InvalidKey("Missing salt".to_string()))?,
    )
    .map_err(|e| PurlError::InvalidKey(format!("Invalid salt hex: {e}")))?;

    let iv = hex::decode(
        crypto["cipherparams"]["iv"]
            .as_str()
            .ok_or_else(|| PurlError::InvalidKey("Missing IV".to_string()))?,
    )
    .map_err(|e| PurlError::InvalidKey(format!("Invalid IV hex: {e}")))?;

    let ciphertext = hex::decode(
        crypto["ciphertext"]
            .as_str()
            .ok_or_else(|| PurlError::InvalidKey("Missing ciphertext".to_string()))?,
    )
    .map_err(|e| PurlError::InvalidKey(format!("Invalid ciphertext hex: {e}")))?;

    let expected_mac = hex::decode(
        crypto["mac"]
            .as_str()
            .ok_or_else(|| PurlError::InvalidKey("Missing MAC".to_string()))?,
    )
    .map_err(|e| PurlError::InvalidKey(format!("Invalid MAC hex: {e}")))?;

    // Extract scrypt parameters
    let n = crypto["kdfparams"]["n"]
        .as_u64()
        .ok_or_else(|| PurlError::InvalidKey("Missing n parameter".to_string()))?
        as usize;

    // Validate that n is a power of two and compute log_n using integer operations
    if n == 0 || !n.is_power_of_two() {
        return Err(PurlError::InvalidKey(format!(
            "Invalid scrypt parameter n={}: must be a power of two",
            n
        )));
    }
    let log_n = n.trailing_zeros() as u8;
    let r = crypto["kdfparams"]["r"]
        .as_u64()
        .ok_or_else(|| PurlError::InvalidKey("Missing r parameter".to_string()))?
        as u32;
    let p = crypto["kdfparams"]["p"]
        .as_u64()
        .ok_or_else(|| PurlError::InvalidKey("Missing p parameter".to_string()))?
        as u32;

    let params = Params::new(log_n, r, p, 32)
        .map_err(|e| PurlError::InvalidKey(format!("Invalid scrypt params: {e}")))?;

    // Helper to attempt decryption with a given password
    let try_decrypt = |password: &str| -> std::result::Result<Vec<u8>, ()> {
        let mut derived_key = [0u8; 32];
        if scrypt(password.as_bytes(), &salt, &params, &mut derived_key).is_err() {
            return Err(());
        }

        // Verify MAC
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&derived_key[16..]);
        mac_input.extend_from_slice(&ciphertext);
        let computed_mac = Keccak256::digest(&mac_input);

        if computed_mac.as_slice() != expected_mac {
            return Err(());
        }

        // Decrypt
        let mut plaintext = ciphertext.clone();
        let mut cipher =
            Ctr128BE::<aes::Aes128>::new(derived_key[..16].into(), iv.as_slice().into());
        cipher.apply_keystream(&mut plaintext);
        Ok(plaintext)
    };

    // If password provided explicitly, try once without retry
    if let Some(p) = password {
        return try_decrypt(p).map_err(|_| PurlError::InvalidPassword);
    }

    // Interactive mode: prompt with retry on failure
    let keystore_name_raw = keystore_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("keystore");
    let safe_keystore_name = sanitize_for_terminal(keystore_name_raw);

    loop {
        print!("Enter {} password: ", safe_keystore_name);
        std::io::Write::flush(&mut std::io::stdout())
            .map_err(|e| PurlError::ConfigMissing(format!("Failed to flush stdout: {e}")))?;
        let password = rpassword::read_password()
            .map_err(|e| PurlError::ConfigMissing(format!("Failed to read password: {e}")))?;

        match try_decrypt(&password) {
            Ok(plaintext) => return Ok(plaintext),
            Err(_) => {
                eprintln!("\x1b[31mError: Invalid password\x1b[0m");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;

    /// Helper to set up a temporary home directory for tests
    fn setup_temp_home(temp_dir: &TempDir) {
        // SAFETY: We use serial_test to ensure tests don't run concurrently
        unsafe { std::env::set_var("HOME", temp_dir.path()) };
    }

    #[test]
    #[serial]
    fn test_keystore_creation_and_listing() {
        let temp_dir = TempDir::new().unwrap();
        setup_temp_home(&temp_dir);

        let private_key = "0x1234567890123456789012345678901234567890123456789012345678901234";
        let password = "test_password";
        let name = "test_keystore";

        let keystore_path = create_keystore(private_key, password, name).unwrap();
        assert!(keystore_path.exists());

        let keystores = list_keystores().unwrap();
        assert_eq!(keystores.len(), 1);
        assert_eq!(keystores[0], keystore_path);
    }

    #[test]
    #[serial]
    fn test_decrypt_keystore() {
        let temp_dir = TempDir::new().unwrap();
        setup_temp_home(&temp_dir);

        let private_key = "0x1234567890123456789012345678901234567890123456789012345678901234";
        let password = "test_password";
        let name = "test_decrypt";

        let keystore_path = create_keystore(private_key, password, name).unwrap();

        let result = decrypt_keystore(&keystore_path, Some(password));
        assert!(result.is_ok());
    }
}
