//! Signer management for loading wallets from various sources
//!
//! Provides functionality for loading signers from keystores, private keys,
//! and other wallet sources.

use crate::error::{PurlError, Result};
use crate::keystore;
use crate::utils::strip_0x_prefix;
use alloy_signer_local::PrivateKeySigner;
use std::path::Path;

/// Trait for types that can provide a wallet signer
pub trait WalletSource {
    /// Load a signer from this wallet source
    fn load_signer(&self, password: Option<&str>) -> Result<PrivateKeySigner>;
}

/// Wallet options for loading a signer
#[derive(Debug, Clone)]
pub enum WalletOpts {
    /// Load from an encrypted keystore file
    Keystore {
        path: std::path::PathBuf,
        password: Option<String>,
    },
    /// Use a raw private key (hex string, with or without 0x prefix)
    PrivateKey { key: String },
}

impl WalletSource for WalletOpts {
    fn load_signer(&self, _password: Option<&str>) -> Result<PrivateKeySigner> {
        match self {
            WalletOpts::Keystore { path, password } => {
                load_keystore_signer(path, password.as_deref())
            }
            WalletOpts::PrivateKey { key } => load_private_key_signer(key),
        }
    }
}

impl WalletSource for crate::config::EvmConfig {
    fn load_signer(&self, password: Option<&str>) -> Result<PrivateKeySigner> {
        let keystore_path = self.keystore.as_ref().ok_or_else(|| {
            PurlError::ConfigMissing(
                "No EVM keystore configured. Run 'purl wallet add' to set up.".to_string(),
            )
        })?;

        load_keystore_signer(keystore_path, password)
    }
}

/// Load a signer from an encrypted keystore file
pub fn load_keystore_signer(
    keystore_path: &Path,
    password: Option<&str>,
) -> Result<PrivateKeySigner> {
    let private_key = keystore::decrypt_keystore(keystore_path, password)?;

    PrivateKeySigner::from_slice(&private_key)
        .map_err(|e| PurlError::InvalidKey(format!("Invalid private key: {e}")))
}

/// Load a signer from a raw private key string
pub fn load_private_key_signer(private_key: &str) -> Result<PrivateKeySigner> {
    let key = strip_0x_prefix(private_key);

    let signer = key
        .parse::<PrivateKeySigner>()
        .map_err(|e| PurlError::InvalidKey(format!("Invalid private key: {e}")))?;

    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_private_key_signer() {
        let key = "0x1234567890123456789012345678901234567890123456789012345678901234";
        let result = load_private_key_signer(key);
        assert!(result.is_ok());

        let key = "1234567890123456789012345678901234567890123456789012345678901234";
        let result = load_private_key_signer(key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_invalid_private_key() {
        let key = "invalid_key";
        let result = load_private_key_signer(key);
        assert!(result.is_err());
    }
}
