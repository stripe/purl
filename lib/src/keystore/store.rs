//! Keystore types and loading functionality
//!
//! Provides types for representing and loading keystore files.

use crate::error::{PurlError, Result};
use crate::utils::format_eth_address;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Represents a loaded keystore file
#[derive(Debug, Clone)]
pub struct Keystore {
    /// Path to the keystore file
    pub path: PathBuf,
    /// Parsed JSON content of the keystore
    pub content: Value,
}

impl Keystore {
    /// Load a keystore from a file path
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            PurlError::ConfigMissing(format!(
                "Failed to read keystore at {}: {}",
                path.display(),
                e
            ))
        })?;

        let json: Value = serde_json::from_str(&content).map_err(|e| {
            PurlError::ConfigMissing(format!(
                "Invalid keystore JSON at {}: {}",
                path.display(),
                e
            ))
        })?;

        Ok(Self {
            path: path.to_path_buf(),
            content: json,
        })
    }

    /// Get the raw address from the keystore (without 0x prefix)
    pub fn address(&self) -> Option<&str> {
        self.content["address"].as_str()
    }

    /// Get the address with 0x prefix
    pub fn formatted_address(&self) -> Option<String> {
        self.address().map(format_eth_address)
    }

    /// Decrypt the keystore with the given password
    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>> {
        eth_keystore::decrypt_key(&self.path, password)
            .map_err(|e| PurlError::InvalidKey(format!("Failed to decrypt keystore: {e}")))
    }

    /// Validate that this is a properly formatted keystore file
    pub fn validate(&self) -> Result<()> {
        if !self.content.is_object() {
            return Err(PurlError::ConfigMissing(
                "Keystore must be a JSON object".to_string(),
            ));
        }

        // Support both 'crypto' and 'Crypto' (standard v3 keystore uses 'crypto')
        if !self.content["crypto"].is_object() && !self.content["Crypto"].is_object() {
            return Err(PurlError::ConfigMissing(
                "Keystore missing crypto field".to_string(),
            ));
        }

        Ok(())
    }
}

/// Information about a keystore file (for display purposes)
#[derive(Debug, Clone)]
pub struct KeystoreInfo {
    /// Path to the keystore file
    pub path: PathBuf,
    /// Filename
    pub filename: String,
    /// Formatted address (with 0x prefix), if available
    pub address: Option<String>,
    /// Whether the keystore is valid
    pub valid: bool,
}

impl KeystoreInfo {
    /// Load keystore info from a path
    pub fn from_path(path: &Path) -> Self {
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown")
            .to_string();

        match Keystore::load(path) {
            Ok(keystore) => Self {
                path: path.to_path_buf(),
                filename,
                address: keystore.formatted_address(),
                valid: keystore.validate().is_ok(),
            },
            Err(_) => Self {
                path: path.to_path_buf(),
                filename,
                address: None,
                valid: false,
            },
        }
    }

    /// Format for display
    pub fn display(&self) -> String {
        if let Some(ref addr) = self.address {
            format!("{} ({})", self.filename, addr)
        } else if !self.valid {
            format!("{} (invalid)", self.filename)
        } else {
            format!("{} (no address)", self.filename)
        }
    }
}
