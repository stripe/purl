//! Configuration loading utilities for the CLI

use anyhow::{Context, Result};
use purl_lib::Config;
use std::path::Path;

/// Load configuration from CLI arguments or default location.
pub fn load_config(config_path: Option<impl AsRef<Path>>) -> Result<Config> {
    Config::load_from(config_path).context("Failed to load configuration")
}
