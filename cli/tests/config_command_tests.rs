//! Integration tests for the config command

use assert_cmd::prelude::*;
use predicates::prelude::*;

mod common;
use common::{
    get_test_keystores_dir, setup_test_config, test_command, TestConfigBuilder,
    TEST_EVM_KEY as VALID_EVM_KEY, TEST_SOLANA_PUBKEY,
};

#[test]
fn test_config_text_output() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::contains("[evm]"))
        .stdout(predicate::str::contains("address = "))
        .stdout(predicate::str::contains("0x"))
        .stdout(predicate::str::contains(VALID_EVM_KEY).not());
}

#[test]
fn test_config_json_output() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "--output-format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"address\""))
        .stdout(predicate::str::contains("config_path"))
        .stdout(predicate::str::contains(VALID_EVM_KEY).not());
}

#[test]
fn test_config_yaml_output() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "--output-format", "yaml"])
        .assert()
        .success()
        .stdout(predicate::str::contains("address:"))
        .stdout(predicate::str::contains(VALID_EVM_KEY).not());
}

#[test]
fn test_config_empty() {
    let temp = setup_test_config(None, None);

    test_command(&temp)
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::contains("No payment methods configured"));
}

#[test]
fn test_config_evm_only() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::contains("[evm]"))
        .stdout(predicate::str::contains("[solana]").not());
}

#[test]
fn test_config_solana_only() {
    let temp = setup_test_config(None, Some(TEST_SOLANA_PUBKEY));

    test_command(&temp)
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::contains("[solana]"))
        .stdout(predicate::str::contains("[evm]").not());
}

#[test]
fn test_config_evm_and_solana() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), Some(TEST_SOLANA_PUBKEY));

    test_command(&temp)
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::contains("[evm]"))
        .stdout(predicate::str::contains("[solana]"));
}

#[test]
fn test_config_evm_keystore() {
    let temp = TestConfigBuilder::new()
        .with_evm_keystore("test-wallet", VALID_EVM_KEY)
        .build();

    test_command(&temp)
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::contains("[evm]"))
        .stdout(predicate::str::contains("keystore"));
}

#[test]
fn test_config_solana_keystore() {
    let temp = TestConfigBuilder::new()
        .with_solana_keystore("solana-wallet", TEST_SOLANA_PUBKEY)
        .build();

    test_command(&temp)
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::contains("[solana]"))
        .stdout(predicate::str::contains("keystore"));
}

#[test]
fn test_config_get_evm_address() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "get", "evm.address"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0x"));
}

#[test]
fn test_config_get_evm_keystore() {
    let temp = TestConfigBuilder::new()
        .with_evm_keystore("test-wallet", VALID_EVM_KEY)
        .build();

    test_command(&temp)
        .args(["config", "get", "evm.keystore"])
        .assert()
        .success()
        .stdout(predicate::str::contains("purl"))
        .stdout(predicate::str::contains("keystores"))
        .stdout(predicate::str::contains("test-wallet.json"));
}

#[test]
fn test_config_get_solana_public_key() {
    let temp = setup_test_config(None, Some(TEST_SOLANA_PUBKEY));

    test_command(&temp)
        .args(["config", "get", "solana.public_key"])
        .assert()
        .success();
}

#[test]
fn test_config_get_entire_section() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "get", "evm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keystore"));
}

#[test]
fn test_config_get_json_output() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "get", "evm.address", "--output-format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"0x"));
}

#[test]
fn test_config_get_yaml_output() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "get", "evm.address", "--output-format", "yaml"])
        .assert()
        .success();
}

#[test]
fn test_config_get_nonexistent_key() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "get", "nonexistent.key"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_config_get_missing_section() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "get", "solana.public_key"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_config_validate_valid_config() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "validate"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Configuration is valid"));
}

#[test]
fn test_config_validate_with_both_methods() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), Some(TEST_SOLANA_PUBKEY));

    test_command(&temp)
        .args(["config", "validate"])
        .assert()
        .success()
        .stdout(predicate::str::contains("evm configuration: OK"))
        .stdout(predicate::str::contains("solana configuration: OK"));
}

#[test]
fn test_config_validate_empty_config() {
    let temp = setup_test_config(None, None);

    test_command(&temp)
        .args(["config", "validate"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("No payment methods configured"));
}

#[test]
fn test_config_validate_missing_keystore() {
    use std::fs;
    let temp = TestConfigBuilder::new()
        .with_evm_keystore("missing-wallet", VALID_EVM_KEY)
        .build();

    let keystore_path = get_test_keystores_dir(&temp).join("missing-wallet.json");
    if keystore_path.exists() {
        fs::remove_file(keystore_path).unwrap();
    }

    test_command(&temp)
        .args(["config", "validate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("keystore file not found"));
}
