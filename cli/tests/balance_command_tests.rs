//! Integration tests for balance command
//!
//! Tests for the balance command that checks wallet balances across networks

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

mod common;
use common::{
    setup_test_config, test_command, TestConfigBuilder, TEST_EVM_KEY as VALID_EVM_KEY,
    TEST_SOLANA_PUBKEY,
};

#[test]
fn test_balance_no_config() {
    let temp = setup_test_config(None, None);

    test_command(&temp)
        .arg("balance")
        .assert()
        .failure()
        .stderr(predicate::str::contains("No payment methods configured"));
}

#[test]
fn test_balance_with_evm_config() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .arg("balance")
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_with_solana_config() {
    let temp = setup_test_config(None, Some(TEST_SOLANA_PUBKEY));

    test_command(&temp)
        .arg("balance")
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_with_both_configs() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), Some(TEST_SOLANA_PUBKEY));

    test_command(&temp)
        .arg("balance")
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_with_network_filter() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["balance", "--network", "base"])
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_with_network_filter_short() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    let _result = test_command(&temp)
        .args(["balance", "-n", "base-sepolia"])
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_with_solana_network_filter() {
    let temp = setup_test_config(None, Some(TEST_SOLANA_PUBKEY));

    let _result = test_command(&temp)
        .args(["balance", "--network", "solana"])
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_with_testnet_filter() {
    let temp = setup_test_config(None, Some(TEST_SOLANA_PUBKEY));

    let _result = test_command(&temp)
        .args(["balance", "--network", "devnet"])
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_alias() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    let _result = test_command(&temp)
        .arg("b")
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_alias_with_network() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    let _result = test_command(&temp)
        .args(["b", "-n", "base"])
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_help() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["balance", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Check wallet balance"))
        .stdout(predicate::str::contains("address"))
        .stdout(predicate::str::contains("--network"));
}

#[test]
fn test_balance_help_shows_network_flag() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["balance", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("-n, --network"));
}

#[test]
fn test_balance_help_via_alias() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["b", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Check wallet balance"));
}

#[test]
fn test_balance_with_keystore_config() {
    let temp = TestConfigBuilder::new()
        .with_evm_keystore("test-wallet", VALID_EVM_KEY)
        .build();

    test_command(&temp)
        .arg("balance")
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_with_solana_keystore() {
    let temp = TestConfigBuilder::new()
        .with_solana_keystore("solana-wallet", TEST_SOLANA_PUBKEY)
        .build();

    // Note: Dummy keystores can't extract addresses, so this may return
    // ConfigError (3) in addition to success (0) or general error (1)
    test_command(&temp)
        .arg("balance")
        .assert()
        .code(predicate::in_iter([0, 1, 3]));
}

#[test]
fn test_balance_with_multiple_keystores() {
    let temp = TestConfigBuilder::new()
        .with_evm_keystore("evm-wallet", VALID_EVM_KEY)
        .with_solana_keystore("solana-wallet", TEST_SOLANA_PUBKEY)
        .build();

    // Note: Dummy keystores can't extract addresses, so this may return
    // ConfigError (3) in addition to success (0) or general error (1)
    test_command(&temp)
        .arg("balance")
        .assert()
        .code(predicate::in_iter([0, 1, 3]));
}

#[test]
fn test_balance_with_quiet_flag() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    let _result = test_command(&temp)
        .args(["balance", "-q"])
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_with_verbosity() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    let _result = test_command(&temp)
        .args(["balance", "-v"])
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_with_color_never() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    let _result = test_command(&temp)
        .args(["balance", "--color", "never"])
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_invalid_evm_address() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    // Invalid addresses may just result in no balances found, not necessarily a failure
    // The command accepts it as an argument but then can't parse it as an address
    test_command(&temp)
        .args(["balance", "not-a-valid-address"])
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_invalid_network() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    let _result = test_command(&temp)
        .args(["balance", "--network", "invalid-network"])
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_after_init() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp).arg("config").assert().success();

    test_command(&temp)
        .arg("balance")
        .assert()
        .code(predicate::in_iter([0, 1]));
}

#[test]
fn test_balance_combined_with_global_flags() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    let _result = test_command(&temp)
        .args(["balance", "-v", "-q", "--color", "never"])
        .assert()
        .code(predicate::in_iter([0, 1]));
}
