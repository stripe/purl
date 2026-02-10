use assert_cmd::prelude::*;
use predicates::prelude::*;
use serial_test::serial;
use std::fs;
use std::process::Command;

mod common;
use common::{
    get_test_keystores_dir, setup_test_config, test_command, TestConfigBuilder,
    TEST_EVM_KEY as VALID_EVM_KEY,
};

#[test]
fn test_wallet_list_no_keystores() {
    // Setup with no config at all - just an empty temp directory
    let temp = setup_test_config(None, None);

    test_command(&temp)
        .args(["wallet", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No wallets found"))
        .stdout(predicate::str::contains("purl wallet create"));
}

#[test]
fn test_wallet_list_with_keystores() {
    let temp = TestConfigBuilder::new()
        .with_evm_keystore("test-wallet", VALID_EVM_KEY)
        .build();

    test_command(&temp)
        .args(["wallet", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Wallets:"))
        .stdout(predicate::str::contains("test-wallet"));
}

#[test]
fn test_wallet_list_multiple_keystores() {
    let temp = TestConfigBuilder::new()
        .with_evm_keystore("wallet-one", VALID_EVM_KEY)
        .build();

    let keystores_dir = get_test_keystores_dir(&temp);
    fs::create_dir_all(&keystores_dir).unwrap();
    fs::write(
        keystores_dir.join("wallet-two.json"),
        r#"{"address":"0x1234567890123456789012345678901234567890","crypto":{}}"#,
    )
    .unwrap();

    test_command(&temp)
        .args(["wallet", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("wallet-one"))
        .stdout(predicate::str::contains("wallet-two"));
}

#[test]
fn test_wallet_list_alias() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp).args(["w", "list"]).assert().success();
}

#[test]
fn test_wallet_show_nonexistent_keystore() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["wallet", "show", "nonexistent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
#[serial]
fn test_wallet_show_existing_keystore() {
    let temp = tempfile::TempDir::new().unwrap();

    let _keystore_path =
        common::create_test_keystore(&temp, "test-wallet", VALID_EVM_KEY, "test-password");

    test_command(&temp)
        .args(["wallet", "show", "test-wallet"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Wallet Details:"))
        .stdout(predicate::str::contains("Name: test-wallet"))
        .stdout(predicate::str::contains("Address:"));
}

#[test]
#[serial]
fn test_wallet_show_displays_path() {
    let temp = tempfile::TempDir::new().unwrap();

    let _keystore_path =
        common::create_test_keystore(&temp, "test-wallet", VALID_EVM_KEY, "test-password");

    test_command(&temp)
        .args(["wallet", "show", "test-wallet"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Path:"))
        .stdout(predicate::str::contains("purl"))
        .stdout(predicate::str::contains("keystores"))
        .stdout(predicate::str::contains("test-wallet.json"));
}

#[test]
#[serial]
fn test_wallet_show_displays_encryption_info() {
    let temp = tempfile::TempDir::new().unwrap();

    let _keystore_path =
        common::create_test_keystore(&temp, "test-wallet", VALID_EVM_KEY, "test-password");

    test_command(&temp)
        .args(["wallet", "show", "test-wallet"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encryption:"));
}

#[test]
#[serial]
fn test_wallet_show_name_without_json_extension() {
    let temp = tempfile::TempDir::new().unwrap();

    let _keystore_path =
        common::create_test_keystore(&temp, "test-wallet", VALID_EVM_KEY, "test-password");

    // Should work with or without .json extension
    test_command(&temp)
        .args(["wallet", "show", "test-wallet"])
        .assert()
        .success();
}

#[test]
fn test_wallet_verify_nonexistent_keystore() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["wallet", "verify", "nonexistent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_wallet_alias_list() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp).args(["w", "list"]).assert().success();
}

#[test]
#[serial]
fn test_wallet_alias_show() {
    let temp = tempfile::TempDir::new().unwrap();

    let _keystore_path =
        common::create_test_keystore(&temp, "test-wallet", VALID_EVM_KEY, "test-password");

    test_command(&temp)
        .args(["w", "show", "test-wallet"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Wallet Details:"));
}

#[test]
fn test_wallet_help() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["wallet", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Manage wallets"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("add"))
        .stdout(predicate::str::contains("show"))
        .stdout(predicate::str::contains("verify"));
}

#[test]
fn test_wallet_list_help() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["wallet", "list", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("List available wallets"));
}

#[test]
fn test_wallet_create_alias_help() {
    // "create" is now an alias for "add"
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["wallet", "create", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Create a new wallet"))
        .stdout(predicate::str::contains("--wallet-type"))
        .stdout(predicate::str::contains("--private-key"));
}

#[test]
fn test_wallet_add_help() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["wallet", "add", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Create a new wallet"))
        .stdout(predicate::str::contains("--name"))
        .stdout(predicate::str::contains("--wallet-type"))
        .stdout(predicate::str::contains("--private-key"));
}

#[test]
fn test_wallet_show_help() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["wallet", "show", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Show wallet details"));
}

#[test]
fn test_wallet_verify_help() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["wallet", "verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Verify wallet integrity"));
}

#[test]
fn test_wallet_invalid_subcommand() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["wallet", "invalid"])
        .assert()
        .failure();
}

#[test]
fn test_wallet_show_corrupted_keystore() {
    let temp = tempfile::TempDir::new().unwrap();
    let keystores_dir = get_test_keystores_dir(&temp);
    fs::create_dir_all(&keystores_dir).unwrap();

    fs::write(
        keystores_dir.join("corrupted.json"),
        "this is not valid json",
    )
    .unwrap();

    test_command(&temp)
        .args(["wallet", "show", "corrupted"])
        .assert()
        .failure();
}

#[test]
fn test_wallet_list_displays_address_if_available() {
    let temp = tempfile::TempDir::new().unwrap();
    let keystores_dir = get_test_keystores_dir(&temp);
    fs::create_dir_all(&keystores_dir).unwrap();

    fs::write(
        keystores_dir.join("with-address.json"),
        r#"{"address":"1234567890abcdef1234567890abcdef12345678","crypto":{}}"#,
    )
    .unwrap();

    test_command(&temp)
        .args(["wallet", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "0x1234567890abcdef1234567890abcdef12345678",
        ));
}

#[test]
fn test_wallet_list_handles_keystore_without_address() {
    let temp = tempfile::TempDir::new().unwrap();
    let keystores_dir = get_test_keystores_dir(&temp);
    fs::create_dir_all(&keystores_dir).unwrap();

    fs::write(keystores_dir.join("no-address.json"), r#"{"crypto":{}}"#).unwrap();

    test_command(&temp)
        .args(["wallet", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no-address"))
        .stdout(predicate::str::contains("no identifier"));
}

#[test]
fn test_wallet_show_with_configured_keystore() {
    let temp = TestConfigBuilder::new()
        .with_evm_keystore("configured-wallet", VALID_EVM_KEY)
        .build();

    test_command(&temp)
        .args(["wallet", "show", "configured-wallet"])
        .assert()
        .success()
        .stdout(predicate::str::contains("configured-wallet"));
}

#[test]
fn test_wallet_list_after_config_init() {
    let temp = TestConfigBuilder::new()
        .with_evm_keystore("init-wallet", VALID_EVM_KEY)
        .with_solana_keystore("solana-wallet", common::TEST_SOLANA_PUBKEY)
        .build();

    test_command(&temp)
        .args(["wallet", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Wallets:"))
        .stdout(predicate::str::contains("init-wallet"))
        .stdout(predicate::str::contains("solana-wallet"));
}

#[test]
fn test_wallet_list_with_quiet_flag() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["wallet", "list", "-q"])
        .assert()
        .success();
}

#[test]
fn test_wallet_list_with_verbosity() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["wallet", "list", "-v"])
        .assert()
        .success();
}

#[test]
#[serial]
fn test_wallet_show_with_color_options() {
    let temp = tempfile::TempDir::new().unwrap();

    let _keystore_path =
        common::create_test_keystore(&temp, "test-wallet", VALID_EVM_KEY, "test-password");

    test_command(&temp)
        .args(["wallet", "show", "test-wallet", "--color", "never"])
        .assert()
        .success();
}
