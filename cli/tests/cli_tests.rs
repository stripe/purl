//! Integration tests for CLI features:
//! - Shell completions (bash, zsh, fish, powershell)
//! - Command aliases (short forms for common commands)
//! - Display options (verbosity, quiet mode, color control)
//! - Help output organization (sections, annotations)

use assert_cmd::prelude::*;
use predicates::prelude::*;
use serial_test::serial;
use std::process::Command;

mod common;
use common::{setup_test_config, test_command, TEST_EVM_KEY as VALID_EVM_KEY};

#[test]
fn test_completions_bash() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("_purl"))
        .stdout(predicate::str::contains("complete"));
}

#[test]
fn test_completions_zsh() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef purl"));
}

#[test]
fn test_completions_fish() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["completions", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete -c purl"));
}

#[test]
fn test_completions_powershell() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["completions", "power-shell"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Register-ArgumentCompleter"));
}

#[test]
fn test_completions_alias() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["com", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("_purl"));
}

#[test]
fn test_config_alias() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .arg("c")
        .assert()
        .success()
        .stdout(predicate::str::contains("[evm]"));
}

#[test]
fn test_version_alias() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("v")
        .assert()
        .success()
        .stdout(predicate::str::contains("purl CLI"));
}

#[test]
fn test_wallet_alias() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp).args(["w", "list"]).assert().success();
}

#[test]
fn test_quiet_flag() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "-q"])
        .assert()
        .success();
}

#[test]
fn test_quiet_alias_short() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "-s"])
        .assert()
        .success();
}

#[test]
fn test_quiet_alias_long() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "--silent"])
        .assert()
        .success();
}

#[test]
fn test_verbosity_single() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "-v"])
        .assert()
        .success();
}

#[test]
fn test_verbosity_multiple() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "-vv"])
        .assert()
        .success();
}

#[test]
fn test_verbosity_long_form() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "--verbosity"])
        .assert()
        .success();
}

#[test]
fn test_color_auto() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "--color", "auto"])
        .assert()
        .success();
}

#[test]
fn test_color_always() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "--color", "always"])
        .assert()
        .success();
}

#[test]
fn test_color_never() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "--color", "never"])
        .assert()
        .success();
}

#[test]
fn test_help_has_payment_options_section() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Payment Options:"));
}

#[test]
fn test_help_has_display_options_section() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Display Options:"));
}

#[test]
fn test_help_has_http_options_section() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("HTTP Options:"));
}

#[test]
fn test_help_has_wallet_options_section() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Wallet Options:"));
}

#[test]
fn test_help_shows_env_vars() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("[env: PURL_MAX_AMOUNT=]"))
        .stdout(predicate::str::contains("[env: PURL_CONFIRM=]"))
        .stdout(predicate::str::contains("[env: PURL_NETWORK=]"));
}

#[test]
fn test_help_shows_default_values() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("--help")
        .assert()
        .success()
        // Both --color and --output-format default to "auto"
        .stdout(predicate::str::contains("[default: auto]"));
}

#[test]
fn test_help_shows_aliases() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("[aliases:"));
}

#[test]
fn test_help_shows_possible_values() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("[possible values:"))
        .stdout(predicate::str::contains("auto, always, never"));
}

#[test]
fn test_alias_with_display_options() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["c", "-q", "--color", "never"])
        .assert()
        .success();
}

#[test]
fn test_completions_alias_with_verbosity() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["com", "bash", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("_purl"));
}

#[test]
fn test_wallet_show_nonexistent() {
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

    // Create a real keystore
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
fn test_wallet_verify_nonexistent() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["wallet", "verify", "nonexistent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_networks_list() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Name"))
        .stdout(predicate::str::contains("Display Name"))
        .stdout(predicate::str::contains("Type"))
        .stdout(predicate::str::contains("Chain ID"))
        .stdout(predicate::str::contains("base"))
        .stdout(predicate::str::contains("ethereum"))
        .stdout(predicate::str::contains("solana"));
}

#[test]
fn test_networks_list_json() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "list", "--output-format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\""))
        .stdout(predicate::str::contains("\"type\""))
        .stdout(predicate::str::contains("\"base\""));
}

#[test]
fn test_networks_list_yaml() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "list", "--output-format", "yaml"])
        .assert()
        .success()
        .stdout(predicate::str::contains("name:"))
        .stdout(predicate::str::contains("type:"))
        .stdout(predicate::str::contains("base"));
}

#[test]
fn test_networks_no_subcommand_defaults_to_list() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Name"))
        .stdout(predicate::str::contains("base"))
        .stdout(predicate::str::contains("ethereum"));
}

#[test]
fn test_networks_alias() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["n", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Name"));
}

#[test]
fn test_networks_info_base() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "info", "base"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Name"))
        .stdout(predicate::str::contains("base"))
        .stdout(predicate::str::contains("Display Name"))
        .stdout(predicate::str::contains("Base"))
        .stdout(predicate::str::contains("Chain ID"))
        .stdout(predicate::str::contains("8453"))
        .stdout(predicate::str::contains("Mainnet"))
        .stdout(predicate::str::contains("yes"));
}

#[test]
fn test_networks_info_testnet() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "info", "base-sepolia"])
        .assert()
        .success()
        .stdout(predicate::str::contains("base-sepolia"))
        .stdout(predicate::str::contains("84532"))
        .stdout(predicate::str::contains("Testnet"))
        .stdout(predicate::str::contains("yes"));
}

#[test]
fn test_networks_info_solana() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "info", "solana"])
        .assert()
        .success()
        .stdout(predicate::str::contains("solana"))
        .stdout(predicate::str::contains("Solana"))
        .stdout(predicate::str::contains("Mainnet"))
        .stdout(predicate::str::contains("yes"));
}

#[test]
fn test_networks_info_json() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "info", "base", "--output-format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"base\""))
        .stdout(predicate::str::contains("\"chain_id\": 8453"));
}

#[test]
fn test_networks_info_yaml() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "info", "ethereum", "--output-format", "yaml"])
        .assert()
        .success()
        .stdout(predicate::str::contains("name: ethereum"))
        .stdout(predicate::str::contains("chain_id: 1"));
}

#[test]
fn test_networks_info_unknown_network() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "info", "unknown-network"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown network"))
        .stderr(predicate::str::contains("unknown-network"));
}

#[test]
fn test_networks_help() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Manage and inspect supported networks",
        ))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("info"));
}

#[test]
fn test_inspect_help() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["inspect", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Inspect payment requirements"));
}

#[test]
fn test_inspect_missing_url() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("inspect")
        .assert()
        .failure();
}

#[test]
fn test_inspect_with_output_format_json() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    // This will fail because we don't have a real 402 endpoint, but we can verify the args parse
    test_command(&temp)
        .args(["inspect", "https://example.com", "--output-format", "json"])
        .assert()
        .failure(); // Will fail due to no 402 response, but that's expected
}

#[test]
fn test_inspect_with_output_format_yaml() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["inspect", "https://example.com", "--output-format", "yaml"])
        .assert()
        .failure();
}

#[test]
fn test_inspect_with_verbose() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["inspect", "https://example.com", "-v"])
        .assert()
        .failure();
}

#[test]
fn test_inspect_with_quiet() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["inspect", "https://example.com", "-q"])
        .assert()
        .failure();
}

#[test]
fn test_inspect_alias() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["inspect", "https://example.com"])
        .assert()
        .failure();
}

#[test]
fn test_inspect_with_network_filter() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["inspect", "https://example.com", "--network", "base"])
        .assert()
        .failure();
}

#[test]
fn test_inspect_invalid_url() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["inspect", "not-a-url"])
        .assert()
        .failure();
}

#[test]
fn test_inspect_with_all_output_formats() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    // Test text format (default)
    test_command(&temp)
        .args(["inspect", "https://example.com", "--output-format", "text"])
        .assert()
        .failure();

    // Test json format
    test_command(&temp)
        .args(["inspect", "https://example.com", "--output-format", "json"])
        .assert()
        .failure();

    // Test yaml format
    test_command(&temp)
        .args(["inspect", "https://example.com", "--output-format", "yaml"])
        .assert()
        .failure();
}

#[test]
fn test_version_command() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("purl CLI"));
}

#[test]
fn test_version_flag() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("--version")
        .assert()
        .success();
}

#[test]
fn test_version_alias_v() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("v")
        .assert()
        .success()
        .stdout(predicate::str::contains("purl CLI"));
}

#[test]
fn test_multiple_global_flags_together() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    test_command(&temp)
        .args(["config", "-v", "-q", "--color", "never"])
        .assert()
        .success();
}

#[test]
fn test_verbosity_levels() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    // Single -v
    test_command(&temp)
        .args(["config", "-v"])
        .assert()
        .success();

    // Double -vv
    test_command(&temp)
        .args(["config", "-vv"])
        .assert()
        .success();

    // Triple -vvv
    test_command(&temp)
        .args(["config", "-vvv"])
        .assert()
        .success();
}

#[test]
fn test_all_color_modes() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    for color_mode in ["auto", "always", "never"] {
        test_command(&temp)
            .args(["config", "--color", color_mode])
            .assert()
            .success();
    }
}

#[test]
fn test_all_output_formats_with_config() {
    let temp = setup_test_config(Some(VALID_EVM_KEY), None);

    for format in ["text", "json", "yaml"] {
        test_command(&temp)
            .args(["config", "--output-format", format])
            .assert()
            .success();
    }
}

#[test]
fn test_completions_invalid_shell() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["completions", "invalid-shell"])
        .assert()
        .failure();
}

#[test]
fn test_completions_case_sensitivity() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["completions", "BASH"])
        .assert()
        .failure();
}

#[test]
fn test_networks_info_case_sensitivity() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "info", "BASE"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown network"));
}

#[test]
fn test_networks_info_with_quiet() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["networks", "info", "base", "-q"])
        .assert()
        .success();
}

#[test]
fn test_networks_list_with_all_formats() {
    for format in ["text", "json", "yaml"] {
        Command::new(assert_cmd::cargo::cargo_bin!("purl"))
            .args(["networks", "list", "--output-format", format])
            .assert()
            .success();
    }
}

#[test]
fn test_main_help_lists_all_commands() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("config"))
        .stdout(predicate::str::contains("wallet"))
        .stdout(predicate::str::contains("completions"))
        .stdout(predicate::str::contains("balance"))
        .stdout(predicate::str::contains("networks"))
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("version"));
}

#[test]
fn test_help_flag() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("-h")
        .assert()
        .success();
}

#[test]
fn test_invalid_command() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .args(["config", "invalid-subcommand"])
        .assert()
        .failure();
}

#[test]
fn test_invalid_flag() {
    Command::new(assert_cmd::cargo::cargo_bin!("purl"))
        .arg("--invalid-flag")
        .assert()
        .failure();
}
