//! Integration tests for payment providers

use purl_lib::{Config, EvmConfig, SolanaConfig, PROVIDER_REGISTRY};

#[test]
fn test_provider_registry_is_initialized() {
    let registry = &*PROVIDER_REGISTRY;
    assert!(registry.find_provider("base").is_some());
    assert!(registry.find_provider("solana").is_some());
}

#[test]
fn test_find_provider_for_networks() {
    let registry = &*PROVIDER_REGISTRY;

    let test_cases = vec![
        ("ethereum", true),
        ("base", true),
        ("base-sepolia", true),
        ("solana", true),
        ("solana-devnet", true),
        ("xx-unknown", false),
    ];

    for (network, should_exist) in test_cases {
        assert_eq!(
            registry.find_provider(network).is_some(),
            should_exist,
            "Provider for network {} should {}",
            network,
            if should_exist { "exist" } else { "not exist" }
        );
    }
}

#[test]
fn test_provider_not_found_for_unknown_network() {
    let registry = &*PROVIDER_REGISTRY;

    let test_cases = vec!["unknown-network", "bitcoin", ""];

    for network in test_cases {
        assert!(
            registry.find_provider(network).is_none(),
            "Provider for unknown network '{network}' should not exist"
        );
    }
}

#[test]
fn test_provider_names() {
    let registry = &*PROVIDER_REGISTRY;

    let test_cases = vec![("base", "EVM"), ("solana", "Solana")];

    for (network, expected_name) in test_cases {
        let provider = registry
            .find_provider(network)
            .unwrap_or_else(|| panic!("Should find {network} provider"));

        assert_eq!(
            provider.name(),
            expected_name,
            "Provider for network {network} should have name {expected_name}"
        );
    }
}

#[test]
fn test_validate_empty_config() {
    let config = Config {
        evm: None,
        solana: None,
        ..Default::default()
    };

    // Empty config should be valid (no wallets configured is OK)
    let result = config.validate();
    assert!(result.is_ok());
}

#[test]
fn test_validate_evm_config_keystore() {
    // Config without keystore should be valid (no wallet configured)
    let config = Config {
        evm: Some(EvmConfig { keystore: None }),
        solana: None,
        ..Default::default()
    };
    assert!(
        config.validate().is_ok(),
        "EVM config without keystore should be valid"
    );

    // Config with non-existent keystore should be invalid
    let config_with_bad_keystore = Config {
        evm: Some(EvmConfig {
            keystore: Some(std::path::PathBuf::from("/nonexistent/keystore.json")),
        }),
        solana: None,
        ..Default::default()
    };
    assert!(
        config_with_bad_keystore.validate().is_err(),
        "EVM config with non-existent keystore should be invalid"
    );
}

#[test]
fn test_validate_both_configs_without_keystores() {
    // Config with both EVM and Solana sections but no keystores should be valid
    let config = Config {
        evm: Some(EvmConfig { keystore: None }),
        solana: Some(SolanaConfig { keystore: None }),
        ..Default::default()
    };

    // This should be valid - no keystores configured
    assert!(config.validate().is_ok());
}

#[test]
fn test_provider_supports_correct_networks() {
    let registry = &*PROVIDER_REGISTRY;

    let evm_provider = registry.find_provider("base").unwrap();
    let evm_test_cases = vec![("base", true), ("ethereum", true), ("solana", false)];

    for (network, should_support) in evm_test_cases {
        assert_eq!(
            evm_provider.supports_network(network),
            should_support,
            "EVM provider should {} support network {}",
            if should_support { "" } else { "not" },
            network
        );
    }

    let solana_provider = registry.find_provider("solana").unwrap();
    let solana_test_cases = vec![("solana", true), ("solana-devnet", true), ("base", false)];

    for (network, should_support) in solana_test_cases {
        assert_eq!(
            solana_provider.supports_network(network),
            should_support,
            "Solana provider should {} support network {}",
            if should_support { "" } else { "not" },
            network
        );
    }
}

#[test]
fn test_find_provider_is_case_sensitive() {
    let registry = &*PROVIDER_REGISTRY;

    let test_cases = vec![("base", true), ("BASE", false), ("Base", false)];

    for (network, should_exist) in test_cases {
        assert_eq!(
            registry.find_provider(network).is_some(),
            should_exist,
            "Provider lookup for '{}' should {} (case-sensitive)",
            network,
            if should_exist { "succeed" } else { "fail" }
        );
    }
}

#[test]
fn test_multiple_providers_dont_conflict() {
    let registry = &*PROVIDER_REGISTRY;

    let evm = registry.find_provider("base");
    let solana = registry.find_provider("solana");

    assert!(evm.is_some());
    assert!(solana.is_some());
    assert_ne!(evm.unwrap().name(), solana.unwrap().name());
}
