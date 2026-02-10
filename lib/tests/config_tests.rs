//! Integration tests for configuration management

use purl_lib::{Config, EvmConfig, PaymentMethod, SolanaConfig};

#[test]
fn test_config_serialization_roundtrip() {
    let config = Config {
        evm: Some(EvmConfig {
            keystore: Some(std::path::PathBuf::from("/path/to/evm.json")),
        }),
        solana: Some(SolanaConfig {
            keystore: Some(std::path::PathBuf::from("/path/to/solana.json")),
        }),
        ..Default::default()
    };

    let toml_str = toml::to_string_pretty(&config).expect("Failed to serialize");
    let deserialized: Config = toml::from_str(&toml_str).expect("Failed to deserialize");

    assert!(deserialized.evm.is_some());
    assert!(deserialized.solana.is_some());
    assert_eq!(
        deserialized.evm.as_ref().unwrap().keystore,
        config.evm.as_ref().unwrap().keystore
    );
    assert_eq!(
        deserialized.solana.as_ref().unwrap().keystore,
        config.solana.as_ref().unwrap().keystore
    );
}

#[test]
fn test_available_payment_methods() {
    struct TestCase {
        evm: Option<EvmConfig>,
        solana: Option<SolanaConfig>,
        expected_len: usize,
        should_contain_evm: bool,
        should_contain_solana: bool,
    }

    let test_cases = vec![
        TestCase {
            evm: Some(EvmConfig {
                keystore: Some(std::path::PathBuf::from("/path/to/evm.json")),
            }),
            solana: Some(SolanaConfig {
                keystore: Some(std::path::PathBuf::from("/path/to/solana.json")),
            }),
            expected_len: 2,
            should_contain_evm: true,
            should_contain_solana: true,
        },
        TestCase {
            evm: Some(EvmConfig {
                keystore: Some(std::path::PathBuf::from("/path/to/evm.json")),
            }),
            solana: None,
            expected_len: 1,
            should_contain_evm: true,
            should_contain_solana: false,
        },
        TestCase {
            evm: None,
            solana: Some(SolanaConfig {
                keystore: Some(std::path::PathBuf::from("/path/to/solana.json")),
            }),
            expected_len: 1,
            should_contain_evm: false,
            should_contain_solana: true,
        },
        TestCase {
            evm: None,
            solana: None,
            expected_len: 0,
            should_contain_evm: false,
            should_contain_solana: false,
        },
    ];

    for test_case in test_cases {
        let config = Config {
            evm: test_case.evm,
            solana: test_case.solana,
            ..Default::default()
        };

        let methods = config.available_payment_methods();
        assert_eq!(
            methods.len(),
            test_case.expected_len,
            "Expected {} payment methods",
            test_case.expected_len
        );
        assert_eq!(
            methods.contains(&PaymentMethod::Evm),
            test_case.should_contain_evm,
            "EVM method presence should be {}",
            test_case.should_contain_evm
        );
        assert_eq!(
            methods.contains(&PaymentMethod::Solana),
            test_case.should_contain_solana,
            "Solana method presence should be {}",
            test_case.should_contain_solana
        );
    }
}

#[test]
fn test_config_validation_evm_keystore() {
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

    // Config with non-existent keystore should fail validation
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
fn test_payment_method_as_str() {
    let test_cases = vec![
        (PaymentMethod::Evm, "evm"),
        (PaymentMethod::Solana, "solana"),
    ];

    for (method, expected_str) in test_cases {
        assert_eq!(
            method.as_str(),
            expected_str,
            "PaymentMethod::{method:?} should have string representation '{expected_str}'"
        );
    }
}

#[test]
fn test_config_partial_deserialization() {
    let toml = r#"
        [evm]
        keystore = "/path/to/evm.json"
    "#;

    let config: Config = toml::from_str(toml).expect("Failed to parse");
    assert!(config.evm.is_some());
    assert!(config.solana.is_none());
    assert_eq!(
        config.evm.as_ref().unwrap().keystore,
        Some(std::path::PathBuf::from("/path/to/evm.json"))
    );
}

#[test]
fn test_config_empty_is_valid() {
    let toml = r#""#;

    let config: Config = toml::from_str(toml).expect("Failed to parse empty config");
    assert!(config.evm.is_none());
    assert!(config.solana.is_none());
}
