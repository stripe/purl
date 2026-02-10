//! Integration tests for network and token configuration

use purl_lib::constants::get_token_decimals;
use purl_lib::network::{
    get_evm_chain_id, get_network, is_evm_network, is_solana_network, ChainType, Network,
};

#[test]
fn test_network_enum_has_entries() {
    assert!(!Network::all().is_empty());
}

#[test]
fn test_get_network() {
    struct TestCase {
        name: &'static str,
        expected_chain_type: ChainType,
        expected_chain_id: Option<u64>,
        expected_mainnet: bool,
        expected_display_name: Option<&'static str>,
    }

    let test_cases = vec![
        TestCase {
            name: "ethereum",
            expected_chain_type: ChainType::Evm,
            expected_chain_id: Some(1),
            expected_mainnet: true,
            expected_display_name: Some("Ethereum"),
        },
        TestCase {
            name: "base",
            expected_chain_type: ChainType::Evm,
            expected_chain_id: Some(8453),
            expected_mainnet: true,
            expected_display_name: None,
        },
        TestCase {
            name: "base-sepolia",
            expected_chain_type: ChainType::Evm,
            expected_chain_id: Some(84532),
            expected_mainnet: false,
            expected_display_name: None,
        },
        TestCase {
            name: "solana",
            expected_chain_type: ChainType::Solana,
            expected_chain_id: None,
            expected_mainnet: true,
            expected_display_name: None,
        },
        TestCase {
            name: "solana-devnet",
            expected_chain_type: ChainType::Solana,
            expected_chain_id: None,
            expected_mainnet: false,
            expected_display_name: None,
        },
    ];

    for test_case in test_cases {
        let network = get_network(test_case.name);
        assert!(network.is_some(), "Network {} should exist", test_case.name);

        let info = network.unwrap();
        // Note: name is derived from the lookup key, not stored in NetworkInfo
        assert_eq!(info.chain_type, test_case.expected_chain_type);
        assert_eq!(info.chain_id, test_case.expected_chain_id);
        assert_eq!(info.mainnet, test_case.expected_mainnet);
        if let Some(expected_display_name) = test_case.expected_display_name {
            assert_eq!(info.display_name, expected_display_name);
        }
        if !test_case.expected_mainnet {
            assert!(
                info.is_testnet(),
                "Testnet network {} should return true for is_testnet()",
                test_case.name
            );
        }
    }
}

#[test]
fn test_get_network_unknown() {
    let network = get_network("unknown-network");
    assert!(network.is_none());

    let network = get_network("");
    assert!(network.is_none());
}

#[test]
fn test_is_evm_network() {
    let test_cases = vec![
        ("ethereum", true),
        ("base", true),
        ("base-sepolia", true),
        ("polygon", true),
        ("arbitrum", true),
        ("optimism", true),
        ("solana", false),
        ("solana-devnet", false),
        ("unknown", false),
    ];

    for (network, expected) in test_cases {
        assert_eq!(
            is_evm_network(network),
            expected,
            "is_evm_network({network}) should be {expected}"
        );
    }
}

#[test]
fn test_is_solana_network() {
    let test_cases = vec![
        ("solana", true),
        ("solana-devnet", true),
        ("ethereum", false),
        ("base", false),
        ("unknown", false),
    ];

    for (network, expected) in test_cases {
        assert_eq!(
            is_solana_network(network),
            expected,
            "is_solana_network({network}) should be {expected}"
        );
    }
}

#[test]
fn test_get_evm_chain_id() {
    let test_cases = vec![
        ("ethereum", Some(1)),
        ("base", Some(8453)),
        ("base-sepolia", Some(84532)),
        ("ethereum-sepolia", Some(11155111)),
        ("polygon", Some(137)),
        ("arbitrum", Some(42161)),
        ("optimism", Some(10)),
        ("avalanche", Some(43114)),
        ("avalanche-fuji", Some(43113)),
        // Solana networks don't have EVM chain IDs
        ("solana", None),
        ("unknown", None),
    ];

    for (network, expected_chain_id) in test_cases {
        assert_eq!(
            get_evm_chain_id(network),
            expected_chain_id,
            "get_evm_chain_id({network}) should be {expected_chain_id:?}"
        );
    }
}

#[test]
fn test_network_mainnet_flag() {
    let test_cases = vec![
        ("ethereum", true),
        ("base", true),
        ("solana", true),
        ("ethereum-sepolia", false),
        ("base-sepolia", false),
        ("solana-devnet", false),
    ];

    for (network, expected_mainnet) in test_cases {
        let info = get_network(network).unwrap();
        assert_eq!(
            info.mainnet, expected_mainnet,
            "Network {network} mainnet flag should be {expected_mainnet}"
        );
    }
}

#[test]
fn test_network_is_testnet_method() {
    let test_cases = vec![
        ("ethereum", false),
        ("base", false),
        ("ethereum-sepolia", true),
        ("base-sepolia", true),
    ];

    for (network, expected_is_testnet) in test_cases {
        let info = get_network(network).unwrap();
        assert_eq!(
            info.is_testnet(),
            expected_is_testnet,
            "Network {network} is_testnet() should be {expected_is_testnet}"
        );
    }
}

#[test]
fn test_all_evm_networks_have_chain_ids() {
    for network in Network::all() {
        let info = network.info();
        if info.chain_type == ChainType::Evm {
            assert!(
                info.chain_id.is_some(),
                "EVM network {network} should have a chain_id"
            );
        }
    }
}

#[test]
fn test_solana_networks_have_no_chain_ids() {
    for network in Network::all() {
        let info = network.info();
        if info.chain_type == ChainType::Solana {
            assert!(
                info.chain_id.is_none(),
                "Solana network {network} should not have a chain_id"
            );
        }
    }
}

// Token configuration tests

#[test]
fn test_get_token_decimals() {
    // Test success cases
    let success_cases = vec![
        ("solana", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", 6),
        (
            "solana-devnet",
            "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            6,
        ),
        ("base", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", 6),
        // evm addresses not case sensitive
        ("base", "0x833589FCD6EDB6E08F4C7C32D4F71B54BDA02913", 6),
        ("ethereum", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6),
    ];

    for (network, token_address, expected_decimals) in success_cases {
        let result = get_token_decimals(network, token_address);
        assert!(
            result.is_ok(),
            "get_token_decimals({network}, {token_address}) should succeed"
        );
        assert_eq!(
            result.unwrap(),
            expected_decimals,
            "get_token_decimals({network}, {token_address}) should return {expected_decimals}"
        );
    }

    let error_cases = vec![
        ("base", "0x0000000000000000000000000000000000000000"),
        (
            "unknown-network",
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        ),
        ("", ""),
    ];

    for (network, token_address) in error_cases {
        let result = get_token_decimals(network, token_address);
        assert!(
            result.is_err(),
            "get_token_decimals({network}, {token_address}) should return error"
        );
    }
}

#[test]
fn test_solana_addresses_are_case_sensitive() {
    let decimals = get_token_decimals("solana", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    assert!(decimals.is_ok());
    assert_eq!(decimals.unwrap(), 6);

    let decimals_wrong_case =
        get_token_decimals("solana", "epjfwdd5aufqssqem2qn1xzybapC8G4wEGGkZwyTDt1v");
    assert!(decimals_wrong_case.is_err());
}

#[test]
fn test_chain_type_equality() {
    assert_eq!(ChainType::Evm, ChainType::Evm);
    assert_eq!(ChainType::Solana, ChainType::Solana);
    assert_ne!(ChainType::Evm, ChainType::Solana);
}
