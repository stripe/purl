//! Integration tests for x402 protocol types

use purl_lib::x402::{v1, v2, Amount, PaymentRequirements};
use purl_lib::{PaymentPayload, PaymentRequirementsResponse, SettlementResponse};

#[test]
fn test_parse_payment_requirements_response() {
    let json = r#"{
        "x402Version": 1,
        "error": "Payment Required",
        "accepts": [
            {
                "scheme": "eip3009",
                "network": "base-sepolia",
                "maxAmountRequired": "1000",
                "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                "payTo": "0x1234567890abcdef1234567890abcdef12345678",
                "resource": "/api/data",
                "description": "Premium data access",
                "mimeType": "application/json",
                "maxTimeoutSeconds": 300
            }
        ]
    }"#;

    let response: PaymentRequirementsResponse =
        serde_json::from_str(json).expect("Failed to parse");

    assert_eq!(response.version(), 1);
    assert_eq!(response.error(), Some("Payment Required"));
    let accepts = response.accepts();
    assert_eq!(accepts.len(), 1);

    let req = &accepts[0];
    assert_eq!(req.scheme(), "eip3009");
    assert_eq!(req.network(), "base-sepolia");
    assert_eq!(req.parse_max_amount().unwrap().as_atomic_units(), 1000);
    assert_eq!(req.asset(), "0x036CbD53842c5426634e7929541eC2318f3dCF7e");
}

#[test]
fn test_parse_payment_requirements_with_extra() {
    let json = r#"{
        "x402Version": 1,
        "error": "Payment Required",
        "accepts": [
            {
                "scheme": "eip3009",
                "network": "base",
                "maxAmountRequired": "500",
                "asset": "0x833589fCD6EDB6E08F4C7C32D4F71B54bda02913",
                "payTo": "0x1234567890abcdef1234567890abcdef12345678",
                "resource": "/premium",
                "description": "Premium access",
                "mimeType": "application/json",
                "maxTimeoutSeconds": 600,
                "extra": {
                    "name": "USD Coin",
                    "version": "2"
                }
            }
        ]
    }"#;

    let response: PaymentRequirementsResponse =
        serde_json::from_str(json).expect("Failed to parse");

    let accepts = response.accepts();
    let req = &accepts[0];
    assert!(req.extra().is_some());

    let (name, version) = req.evm_token_metadata().expect("Should have metadata");
    assert_eq!(name, "USD Coin");
    assert_eq!(version, "2");
}

#[test]
fn test_parse_payment_requirements_solana() {
    let json = r#"{
        "x402Version": 1,
        "error": "Payment Required",
        "accepts": [
            {
                "scheme": "solana-transfer",
                "network": "solana-devnet",
                "maxAmountRequired": "1000000",
                "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                "payTo": "BxYzKTc8Px3pLzXKqbPaXZH6R7a1c9xH8Dq2Ux6VZfZf",
                "resource": "/api/v1/data",
                "description": "Data access",
                "mimeType": "application/json",
                "maxTimeoutSeconds": 300,
                "extra": {
                    "feePayer": "FeePayerAddress123",
                    "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                }
            }
        ]
    }"#;

    let response: PaymentRequirementsResponse =
        serde_json::from_str(json).expect("Failed to parse");

    let accepts = response.accepts();
    let req = &accepts[0];
    assert_eq!(req.scheme(), "solana-transfer");
    assert_eq!(req.network(), "solana-devnet");
    assert!(req.is_solana());
    assert!(!req.is_evm());

    assert_eq!(req.solana_fee_payer().unwrap(), "FeePayerAddress123");
    assert_eq!(
        req.solana_token_program().unwrap(),
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    );
}

#[test]
fn test_payment_requirements_chain_type_detection() {
    struct TestCase {
        scheme: &'static str,
        network: &'static str,
        asset: &'static str,
        expected_is_evm: bool,
        expected_is_solana: bool,
    }

    let test_cases = vec![
        TestCase {
            scheme: "eip3009",
            network: "base",
            asset: "0x1234567890123456789012345678901234567891",
            expected_is_evm: true,
            expected_is_solana: false,
        },
        TestCase {
            scheme: "solana-transfer",
            network: "solana",
            asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            expected_is_evm: false,
            expected_is_solana: true,
        },
    ];

    for test_case in test_cases {
        let req = PaymentRequirements::V1(v1::PaymentRequirements {
            scheme: test_case.scheme.to_string(),
            network: test_case.network.to_string(),
            max_amount_required: "1000".to_string(),
            asset: test_case.asset.to_string(),
            pay_to: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            resource: "/data".to_string(),
            description: "test".to_string(),
            mime_type: "application/json".to_string(),
            output_schema: None,
            max_timeout_seconds: 300,
            extra: None,
        });

        assert_eq!(
            req.is_evm(),
            test_case.expected_is_evm,
            "is_evm() should be {} for scheme {}",
            test_case.expected_is_evm,
            test_case.scheme
        );
        assert_eq!(
            req.is_solana(),
            test_case.expected_is_solana,
            "is_solana() should be {} for scheme {}",
            test_case.expected_is_solana,
            test_case.scheme
        );
    }
}

#[test]
fn test_payment_requirements_parse_max_amount() {
    struct TestCase {
        max_amount_required: &'static str,
        expected_result: Option<u128>,
        description: &'static str,
    }

    let test_cases = vec![
        TestCase {
            max_amount_required: "123456789",
            expected_result: Some(123456789u128),
            description: "valid number",
        },
        TestCase {
            max_amount_required: "not-a-number",
            expected_result: None,
            description: "invalid number",
        },
    ];

    for test_case in test_cases {
        let req = PaymentRequirements::V1(v1::PaymentRequirements {
            scheme: "eip3009".to_string(),
            network: "base".to_string(),
            max_amount_required: test_case.max_amount_required.to_string(),
            asset: "0x1234567890123456789012345678901234567891".to_string(),
            pay_to: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            resource: "/data".to_string(),
            description: "test".to_string(),
            mime_type: "application/json".to_string(),
            output_schema: None,
            max_timeout_seconds: 300,
            extra: None,
        });

        let result = req.parse_max_amount();
        match test_case.expected_result {
            Some(expected_amount) => {
                assert_eq!(
                    result.expect("Should parse"),
                    Amount::from_atomic_units(expected_amount),
                    "Should parse {} correctly",
                    test_case.description
                );
            }
            None => {
                assert!(
                    result.is_err(),
                    "Should fail to parse {}",
                    test_case.description
                );
            }
        }
    }
}

#[test]
fn test_parse_settlement_response() {
    struct TestCase {
        json: &'static str,
        expected_success: Option<bool>,
        expected_transaction: &'static str,
        expected_network: &'static str,
        expected_error_reason: Option<&'static str>,
    }

    let test_cases = vec![
        TestCase {
            json: r#"{
                "success": true,
                "transaction": "0xabc123def456",
                "network": "base-sepolia",
                "payer": "0x1234567890abcdef1234567890abcdef12345678"
            }"#,
            expected_success: Some(true),
            expected_transaction: "0xabc123def456",
            expected_network: "base-sepolia",
            expected_error_reason: None,
        },
        TestCase {
            json: r#"{
                "success": false,
                "errorReason": "Insufficient balance",
                "transaction": "",
                "network": "base",
                "payer": "0x1234567890abcdef1234567890abcdef12345678"
            }"#,
            expected_success: Some(false),
            expected_transaction: "",
            expected_network: "base",
            expected_error_reason: Some("Insufficient balance"),
        },
    ];

    for test_case in test_cases {
        let response: SettlementResponse =
            serde_json::from_str(test_case.json).expect("Failed to parse");

        // For v1, success returns Option<bool>; is_success() returns bool
        let success_matches = match test_case.expected_success {
            Some(expected) => response.is_success() == expected,
            None => true, // If no expectation, consider it passing
        };
        assert!(
            success_matches,
            "Success flag should be {:?}",
            test_case.expected_success
        );
        assert_eq!(
            response.transaction(),
            test_case.expected_transaction,
            "Transaction should match"
        );
        assert_eq!(
            response.network(),
            test_case.expected_network,
            "Network should match"
        );
        assert_eq!(
            response.error_reason(),
            test_case.expected_error_reason,
            "Error reason should match"
        );
    }
}

#[test]
fn test_payment_payload_serialization() {
    let payload = PaymentPayload::new_v1(
        "eip3009".to_string(),
        "base".to_string(),
        serde_json::json!({
            "signature": "0xsignature",
            "authorization": {
                "from": "0xfrom",
                "to": "0xto",
                "value": "1000"
            }
        }),
    );

    let json = serde_json::to_string(&payload).expect("Failed to serialize");
    assert!(json.contains("eip3009"));
    assert!(json.contains("base"));
    assert!(json.contains("signature"));
}

#[test]
fn test_payment_payload_roundtrip() {
    let original = PaymentPayload::new_v1(
        "eip3009".to_string(),
        "base-sepolia".to_string(),
        serde_json::json!({
            "test": "data"
        }),
    );

    let json = serde_json::to_string(&original).expect("Failed to serialize");
    let deserialized: PaymentPayload = serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(deserialized.x402_version, original.x402_version);
    // Both should serialize/deserialize correctly
    assert!(json.contains("base-sepolia"));
}

#[test]
fn test_multiple_accepts_in_response() {
    let json = r#"{
        "x402Version": 1,
        "error": "Payment Required",
        "accepts": [
            {
                "scheme": "eip3009",
                "network": "base",
                "maxAmountRequired": "1000",
                "asset": "0x833589fCD6EDB6E08F4C7C32D4F71B54bda02913",
                "payTo": "0x1234567890abcdef1234567890abcdef12345678",
                "resource": "/data",
                "description": "Base payment",
                "mimeType": "application/json",
                "maxTimeoutSeconds": 300
            },
            {
                "scheme": "eip3009",
                "network": "ethereum",
                "maxAmountRequired": "1000",
                "asset": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "payTo": "0x1234567890abcdef1234567890abcdef12345678",
                "resource": "/data",
                "description": "Ethereum payment",
                "mimeType": "application/json",
                "maxTimeoutSeconds": 300
            }
        ]
    }"#;

    let response: PaymentRequirementsResponse =
        serde_json::from_str(json).expect("Failed to parse");

    let accepts = response.accepts();
    assert_eq!(accepts.len(), 2);
    assert_eq!(accepts[0].network(), "base");
    assert_eq!(accepts[1].network(), "ethereum");
}

#[test]
fn test_payment_requirements_without_extra() {
    let req = PaymentRequirements::V1(v1::PaymentRequirements {
        scheme: "eip3009".to_string(),
        network: "base".to_string(),
        max_amount_required: "1000".to_string(),
        asset: "0x1234567890123456789012345678901234567891".to_string(),
        pay_to: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        resource: "/data".to_string(),
        description: "test".to_string(),
        mime_type: "application/json".to_string(),
        output_schema: None,
        max_timeout_seconds: 300,
        extra: None,
    });

    assert!(req.evm_token_metadata().is_none());
    assert!(req.solana_fee_payer().is_none());
    assert!(req.solana_token_program().is_none());
}

#[test]
fn test_parse_v2_payment_requirements() {
    let json = r#"{
        "x402Version": 2,
        "error": "PAYMENT-SIGNATURE header is required",
        "resource": {
            "url": "https://api.example.com/premium-data",
            "description": "Access to premium market data",
            "mimeType": "application/json"
        },
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:84532",
                "amount": "10000",
                "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                "maxTimeoutSeconds": 60,
                "extra": {
                    "name": "USDC",
                    "version": "2"
                }
            }
        ],
        "extensions": {}
    }"#;

    let response: PaymentRequirementsResponse =
        serde_json::from_str(json).expect("should parse v2 requirements");
    assert_eq!(response.version(), 2);
    assert_eq!(
        response.error(),
        Some("PAYMENT-SIGNATURE header is required")
    );

    let accepts = response.accepts();
    assert_eq!(accepts.len(), 1);
    let req = &accepts[0];

    assert_eq!(req.scheme(), "exact");
    assert_eq!(req.network(), "eip155:84532");
    assert_eq!(req.parse_max_amount().unwrap().as_atomic_units(), 10000);
    assert_eq!(req.asset(), "0x036CbD53842c5426634e7929541eC2318f3dCF7e");
    assert_eq!(req.pay_to(), "0x209693Bc6afc0C5328bA36FaF03C514EF312287C");
    assert_eq!(req.max_timeout_seconds(), 60);
    assert_eq!(req.resource(), "https://api.example.com/premium-data");
    assert_eq!(req.description(), "Access to premium market data");
    assert_eq!(req.mime_type(), "application/json");

    // Check v2 network format detection
    assert!(req.is_evm());
    assert!(!req.is_solana());

    // Verify EVM token metadata is available
    let (name, version) = req
        .evm_token_metadata()
        .expect("should have token metadata");
    assert_eq!(name, "USDC");
    assert_eq!(version, "2");
}

#[test]
fn test_v2_payment_payload_creation() {
    let resource_info = v2::ResourceInfo {
        url: "https://api.example.com/data".to_string(),
        description: Some("Test resource".to_string()),
        mime_type: Some("application/json".to_string()),
    };

    let requirements = v2::PaymentRequirements {
        scheme: "exact".to_string(),
        network: "eip155:84532".to_string(),
        amount: "10000".to_string(),
        asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_string(),
        pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C".to_string(),
        max_timeout_seconds: 60,
        extra: Some(serde_json::json!({
            "name": "USDC",
            "version": "2"
        })),
    };

    let payload = PaymentPayload::new_v2(
        Some(resource_info),
        requirements,
        serde_json::json!({
            "signature": "0x...",
            "authorization": {}
        }),
        None,
    );

    // Verify v2 payload uses correct header names
    assert_eq!(payload.payment_header_name(), "PAYMENT-SIGNATURE");
    assert_eq!(payload.response_header_name(), "payment-response");
    assert_eq!(payload.x402_version, 2);

    // Serialize and verify structure
    let json = serde_json::to_string(&payload).expect("should serialize");
    assert!(json.contains("\"x402Version\":2"));
    assert!(json.contains("eip155:84532"));
    assert!(json.contains("accepted"));
}

#[test]
fn test_v2_payment_requirements_chain_type_detection() {
    struct TestCase {
        network: &'static str,
        expected_is_evm: bool,
        expected_is_solana: bool,
    }

    let test_cases = vec![
        TestCase {
            network: "eip155:8453",
            expected_is_evm: true,
            expected_is_solana: false,
        },
        TestCase {
            network: "eip155:84532",
            expected_is_evm: true,
            expected_is_solana: false,
        },
        TestCase {
            network: "solana:mainnet",
            expected_is_evm: false,
            expected_is_solana: true,
        },
        TestCase {
            network: "solana:devnet",
            expected_is_evm: false,
            expected_is_solana: true,
        },
    ];

    for test_case in test_cases {
        let resource_info = v2::ResourceInfo {
            url: "https://example.com".to_string(),
            description: None,
            mime_type: None,
        };

        let requirements = v2::PaymentRequirements {
            scheme: "exact".to_string(),
            network: test_case.network.to_string(),
            amount: "1000".to_string(),
            asset: "0x1234567890123456789012345678901234567891".to_string(),
            pay_to: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            max_timeout_seconds: 60,
            extra: None,
        };

        let req = PaymentRequirements::V2 {
            requirements,
            resource_info,
        };

        assert_eq!(
            req.is_evm(),
            test_case.expected_is_evm,
            "is_evm() should be {} for network {}",
            test_case.expected_is_evm,
            test_case.network
        );
        assert_eq!(
            req.is_solana(),
            test_case.expected_is_solana,
            "is_solana() should be {} for network {}",
            test_case.expected_is_solana,
            test_case.network
        );
    }
}
