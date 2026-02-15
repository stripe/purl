//! get_token_symbol tests

use purl_lib::x402::{v2, PaymentRequirements};

use super::*;

/// Helper to create a test payment requirement
fn create_test_requirement(
    network: &str,
    asset: &str,
    extra: Option<serde_json::Value>,
) -> PaymentRequirements {
    PaymentRequirements::V2 {
        requirements: v2::PaymentRequirements {
            scheme: "eip3009".to_string(),
            network: network.to_string(),
            amount: "1000000".to_string(),
            asset: asset.to_string(),
            pay_to: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            max_timeout_seconds: 300,
            extra,
        },
        resource_info: v2::ResourceInfo {
            url: "/".to_string(),
            description: None,
            mime_type: None,
        },
    }
}

#[test]
fn test_get_token_symbol_registry() {
    // USDC on Base (eip155:8453) is in the built-in registry
    let requirement = create_test_requirement(
        "eip155:8453",
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        None,
    );
    let (symbol, seller_provided) = get_token_symbol(&requirement);
    assert_eq!(symbol, "USDC");
    assert!(!seller_provided);
}

#[test]
fn test_get_token_symbol_extra_unknown() {
    // Benign: token not in our registry; seller provides symbol for their token
    let requirement = create_test_requirement(
        "eip155:8453",
        "0xunknown_token_not_in_registry",
        Some(serde_json::json!({"symbol": "CUSTOM"})),
    );
    let (symbol, seller_provided) = get_token_symbol(&requirement);
    assert_eq!(symbol, "CUSTOM");
    assert!(seller_provided);
}

#[test]
fn test_get_token_symbol_extra_fake() {
    // Malignant: unknown address claims canonical symbol (e.g. drainer)
    let requirement = create_test_requirement(
        "eip155:8453",
        "0xnot_the_real_usdc_address",
        Some(serde_json::json!({"symbol": "USDC"})),
    );
    let (symbol, seller_provided) = get_token_symbol(&requirement);
    assert_eq!(symbol, "USDC");
    assert!(seller_provided);
}

#[test]
fn test_get_token_symbol_fallback() {
    let requirement = create_test_requirement("eip155:8453", "0xunknown_token", None);
    let (symbol, seller_provided) = get_token_symbol(&requirement);
    assert_eq!(symbol, "0xunknown_token");
    assert!(!seller_provided);
}
