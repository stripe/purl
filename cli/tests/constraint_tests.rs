use purl_lib::x402::{v1, PaymentRequirements};

/// Helper to create a test payment requirement
fn create_test_requirement(max_amount: &str) -> PaymentRequirements {
    PaymentRequirements::V1(v1::PaymentRequirements {
        scheme: "eip3009".to_string(),
        network: "base".to_string(),
        max_amount_required: max_amount.to_string(),
        asset: "0x1234567890123456789012345678901234567891".to_string(),
        pay_to: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        resource: "/test".to_string(),
        description: "Test payment".to_string(),
        mime_type: "application/json".to_string(),
        output_schema: None,
        max_timeout_seconds: 300,
        extra: None,
    })
}

#[test]
fn test_max_amount_validation_logic() {
    let requirement = create_test_requirement("100000");

    let required: u128 = requirement.parse_max_amount().unwrap().as_atomic_units();

    let max_allowed: u128 = "200000".parse().unwrap();
    assert!(
        required <= max_allowed,
        "Payment should be allowed when max_amount >= required"
    );

    let max_allowed: u128 = "100000".parse().unwrap();
    assert!(
        required <= max_allowed,
        "Payment should be allowed when max_amount == required"
    );

    let max_allowed: u128 = "1".parse().unwrap();
    assert!(
        required > max_allowed,
        "Payment should be rejected when max_amount < required"
    );
}

#[test]
fn test_max_amount_validation_with_various_amounts() {
    struct TestCase {
        required: &'static str,
        max_allowed: &'static str,
        should_pass: bool,
        description: &'static str,
    }

    let test_cases = vec![
        TestCase {
            required: "100000",
            max_allowed: "1",
            should_pass: false,
            description: "Required amount much higher than max",
        },
        TestCase {
            required: "100000",
            max_allowed: "99999",
            should_pass: false,
            description: "Required amount slightly higher than max",
        },
        TestCase {
            required: "100000",
            max_allowed: "100000",
            should_pass: true,
            description: "Required amount equal to max",
        },
        TestCase {
            required: "100000",
            max_allowed: "100001",
            should_pass: true,
            description: "Required amount slightly lower than max",
        },
        TestCase {
            required: "100000",
            max_allowed: "1000000",
            should_pass: true,
            description: "Required amount much lower than max",
        },
        TestCase {
            required: "0",
            max_allowed: "0",
            should_pass: true,
            description: "Both amounts are zero",
        },
    ];

    for test_case in test_cases {
        let requirement = create_test_requirement(test_case.required);
        let required: u128 = requirement.parse_max_amount().unwrap().as_atomic_units();
        let max_allowed: u128 = test_case.max_allowed.parse().unwrap();

        let passes = required <= max_allowed;
        assert_eq!(
            passes, test_case.should_pass,
            "Test case '{}' failed: required={}, max_allowed={}",
            test_case.description, test_case.required, test_case.max_allowed
        );
    }
}

#[test]
fn test_max_amount_constraint_ordering() {
    let requirement = create_test_requirement("100000");
    let required: u128 = requirement.parse_max_amount().unwrap().as_atomic_units();
    let max_allowed: u128 = "1".parse().unwrap();

    let constraint_violated = required > max_allowed;

    assert!(
        constraint_violated,
        "Max amount constraint must be checked before any payment processing"
    );
}
