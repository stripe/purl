//! X402 Protocol V1 Types
//!
//! This module contains the type definitions for the x402 protocol version 1.

use serde::{Deserialize, Serialize};

/// Payment Requirements Response (402 response body) - V1
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirementsResponse {
    pub x402_version: u32,
    pub error: String,
    pub accepts: Vec<PaymentRequirements>,
}

/// Payment Requirements for a specific payment method - V1
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub max_amount_required: String,
    pub asset: String,
    pub pay_to: String,
    pub resource: String,
    pub description: String,
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    pub max_timeout_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Payment Payload (X-PAYMENT header content) - V1
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
    pub payload: serde_json::Value,
}

/// Settlement Response (X-PAYMENT-RESPONSE header content) - V1
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    pub transaction: String,
    pub network: String,
    #[serde(default)]
    pub payer: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_payment_requirements() {
        let json = r#"{
            "x402Version": 1,
            "error": "Payment Required",
            "accepts": [
                {
                    "scheme": "eip3009",
                    "network": "base-sepolia",
                    "maxAmountRequired": "1000",
                    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                    "payTo": "0x5678...",
                    "resource": "/api/data",
                    "description": "Premium data access",
                    "mimeType": "application/json",
                    "maxTimeoutSeconds": 300,
                    "extra": {
                        "name": "USDC",
                        "version": "1"
                    }
                }
            ]
        }"#;

        let response: PaymentRequirementsResponse =
            serde_json::from_str(json).expect("should parse");
        assert_eq!(response.x402_version, 1);
        assert_eq!(response.accepts.len(), 1);

        let req = &response.accepts[0];
        assert_eq!(req.scheme, "eip3009");
        assert_eq!(req.network, "base-sepolia");
        assert_eq!(req.max_amount_required, "1000");
    }

    #[test]
    fn test_payment_requirements_evm_metadata() {
        let req = PaymentRequirements {
            scheme: "eip3009".to_string(),
            network: "base".to_string(),
            max_amount_required: "1000".to_string(),
            asset: "0x123".to_string(),
            pay_to: "0x456".to_string(),
            resource: "/data".to_string(),
            description: "test".to_string(),
            mime_type: "application/json".to_string(),
            output_schema: None,
            max_timeout_seconds: 300,
            extra: Some(serde_json::json!({
                "name": "USDC",
                "version": "1"
            })),
        };

        assert!(req.extra.is_some());
    }

    #[test]
    fn test_parse_settlement_response() {
        let json = r#"{
            "success": true,
            "transaction": "0xabc123",
            "network": "base-sepolia",
            "payer": "0x1234..."
        }"#;

        let response: SettlementResponse = serde_json::from_str(json).expect("should parse");
        assert_eq!(response.success, Some(true));
        assert_eq!(response.transaction, "0xabc123");
        assert_eq!(response.network, "base-sepolia");
        assert_eq!(response.payer, "0x1234...");
        assert!(response.error_reason.is_none());
    }

    #[test]
    fn test_parse_minimal_settlement_response() {
        // Some servers only return transaction and network fields
        let json = r#"{
            "transaction": "64sbPwy1EwwgZGeUQ7zRzmKe5aoPo",
            "network": "solana"
        }"#;

        let response: SettlementResponse =
            serde_json::from_str(json).expect("should parse minimal response");
        assert_eq!(response.transaction, "64sbPwy1EwwgZGeUQ7zRzmKe5aoPo");
        assert_eq!(response.network, "solana");
        assert_eq!(response.payer, ""); // defaults to empty string
        assert!(response.success.is_none());
    }
}
