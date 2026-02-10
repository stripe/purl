//! X402 Protocol V2 Types
//!
//! This module contains the type definitions for the x402 protocol version 2.

use serde::{Deserialize, Serialize};

/// Resource information - V2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Extension information - V2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionInfo {
    pub info: serde_json::Value,
    pub schema: serde_json::Value,
}

/// Payment Required Response (402 response body) - V2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirements>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Payment Requirements for a specific payment method - V2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String, // CAIP-2 format (e.g., "eip155:84532")
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Payment Payload (PAYMENT-SIGNATURE header content) - V2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    pub accepted: PaymentRequirements,
    pub payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Settlement Response (PAYMENT-RESPONSE header content) - V2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    pub transaction: String,
    pub network: String, // CAIP-2 format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}

/// Verify Response - V2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}

/// Supported Kind - V2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedKind {
    pub x402_version: u32,
    pub scheme: String,
    pub network: String, // CAIP-2 format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Supported Response - V2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedResponse {
    pub kinds: Vec<SupportedKind>,
    pub extensions: Vec<String>,
    pub signers: std::collections::HashMap<String, Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_payment_required() {
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

        let response: PaymentRequired = serde_json::from_str(json).expect("should parse");
        assert_eq!(response.x402_version, 2);
        assert_eq!(response.accepts.len(), 1);
        assert_eq!(
            response.resource.url,
            "https://api.example.com/premium-data"
        );

        let req = &response.accepts[0];
        assert_eq!(req.scheme, "exact");
        assert_eq!(req.network, "eip155:84532");
        assert_eq!(req.amount, "10000");
    }

    #[test]
    fn test_parse_payment_payload() {
        let json = r#"{
            "x402Version": 2,
            "resource": {
                "url": "https://api.example.com/premium-data",
                "description": "Access to premium market data",
                "mimeType": "application/json"
            },
            "accepted": {
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
            },
            "payload": {
                "signature": "0x...",
                "authorization": {
                    "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
                    "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                    "value": "10000",
                    "validAfter": "1740672089",
                    "validBefore": "1740672154",
                    "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"
                }
            },
            "extensions": {}
        }"#;

        let payload: PaymentPayload = serde_json::from_str(json).expect("should parse");
        assert_eq!(payload.x402_version, 2);
        assert_eq!(payload.accepted.scheme, "exact");
        assert_eq!(payload.accepted.network, "eip155:84532");
    }

    #[test]
    fn test_parse_settlement_response() {
        let json = r#"{
            "success": true,
            "transaction": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "network": "eip155:84532",
            "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66"
        }"#;

        let response: SettlementResponse = serde_json::from_str(json).expect("should parse");
        assert_eq!(response.success, true);
        assert_eq!(
            response.transaction,
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(response.network, "eip155:84532");
        assert_eq!(
            response.payer,
            Some("0x857b06519E91e3A54538791bDbb0E22373e36b66".to_string())
        );
    }
}
