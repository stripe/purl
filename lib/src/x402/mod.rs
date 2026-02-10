use crate::network::{is_evm_network, is_solana_network};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

// Sub-modules for version-specific types
pub mod v1;
pub mod v2;

// ==================== Payment Header Constants ====================

/// x402 v1 payment header name
pub const V1_X_PAYMENT_HEADER: &str = "X-PAYMENT";

/// x402 v1 payment response header name (lowercase for matching)
pub const V1_X_PAYMENT_RESPONSE_HEADER: &str = "x-payment-response";

/// x402 v2 payment header name
pub const PAYMENT_SIGNATURE_HEADER: &str = "PAYMENT-SIGNATURE";

/// x402 v2 payment response header name (lowercase for matching)
pub const PAYMENT_RESPONSE_HEADER: &str = "payment-response";

/// x402 v2 payment required header name (lowercase for matching)
pub const PAYMENT_REQUIRED_HEADER: &str = "payment-required";

// ==================== Helper Functions ====================

/// Get the payment requirements JSON from an HTTP 402 response.
///
/// For x402 v2, payment requirements are sent in the PAYMENT-REQUIRED header (base64 encoded).
/// For backwards compatibility with v1, this also falls back to the response body.
///
/// # Errors
/// Returns an error if the header is present but cannot be decoded, or if the body is not valid UTF-8.
pub fn payment_requirements_json(
    response: &crate::http::HttpResponse,
) -> crate::error::Result<String> {
    use base64::Engine;

    // First, try the PAYMENT-REQUIRED header (v2 style)
    if let Some(header_value) = response.get_header(PAYMENT_REQUIRED_HEADER) {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(header_value)
            .map_err(|e| {
                crate::error::PurlError::Http(format!(
                    "Failed to decode PAYMENT-REQUIRED header: {}",
                    e
                ))
            })?;
        return String::from_utf8(decoded).map_err(|e| {
            crate::error::PurlError::Http(format!(
                "PAYMENT-REQUIRED header is not valid UTF-8: {}",
                e
            ))
        });
    }

    // Fall back to response body (v1 style)
    response.body_string()
}

/// A type-safe wrapper around payment amounts in atomic units.
///
/// This ensures amounts are validated once and prevents repeated string parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u128);

impl Amount {
    /// Create a new Amount from a u128 value.
    pub fn from_atomic_units(value: u128) -> Self {
        Self(value)
    }

    /// Get the amount in atomic units.
    pub fn as_atomic_units(&self) -> u128 {
        self.0
    }

    /// Try to convert to u64, returning an error if the amount is too large.
    pub fn try_as_u64(&self) -> Result<u64, &'static str> {
        self.0.try_into().map_err(|_| "Amount exceeds u64::MAX")
    }
}

impl FromStr for Amount {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u128>().map(Amount)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Amount> for u128 {
    fn from(amount: Amount) -> Self {
        amount.0
    }
}

impl From<u128> for Amount {
    fn from(value: u128) -> Self {
        Amount(value)
    }
}

// ==================== Unified Types ====================
// These types can handle both v1 and v2, internally using v2 format

/// Payment Requirements Response (402 response body)
///
/// This is a unified type that can represent both v1 and v2 protocol responses.
/// Internally uses v2 format, with conversion from v1 when needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PaymentRequirementsResponse {
    V1(v1::PaymentRequirementsResponse),
    V2(v2::PaymentRequired),
}

impl PaymentRequirementsResponse {
    /// Get the protocol version
    pub fn version(&self) -> u32 {
        match self {
            PaymentRequirementsResponse::V1(v1) => v1.x402_version,
            PaymentRequirementsResponse::V2(v2) => v2.x402_version,
        }
    }

    /// Get the error message, if any
    pub fn error(&self) -> Option<&str> {
        match self {
            PaymentRequirementsResponse::V1(v1) => Some(&v1.error),
            PaymentRequirementsResponse::V2(v2) => v2.error.as_deref(),
        }
    }

    /// Get the list of accepted payment methods as unified PaymentRequirements
    pub fn accepts(&self) -> Vec<PaymentRequirements> {
        match self {
            PaymentRequirementsResponse::V1(v1) => v1
                .accepts
                .iter()
                .map(|req| PaymentRequirements::V1(req.clone()))
                .collect(),
            PaymentRequirementsResponse::V2(v2) => v2
                .accepts
                .iter()
                .map(|req| PaymentRequirements::V2 {
                    requirements: req.clone(),
                    resource_info: v2.resource.clone(),
                })
                .collect(),
        }
    }
}

/// Payment Requirements for a specific payment method
///
/// This is a unified type that can represent both v1 and v2 protocol requirements.
#[derive(Debug, Clone)]
pub enum PaymentRequirements {
    V1(v1::PaymentRequirements),
    V2 {
        requirements: v2::PaymentRequirements,
        resource_info: v2::ResourceInfo,
    },
}

impl PaymentRequirements {
    pub fn is_evm(&self) -> bool {
        match self {
            PaymentRequirements::V1(v1) => is_evm_network(&v1.network),
            PaymentRequirements::V2 { requirements, .. } => {
                // Check if network is in eip155 namespace
                requirements.network.starts_with("eip155:")
            }
        }
    }

    pub fn is_solana(&self) -> bool {
        match self {
            PaymentRequirements::V1(v1) => is_solana_network(&v1.network),
            PaymentRequirements::V2 { requirements, .. } => {
                // Check if network is in solana namespace
                requirements.network.starts_with("solana:")
            }
        }
    }

    /// Parse the max amount required as Amount
    pub fn parse_max_amount(&self) -> Result<Amount, std::num::ParseIntError> {
        let amount_str = match self {
            PaymentRequirements::V1(v1) => &v1.max_amount_required,
            PaymentRequirements::V2 { requirements, .. } => &requirements.amount,
        };
        amount_str.parse()
    }

    /// Get the scheme
    pub fn scheme(&self) -> &str {
        match self {
            PaymentRequirements::V1(v1) => &v1.scheme,
            PaymentRequirements::V2 { requirements, .. } => &requirements.scheme,
        }
    }

    /// Get the network (in original format - v1 or v2)
    pub fn network(&self) -> &str {
        match self {
            PaymentRequirements::V1(v1) => &v1.network,
            PaymentRequirements::V2 { requirements, .. } => &requirements.network,
        }
    }

    /// Get the asset address
    pub fn asset(&self) -> &str {
        match self {
            PaymentRequirements::V1(v1) => &v1.asset,
            PaymentRequirements::V2 { requirements, .. } => &requirements.asset,
        }
    }

    /// Get the pay_to address
    pub fn pay_to(&self) -> &str {
        match self {
            PaymentRequirements::V1(v1) => &v1.pay_to,
            PaymentRequirements::V2 { requirements, .. } => &requirements.pay_to,
        }
    }

    /// Get max timeout seconds
    pub fn max_timeout_seconds(&self) -> u64 {
        match self {
            PaymentRequirements::V1(v1) => v1.max_timeout_seconds,
            PaymentRequirements::V2 { requirements, .. } => requirements.max_timeout_seconds,
        }
    }

    /// Get the resource URL
    pub fn resource(&self) -> &str {
        match self {
            PaymentRequirements::V1(v1) => &v1.resource,
            PaymentRequirements::V2 { resource_info, .. } => &resource_info.url,
        }
    }

    /// Get the description
    pub fn description(&self) -> &str {
        match self {
            PaymentRequirements::V1(v1) => &v1.description,
            PaymentRequirements::V2 { resource_info, .. } => {
                resource_info.description.as_deref().unwrap_or("")
            }
        }
    }

    /// Get the MIME type
    pub fn mime_type(&self) -> &str {
        match self {
            PaymentRequirements::V1(v1) => &v1.mime_type,
            PaymentRequirements::V2 { resource_info, .. } => {
                resource_info.mime_type.as_deref().unwrap_or("")
            }
        }
    }

    /// Get the extra field
    pub fn extra(&self) -> Option<&serde_json::Value> {
        match self {
            PaymentRequirements::V1(v1) => v1.extra.as_ref(),
            PaymentRequirements::V2 { requirements, .. } => requirements.extra.as_ref(),
        }
    }

    /// Get the facilitator fee payer for Solana (from extra field)
    pub fn solana_fee_payer(&self) -> Option<String> {
        self.extra()
            .and_then(|extra| extra.get("feePayer"))
            .and_then(|fp| fp.as_str())
            .map(|s| s.to_string())
    }

    /// Get the Solana token program from extra field
    pub fn solana_token_program(&self) -> Option<String> {
        self.extra()
            .and_then(|extra| extra.get("tokenProgram"))
            .and_then(|tp| tp.as_str())
            .map(|s| s.to_string())
    }

    /// Get EVM token metadata (name and version from extra field)
    pub fn evm_token_metadata(&self) -> Option<(String, String)> {
        let extra = self.extra()?;
        let name = extra.get("name")?.as_str()?.to_string();
        let version = extra.get("version")?.as_str()?.to_string();
        Some((name, version))
    }
}

/// Payment Payload (X-PAYMENT or PAYMENT-SIGNATURE header content)
///
/// This is a unified type that can represent both v1 and v2 protocol payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u32,
    #[serde(flatten)]
    pub inner: PaymentPayloadInner,
}

impl PaymentPayload {
    /// Get the appropriate payment header name for this version
    pub fn payment_header_name(&self) -> &'static str {
        if self.x402_version == 2 {
            PAYMENT_SIGNATURE_HEADER
        } else {
            V1_X_PAYMENT_HEADER
        }
    }

    /// Get the appropriate response header name for this version
    pub fn response_header_name(&self) -> &'static str {
        if self.x402_version == 2 {
            PAYMENT_RESPONSE_HEADER
        } else {
            V1_X_PAYMENT_RESPONSE_HEADER
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PaymentPayloadInner {
    V1 {
        scheme: String,
        network: String,
        payload: serde_json::Value,
    },
    V2 {
        #[serde(skip_serializing_if = "Option::is_none")]
        resource: Option<v2::ResourceInfo>,
        accepted: Box<v2::PaymentRequirements>,
        payload: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        extensions: Option<serde_json::Value>,
    },
}

impl PaymentPayload {
    /// Create a new v1 payment payload
    pub fn new_v1(scheme: String, network: String, payload: serde_json::Value) -> Self {
        Self {
            x402_version: 1,
            inner: PaymentPayloadInner::V1 {
                scheme,
                network,
                payload,
            },
        }
    }

    /// Create a new v2 payment payload
    pub fn new_v2(
        resource: Option<v2::ResourceInfo>,
        accepted: v2::PaymentRequirements,
        payload: serde_json::Value,
        extensions: Option<serde_json::Value>,
    ) -> Self {
        Self {
            x402_version: 2,
            inner: PaymentPayloadInner::V2 {
                resource,
                accepted: Box::new(accepted),
                payload,
                extensions,
            },
        }
    }

    /// Get the payload data
    pub fn payload(&self) -> &serde_json::Value {
        match &self.inner {
            PaymentPayloadInner::V1 { payload, .. } => payload,
            PaymentPayloadInner::V2 { payload, .. } => payload,
        }
    }
}

/// Settlement Response (X-PAYMENT-RESPONSE header content)
///
/// This is a unified type that can represent both v1 and v2 protocol responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SettlementResponse {
    V1(v1::SettlementResponse),
    V2(v2::SettlementResponse),
}

impl SettlementResponse {
    /// Check if the settlement was successful
    pub fn is_success(&self) -> bool {
        match self {
            SettlementResponse::V1(v1) => v1.success.unwrap_or(false),
            SettlementResponse::V2(v2) => v2.success,
        }
    }

    /// Get the error reason, if any
    pub fn error_reason(&self) -> Option<&str> {
        match self {
            SettlementResponse::V1(v1) => v1.error_reason.as_deref(),
            SettlementResponse::V2(v2) => v2.error_reason.as_deref(),
        }
    }

    /// Get the transaction hash
    pub fn transaction(&self) -> &str {
        match self {
            SettlementResponse::V1(v1) => &v1.transaction,
            SettlementResponse::V2(v2) => &v2.transaction,
        }
    }

    /// Get the network (in original format - v1 or v2)
    pub fn network(&self) -> &str {
        match self {
            SettlementResponse::V1(v1) => &v1.network,
            SettlementResponse::V2(v2) => &v2.network,
        }
    }

    /// Get the payer address, if available
    pub fn payer(&self) -> Option<&str> {
        match self {
            SettlementResponse::V1(v1) => {
                if v1.payer.is_empty() {
                    None
                } else {
                    Some(&v1.payer)
                }
            }
            SettlementResponse::V2(v2) => v2.payer.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v1_payment_requirements() {
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
        assert_eq!(response.version(), 1);
        let accepts = response.accepts();
        assert_eq!(accepts.len(), 1);
        assert_eq!(accepts[0].scheme(), "eip3009");
        assert!(accepts[0].is_evm());
        assert!(!accepts[0].is_solana());
    }

    #[test]
    fn test_parse_v2_payment_required() {
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
            serde_json::from_str(json).expect("should parse");
        assert_eq!(response.version(), 2);
        let accepts = response.accepts();
        assert_eq!(accepts.len(), 1);
        assert_eq!(accepts[0].scheme(), "exact");
        assert!(accepts[0].is_evm());
        assert!(!accepts[0].is_solana());
    }

    #[test]
    fn test_parse_v1_settlement_response() {
        let json = r#"{
            "success": true,
            "transaction": "0xabc123",
            "network": "base-sepolia",
            "payer": "0x1234..."
        }"#;

        let response: SettlementResponse = serde_json::from_str(json).expect("should parse");
        assert!(response.is_success());
        assert_eq!(response.transaction(), "0xabc123");
        assert_eq!(response.network(), "base-sepolia");
        assert_eq!(response.payer(), Some("0x1234..."));
    }

    #[test]
    fn test_parse_v2_settlement_response() {
        let json = r#"{
            "success": true,
            "transaction": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "network": "eip155:84532",
            "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66"
        }"#;

        let response: SettlementResponse = serde_json::from_str(json).expect("should parse");
        assert!(response.is_success());
        assert_eq!(
            response.transaction(),
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(response.network(), "eip155:84532");
    }

    #[test]
    fn test_v1_requirements_helpers() {
        let req = v1::PaymentRequirements {
            scheme: "exact".to_string(),
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

        let unified = PaymentRequirements::V1(req);
        assert_eq!(unified.scheme(), "exact");
        assert_eq!(unified.network(), "base");
        assert_eq!(unified.asset(), "0x123");
        assert_eq!(unified.pay_to(), "0x456");
        assert_eq!(unified.resource(), "/data");
        assert_eq!(unified.description(), "test");
        assert_eq!(unified.mime_type(), "application/json");

        let (name, version) = unified.evm_token_metadata().expect("should have metadata");
        assert_eq!(name, "USDC");
        assert_eq!(version, "1");
    }

    #[test]
    fn test_payment_payload_header_names() {
        // V1 payload should use X-PAYMENT headers
        let v1_payload = PaymentPayload {
            x402_version: 1,
            inner: PaymentPayloadInner::V1 {
                scheme: "exact".to_string(),
                network: "base-sepolia".to_string(),
                payload: serde_json::json!({}),
            },
        };
        assert_eq!(v1_payload.payment_header_name(), V1_X_PAYMENT_HEADER);
        assert_eq!(v1_payload.payment_header_name(), "X-PAYMENT");
        assert_eq!(
            v1_payload.response_header_name(),
            V1_X_PAYMENT_RESPONSE_HEADER
        );
        assert_eq!(v1_payload.response_header_name(), "x-payment-response");

        // V2 payload should use PAYMENT-SIGNATURE headers
        let v2_resource = v2::ResourceInfo {
            url: "http://test.com".to_string(),
            description: None,
            mime_type: None,
        };
        let v2_requirements = v2::PaymentRequirements {
            scheme: "exact".to_string(),
            network: "eip155:84532".to_string(),
            amount: "10000".to_string(),
            asset: "0x123".to_string(),
            pay_to: "0x456".to_string(),
            max_timeout_seconds: 60,
            extra: None,
        };
        let v2_payload = PaymentPayload {
            x402_version: 2,
            inner: PaymentPayloadInner::V2 {
                resource: Some(v2_resource),
                accepted: Box::new(v2_requirements),
                payload: serde_json::json!({}),
                extensions: None,
            },
        };
        assert_eq!(v2_payload.payment_header_name(), PAYMENT_SIGNATURE_HEADER);
        assert_eq!(v2_payload.payment_header_name(), "PAYMENT-SIGNATURE");
        assert_eq!(v2_payload.response_header_name(), PAYMENT_RESPONSE_HEADER);
        assert_eq!(v2_payload.response_header_name(), "payment-response");
    }
}
