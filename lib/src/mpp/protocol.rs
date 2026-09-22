//! MPP protocol implementation.
//!
//! This module implements the PaymentProtocol trait for MPP,
//! detecting `WWW-Authenticate: Payment` headers on 402 responses.

use crate::error::{PurlError, Result};
use crate::http::HttpResponse;
use crate::protocol::{CredentialPayload, PaymentChallenge, PaymentProtocol};

use super::policy::{decode_and_validate, require_amount, require_recipient, tempo_chain_id};
use super::MppChallenge;

/// Protocol name constant for MPP
pub const PROTOCOL_NAME: &str = "mpp";

/// WWW-Authenticate header name (lowercase for matching)
const WWW_AUTHENTICATE_HEADER: &str = "www-authenticate";

/// Payment-Receipt header name (lowercase for matching)
const PAYMENT_RECEIPT_HEADER: &str = "payment-receipt";

/// MPP protocol implementation.
///
/// Detects `WWW-Authenticate: Payment` headers on HTTP 402 responses
/// and handles the Machine Payments Protocol flow.
pub struct MppProtocol;

impl PaymentProtocol for MppProtocol {
    fn name(&self) -> &str {
        PROTOCOL_NAME
    }

    fn should_handle(&self, response: &HttpResponse) -> bool {
        if response.status_code != 402 {
            return false;
        }

        // Check for WWW-Authenticate: Payment header
        if let Some(header) = response.get_header(WWW_AUTHENTICATE_HEADER) {
            // Check if the header starts with "Payment " (case-insensitive)
            let trimmed = header.trim_start();
            if trimmed.len() >= 8 {
                let prefix = &trimmed[..8];
                return prefix.eq_ignore_ascii_case("payment ");
            }
        }

        false
    }

    fn parse_challenges(&self, response: &HttpResponse) -> Result<Vec<Box<dyn PaymentChallenge>>> {
        let header = response
            .get_header(WWW_AUTHENTICATE_HEADER)
            .ok_or_else(|| PurlError::Http("Missing WWW-Authenticate header".to_string()))?;

        // Parse the challenge using mpp-rs
        let challenge = mpp::parse_www_authenticate(header)
            .map_err(|e| PurlError::Http(format!("Failed to parse MPP challenge: {}", e)))?;

        // Wrap in MppChallenge to preserve native challenge
        let mpp_challenge = MppChallenge::from_mpp_challenge(challenge)?;

        Ok(vec![Box::new(mpp_challenge) as Box<dyn PaymentChallenge>])
    }

    #[allow(deprecated)]
    fn parse_challenge_json(&self, response: &HttpResponse) -> Result<String> {
        let header = response
            .get_header(WWW_AUTHENTICATE_HEADER)
            .ok_or_else(|| PurlError::Http("Missing WWW-Authenticate header".to_string()))?;

        // Parse the challenge using mpp-rs
        let challenge = mpp::parse_www_authenticate(header)
            .map_err(|e| PurlError::Http(format!("Failed to parse MPP challenge: {}", e)))?;

        // Convert MPP challenge to x402-compatible format for the negotiator
        let x402_response = convert_mpp_to_x402(&challenge)?;
        let json = serde_json::to_string(&x402_response)
            .map_err(|e| PurlError::Http(format!("Failed to serialize challenge: {}", e)))?;

        Ok(json)
    }

    fn create_credential_header(&self, payload: &CredentialPayload) -> (String, String) {
        // MPP uses Authorization: Payment <base64url-json>
        // The payload.data is base64-encoded JSON of a PaymentPayload.
        // We need to extract the mpp_authorization field from the inner payload.

        // Decode the base64 payload
        if let Ok(decoded) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &payload.data)
        {
            if let Ok(json_str) = String::from_utf8(decoded) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    // Extract mpp_authorization from the payload field
                    if let Some(inner_payload) = json.get("payload") {
                        if let Some(mpp_auth) = inner_payload.get("mpp_authorization") {
                            if let Some(auth_str) = mpp_auth.as_str() {
                                return ("Authorization".to_string(), auth_str.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Fallback: use data as-is (shouldn't happen for MPP)
        ("Authorization".to_string(), payload.data.clone())
    }

    fn receipt_header_name(&self, _version: u32) -> &str {
        PAYMENT_RECEIPT_HEADER
    }

    fn parse_receipt_json(&self, response: &HttpResponse, _version: u32) -> Result<Option<String>> {
        if let Some(header) = response.get_header(PAYMENT_RECEIPT_HEADER) {
            let receipt = mpp::parse_receipt(header)
                .map_err(|e| PurlError::Http(format!("Failed to parse MPP receipt: {}", e)))?;

            let json = serde_json::to_string(&receipt)
                .map_err(|e| PurlError::Http(format!("Failed to serialize receipt: {}", e)))?;

            Ok(Some(json))
        } else {
            Ok(None)
        }
    }
}

/// Convert an MPP PaymentChallenge to x402-compatible PaymentRequirementsResponse format.
///
/// This allows the existing negotiator to work with MPP challenges.
fn convert_mpp_to_x402(challenge: &mpp::PaymentChallenge) -> Result<serde_json::Value> {
    let request = decode_and_validate(challenge)?;

    // Extract fields from the request
    let amount = require_amount(&request)?.to_string();
    let currency = request
        .get("currency")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let recipient = require_recipient(&request)?.to_string();

    // Get chain ID from methodDetails if available
    let chain_id = tempo_chain_id(&request)?;

    let network = format!("eip155:{}", chain_id);

    // Build x402 v1-compatible response
    // We use v1 format since it's simpler and sufficient
    let x402_response = serde_json::json!({
        "x402Version": 1,
        "error": challenge.description.clone().unwrap_or_else(|| "Payment Required".to_string()),
        "accepts": [{
            "scheme": "mpp",
            "network": network,
            "maxAmountRequired": amount,
            "asset": currency,
            "payTo": recipient,
            "resource": challenge.realm.clone(),
            "description": challenge.description.clone().unwrap_or_default(),
            "mimeType": "application/json",
            "maxTimeoutSeconds": 300,
            "extra": {
                "mppChallengeId": challenge.id.clone(),
                "mppMethod": challenge.method.as_str(),
                "mppIntent": challenge.intent.as_str(),
                "mppRequest": challenge.request.raw(),
                "mppExpires": challenge.expires.clone()
            }
        }]
    });

    Ok(x402_response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_response(status: u32, headers: Vec<(&str, &str)>, body: &str) -> HttpResponse {
        let mut header_map = HashMap::new();
        for (k, v) in headers {
            header_map.insert(k.to_lowercase(), v.to_string());
        }
        HttpResponse {
            status_code: status,
            headers: header_map,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn test_should_handle_mpp_response() {
        let protocol = MppProtocol;

        // Valid MPP challenge header
        let header = r#"Payment id="abc123", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIn0""#;
        let response = make_response(402, vec![("www-authenticate", header)], "");
        assert!(protocol.should_handle(&response));
    }

    #[test]
    fn test_should_handle_non_402() {
        let protocol = MppProtocol;
        let header =
            r#"Payment id="abc123", realm="api", method="tempo", intent="charge", request="e30""#;
        let response = make_response(200, vec![("www-authenticate", header)], "");
        assert!(!protocol.should_handle(&response));
    }

    #[test]
    fn test_should_handle_missing_header() {
        let protocol = MppProtocol;
        let response = make_response(402, vec![], "");
        assert!(!protocol.should_handle(&response));
    }

    #[test]
    fn test_should_handle_non_payment_scheme() {
        let protocol = MppProtocol;
        let response = make_response(402, vec![("www-authenticate", "Bearer token")], "");
        assert!(!protocol.should_handle(&response));
    }

    #[test]
    fn test_should_not_handle_x402_body() {
        let protocol = MppProtocol;
        // x402 uses JSON body, not WWW-Authenticate header
        let body = r#"{"x402Version": 1, "error": "Payment Required", "accepts": []}"#;
        let response = make_response(402, vec![], body);
        assert!(!protocol.should_handle(&response));
    }

    #[test]
    #[allow(deprecated)]
    fn test_parse_rejects_tempo_split_payments_on_all_paths() {
        use mpp::protocol::core::Base64UrlJson;

        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x1111111111111111111111111111111111111111",
            "methodDetails": {
                "chainId": 42431,
                "feePayer": true,
                "splits": [{
                    "amount": "999999",
                    "recipient": "0x2222222222222222222222222222222222222222"
                }]
            }
        }))
        .unwrap();
        let challenge = mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            "tempo",
            "charge",
            request,
        );
        let header = mpp::format_www_authenticate(&challenge).unwrap();
        let response = make_response(402, vec![("www-authenticate", &header)], "");
        let protocol = MppProtocol;

        let native_error = protocol.parse_challenges(&response).unwrap_err();
        let legacy_error = protocol.parse_challenge_json(&response).unwrap_err();

        assert!(native_error
            .to_string()
            .contains("split-payment challenges"));
        assert!(legacy_error
            .to_string()
            .contains("split-payment challenges"));
    }

    #[test]
    #[allow(deprecated)]
    fn test_parse_rejects_missing_recipient_on_all_paths() {
        use mpp::protocol::core::Base64UrlJson;

        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "methodDetails": { "chainId": 42431 }
        }))
        .unwrap();
        let challenge = mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            "tempo",
            "charge",
            request,
        );
        let header = mpp::format_www_authenticate(&challenge).unwrap();
        let response = make_response(402, vec![("www-authenticate", &header)], "");
        let protocol = MppProtocol;

        let native_error = protocol.parse_challenges(&response).unwrap_err();
        let legacy_error = protocol.parse_challenge_json(&response).unwrap_err();

        assert!(native_error
            .to_string()
            .contains("did not provide a recipient"));
        assert!(legacy_error
            .to_string()
            .contains("did not provide a recipient"));
    }

    #[test]
    fn test_create_credential_header() {
        use base64::Engine;

        let protocol = MppProtocol;

        // Create a PaymentPayload-like JSON with mpp_authorization
        let payload_json = serde_json::json!({
            "x402Version": 1,
            "scheme": "mpp",
            "network": "eip155:42431",
            "payload": {
                "mpp_authorization": "Payment eyJhYmMi",
                "source": "0x1234"
            }
        });
        let json_str = serde_json::to_string(&payload_json).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json_str);

        let credential = CredentialPayload {
            data: encoded,
            version: 1,
        };
        let (name, value) = protocol.create_credential_header(&credential);
        assert_eq!(name, "Authorization");
        // Should extract mpp_authorization, not the whole payload
        assert_eq!(value, "Payment eyJhYmMi");
    }

    #[test]
    fn test_receipt_header_name() {
        let protocol = MppProtocol;
        assert_eq!(protocol.receipt_header_name(1), "payment-receipt");
    }
}
