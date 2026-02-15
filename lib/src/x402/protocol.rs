//! X402 protocol implementation.
//!
//! This module implements the PaymentProtocol trait for the x402 protocol,
//! supporting both v1 and v2 versions.

use crate::error::Result;
use crate::http::HttpResponse;
use crate::protocol::{CredentialPayload, PaymentProtocol};

use super::{
    PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER,
    V1_X_PAYMENT_HEADER, V1_X_PAYMENT_RESPONSE_HEADER,
};

/// X402 protocol implementation.
///
/// Supports both v1 and v2 of the x402 payment protocol:
/// - v1: Uses `X-PAYMENT` header for credentials, body for requirements
/// - v2: Uses `PAYMENT-SIGNATURE` header for credentials, `PAYMENT-REQUIRED` header for requirements
pub struct X402Protocol;

impl PaymentProtocol for X402Protocol {
    fn name(&self) -> &str {
        "x402"
    }

    fn detect(&self, response: &HttpResponse) -> bool {
        if response.status_code != 402 {
            return false;
        }

        // Check for v2 style (PAYMENT-REQUIRED header)
        if response.get_header(PAYMENT_REQUIRED_HEADER).is_some() {
            return true;
        }

        // Check for v1 style (JSON body with x402Version)
        if let Ok(body) = response.body_string() {
            if body.contains("x402Version") || body.contains("\"accepts\"") {
                return true;
            }
        }

        false
    }

    fn parse_challenge_json(&self, response: &HttpResponse) -> Result<String> {
        super::payment_requirements_json(response)
    }

    fn create_credential_header(&self, payload: &CredentialPayload) -> (String, String) {
        let header_name = if payload.version == 2 {
            PAYMENT_SIGNATURE_HEADER
        } else {
            V1_X_PAYMENT_HEADER
        };
        (header_name.to_string(), payload.data.clone())
    }

    fn receipt_header_name(&self, version: u32) -> &str {
        if version == 2 {
            PAYMENT_RESPONSE_HEADER
        } else {
            V1_X_PAYMENT_RESPONSE_HEADER
        }
    }

    fn parse_receipt_json(&self, response: &HttpResponse, version: u32) -> Result<Option<String>> {
        use base64::Engine;

        let header_name = self.receipt_header_name(version);
        if let Some(header) = response.get_header(header_name) {
            let decoded = base64::engine::general_purpose::STANDARD.decode(header)?;
            let json = String::from_utf8(decoded)?;
            Ok(Some(json))
        } else {
            Ok(None)
        }
    }
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
    fn test_detect_v1_response() {
        let protocol = X402Protocol;
        let body = r#"{"x402Version": 1, "error": "Payment Required", "accepts": []}"#;
        let response = make_response(402, vec![], body);
        assert!(protocol.detect(&response));
    }

    #[test]
    fn test_detect_v2_response() {
        let protocol = X402Protocol;
        let response = make_response(
            402,
            vec![("payment-required", "eyJ4NDAyVmVyc2lvbiI6Mn0=")],
            "",
        );
        assert!(protocol.detect(&response));
    }

    #[test]
    fn test_detect_non_402() {
        let protocol = X402Protocol;
        let response = make_response(200, vec![], r#"{"x402Version": 1}"#);
        assert!(!protocol.detect(&response));
    }

    #[test]
    fn test_detect_non_x402_402() {
        let protocol = X402Protocol;
        let response = make_response(402, vec![], "Payment required");
        assert!(!protocol.detect(&response));
    }

    #[test]
    fn test_create_credential_header_v1() {
        let protocol = X402Protocol;
        let payload = CredentialPayload {
            data: "base64data".to_string(),
            version: 1,
        };
        let (name, value) = protocol.create_credential_header(&payload);
        assert_eq!(name, "X-PAYMENT");
        assert_eq!(value, "base64data");
    }

    #[test]
    fn test_create_credential_header_v2() {
        let protocol = X402Protocol;
        let payload = CredentialPayload {
            data: "base64data".to_string(),
            version: 2,
        };
        let (name, value) = protocol.create_credential_header(&payload);
        assert_eq!(name, "PAYMENT-SIGNATURE");
        assert_eq!(value, "base64data");
    }

    #[test]
    fn test_receipt_header_names() {
        let protocol = X402Protocol;
        assert_eq!(protocol.receipt_header_name(1), "x-payment-response");
        assert_eq!(protocol.receipt_header_name(2), "payment-response");
    }
}
