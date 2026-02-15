//! Protocol registry for detecting and managing payment protocols.

use super::PaymentProtocol;
use crate::http::HttpResponse;
use once_cell::sync::Lazy;

/// Registry of payment protocols.
///
/// The registry holds all available protocol implementations and provides
/// methods for detecting which protocol to use for a given HTTP response.
pub struct ProtocolRegistry {
    protocols: Vec<Box<dyn PaymentProtocol>>,
}

impl ProtocolRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            protocols: Vec::new(),
        }
    }

    /// Create a registry with the default protocols (x402)
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(crate::x402::X402Protocol));
        registry
    }

    /// Register a protocol implementation
    pub fn register(&mut self, protocol: Box<dyn PaymentProtocol>) {
        self.protocols.push(protocol);
    }

    /// Detect which protocol should handle the response.
    ///
    /// Returns the first protocol whose `detect()` method returns true,
    /// or None if no protocol matches.
    pub fn detect(&self, response: &HttpResponse) -> Option<&dyn PaymentProtocol> {
        self.protocols
            .iter()
            .find(|p| p.detect(response))
            .map(|p| p.as_ref())
    }

    /// Get a protocol by name
    pub fn get(&self, name: &str) -> Option<&dyn PaymentProtocol> {
        self.protocols
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    /// List all registered protocol names
    pub fn protocol_names(&self) -> Vec<&str> {
        self.protocols.iter().map(|p| p.name()).collect()
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Global static protocol registry
pub static PROTOCOL_REGISTRY: Lazy<ProtocolRegistry> = Lazy::new(ProtocolRegistry::with_defaults);

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
    fn test_registry_default_has_x402() {
        let registry = ProtocolRegistry::with_defaults();
        assert!(registry.get("x402").is_some());
        assert_eq!(registry.protocol_names(), vec!["x402"]);
    }

    #[test]
    fn test_registry_detect_x402_v1() {
        let registry = ProtocolRegistry::with_defaults();
        let body = r#"{"x402Version": 1, "error": "Payment Required", "accepts": []}"#;
        let response = make_response(402, vec![], body);

        let protocol = registry.detect(&response);
        assert!(protocol.is_some());
        assert_eq!(protocol.unwrap().name(), "x402");
    }

    #[test]
    fn test_registry_detect_x402_v2() {
        let registry = ProtocolRegistry::with_defaults();
        let response = make_response(
            402,
            vec![("payment-required", "eyJ4NDAyVmVyc2lvbiI6Mn0=")],
            "",
        );

        let protocol = registry.detect(&response);
        assert!(protocol.is_some());
        assert_eq!(protocol.unwrap().name(), "x402");
    }

    #[test]
    fn test_registry_detect_non_payment_response() {
        let registry = ProtocolRegistry::with_defaults();
        let response = make_response(200, vec![], "OK");

        let protocol = registry.detect(&response);
        assert!(protocol.is_none());
    }

    #[test]
    fn test_registry_detect_unknown_402() {
        let registry = ProtocolRegistry::with_defaults();
        let response = make_response(402, vec![], "Payment required");

        let protocol = registry.detect(&response);
        assert!(protocol.is_none());
    }

    #[test]
    fn test_global_protocol_registry() {
        assert!(PROTOCOL_REGISTRY.get("x402").is_some());
    }
}
