//! Protocol registry for detecting and managing payment protocols.

use std::collections::HashMap;

use super::PaymentProtocol;
use crate::http::HttpResponse;
use once_cell::sync::Lazy;

/// Registry of payment protocols.
///
/// The registry holds all available protocol implementations and provides
/// methods for detecting which protocol to use for a given HTTP response.
///
/// Protocols are checked in registration order. More specific protocols
/// (like MPP with header-based detection) should be registered before
/// more general protocols (like x402 with body-based detection).
pub struct ProtocolRegistry {
    /// Protocols in registration order for deterministic detection
    protocols_ordered: Vec<Box<dyn PaymentProtocol>>,
    /// Name-to-index map for O(1) lookups by name
    name_index: HashMap<String, usize>,
}

impl ProtocolRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            protocols_ordered: Vec::new(),
            name_index: HashMap::new(),
        }
    }

    /// Create a registry with the default protocols.
    ///
    /// MPP is registered first because it has more specific detection
    /// (WWW-Authenticate: Payment header) compared to x402's body-based detection.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        // MPP first - more specific header-based detection
        registry.register(Box::new(crate::mpp::MppProtocol));
        // x402 second - more general body-based detection
        registry.register(Box::new(crate::x402::X402Protocol));
        registry
    }

    /// Register a protocol implementation
    pub fn register(&mut self, protocol: Box<dyn PaymentProtocol>) {
        let name = protocol.name().to_string();
        let index = self.protocols_ordered.len();
        self.protocols_ordered.push(protocol);
        self.name_index.insert(name, index);
    }

    /// Find which protocol should handle the response.
    ///
    /// Protocols are checked in registration order. Returns the first protocol
    /// whose `should_handle()` method returns true, or None if no protocol matches.
    pub fn find_handler(&self, response: &HttpResponse) -> Option<&dyn PaymentProtocol> {
        self.protocols_ordered
            .iter()
            .find(|p| p.should_handle(response))
            .map(|p| p.as_ref())
    }

    /// Find all protocols that can handle the response.
    ///
    /// Returns every protocol whose `should_handle()` returns true,
    /// preserving registration order.
    pub fn find_all_handlers(&self, response: &HttpResponse) -> Vec<&dyn PaymentProtocol> {
        self.protocols_ordered
            .iter()
            .filter(|p| p.should_handle(response))
            .map(|p| p.as_ref())
            .collect()
    }

    /// Get a protocol by name
    pub fn get(&self, name: &str) -> Option<&dyn PaymentProtocol> {
        self.name_index
            .get(name)
            .and_then(|&idx| self.protocols_ordered.get(idx))
            .map(|p| p.as_ref())
    }

    /// List all registered protocol names
    pub fn protocol_names(&self) -> Vec<&str> {
        self.protocols_ordered.iter().map(|p| p.name()).collect()
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
            url: "https://example.com/".to_string(),
            headers: header_map,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn test_registry_default_has_x402() {
        let registry = ProtocolRegistry::with_defaults();
        assert!(registry.get(crate::x402::PROTOCOL_NAME).is_some());
        assert!(registry.get(crate::mpp::protocol::PROTOCOL_NAME).is_some());
        let names = registry.protocol_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&crate::x402::PROTOCOL_NAME));
        assert!(names.contains(&crate::mpp::protocol::PROTOCOL_NAME));
    }

    #[test]
    fn test_registry_find_handler_x402_v1() {
        let registry = ProtocolRegistry::with_defaults();
        let body = r#"{"x402Version": 1, "error": "Payment Required", "accepts": []}"#;
        let response = make_response(402, vec![], body);

        let protocol = registry.find_handler(&response);
        assert!(protocol.is_some());
        assert_eq!(protocol.unwrap().name(), crate::x402::PROTOCOL_NAME);
    }

    #[test]
    fn test_registry_find_handler_x402_v2() {
        let registry = ProtocolRegistry::with_defaults();
        let response = make_response(
            402,
            vec![("payment-required", "eyJ4NDAyVmVyc2lvbiI6Mn0=")],
            "",
        );

        let protocol = registry.find_handler(&response);
        assert!(protocol.is_some());
        assert_eq!(protocol.unwrap().name(), crate::x402::PROTOCOL_NAME);
    }

    #[test]
    fn test_registry_find_handler_non_payment_response() {
        let registry = ProtocolRegistry::with_defaults();
        let response = make_response(200, vec![], "OK");

        let protocol = registry.find_handler(&response);
        assert!(protocol.is_none());
    }

    #[test]
    fn test_registry_find_handler_unknown_402() {
        let registry = ProtocolRegistry::with_defaults();
        let response = make_response(402, vec![], "Payment required");

        let protocol = registry.find_handler(&response);
        assert!(protocol.is_none());
    }

    #[test]
    fn test_registry_find_handler_mpp() {
        let registry = ProtocolRegistry::with_defaults();
        // MPP uses WWW-Authenticate: Payment header
        let header = r#"Payment id="abc123", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIn0""#;
        let response = make_response(402, vec![("www-authenticate", header)], "");

        let protocol = registry.find_handler(&response);
        assert!(protocol.is_some());
        assert_eq!(
            protocol.unwrap().name(),
            crate::mpp::protocol::PROTOCOL_NAME
        );
    }

    #[test]
    fn test_registry_mpp_takes_precedence_over_x402() {
        let registry = ProtocolRegistry::with_defaults();
        // Response with both MPP header AND x402-like body
        // MPP should win because it's checked first and has specific header
        let header = r#"Payment id="abc123", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIn0""#;
        let body = r#"{"accepts": []}"#; // x402-like body
        let response = make_response(402, vec![("www-authenticate", header)], body);

        let protocol = registry.find_handler(&response);
        assert!(protocol.is_some());
        assert_eq!(
            protocol.unwrap().name(),
            crate::mpp::protocol::PROTOCOL_NAME
        );
    }

    #[test]
    fn test_global_protocol_registry() {
        assert!(PROTOCOL_REGISTRY.get(crate::x402::PROTOCOL_NAME).is_some());
    }

    #[test]
    fn test_find_all_handlers_single_protocol() {
        let registry = ProtocolRegistry::with_defaults();
        // Only x402 body, no MPP header
        let body = r#"{"x402Version": 1, "error": "Payment Required", "accepts": []}"#;
        let response = make_response(402, vec![], body);

        let handlers = registry.find_all_handlers(&response);
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].name(), crate::x402::PROTOCOL_NAME);
    }

    #[test]
    fn test_find_all_handlers_both_protocols() {
        let registry = ProtocolRegistry::with_defaults();
        // Response with both MPP header AND x402 body
        let header = r#"Payment id="abc123", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIn0""#;
        let body = r#"{"x402Version": 1, "error": "Payment Required", "accepts": []}"#;
        let response = make_response(402, vec![("www-authenticate", header)], body);

        let handlers = registry.find_all_handlers(&response);
        assert_eq!(handlers.len(), 2);
        assert_eq!(handlers[0].name(), crate::mpp::protocol::PROTOCOL_NAME);
        assert_eq!(handlers[1].name(), crate::x402::PROTOCOL_NAME);
    }

    #[test]
    fn test_find_all_handlers_no_match() {
        let registry = ProtocolRegistry::with_defaults();
        let response = make_response(402, vec![], "Payment required");

        let handlers = registry.find_all_handlers(&response);
        assert!(handlers.is_empty());
    }
}
