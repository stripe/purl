//! Payment protocol abstraction layer.
//!
//! This module provides traits and types for abstracting payment protocols,
//! allowing the client and negotiator to work with any protocol without
//! hardcoded dependencies.
//!
//! # Architecture
//!
//! - [`PaymentProtocol`] - Main trait for protocol implementations
//! - [`PaymentChallenge`] - Abstract payment requirements from 402 responses
//! - [`PaymentReceipt`] - Abstract settlement responses
//! - [`ProtocolRegistry`] - Registry for detecting and selecting protocols

mod registry;
mod types;

pub use registry::{ProtocolRegistry, PROTOCOL_REGISTRY};
pub use types::{CredentialPayload, PaymentChallenge, PaymentReceipt};

use crate::error::Result;
use crate::http::HttpResponse;

/// Trait for payment protocol implementations.
///
/// Each protocol implements this trait to handle its specific detection logic,
/// challenge parsing, credential creation, and receipt parsing.
///
/// # Example
///
/// ```ignore
/// struct MyProtocol;
///
/// impl PaymentProtocol for MyProtocol {
///     fn name(&self) -> &str { "my-protocol" }
///     fn detect(&self, response: &HttpResponse) -> bool {
///         response.status_code == 402 && response.get_header("my-header").is_some()
///     }
///     // ... implement other methods
/// }
/// ```
pub trait PaymentProtocol: Send + Sync {
    /// Get the protocol name for logging/debugging
    fn name(&self) -> &str;

    /// Detect if this protocol should handle the response.
    ///
    /// Called on 402 responses to determine which protocol to use.
    /// Should check for protocol-specific headers or body markers.
    fn detect(&self, response: &HttpResponse) -> bool;

    /// Parse the payment challenge from the 402 response.
    ///
    /// Returns the raw requirements JSON for further processing by the negotiator.
    /// The negotiator will parse this into protocol-specific types.
    fn parse_challenge_json(&self, response: &HttpResponse) -> Result<String>;

    /// Create the credential header for the payment request.
    ///
    /// Returns (header_name, header_value) tuple to add to the retry request.
    fn create_credential_header(&self, payload: &CredentialPayload) -> (String, String);

    /// Get the response header name where receipt will be found
    fn receipt_header_name(&self, version: u32) -> &str;

    /// Parse the payment receipt from a successful response.
    ///
    /// Returns the raw receipt JSON for further processing.
    fn parse_receipt_json(&self, response: &HttpResponse, version: u32) -> Result<Option<String>>;
}
