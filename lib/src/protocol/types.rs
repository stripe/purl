//! Protocol-agnostic traits for payment concepts.
//!
//! These traits define the core abstractions shared across different payment protocols,
//! allowing protocol-independent code in the client and negotiator.

use std::any::Any;
use std::fmt::Debug;

/// A payment challenge from a server's 402 response.
///
/// This trait abstracts the common properties of payment requirements across
/// payment protocols.
pub trait PaymentChallenge: Send + Sync + Debug {
    /// Get the network identifier (e.g., "base-sepolia" or "eip155:84532")
    fn network(&self) -> &str;

    /// Get the payment amount in atomic units
    fn amount(&self) -> &str;

    /// Get the asset/token address
    fn asset(&self) -> &str;

    /// Get the recipient address
    fn recipient(&self) -> &str;

    /// Check if this is an EVM-compatible network
    fn is_evm(&self) -> bool;

    /// Check if this is a Solana network
    fn is_solana(&self) -> bool;

    /// Get the maximum timeout in seconds
    fn max_timeout_seconds(&self) -> u64;

    /// Get the payment scheme (e.g., "exact", "eip3009")
    fn scheme(&self) -> &str;

    /// Get the resource URL
    fn resource(&self) -> &str;

    /// Get optional extra data as JSON
    fn extra(&self) -> Option<&serde_json::Value>;

    /// Get description of the payment
    fn description(&self) -> &str;

    /// Get the MIME type of the resource
    fn mime_type(&self) -> &str;

    /// Downcast to concrete type for protocol-specific operations
    fn as_any(&self) -> &dyn Any;
}

/// A payment receipt from a server's response after payment.
///
/// This trait abstracts the common properties of settlement responses across
/// different protocols.
pub trait PaymentReceipt: Send + Sync + Debug {
    /// Check if the payment was successful
    fn is_success(&self) -> bool;

    /// Get the transaction hash/signature
    fn transaction(&self) -> &str;

    /// Get the network identifier
    fn network(&self) -> &str;

    /// Get the error reason if payment failed
    fn error_reason(&self) -> Option<&str>;

    /// Get the payer address if available
    fn payer(&self) -> Option<&str>;

    /// Downcast to concrete type for protocol-specific operations
    fn as_any(&self) -> &dyn Any;
}

/// Credential payload to send with payment request
#[derive(Debug, Clone)]
pub struct CredentialPayload {
    /// The signed/encoded payment data
    pub data: String,
    /// Protocol-specific version info
    pub version: u32,
}
