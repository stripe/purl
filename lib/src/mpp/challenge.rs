//! MPP Challenge wrapper implementing purl's PaymentChallenge trait.
//!
//! This module provides a wrapper around mpp::PaymentChallenge that implements
//! purl's protocol-agnostic PaymentChallenge trait, allowing native MPP challenges
//! to flow through the purl payment pipeline without lossy conversion.

use crate::protocol::PaymentChallenge;
use std::any::Any;
use std::fmt;

/// Wrapper around mpp::PaymentChallenge that implements purl's PaymentChallenge trait.
///
/// This wrapper preserves the native MPP challenge data, allowing the Tempo provider
/// to downcast and use the original challenge directly without reconstruction.
pub struct MppChallenge {
    /// The native MPP challenge
    pub inner: mpp::PaymentChallenge,
    /// Network identifier (e.g., "eip155:42431" for Tempo Moderato)
    pub network: String,
    /// Payment amount in atomic units
    pub amount: String,
    /// Asset/currency identifier
    pub asset: String,
    /// Recipient address
    pub recipient: String,
    /// Resource URL
    pub resource: String,
    /// Description of the payment
    pub description: String,
}

impl fmt::Debug for MppChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MppChallenge")
            .field("network", &self.network)
            .field("amount", &self.amount)
            .field("asset", &self.asset)
            .field("recipient", &self.recipient)
            .field("resource", &self.resource)
            .field("description", &self.description)
            .field("inner.id", &self.inner.id)
            .finish()
    }
}

impl MppChallenge {
    /// Create a new MppChallenge from a native mpp::PaymentChallenge.
    ///
    /// Extracts relevant fields from the challenge's request payload.
    pub fn from_mpp_challenge(challenge: mpp::PaymentChallenge) -> crate::error::Result<Self> {
        let request = super::policy::decode_and_validate(&challenge)?;

        // Extract fields from the request
        let amount = super::policy::require_amount(&request)?.to_string();
        let asset = request
            .get("currency")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let recipient = super::policy::require_recipient(&request)?.to_string();

        // Get chain ID from methodDetails if available
        let chain_id = super::policy::tempo_chain_id(&request)?;

        // Determine network from method and chain ID
        let network = format!("eip155:{}", chain_id);

        let resource = challenge.realm.clone();
        let description = challenge.description.clone().unwrap_or_default();

        Ok(Self {
            inner: challenge,
            network,
            amount,
            asset,
            recipient,
            resource,
            description,
        })
    }
}

/// Decode an MPP challenge's base64url request payload into JSON.
///
/// This is a plain decode. Callers that are about to act on the result should go
/// through [`super::policy::decode_and_validate`] instead, which applies purl's
/// display-safety rules on top of this.
pub(crate) fn decode_request(
    challenge: &mpp::PaymentChallenge,
) -> crate::error::Result<serde_json::Value> {
    challenge
        .request
        .decode_value()
        .map_err(|e| crate::error::PurlError::Http(format!("Failed to decode MPP request: {}", e)))
}

impl PaymentChallenge for MppChallenge {
    fn network(&self) -> &str {
        &self.network
    }

    fn amount(&self) -> &str {
        &self.amount
    }

    fn asset(&self) -> &str {
        &self.asset
    }

    fn recipient(&self) -> &str {
        &self.recipient
    }

    fn is_evm(&self) -> bool {
        // MPP challenges on Tempo use EVM-compatible addresses
        self.network.starts_with("eip155:")
    }

    fn is_solana(&self) -> bool {
        false
    }

    fn is_tempo(&self) -> bool {
        crate::network::is_tempo_network(&self.network) || self.inner.method.as_str() == "tempo"
    }

    fn max_timeout_seconds(&self) -> u64 {
        // MPP challenges may have an expires field, but default to 300 seconds
        300
    }

    fn scheme(&self) -> &str {
        "mpp"
    }

    fn resource(&self) -> &str {
        &self.resource
    }

    fn extra(&self) -> Option<&serde_json::Value> {
        // MPP doesn't use the extra field in the same way
        None
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn mime_type(&self) -> &str {
        "application/json"
    }

    fn protocol_name(&self) -> &str {
        "mpp"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_challenge(method: &str, request_json: serde_json::Value) -> MppChallenge {
        try_make_challenge(method, request_json).unwrap()
    }

    fn try_make_challenge(
        method: &str,
        request_json: serde_json::Value,
    ) -> crate::error::Result<MppChallenge> {
        use mpp::protocol::core::Base64UrlJson;
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let inner = mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            method,
            "charge",
            request,
        );
        MppChallenge::from_mpp_challenge(inner)
    }

    #[test]
    fn test_mpp_challenge_is_tempo() {
        let challenge = make_challenge(
            "tempo",
            serde_json::json!({
                "amount": "1000",
                "currency": "USDC",
                "recipient": "0x1234",
            }),
        );

        assert!(challenge.is_tempo());
        assert!(challenge.is_evm());
        assert!(!challenge.is_solana());
        assert_eq!(challenge.scheme(), "mpp");
        assert_eq!(challenge.amount(), "1000");
        assert_eq!(challenge.asset(), "USDC");
    }

    #[test]
    fn test_mpp_challenge_fields() {
        let challenge = make_challenge(
            "tempo",
            serde_json::json!({
                "amount": "5000000",
                "currency": "pathUSD",
                "recipient": "0xabcdef1234567890abcdef1234567890abcdef12",
            }),
        );

        assert_eq!(challenge.amount(), "5000000");
        assert_eq!(challenge.asset(), "pathUSD");
        assert_eq!(
            challenge.recipient(),
            "0xabcdef1234567890abcdef1234567890abcdef12"
        );
        assert_eq!(challenge.resource(), "https://example.com/api");
        assert_eq!(challenge.mime_type(), "application/json");
        assert_eq!(challenge.max_timeout_seconds(), 300);
        assert!(challenge.extra().is_none());
    }

    #[test]
    fn test_mpp_challenge_network_from_chain_id() {
        // With explicit chainId for mainnet
        let challenge = make_challenge(
            "tempo",
            serde_json::json!({
                "amount": "1000",
                "currency": "USDC",
                "recipient": "0x1234",
                "methodDetails": { "chainId": 4217 },
            }),
        );
        assert_eq!(challenge.network(), "eip155:4217");
        assert!(challenge.is_tempo());

        // With explicit chainId for testnet
        let challenge = make_challenge(
            "tempo",
            serde_json::json!({
                "amount": "1000",
                "currency": "USDC",
                "recipient": "0x1234",
                "methodDetails": { "chainId": 42431 },
            }),
        );
        assert_eq!(challenge.network(), "eip155:42431");
        assert!(challenge.is_tempo());

        // Without methodDetails - defaults to 42431 for backward compat
        let challenge = make_challenge(
            "tempo",
            serde_json::json!({
                "amount": "1000",
                "currency": "USDC",
                "recipient": "0x1234",
            }),
        );
        assert_eq!(challenge.network(), "eip155:42431");
    }

    #[test]
    fn test_mpp_challenge_missing_amount_is_rejected() {
        let error =
            try_make_challenge("tempo", serde_json::json!({ "recipient": "0x1234" })).unwrap_err();

        assert!(error.to_string().contains("missing required field: amount"));
    }

    /// `super::policy` owns the per-rule cases; this only proves construction is
    /// routed through it and cannot yield an unshowable challenge.
    #[test]
    fn test_mpp_challenge_construction_applies_display_policy() {
        let missing_recipient = try_make_challenge("tempo", serde_json::json!({})).unwrap_err();
        assert!(missing_recipient
            .to_string()
            .contains("did not provide a recipient"));

        let split_payment = try_make_challenge(
            "tempo",
            serde_json::json!({
                "amount": "1000000",
                "recipient": "0x1111111111111111111111111111111111111111",
                "methodDetails": {
                    "splits": [{
                        "amount": "999999",
                        "recipient": "0x2222222222222222222222222222222222222222"
                    }]
                }
            }),
        )
        .unwrap_err();
        assert!(split_payment
            .to_string()
            .contains("split-payment challenges"));
    }

    #[test]
    fn test_mpp_challenge_non_tempo_method() {
        // A non-tempo method should still produce an eip155 network
        let challenge = make_challenge(
            "other-method",
            serde_json::json!({
                "amount": "100",
                "currency": "USDC",
                "recipient": "0x1234",
                "methodDetails": { "chainId": 1 },
            }),
        );

        assert_eq!(challenge.network(), "eip155:1");
        // is_tempo checks both network and method
        assert!(!challenge.is_tempo());
        assert!(challenge.is_evm());
    }

    #[test]
    fn test_mpp_challenge_as_any_downcast() {
        let challenge = make_challenge(
            "tempo",
            serde_json::json!({
                "amount": "1000",
                "currency": "USDC",
                "recipient": "0x1234",
            }),
        );

        // Should be able to downcast from trait object
        let trait_obj: &dyn PaymentChallenge = &challenge;
        let downcasted = trait_obj.as_any().downcast_ref::<MppChallenge>();
        assert!(downcasted.is_some());
        assert_eq!(downcasted.unwrap().amount(), "1000");
    }

    #[test]
    fn test_mpp_challenge_debug_format() {
        let challenge = make_challenge(
            "tempo",
            serde_json::json!({
                "amount": "1000",
                "currency": "USDC",
                "recipient": "0x1234",
            }),
        );

        let debug = format!("{:?}", challenge);
        assert!(debug.contains("MppChallenge"));
        assert!(debug.contains("eip155:42431"));
        assert!(debug.contains("USDC"));
    }
}
