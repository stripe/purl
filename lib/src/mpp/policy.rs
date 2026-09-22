//! Display-safety policy for inbound MPP challenges.
//!
//! purl only signs a payment it can describe to the user first. A challenge that
//! encodes semantics no purl payment view can render is refused here, at parse time,
//! rather than surfacing as a payment the user approved without seeing.
//!
//! Every path that turns a raw `mpp::PaymentChallenge` into something purl acts on
//! goes through [`decode_and_validate`], so the rules below cannot be bypassed by
//! adding a new caller.

use crate::error::{PurlError, Result};

use super::challenge::decode_request;

/// Tempo Moderato is purl's default when a challenge omits `chainId`.
///
/// Keep this default in one place and pin the signer to the resolved value. Without
/// the pin, mpp-rs uses its own (mainnet) default for the same missing field.
pub(crate) const DEFAULT_TEMPO_CHAIN_ID: u64 = 42431;

/// Decode a challenge's request payload and apply purl's display-safety rules.
pub(crate) fn decode_and_validate(challenge: &mpp::PaymentChallenge) -> Result<serde_json::Value> {
    let request = decode_request(challenge)?;
    reject_undisclosed_transfers(challenge, &request)?;
    require_recipient(&request)?;
    require_amount(&request)?;
    if challenge.method.as_str() == "tempo" {
        tempo_chain_id(&request)?;
    }
    Ok(request)
}

/// Read an amount that every purl payment view can faithfully represent.
///
/// MPP amounts are decimal strings in atomic units. In particular, accepting a
/// second syntax here (such as a hex string accepted by a downstream signer)
/// would let the display and signing paths interpret the same input differently.
pub(crate) fn require_amount(request: &serde_json::Value) -> Result<&str> {
    let amount = request
        .get("amount")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PurlError::MissingRequirement("amount".to_string()))?;

    if amount.is_empty()
        || !amount.bytes().all(|byte| byte.is_ascii_digit())
        || amount.parse::<u128>().is_err()
    {
        return Err(PurlError::InvalidAmount(amount.to_string()));
    }

    Ok(amount)
}

/// Resolve the Tempo chain purl displays and later pins in mpp-rs.
pub(crate) fn tempo_chain_id(request: &serde_json::Value) -> Result<u64> {
    match request
        .get("methodDetails")
        .and_then(|details| details.get("chainId"))
    {
        Some(chain_id) => chain_id.as_u64().ok_or_else(|| {
            PurlError::Http(
                "Invalid Tempo methodDetails.chainId: expected an unsigned integer".to_string(),
            )
        }),
        None => Ok(DEFAULT_TEMPO_CHAIN_ID),
    }
}

/// Reject challenges that move funds purl would not name in the payment view.
///
/// The MPP Tempo signer treats `methodDetails.splits` as additional token transfers.
/// Until every purl payment view can display and confirm that exact transfer plan,
/// accepting such a challenge would let the signer pay undisclosed recipients.
fn reject_undisclosed_transfers(
    challenge: &mpp::PaymentChallenge,
    request: &serde_json::Value,
) -> Result<()> {
    let contains_splits = request
        .get("methodDetails")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|details| details.contains_key("splits"));

    if challenge.method.as_str() == "tempo" && contains_splits {
        return Err(PurlError::Http(
            "Tempo split-payment challenges are not supported".to_string(),
        ));
    }

    Ok(())
}

/// Read the recipient purl will pay out of a decoded MPP request.
///
/// A challenge with no recipient would render as a blank address in every payment
/// view, so purl refuses it instead of asking the user to confirm a payment whose
/// destination it cannot name.
pub(crate) fn require_recipient(request: &serde_json::Value) -> Result<&str> {
    let recipient = request
        .get("recipient")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    if recipient.is_empty() {
        return Err(PurlError::invalid_address(
            "The server did not provide a recipient address for this MPP challenge.",
        ));
    }

    Ok(recipient)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpp::protocol::core::Base64UrlJson;

    fn challenge_with(method: &str, request_json: serde_json::Value) -> mpp::PaymentChallenge {
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        mpp::PaymentChallenge::new(
            "test-id".to_string(),
            "https://example.com/api",
            method,
            "charge",
            request,
        )
    }

    #[test]
    fn test_accepts_a_single_recipient_charge() {
        let challenge = challenge_with(
            "tempo",
            serde_json::json!({
                "amount": "1000000",
                "recipient": "0x1111111111111111111111111111111111111111",
            }),
        );

        let request = decode_and_validate(&challenge).unwrap();
        assert_eq!(
            require_recipient(&request).unwrap(),
            "0x1111111111111111111111111111111111111111"
        );
        assert_eq!(require_amount(&request).unwrap(), "1000000");
        assert_eq!(tempo_chain_id(&request).unwrap(), DEFAULT_TEMPO_CHAIN_ID);
    }

    #[test]
    fn test_rejects_amounts_the_display_cannot_represent() {
        for amount in [
            serde_json::Value::Null,
            serde_json::json!(1000000),
            serde_json::json!(""),
            serde_json::json!("0x3B9ACA00"),
            serde_json::json!("340282366920938463463374607431768211456"),
        ] {
            let challenge = challenge_with(
                "tempo",
                serde_json::json!({
                    "amount": amount,
                    "recipient": "0x1111111111111111111111111111111111111111"
                }),
            );
            let error = decode_and_validate(&challenge).unwrap_err();
            assert!(
                matches!(
                    error,
                    PurlError::InvalidAmount(_) | PurlError::MissingRequirement(_)
                ),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn test_tempo_chain_id_uses_one_validated_default() {
        let absent = serde_json::json!({});
        assert_eq!(tempo_chain_id(&absent).unwrap(), DEFAULT_TEMPO_CHAIN_ID);

        let explicit = serde_json::json!({ "methodDetails": { "chainId": 4217 } });
        assert_eq!(tempo_chain_id(&explicit).unwrap(), 4217);

        let malformed = serde_json::json!({
            "methodDetails": { "chainId": "not-a-number" }
        });
        assert!(tempo_chain_id(&malformed).is_err());
    }

    #[test]
    fn test_rejects_tempo_splits() {
        let challenge = challenge_with(
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
        );

        let error = decode_and_validate(&challenge).unwrap_err();
        assert!(error.to_string().contains("split-payment challenges"));
    }

    #[test]
    fn test_rejects_missing_or_blank_recipient() {
        for request_json in [
            serde_json::json!({ "amount": "1000000" }),
            serde_json::json!({ "recipient": "" }),
            serde_json::json!({ "recipient": serde_json::Value::Null }),
        ] {
            let challenge = challenge_with("tempo", request_json.clone());
            let error = decode_and_validate(&challenge).unwrap_err();
            assert!(
                error.to_string().contains("did not provide a recipient"),
                "unexpected error for {request_json}: {error}"
            );
        }
    }

    #[test]
    fn test_reports_splits_before_recipient_when_both_are_wrong() {
        // The more specific rule should win, so the user sees why the shape of the
        // challenge was refused rather than a generic missing-field message.
        let challenge = challenge_with(
            "tempo",
            serde_json::json!({
                "methodDetails": { "splits": [] }
            }),
        );

        let error = decode_and_validate(&challenge).unwrap_err();
        assert!(error.to_string().contains("split-payment challenges"));
    }
}
