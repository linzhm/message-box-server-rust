//! Offline metadata check for the legacy server delivery remittance.
//!
//! This checks only canonical sender identity and derivation metadata. It does
//! not authenticate the caller, inspect BEEF or output value, verify a locking
//! script or chain, internalize funds, claim replay, or authorize message delivery.
//! The authenticated Identity must come from a trusted transport, not a header.
use crate::Identity;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;

pub(crate) fn canonical_token(value: &Value) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    if text.is_empty() || text.len() > 128 {
        return false;
    }
    STANDARD
        .decode(text)
        .is_ok_and(|bytes| STANDARD.encode(bytes) == text)
}
/// Check metadata on the first delivery remittance. The caller must select the
/// first payment output and authenticate the sender before calling this helper.
/// Extra fields are ignored here, as in the upstream metadata predicate; this
/// function does not validate the rest of the request. `None` means an
/// unsupported floating-point index representation, not an upstream rejection.
pub fn has_canonical_delivery_remittance(
    output: &Value,
    authenticated_sender: &Identity,
) -> Option<bool> {
    let index = match crate::payment_index::safe_index(output.get("outputIndex")) {
        Ok(Some(index)) => index,
        Ok(None) => return Some(false),
        Err(()) => return None,
    };
    let _ = index;
    if output.get("protocol").and_then(Value::as_str) != Some("wallet payment") {
        return Some(false);
    }
    let Some(remittance) = output.get("paymentRemittance").and_then(Value::as_object) else {
        return Some(false);
    };
    let (Some(prefix), Some(suffix)) = (
        remittance.get("derivationPrefix"),
        remittance.get("derivationSuffix"),
    ) else {
        return Some(false);
    };
    Some(
        canonical_token(prefix)
            && canonical_token(suffix)
            && remittance.get("senderIdentityKey").and_then(Value::as_str)
                == Some(authenticated_sender.as_str()),
    )
}
