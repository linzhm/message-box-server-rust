//! Offline parser for the fixed BRC-105 payment-header JSON shape.
//!
//! A parsed header is untrusted. This module does not verify a nonce, parse a
//! transaction, check amounts, internalize funds, prevent replay, or authorize
//! a request. Authenticated business routes continue to reject payment headers.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentHeader {
    pub derivation_prefix: String,
    pub derivation_suffix: String,
    pub transaction: String,
}

/// Parse the upstream JSON object and three canonical, nonempty Base64 fields.
/// Extra object fields are ignored as in the pinned middleware. The caller must
/// enforce transport-size limits before passing untrusted input to this function.
/// serde_json's parser limits and Unicode rules may reject inputs accepted by JS.
pub fn parse_payment_header(raw: &str) -> Option<PaymentHeader> {
    let value: Value = serde_json::from_str(raw).ok()?;
    let object = value.as_object()?;
    let field = |name: &str| -> Option<String> {
        let text = object.get(name)?.as_str()?;
        if text.is_empty() {
            return None;
        }
        let decoded = STANDARD.decode(text).ok()?;
        if STANDARD.encode(decoded) != text {
            return None;
        }
        Some(text.to_owned())
    };
    Some(PaymentHeader {
        derivation_prefix: field("derivationPrefix")?,
        derivation_suffix: field("derivationSuffix")?,
        transaction: field("transaction")?,
    })
}

/// Verify the derivation prefix using the pinned middleware's SDK nonce call.
/// As in that middleware, wallet errors are treated as an invalid prefix.
/// A true result proves neither freshness nor payment and must never by itself
/// authorize a request or transaction.
pub async fn verify_payment_prefix<W: crate::auth_nonce::NonceWallet>(
    wallet: &W,
    header: &PaymentHeader,
) -> bool {
    crate::auth_nonce::verify_nonce(wallet, &header.derivation_prefix, "self", None)
        .await
        .unwrap_or(false)
}
