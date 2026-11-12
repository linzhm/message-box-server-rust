//! Offline fixed-SDK BRC-29 recipient script derivation.
//!
//! The "anyone" wallet uses the publicly known private scalar 1. It must never
//! be treated as a secret. This derives only an expected P2PKH locking script;
//! it does not inspect a transaction or prove chain validity, spendability,
//! payment, authentication, replay protection, or message delivery.
use crate::{Identity, brc42::derive_public_child, delivery_remittance::canonical_token};
use k256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use ripemd::Ripemd160;
use serde_json::Value;
use sha2::{Digest, Sha256};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientScript {
    pub public_key: String,
    pub locking_script: [u8; 25],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRemittance;
/// Derive the recipient P2PKH script used by the pinned server's anyone wallet.
/// The recipient identity and metadata must already be associated with the
/// authenticated, validated request. The caller must separately require the
/// remittance sender to equal the fixed anyone identity, and compare the
/// transaction output. The output is not evidence of payment.
pub fn derive_recipient_script(
    recipient: &Identity,
    prefix: &str,
    suffix: &str,
) -> Result<RecipientScript, InvalidRemittance> {
    if !canonical_token(&Value::String(prefix.to_owned()))
        || !canonical_token(&Value::String(suffix.to_owned()))
    {
        return Err(InvalidRemittance);
    }
    let public = PublicKey::from_sec1_bytes(
        &hex::decode(recipient.as_str()).map_err(|_| InvalidRemittance)?,
    )
    .map_err(|_| InvalidRemittance)?;
    let mut one = [0u8; 32];
    one[31] = 1;
    let anyone = SecretKey::from_slice(&one).map_err(|_| InvalidRemittance)?;
    let invoice = format!("2-3241645161d8-{prefix} {suffix}");
    let child = derive_public_child(&anyone, &public, &invoice).map_err(|_| InvalidRemittance)?;
    let encoded = child.to_encoded_point(true);
    let hash = Ripemd160::digest(Sha256::digest(encoded.as_bytes()));
    let mut script = [0u8; 25];
    script[..3].copy_from_slice(&[0x76, 0xa9, 0x14]);
    script[3..23].copy_from_slice(&hash);
    script[23..].copy_from_slice(&[0x88, 0xac]);
    Ok(RecipientScript {
        public_key: hex::encode(encoded.as_bytes()),
        locking_script: script,
    })
}
