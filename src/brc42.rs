//! BRC-42 child-key derivation used by the pinned SDK's wallet.
//!
//! This deterministic derivation is not an authenticated key exchange, does not
//! authenticate a peer, and provides neither forward secrecy nor replay defense.
use hmac::{Hmac, Mac};
use k256::{
    ProjectivePoint, PublicKey, Scalar, SecretKey, U256,
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
};
use sha2::Sha256;

#[derive(Debug)]
pub struct InvalidDerivedKey;

fn tweak(own_secret: &SecretKey, peer_public: &PublicKey, invoice: &str) -> Scalar {
    let shared = ProjectivePoint::from(*peer_public.as_affine()) * *own_secret.to_nonzero_scalar();
    let encoded = shared.to_affine().to_encoded_point(true);
    // HMAC accepts keys of every length; SEC1 compressed points are 33 bytes.
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(encoded.as_bytes()).expect("HMAC accepts any key length");
    hmac.update(invoice.as_bytes());
    let digest = hmac.finalize().into_bytes();
    <Scalar as Reduce<U256>>::reduce_bytes(&digest)
}

/// Derives the caller's private child using the peer's public identity key.
/// `invoice` is the exact SDK invoice string; this low-level function does not
/// validate or construct protocol identifiers or key IDs.
pub fn derive_private_child(
    own_secret: &SecretKey,
    peer_public: &PublicKey,
    invoice: &str,
) -> Result<SecretKey, InvalidDerivedKey> {
    let scalar = *own_secret.to_nonzero_scalar() + tweak(own_secret, peer_public, invoice);
    SecretKey::from_bytes(&scalar.to_bytes()).map_err(|_| InvalidDerivedKey)
}

/// Derives the peer's corresponding public child using the caller's secret.
pub fn derive_public_child(
    own_secret: &SecretKey,
    peer_public: &PublicKey,
    invoice: &str,
) -> Result<PublicKey, InvalidDerivedKey> {
    let point = ProjectivePoint::from(*peer_public.as_affine())
        + ProjectivePoint::GENERATOR * tweak(own_secret, peer_public, invoice);
    PublicKey::from_affine(point.to_affine()).map_err(|_| InvalidDerivedKey)
}

/// Signs SHA-256 of `message` using the caller's BRC-42-derived child key.
/// The invoice must be constructed and validated by the caller.
pub fn sign_message(
    own_secret: &SecretKey,
    peer_public: &PublicKey,
    invoice: &str,
    message: &[u8],
) -> Result<Vec<u8>, InvalidDerivedKey> {
    use k256::ecdsa::{Signature, SigningKey, signature::Signer};
    let child = derive_private_child(own_secret, peer_public, invoice)?;
    let signature: Signature = SigningKey::from(child).sign(message);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// Verifies a DER signature with the peer's derived public child. Both low-S
/// and high-S signatures are accepted, matching the pinned SDK's ECDSA verify.
pub fn verify_message(
    own_secret: &SecretKey,
    peer_public: &PublicKey,
    invoice: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, InvalidDerivedKey> {
    use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let child = derive_public_child(own_secret, peer_public, invoice)?;
    let Ok(signature) = Signature::from_der(signature) else {
        return Ok(false);
    };
    let signature = signature.normalize_s().unwrap_or(signature);
    Ok(VerifyingKey::from(child)
        .verify(message, &signature)
        .is_ok())
}

// The SDK constructs a SymmetricKey from the child ECDH x coordinate, then
// HMACs with BigNumber.toArray()'s minimal big-endian encoding, not a
// zero-padded 32-byte representation.
fn symmetric_hmac(
    own_secret: &SecretKey,
    peer_public: &PublicKey,
    invoice: &str,
) -> Result<Hmac<Sha256>, InvalidDerivedKey> {
    let private_child = derive_private_child(own_secret, peer_public, invoice)?;
    let public_child = derive_public_child(own_secret, peer_public, invoice)?;
    let shared =
        ProjectivePoint::from(*public_child.as_affine()) * *private_child.to_nonzero_scalar();
    let point = shared.to_affine().to_encoded_point(false);
    let x = point.x().ok_or(InvalidDerivedKey)?;
    let first = x.iter().position(|byte| *byte != 0).unwrap_or(x.len() - 1);
    Ok(Hmac::<Sha256>::new_from_slice(&x[first..]).expect("HMAC accepts any key length"))
}

/// Creates an SDK-style BRC-derived HMAC for the exact invoice and data.
pub fn create_hmac(
    own_secret: &SecretKey,
    peer_public: &PublicKey,
    invoice: &str,
    data: &[u8],
) -> Result<[u8; 32], InvalidDerivedKey> {
    let mut hmac = symmetric_hmac(own_secret, peer_public, invoice)?;
    hmac.update(data);
    Ok(hmac.finalize().into_bytes().into())
}

/// Checks an SDK-style BRC-derived HMAC using the HMAC crate's constant-time check.
pub fn verify_hmac(
    own_secret: &SecretKey,
    peer_public: &PublicKey,
    invoice: &str,
    data: &[u8],
    tag: &[u8; 32],
) -> Result<bool, InvalidDerivedKey> {
    let mut hmac = symmetric_hmac(own_secret, peer_public, invoice)?;
    hmac.update(data);
    Ok(hmac.verify_slice(tag).is_ok())
}
