//! Local BRC authentication signer backed by a caller-supplied secp256k1 key.
//!
//! This is an authentication-only adapter, not a payment wallet or a secure key
//! store. The host is responsible for obtaining, protecting and rotating the
//! identity key, limiting access, and not using public fixture keys for real
//! identities. No key generation, persistence or logging occurs here. This
//! signer does not authenticate callers and must not be exposed as an arbitrary
//! external signing API. Full SDK wallet parameter validation is not claimed.
use crate::{
    auth_nonce::{HmacCheckError, NonceHmacRequest, NonceWallet},
    auth_responder::AuthWallet,
    brc42,
};
use k256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
#[derive(Debug)]
pub struct LocalAuthError;
pub struct LocalAuthWallet {
    secret: SecretKey,
}
impl LocalAuthWallet {
    pub fn new(secret: SecretKey) -> Self {
        Self { secret }
    }
    fn check_nonce_request(request: &NonceHmacRequest) -> Result<(), LocalAuthError> {
        if request.protocol_id != (2, "server hmac")
            || request.counterparty != "self"
            || request.originator.is_some()
        {
            return Err(LocalAuthError);
        }
        Ok(())
    }
    fn peer(value: &str) -> Result<PublicKey, LocalAuthError> {
        let bytes = hex::decode(value).map_err(|_| LocalAuthError)?;
        PublicKey::from_sec1_bytes(&bytes).map_err(|_| LocalAuthError)
    }
}
impl NonceWallet for LocalAuthWallet {
    type Error = LocalAuthError;
    async fn create_hmac(&self, request: &NonceHmacRequest) -> Result<[u8; 32], Self::Error> {
        Self::check_nonce_request(request)?;
        brc42::create_hmac(
            &self.secret,
            &self.secret.public_key(),
            &format!("2-server hmac-{}", request.key_id),
            &request.data,
        )
        .map_err(|_| LocalAuthError)
    }
    async fn verify_hmac(
        &self,
        request: &NonceHmacRequest,
        hmac: &[u8; 32],
    ) -> Result<bool, HmacCheckError<Self::Error>> {
        Self::check_nonce_request(request).map_err(HmacCheckError::Other)?;
        brc42::verify_hmac(
            &self.secret,
            &self.secret.public_key(),
            &format!("2-server hmac-{}", request.key_id),
            &request.data,
            hmac,
        )
        .map_err(|_| HmacCheckError::Other(LocalAuthError))
    }
}
impl AuthWallet for LocalAuthWallet {
    async fn identity_key(&self) -> Result<String, Self::Error> {
        Ok(hex::encode(
            self.secret.public_key().to_encoded_point(true).as_bytes(),
        ))
    }
    async fn sign_auth(
        &self,
        peer: &str,
        key_id: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        brc42::sign_message(
            &self.secret,
            &Self::peer(peer)?,
            &format!("2-auth message signature-{key_id}"),
            data,
        )
        .map_err(|_| LocalAuthError)
    }
    async fn verify_auth(
        &self,
        peer: &str,
        key_id: &str,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        brc42::verify_message(
            &self.secret,
            &Self::peer(peer)?,
            &format!("2-auth message signature-{key_id}"),
            data,
            signature,
        )
        .map_err(|_| LocalAuthError)
    }
}
