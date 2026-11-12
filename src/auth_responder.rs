//! BRC-103 responder subset for a no-certificate handshake and general message.
//!
//! This is not an HTTP server. The transport must reconstruct and bind the
//! signed frame to the actual request, enforce request limits, serialize protocol
//! messages, select the actual response components, and transmit the signed
//! response. A durable session store must enforce expiry and
//! atomic replay claims. Certificate-bearing flows are explicitly unsupported.
use crate::{
    auth_frame::{PreparedResponseFrame, encode_response_frame},
    auth_nonce::{NonceIssueError, NonceWallet, create_nonce, verify_nonce},
    canonical_key,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::future::Future;

/// Wallet operations for the SDK's `[2, "auth message signature"]` protocol.
pub trait AuthWallet: NonceWallet {
    fn identity_key(&self) -> impl Future<Output = Result<String, Self::Error>> + Send;
    fn sign_auth(
        &self,
        peer: &str,
        key_id: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send;
    fn verify_auth(
        &self,
        peer: &str,
        key_id: &str,
        data: &[u8],
        signature: &[u8],
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}

#[derive(Clone, Debug)]
pub struct AuthSession {
    pub session_nonce: String,
    pub peer_nonce: String,
    pub peer_identity: String,
    pub authenticated: bool,
}

/// The host must persist sessions with expiry and make each nonce claim atomic
/// across all server instances. A false claim means replay, never availability.
pub trait AuthSessionStore {
    type Error;
    /// Atomically claim the identity/nonce pair for the configured initial
    /// replay window before any wallet work.
    fn claim_initial(
        &self,
        identity: &str,
        nonce: &str,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
    /// A nonce must uniquely identify an immutable peer binding; reject duplicates.
    fn add_session(
        &self,
        session: AuthSession,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Expired sessions must be returned as absent.
    fn get_session(
        &self,
        nonce: &str,
    ) -> impl Future<Output = Result<Option<AuthSession>, Self::Error>> + Send;
    /// Atomically claim a nonce for an active session. Keep each claim until
    /// that session is no longer valid; capacity exhaustion must return an
    /// error rather than discard a still-live claim.
    fn claim_message(
        &self,
        session: &str,
        nonce: &str,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
    /// Atomically update only a still-existing, unexpired session; return an
    /// error if it disappeared or expired since `get_session`.
    fn mark_authenticated(
        &self,
        nonce: &str,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

#[derive(Debug)]
pub enum ResponderError<W, S> {
    InvalidMessage,
    UnsupportedCertificates,
    FrameMismatch,
    Replay,
    SessionMissing,
    IdentityMismatch,
    InvalidProof,
    Random(getrandom::Error),
    Wallet(W),
    Store(S),
}

pub struct InitialResponse {
    pub identity_key: String,
    pub initial_nonce: String,
    pub your_nonce: String,
    pub signature: Vec<u8>,
}
impl InitialResponse {
    pub fn to_json(&self) -> Value {
        json!({"version":"0.1","messageType":"initialResponse","identityKey":self.identity_key,"initialNonce":self.initial_nonce,"yourNonce":self.your_nonce,"signature":self.signature,"requestedCertificates":{"certifiers":[],"types":{}}})
    }
}

/// Identity is exposed only after nonce, session, signature and replay checks.
pub struct VerifiedGeneral {
    identity_key: String,
    session_nonce: String,
    payload: Vec<u8>,
}
impl VerifiedGeneral {
    pub fn identity_key(&self) -> &str {
        &self.identity_key
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Signed general response for a previously verified peer message.
pub struct SignedResponse {
    pub identity_key: String,
    pub nonce: String,
    pub your_nonce: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
impl SignedResponse {
    pub fn to_json(&self) -> Value {
        json!({"version":"0.1","messageType":"general","identityKey":self.identity_key,"nonce":self.nonce,"yourNonce":self.your_nonce,"payload":self.payload,"signature":self.signature})
    }
}

pub struct AuthResponder<'a, W, S> {
    wallet: &'a W,
    store: &'a S,
}
impl<'a, W: AuthWallet, S: AuthSessionStore> AuthResponder<'a, W, S> {
    pub fn new(wallet: &'a W, store: &'a S) -> Self {
        Self { wallet, store }
    }

    /// Handles an unsigned initial request. It creates an unauthenticated
    /// session; it does not establish the claimed sender's identity.
    pub async fn accept_initial(
        &self,
        message: &Value,
    ) -> Result<InitialResponse, ResponderError<W::Error, S::Error>> {
        let identity = validate_common(message, "initialRequest")?;
        no_certificates(message)?;
        let client_nonce = message
            .get("initialNonce")
            .and_then(Value::as_str)
            .and_then(|n| canonical_base64(n, 48).map(|b| (n, b)))
            .ok_or(ResponderError::InvalidMessage)?;
        if !self
            .store
            .claim_initial(identity, client_nonce.0)
            .await
            .map_err(ResponderError::Store)?
        {
            return Err(ResponderError::Replay);
        }
        let nonce = create_nonce(self.wallet, "self", None)
            .await
            .map_err(|e| match e {
                NonceIssueError::Random(e) => ResponderError::Random(e),
                NonceIssueError::Wallet(e) => ResponderError::Wallet(e),
            })?;
        let our_identity = self
            .wallet
            .identity_key()
            .await
            .map_err(ResponderError::Wallet)?;
        if !canonical_identity(&our_identity) {
            return Err(ResponderError::InvalidMessage);
        }
        let session = AuthSession {
            session_nonce: nonce.clone(),
            peer_nonce: client_nonce.0.to_owned(),
            peer_identity: identity.to_owned(),
            authenticated: false,
        };
        self.store
            .add_session(session)
            .await
            .map_err(ResponderError::Store)?;
        let mut data = client_nonce.1;
        data.extend(canonical_base64(&nonce, 48).ok_or(ResponderError::InvalidMessage)?);
        let signature = self
            .wallet
            .sign_auth(identity, &format!("{} {nonce}", client_nonce.0), &data)
            .await
            .map_err(ResponderError::Wallet)?;
        if signature.is_empty() || signature.len() > 1024 {
            return Err(ResponderError::InvalidMessage);
        }
        Ok(InitialResponse {
            identity_key: our_identity,
            initial_nonce: nonce,
            your_nonce: client_nonce.0.to_owned(),
            signature,
        })
    }

    /// Verifies a general message against the transport-reconstructed frame.
    /// `actual_frame` must come from the same actual request, not from the
    /// untrusted `payload` field. Authentication is not application authority.
    pub async fn accept_general(
        &self,
        message: &Value,
        actual_frame: &[u8],
    ) -> Result<VerifiedGeneral, ResponderError<W::Error, S::Error>> {
        let identity = validate_common(message, "general")?;
        no_certificates(message)?;
        let nonce = message
            .get("nonce")
            .and_then(Value::as_str)
            .filter(|n| canonical_base64(n, 32).is_some())
            .ok_or(ResponderError::InvalidMessage)?;
        let session_nonce = message
            .get("yourNonce")
            .and_then(Value::as_str)
            .filter(|n| canonical_base64(n, 48).is_some())
            .ok_or(ResponderError::InvalidMessage)?;
        let payload = bytes(message.get("payload"), 16 * 1024 * 1024, true)
            .ok_or(ResponderError::InvalidMessage)?;
        let signature =
            bytes(message.get("signature"), 1024, false).ok_or(ResponderError::InvalidMessage)?;
        if payload != actual_frame {
            return Err(ResponderError::FrameMismatch);
        }
        if !verify_nonce(self.wallet, session_nonce, "self", None)
            .await
            .map_err(ResponderError::Wallet)?
        {
            return Err(ResponderError::InvalidProof);
        }
        let session = self
            .store
            .get_session(session_nonce)
            .await
            .map_err(ResponderError::Store)?
            .ok_or(ResponderError::SessionMissing)?;
        if session.peer_identity != identity {
            return Err(ResponderError::IdentityMismatch);
        }
        let valid = self
            .wallet
            .verify_auth(
                identity,
                &format!("{nonce} {session_nonce}"),
                &payload,
                &signature,
            )
            .await
            .map_err(ResponderError::Wallet)?;
        if !valid {
            return Err(ResponderError::InvalidProof);
        }
        if !self
            .store
            .claim_message(session_nonce, nonce)
            .await
            .map_err(ResponderError::Store)?
        {
            return Err(ResponderError::Replay);
        }
        self.store
            .mark_authenticated(session_nonce)
            .await
            .map_err(ResponderError::Store)?;
        Ok(VerifiedGeneral {
            identity_key: identity.to_owned(),
            session_nonce: session_nonce.to_owned(),
            payload,
        })
    }

    /// Signs a response frame whose request ID is taken from the first 32 bytes
    /// of the verified request frame. The caller must select and canonicalize
    /// headers and body from the actual HTTP response before using this method.
    pub async fn sign_http_response(
        &self,
        verified: &VerifiedGeneral,
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<SignedResponse, ResponderError<W::Error, S::Error>> {
        let request_id: [u8; 32] = verified
            .payload
            .get(..32)
            .ok_or(ResponderError::InvalidMessage)?
            .try_into()
            .map_err(|_| ResponderError::InvalidMessage)?;
        let payload = encode_response_frame(&PreparedResponseFrame {
            request_id,
            status,
            headers,
            body,
        });
        self.sign_general_payload(verified, &payload).await
    }

    /// Sign exact application bytes for the peer of an already verified
    /// message. A transport must bind the verified identity to its connection
    /// and must transmit the returned bytes without re-encoding them.
    pub async fn sign_general_payload(
        &self,
        verified: &VerifiedGeneral,
        payload: &[u8],
    ) -> Result<SignedResponse, ResponderError<W::Error, S::Error>> {
        let session = self
            .store
            .get_session(&verified.session_nonce)
            .await
            .map_err(ResponderError::Store)?
            .ok_or(ResponderError::SessionMissing)?;
        if !session.authenticated || session.peer_identity != verified.identity_key {
            return Err(ResponderError::IdentityMismatch);
        }
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(ResponderError::Random)?;
        let nonce = STANDARD.encode(nonce);
        let signature = self
            .wallet
            .sign_auth(
                &session.peer_identity,
                &format!("{nonce} {}", session.peer_nonce),
                payload,
            )
            .await
            .map_err(ResponderError::Wallet)?;
        if signature.is_empty() || signature.len() > 1024 {
            return Err(ResponderError::InvalidMessage);
        }
        let identity_key = self
            .wallet
            .identity_key()
            .await
            .map_err(ResponderError::Wallet)?;
        if !canonical_identity(&identity_key) {
            return Err(ResponderError::InvalidMessage);
        }
        // The store must reject an update if the session expired during signing.
        self.store
            .mark_authenticated(&verified.session_nonce)
            .await
            .map_err(ResponderError::Store)?;
        Ok(SignedResponse {
            identity_key,
            nonce,
            your_nonce: session.peer_nonce,
            payload: payload.to_vec(),
            signature,
        })
    }
}
fn canonical_identity(key: &str) -> bool {
    key.len() == 66 && canonical_key(key).as_deref() == Some(key)
}
fn canonical_base64(value: &str, size: usize) -> Option<Vec<u8>> {
    if value.len() != size.div_ceil(3) * 4 {
        return None;
    }
    let data = STANDARD.decode(value).ok()?;
    if data.len() == size && STANDARD.encode(&data) == value {
        Some(data)
    } else {
        None
    }
}
fn validate_common<'a, W, S>(
    message: &'a Value,
    kind: &str,
) -> Result<&'a str, ResponderError<W, S>> {
    if !message.is_object()
        || message.get("version").and_then(Value::as_str) != Some("0.1")
        || message.get("messageType").and_then(Value::as_str) != Some(kind)
    {
        return Err(ResponderError::InvalidMessage);
    }
    message
        .get("identityKey")
        .and_then(Value::as_str)
        .filter(|s| canonical_identity(s))
        .ok_or(ResponderError::InvalidMessage)
}
fn no_certificates<W, S>(message: &Value) -> Result<(), ResponderError<W, S>> {
    if let Some(certificates) = message.get("certificates")
        && certificates.as_array().is_none_or(|a| !a.is_empty())
    {
        return Err(ResponderError::UnsupportedCertificates);
    }
    if let Some(request) = message.get("requestedCertificates")
        && (!request.is_object()
            || request
                .get("certifiers")
                .and_then(Value::as_array)
                .is_none_or(|a| !a.is_empty())
            || request
                .get("types")
                .and_then(Value::as_object)
                .is_none_or(|m| !m.is_empty()))
    {
        return Err(ResponderError::UnsupportedCertificates);
    }
    Ok(())
}
fn bytes(value: Option<&Value>, max: usize, empty: bool) -> Option<Vec<u8>> {
    let a = value?.as_array()?;
    if a.len() > max || (!empty && a.is_empty()) {
        return None;
    }
    a.iter()
        .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect()
}
