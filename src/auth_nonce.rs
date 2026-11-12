//! Wallet-authenticated nonce codec from the pinned SDK's BRC-103 helpers.
//!
//! A valid nonce alone proves neither identity nor freshness and is not replay
//! protection. Complete BRC authentication, session binding and signed-message
//! verification are not implemented by this module.
use base64::{Engine, engine::general_purpose::STANDARD};
use std::future::Future;

/// Exact wallet parameters for the SDK's `server hmac` protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceHmacRequest {
    pub protocol_id: (u8, &'static str),
    pub key_id: String,
    pub data: [u8; 16],
    pub counterparty: String,
    pub originator: Option<String>,
}

/// A MAC mismatch is a failed verification; other wallet failures propagate.
/// Wallet adapters should map `ERR_INVALID_HMAC` or the exact `HMAC is not
/// valid` rejection to `Invalid`, and preserve other errors as `Other`.
#[derive(Debug)]
pub enum HmacCheckError<E> {
    Invalid,
    Other(E),
}

/// Adapter to the authoritative BRC wallet. An implementation must preserve the
/// requested protocol, key ID, counterparty and originator without substitution.
pub trait NonceWallet {
    type Error;
    fn create_hmac(
        &self,
        request: &NonceHmacRequest,
    ) -> impl Future<Output = Result<[u8; 32], Self::Error>> + Send;
    fn verify_hmac(
        &self,
        request: &NonceHmacRequest,
        hmac: &[u8; 32],
    ) -> impl Future<Output = Result<bool, HmacCheckError<Self::Error>>> + Send;
}

#[derive(Debug)]
pub enum NonceIssueError<E> {
    Random(getrandom::Error),
    Wallet(E),
}

fn request(data: [u8; 16], counterparty: &str, originator: Option<&str>) -> NonceHmacRequest {
    // TextDecoder('utf-8') replaces malformed bytes and removes an initial BOM.
    let text = String::from_utf8_lossy(&data);
    let key_id = text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned();
    NonceHmacRequest {
        protocol_id: (2, "server hmac"),
        key_id,
        data,
        counterparty: counterparty.to_owned(),
        originator: originator.map(str::to_owned),
    }
}

/// Issues the SDK's 48-byte nonce using operating-system randomness and a wallet.
pub async fn create_nonce<W: NonceWallet>(
    wallet: &W,
    counterparty: &str,
    originator: Option<&str>,
) -> Result<String, NonceIssueError<W::Error>> {
    let mut data = [0u8; 16];
    getrandom::fill(&mut data).map_err(NonceIssueError::Random)?;
    let args = request(data, counterparty, originator);
    let hmac = wallet
        .create_hmac(&args)
        .await
        .map_err(NonceIssueError::Wallet)?;
    let mut nonce = [0u8; 48];
    nonce[..16].copy_from_slice(&data);
    nonce[16..].copy_from_slice(&hmac);
    Ok(STANDARD.encode(nonce))
}

/// Checks canonical SDK nonce framing and asks the wallet to verify its HMAC.
/// Returns false for malformed tokens, invalid HMACs or a wallet's false result.
pub async fn verify_nonce<W: NonceWallet>(
    wallet: &W,
    nonce: &str,
    counterparty: &str,
    originator: Option<&str>,
) -> Result<bool, W::Error> {
    if nonce.len() != 64 {
        return Ok(false);
    }
    let Ok(decoded) = STANDARD.decode(nonce) else {
        return Ok(false);
    };
    if decoded.len() != 48 || STANDARD.encode(&decoded) != nonce {
        return Ok(false);
    }
    let mut data = [0u8; 16];
    data.copy_from_slice(&decoded[..16]);
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&decoded[16..]);
    match wallet
        .verify_hmac(&request(data, counterparty, originator), &hmac)
        .await
    {
        Ok(valid) => Ok(valid),
        Err(HmacCheckError::Invalid) => Ok(false),
        Err(HmacCheckError::Other(error)) => Err(error),
    }
}
