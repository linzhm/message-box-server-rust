//! Offline orchestration for a supplied BRC-105 payment header.
//!
//! This is not an HTTP middleware and does not authenticate a request, issue a
//! challenge, verify chain proofs or deliver a message. A host must bind the
//! header, price and sender to an authenticated request, supply a trusted wallet
//! that validates and internalizes funds, and provide durable atomic replay
//! claims. The built-in HTTP adapter does not invoke this module. A wallet may
//! already have side effects even when internalization returns an error or times
//! out, or when a subsequent replay claim fails. There is no cross-system
//! transaction or automatic recovery here.
use crate::{
    Identity,
    auth_nonce::NonceWallet,
    payment_candidate::inspect_payment_candidate,
    payment_header::{parse_payment_header, verify_payment_prefix},
};
use serde_json::Value;
use std::future::Future;

pub struct InternalizeRequest<'a> {
    pub transaction: &'a [u8],
    pub derivation_prefix: &'a str,
    pub derivation_suffix: &'a str,
    pub sender_identity: &'a str,
    pub output_index: u32,
    pub protocol: &'static str,
    pub description: &'static str,
}
/// A trusted wallet is responsible for validating remittance and recording a
/// newly accepted payment. Mock implementations do not prove payment.
pub trait PaymentWallet: NonceWallet {
    fn internalize(
        &self,
        request: &InternalizeRequest<'_>,
    ) -> impl Future<Output = Result<Value, Self::Error>> + Send;
}
/// Atomic replay-claim capability. An error must never be converted to success.
pub trait ReplayClaims {
    type Error;
    fn claim(&self, transaction_id: &str)
    -> impl Future<Output = Result<bool, Self::Error>> + Send;
}
impl ReplayClaims for crate::payment_replay::SqlitePaymentReplayStore {
    type Error = sqlx::Error;
    async fn claim(&self, transaction_id: &str) -> Result<bool, Self::Error> {
        crate::payment_replay::SqlitePaymentReplayStore::claim(self, transaction_id).await
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStageError {
    InvalidPrice,
    Malformed,
    InvalidPrefix,
    InvalidPayment,
    WalletNotNew,
    WalletFailed,
    AlreadyClaimed,
    ReplayUnavailable,
}
impl PaymentStageError {
    /// Source-aligned status for this supplied-header stage only.
    pub fn status(self) -> u16 {
        match self {
            Self::InvalidPrice => 500,
            Self::Malformed | Self::InvalidPrefix | Self::InvalidPayment | Self::WalletFailed => {
                400
            }
            Self::WalletNotNew | Self::AlreadyClaimed => 409,
            Self::ReplayUnavailable => 503,
        }
    }
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidPrice => "ERR_PAYMENT_INTERNAL",
            Self::Malformed => "ERR_MALFORMED_PAYMENT",
            Self::InvalidPrefix => "ERR_INVALID_DERIVATION_PREFIX",
            Self::InvalidPayment => "ERR_INVALID_PAYMENT",
            Self::WalletNotNew | Self::AlreadyClaimed => "ERR_PAYMENT_REPLAYED",
            Self::WalletFailed => "ERR_PAYMENT_FAILED",
            Self::ReplayUnavailable => "ERR_PAYMENT_UNAVAILABLE",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletAcceptedAndClaimed {
    pub transaction_id: String,
    pub satoshis_paid: u64,
    pub normalized_atomic_beef: Vec<u8>,
}
/// JSON data-only equivalent of the pinned wallet result's own-data fields.
/// A real adapter must safely decode the wallet result before constructing Value.
pub fn is_newly_accepted_result(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.get("accepted") == Some(&Value::Bool(true))
        && object
            .get("isMerge")
            .is_none_or(|value| value == &Value::Bool(false))
}
/// Process an already-supplied header for a positive fixed price. This does not
/// issue 402 challenges or support the free-price branch. Unsupported BEEF
/// shapes return `InvalidPayment` even when the fixed SDK can handle them.
/// `WalletAcceptedAndClaimed` records only the injected wallet/claim outcome;
/// it is not independent proof of chain validity or successful message delivery.
pub async fn process_supplied_payment<W: PaymentWallet, R: ReplayClaims>(
    wallet: &W,
    replay: &R,
    sender: &Identity,
    raw_header: &str,
    price: u64,
) -> Result<WalletAcceptedAndClaimed, PaymentStageError> {
    if !(1..=9_007_199_254_740_991).contains(&price) {
        return Err(PaymentStageError::InvalidPrice);
    }
    let payment = parse_payment_header(raw_header).ok_or(PaymentStageError::Malformed)?;
    if !verify_payment_prefix(wallet, &payment).await {
        return Err(PaymentStageError::InvalidPrefix);
    }
    let candidate =
        inspect_payment_candidate(&payment, price).ok_or(PaymentStageError::InvalidPayment)?;
    let request = InternalizeRequest {
        transaction: &candidate.normalized_atomic_beef,
        derivation_prefix: &payment.derivation_prefix,
        derivation_suffix: &payment.derivation_suffix,
        sender_identity: sender.as_str(),
        output_index: 0,
        protocol: "wallet payment",
        description: "Payment for request",
    };
    let result = wallet
        .internalize(&request)
        .await
        .map_err(|_| PaymentStageError::WalletFailed)?;
    if !is_newly_accepted_result(&result) {
        return Err(PaymentStageError::WalletNotNew);
    }
    let claimed = replay
        .claim(&candidate.transaction_id)
        .await
        .map_err(|_| PaymentStageError::ReplayUnavailable)?;
    if !claimed {
        return Err(PaymentStageError::AlreadyClaimed);
    }
    Ok(WalletAcceptedAndClaimed {
        transaction_id: candidate.transaction_id,
        satoshis_paid: candidate.first_output_satoshis,
        normalized_atomic_beef: candidate.normalized_atomic_beef,
    })
}
