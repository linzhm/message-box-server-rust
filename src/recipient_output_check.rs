//! Offline recipient-output checks for a restricted legacy payment flow.
//!
//! This module inspects supplied transaction output frames and remittance
//! metadata only. It does not parse or verify a transaction, check its chain,
//! call a wallet or authorize payment. A caller must validate the original
//! BEEF and bind the supplied groups to the authenticated request and fee
//! policy. The HTTP route does not invoke this module.
use crate::{
    Identity, brc29_recipient_script::derive_recipient_script,
    transaction_frame::TransactionOutputFrame,
};
use serde_json::Value;
use std::collections::HashSet;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
const ANYONE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// An already allocated and authenticated recipient/fee mapping. Allocation,
/// identity authentication and authoritative fees are caller responsibilities.
pub struct RecipientGroup<'a> {
    pub recipient: &'a Identity,
    pub fee: u64,
    pub outputs: &'a [Value],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientOutputError {
    Unsupported,
    MissingOutputs,
    Invalid,
    Insufficient,
}
impl RecipientOutputError {
    pub fn code(self) -> Option<&'static str> {
        match self {
            Self::Unsupported => None,
            Self::MissingOutputs => Some("ERR_MISSING_RECIPIENT_OUTPUTS"),
            Self::Invalid => Some("ERR_INVALID_RECIPIENT_PAYMENT"),
            Self::Insufficient => Some("ERR_INSUFFICIENT_RECIPIENT_PAYMENT"),
        }
    }
}
/// Validate the supplied frames and allocated remittances. Success means only
/// that metadata, P2PKH script and amount matched; trusted chain/transaction
/// verification must still happen separately before accepting any payment.
/// If the total server delivery fee is positive, `delivery_index` must be the
/// already validated first server remittance's output index. Passing `None` in
/// that case can allow one output to be counted for both fee categories. Groups
/// must cover every positive-fee recipient under the authoritative policy, and
/// frames must be from the same original transaction subject. Empty groups do
/// not establish that no recipient payment was required.
pub fn inspect_recipient_outputs(
    frames: &[TransactionOutputFrame],
    groups: &[RecipientGroup<'_>],
    delivery_index: Option<u64>,
) -> Result<(), RecipientOutputError> {
    let mut used = HashSet::new();
    if let Some(index) = delivery_index {
        if index > MAX_SAFE {
            return Err(RecipientOutputError::Invalid);
        }
        used.insert(index);
    }
    for group in groups {
        if group.fee == 0 {
            continue;
        }
        if group.fee > MAX_SAFE {
            return Err(RecipientOutputError::Invalid);
        }
        if group.outputs.is_empty() {
            return Err(RecipientOutputError::MissingOutputs);
        }
        let mut paid = 0u64;
        for output in group.outputs {
            if output.get("protocol").and_then(Value::as_str) != Some("wallet payment") {
                return Err(RecipientOutputError::Invalid);
            }
            let index = crate::payment_index::safe_index(output.get("outputIndex"))
                .map_err(|_| RecipientOutputError::Unsupported)?
                .ok_or(RecipientOutputError::Invalid)?;
            if !used.insert(index) {
                return Err(RecipientOutputError::Invalid);
            }
            let rem = output
                .get("paymentRemittance")
                .and_then(Value::as_object)
                .ok_or(RecipientOutputError::Invalid)?;
            if rem.get("senderIdentityKey").and_then(Value::as_str) != Some(ANYONE) {
                return Err(RecipientOutputError::Invalid);
            }
            let prefix = rem
                .get("derivationPrefix")
                .and_then(Value::as_str)
                .ok_or(RecipientOutputError::Invalid)?;
            let suffix = rem
                .get("derivationSuffix")
                .and_then(Value::as_str)
                .ok_or(RecipientOutputError::Invalid)?;
            let script = derive_recipient_script(group.recipient, prefix, suffix)
                .map_err(|_| RecipientOutputError::Invalid)?;
            let frame = usize::try_from(index)
                .ok()
                .and_then(|i| frames.get(i))
                .ok_or(RecipientOutputError::Invalid)?;
            if frame.satoshis > MAX_SAFE || frame.script.as_slice() != script.locking_script {
                return Err(RecipientOutputError::Invalid);
            }
            paid = paid
                .checked_add(frame.satoshis)
                .filter(|n| *n <= MAX_SAFE)
                .ok_or(RecipientOutputError::Invalid)?;
        }
        if paid < group.fee {
            return Err(RecipientOutputError::Insufficient);
        }
    }
    Ok(())
}
