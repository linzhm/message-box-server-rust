//! Offline, limited BRC-105 structural candidate inspection.
//!
//! This is not payment validation or authorization. In particular it does not
//! verify the prefix/nonce, signed request, scripts, chain state, wallet
//! internalization, replay, or delivery. The HTTP adapter does not call it.
use crate::{
    beef_bump::{
        BumpBeefEntry, normalize_regular_bump_atomic_beef, parse_atomic_beef_with_regular_bumps,
    },
    beef_subset::normalize_acyclic_atomic_beef,
    payment_header::PaymentHeader,
};
use base64::{Engine, engine::general_purpose::STANDARD};

/// Unverified structural observations, never proof that payment was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentCandidate {
    pub transaction_id: String,
    pub first_output_satoshis: u64,
    pub normalized_atomic_beef: Vec<u8>,
}

/// Inspect the first output of a unique-ID candidate with no BUMP or supported
/// regular BUMPs. The traversed subject-reachable graph must be acyclic; the
/// walk stops at matching BUMPs or txid-only placeholders.
/// A parent missing from a dependency walk, and other unsupported forms, return
/// `None` even if the pinned middleware might accept them. A matching BUMP or
/// txid-only placeholder stops that walk without proving its ancestry. `Some`
/// is not acceptance.
/// The caller must bound all input sizes before calling this function.
pub fn inspect_payment_candidate(
    payment: &PaymentHeader,
    required_satoshis: u64,
) -> Option<PaymentCandidate> {
    if !(1..=9_007_199_254_740_991).contains(&required_satoshis) || payment.transaction.is_empty() {
        return None;
    }
    let raw = STANDARD.decode(&payment.transaction).ok()?;
    if STANDARD.encode(&raw) != payment.transaction {
        return None;
    }
    let normalized =
        normalize_acyclic_atomic_beef(&raw).or_else(|| normalize_regular_bump_atomic_beef(&raw))?;
    let beef = parse_atomic_beef_with_regular_bumps(&normalized)?;
    let output = beef.entries.iter().rev().find_map(|entry| match entry {
        BumpBeefEntry::Raw { transaction, .. } if transaction.txid == beef.atomic_txid => {
            transaction.outputs.first().map(|output| output.satoshis)
        }
        _ => None,
    })?;
    if output < required_satoshis {
        return None;
    }
    Some(PaymentCandidate {
        transaction_id: beef.atomic_txid,
        first_output_satoshis: output,
        normalized_atomic_beef: normalized,
    })
}
