//! Offline legacy delivery-output amount observation over a restricted BEEF subset.
//!
//! This is not a transaction, script, chain, wallet, replay, or payment
//! verification. Input must already be size bounded. The result never authorizes
//! delivery. The caller must check authenticated remittance metadata separately.
use crate::{
    beef_bump::{
        BumpBeefEntry, normalize_regular_bump_atomic_beef, parse_atomic_beef_with_regular_bumps,
    },
    beef_subset::normalize_acyclic_atomic_beef,
};
use serde_json::Value;

/// Returns `None` for invalid **or unsupported** framing/graphs. `Some` is an
/// amount/protocol observation only, not a validated transaction. The original
/// packet must have the same transaction entry count as the supported selected
/// subject graph; normalization is never substituted for the original packet.
/// The pinned SDK accepts additional BEEF/BUMP shapes that this function rejects.
pub fn inspect_legacy_delivery_output(raw: &[u8], remittance: &Value, fee: u64) -> Option<bool> {
    let original = parse_atomic_beef_with_regular_bumps(raw)?;
    let normalized =
        normalize_acyclic_atomic_beef(raw).or_else(|| normalize_regular_bump_atomic_beef(raw))?;
    let selected = parse_atomic_beef_with_regular_bumps(&normalized)?;
    if original.atomic_txid != selected.atomic_txid
        || original.entries.len() != selected.entries.len()
    {
        return None;
    }
    let subject = original.entries.iter().find_map(|entry| match entry {
        BumpBeefEntry::Raw { transaction, .. } if transaction.txid == original.atomic_txid => {
            Some(transaction)
        }
        _ => None,
    })?;
    if !(1..=9_007_199_254_740_991).contains(&fee)
        || remittance.get("protocol").and_then(Value::as_str) != Some("wallet payment")
    {
        return Some(false);
    }
    let index = match crate::payment_index::safe_index(remittance.get("outputIndex")) {
        Ok(Some(index)) => index,
        Ok(None) => return Some(false),
        Err(()) => return None,
    };
    Some(
        usize::try_from(index)
            .ok()
            .and_then(|i| subject.outputs.get(i))
            .is_some_and(|output| output.satoshis >= fee),
    )
}
