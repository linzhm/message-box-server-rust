//! Offline restricted allocation of recipient payment outputs.
//!
//! This maps already validated positive-fee recipients to output positions,
//! using the pinned server's tagged/positional rules for the supported JSON
//! subset. It does not authenticate, verify scripts or transactions, call a
//! wallet, validate payment, or authorize delivery. The caller must bound and
//! snapshot inputs and pass recipients in the authoritative fee order.
use serde_json::Value;
use std::collections::{HashMap, HashSet};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationError {
    Unsupported,
    InsufficientOutputs,
}
impl AllocationError {
    /// Source error code where the supported allocation can establish one.
    /// `None` means the input is outside this subset, not a TS rejection.
    pub fn code(self) -> Option<&'static str> {
        match self {
            Self::Unsupported => None,
            Self::InsufficientOutputs => Some("ERR_INSUFFICIENT_OUTPUTS"),
        }
    }
}
fn tag(output: &Value) -> Result<Option<String>, AllocationError> {
    let candidate = output
        .get("insertionRemittance")
        .and_then(|v| v.get("customInstructions"))
        .filter(|v| !v.is_null())
        .or_else(|| {
            output
                .get("paymentRemittance")
                .and_then(|v| v.get("customInstructions"))
                .filter(|v| !v.is_null())
        })
        .or_else(|| output.get("customInstructions").filter(|v| !v.is_null()));
    let Some(raw) = candidate else {
        return Ok(None);
    };
    let parsed;
    let data = match raw {
        Value::String(text) if text.is_empty() => return Ok(None),
        Value::String(text) => {
            parsed =
                serde_json::from_str::<Value>(text).map_err(|_| AllocationError::Unsupported)?;
            &parsed
        }
        _ => raw,
    };
    Ok(data
        .as_object()
        .and_then(|object| object.get("recipientIdentityKey"))
        .and_then(Value::as_str)
        .filter(|recipient| !crate::js_trim(recipient).is_empty())
        .map(str::to_owned))
}
/// Returns output positions for each recipient, in recipient order. Unsupported
/// input includes malformed instruction JSON; the source ignores some such
/// strings, but this function does not equate parser errors with JS semantics.
pub fn allocate_recipient_outputs(
    outputs: &[Value],
    fee_recipients: &[String],
) -> Result<Vec<Vec<usize>>, AllocationError> {
    let mut unique = HashSet::new();
    if fee_recipients.iter().any(|r| !unique.insert(r.as_str())) {
        return Err(AllocationError::Unsupported);
    }
    let mut indexes = Vec::with_capacity(outputs.len());
    for output in outputs {
        if !output.is_object() {
            return Err(AllocationError::Unsupported);
        }
        let index = crate::payment_index::safe_index(output.get("outputIndex"))
            .map_err(|_| AllocationError::Unsupported)?
            .ok_or(AllocationError::Unsupported)?;
        indexes.push(index);
    }
    let mut tagged: HashMap<String, Vec<usize>> = HashMap::new();
    let mut used = HashSet::new();
    for (position, output) in outputs.iter().enumerate() {
        if let Some(recipient) = tag(output)? {
            tagged.entry(recipient).or_default().push(position);
            used.insert(indexes[position]);
        }
    }
    if tagged.is_empty() {
        if outputs.len() < fee_recipients.len() {
            return Err(AllocationError::InsufficientOutputs);
        }
        return Ok((0..fee_recipients.len()).map(|i| vec![i]).collect());
    }
    let remaining: Vec<usize> = indexes
        .iter()
        .enumerate()
        .filter_map(|(pos, index)| (!used.contains(index)).then_some(pos))
        .collect();
    let mut cursor = 0;
    let mut result = Vec::with_capacity(fee_recipients.len());
    for recipient in fee_recipients {
        if let Some(indices) = tagged.get(recipient) {
            result.push(indices.clone());
        } else {
            let Some(&position) = remaining.get(cursor) else {
                return Err(AllocationError::InsufficientOutputs);
            };
            cursor += 1;
            result.push(vec![position]);
        }
    }
    Ok(result)
}
