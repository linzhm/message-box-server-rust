//! Offline restricted AuthSocket application-event payload codec.
//!
//! This module does not implement Socket.IO, BRC authentication, sessions,
//! rooms, authorization or delivery. It supports a subset of JSON values and
//! returns Unsupported rather than claiming the fixed TS source rejects forms
//! outside that subset. A transport must authenticate the original payload
//! bytes, not a re-encoded version.
use serde_json::{Map, Value};
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 100_000;
const MAX_SAFE: i64 = 9_007_199_254_740_991;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    Invalid,
    Unsupported,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEvent {
    pub event_name: String,
    pub data: Option<Value>,
}
fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len()<=256 && !["_unknown","connect","connect_error","disconnect","disconnecting","newListener","removeListener"].contains(&name)
        && !name.chars().any(|c| matches!(c,'\u{0000}'..='\u{001f}'|'\u{007f}'..='\u{009f}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'))
}
fn array_index_key(key: &str) -> bool {
    key.parse::<u32>()
        .ok()
        .is_some_and(|n| n != u32::MAX && n.to_string() == key)
}
fn validate_tree(root: &Value, max_bytes: usize) -> Result<(), PayloadError> {
    validate_pending(vec![(root, 0)], 0, 0, max_bytes)
}
fn validate_pending(
    mut stack: Vec<(&Value, usize)>,
    mut nodes: usize,
    mut bytes: usize,
    max_bytes: usize,
) -> Result<(), PayloadError> {
    if max_bytes == 0 || (max_bytes as u128) > MAX_SAFE as u128 || bytes > max_bytes {
        return Err(PayloadError::Invalid);
    }
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or(PayloadError::Invalid)?;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err(PayloadError::Invalid);
        }
        match value {
            Value::Null | Value::Bool(_) => {
                bytes = bytes.checked_add(4).ok_or(PayloadError::Invalid)?
            }
            Value::String(s) => {
                bytes = bytes
                    .checked_add(s.len() + 2)
                    .ok_or(PayloadError::Invalid)?
            }
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    if !(-MAX_SAFE..=MAX_SAFE).contains(&i) {
                        return Err(PayloadError::Unsupported);
                    }
                } else if let Some(u) = n.as_u64() {
                    if u > MAX_SAFE as u64 {
                        return Err(PayloadError::Unsupported);
                    }
                } else {
                    return Err(PayloadError::Unsupported);
                }
                bytes = bytes.checked_add(24).ok_or(PayloadError::Invalid)?;
            }
            Value::Array(items) => {
                if nodes
                    .saturating_add(stack.len())
                    .saturating_add(items.len())
                    > MAX_NODES
                {
                    return Err(PayloadError::Invalid);
                }
                stack.extend(items.iter().rev().map(|item| (item, depth + 1)));
            }
            Value::Object(map) => {
                if nodes.saturating_add(stack.len()).saturating_add(map.len()) > MAX_NODES {
                    return Err(PayloadError::Invalid);
                }
                for (key, value) in map.iter().rev() {
                    if ["__proto__", "constructor", "prototype"].contains(&key.as_str()) {
                        return Err(PayloadError::Invalid);
                    }
                    if array_index_key(key) {
                        return Err(PayloadError::Unsupported);
                    }
                    bytes = bytes
                        .checked_add(key.len() + 3)
                        .ok_or(PayloadError::Invalid)?;
                    stack.push((value, depth + 1));
                }
            }
        }
        if bytes > max_bytes {
            return Err(PayloadError::Invalid);
        }
    }
    Ok(())
}
/// Encode an event envelope; `None` omits data and `Some(Null)` preserves null.
/// Supported objects retain property order; numeric-index keys and floating
/// numbers are intentionally unsupported.
pub fn encode_event_payload(
    event_name: &str,
    data: Option<&Value>,
    max_bytes: usize,
) -> Result<Vec<u8>, PayloadError> {
    if !valid_name(event_name) {
        return Err(PayloadError::Invalid);
    }
    // Check the borrowed tree, including envelope overhead, before cloning it.
    // The name is already bounded to 256 UTF-8 bytes above.
    let name = Value::String(event_name.to_owned());
    let mut pending = Vec::with_capacity(2);
    if let Some(data) = data {
        pending.push((data, 1));
    }
    pending.push((&name, 1));
    let envelope_key_bytes =
        "eventName".len() + 3 + if data.is_some() { "data".len() + 3 } else { 0 };
    validate_pending(pending, 1, envelope_key_bytes, max_bytes)?;
    let mut envelope = Map::new();
    envelope.insert("eventName".into(), name);
    if let Some(data) = data {
        envelope.insert("data".into(), data.clone());
    }
    let value = Value::Object(envelope);
    let encoded = serde_json::to_vec(&value).map_err(|_| PayloadError::Unsupported)?;
    if encoded.len() > max_bytes {
        return Err(PayloadError::Invalid);
    }
    Ok(encoded)
}
/// Parse an event from the original UTF-8 payload. Parse failures are
/// Unsupported when JavaScript may accept representations Rust cannot express;
/// invalid UTF-8, over-limit or an invalid envelope are Invalid.
pub fn parse_event_payload(payload: &[u8], max_bytes: usize) -> Result<SocketEvent, PayloadError> {
    if max_bytes == 0 || (max_bytes as u128) > MAX_SAFE as u128 || payload.len() > max_bytes {
        return Err(PayloadError::Invalid);
    }
    let text = std::str::from_utf8(payload).map_err(|_| PayloadError::Invalid)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let value: Value = serde_json::from_str(text).map_err(|_| PayloadError::Unsupported)?;
    validate_tree(&value, max_bytes)?;
    let map = value.as_object().ok_or(PayloadError::Invalid)?;
    if map.keys().any(|key| key != "eventName" && key != "data") {
        return Err(PayloadError::Invalid);
    }
    let name = map
        .get("eventName")
        .and_then(Value::as_str)
        .filter(|s| valid_name(s))
        .ok_or(PayloadError::Invalid)?;
    Ok(SocketEvent {
        event_name: name.to_owned(),
        data: map.get("data").cloned(),
    })
}
