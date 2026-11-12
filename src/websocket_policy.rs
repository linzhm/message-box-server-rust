//! Restricted source-aligned room policy, independent of network authentication.
//! The caller must supply a peer identity established by BRC-103, not a claim.
use crate::{canonical_key, exact_text, js_trim};
use serde_json::Value;

// PublicKey.fromString accepts odd-length hex by prefixing zero, as well as
// hybrid 06/07 points when their parity agrees with the supplied y coordinate.
fn sdk_public_key(key: &str) -> Option<String> {
    let normalized;
    let key = if key.len() % 2 == 1 {
        normalized = format!("0{key}");
        normalized.as_str()
    } else {
        key
    };
    let mut bytes = hex::decode(key).ok()?;
    if bytes.len() == 65 && matches!(bytes[0], 0x06 | 0x07) {
        if bytes[64] % 2 != bytes[0] % 2 {
            return None;
        }
        bytes[0] = 0x04;
    }
    canonical_key(&hex::encode(bytes))
}

/// Normalize the authenticated transport identity and optionally check a
/// string claim. This function does not itself authenticate the transport.
pub fn authenticated_identity(
    transport: Option<&Value>,
    claim: Option<&Value>,
) -> Result<String, &'static str> {
    let identity = transport
        .and_then(Value::as_str)
        .filter(|s| !js_trim(s).is_empty())
        .ok_or("Authenticated peer identity is unavailable")?;
    let normalized = sdk_public_key(identity).ok_or("Invalid authenticated identity key")?;
    if claim
        .and_then(Value::as_str)
        .is_some_and(|s| js_trim(s) != normalized)
    {
        return Err("Identity claim does not match authenticated peer");
    }
    Ok(normalized)
}
/// Check a room against a caller-provided identity. Like the fixed TS helper,
/// this does not parse the identity as a public key.
pub fn is_identity_owned_room(identity: &str, room: Option<&Value>) -> bool {
    let Some(room) = room.and_then(Value::as_str) else {
        return false;
    };
    if js_trim(room).is_empty() || room.len() > 195 {
        return false;
    }
    let Some(box_name) = room
        .strip_prefix(identity)
        .and_then(|s| s.strip_prefix('-'))
    else {
        return false;
    };
    exact_text(box_name, 128)
        && !identity
            .chars()
            .any(|c| c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&c))
}
/// Derive a box only for an exact canonical recipient public key and its room.
pub fn message_box_from_recipient_room(recipient: &str, room: Option<&Value>) -> Option<String> {
    let canonical = canonical_key(recipient)?;
    if canonical != recipient || !is_identity_owned_room(&canonical, room) {
        return None;
    }
    let room = room?.as_str()?;
    Some(room[canonical.len() + 1..].to_owned())
}
