//! Offline digest for a strict subset of the fixed TypeScript payment intent.
//!
//! This accepts only the listed JSON shape, rejecting all other fields rather
//! than ignoring data that could distinguish requests. It is not request or
//! payment validation. An authenticated caller must pass the validated snapshot,
//! canonical transaction ID derived from that same transaction, and the original
//! Atomic BEEF bytes. The validated snapshot must already be size bounded. It does not
//! implement arbitrary JSON custom instructions, insertion outputs, all optional
//! payment metadata, JavaScript lone-surrogate strings, or wallet operations.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentDigest {
    pub preimage: String,
    pub sha256_hex: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedInput;
fn object<'a>(
    value: &'a Value,
    names: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, UnsupportedInput> {
    let value = value.as_object().ok_or(UnsupportedInput)?;
    if value.len() != names.len() || names.iter().any(|name| !value.contains_key(*name)) {
        return Err(UnsupportedInput);
    }
    Ok(value)
}
fn object_with_optional<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, UnsupportedInput> {
    let value = value.as_object().ok_or(UnsupportedInput)?;
    if required.iter().any(|key| !value.contains_key(*key))
        || value
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(UnsupportedInput);
    }
    Ok(value)
}
fn optional_instructions(value: Option<&Value>) -> Result<String, UnsupportedInput> {
    match value {
        None => Ok(String::new()),
        Some(Value::Null) => Ok(",\"customInstructions\":null".to_owned()),
        Some(value) => Ok(format!(",\"customInstructions\":{}", quote(value)?)),
    }
}
fn string(value: &Value) -> Result<&str, UnsupportedInput> {
    value.as_str().ok_or(UnsupportedInput)
}
fn quote(value: &Value) -> Result<String, UnsupportedInput> {
    serde_json::to_string(string(value)?).map_err(|_| UnsupportedInput)
}
fn strings(value: &Value, allow_empty: bool) -> Result<String, UnsupportedInput> {
    let values = value.as_array().ok_or(UnsupportedInput)?;
    if values.is_empty() && !allow_empty {
        return Err(UnsupportedInput);
    }
    let result: Result<Vec<_>, _> = values.iter().map(quote).collect();
    Ok(format!("[{}]", result?.join(",")))
}
/// Computes a digest only for ordinary wallet-payment outputs. Fields not
/// represented by this subset cause `Err`, including unsupported optional
/// metadata and non-string/non-null custom instructions; `Err` does not mean the upstream request is invalid.
pub fn compute_digest(input: &Value) -> Result<IntentDigest, UnsupportedInput> {
    let root = object(input, &["sender", "message", "payment"])?;
    let m = object(
        &root["message"],
        &["boxType", "recipients", "messageIds", "body"],
    )?;
    let p = root["payment"].as_object().ok_or(UnsupportedInput)?;
    const REQUIRED: &[&str] = &["transactionId", "tx", "outputs"];
    const ALLOWED: &[&str] = &[
        "transactionId",
        "tx",
        "outputs",
        "description",
        "labels",
        "seekPermission",
    ];
    if REQUIRED.iter().any(|key| !p.contains_key(*key))
        || p.keys().any(|key| !ALLOWED.contains(&key.as_str()))
    {
        return Err(UnsupportedInput);
    }
    let mut metadata = String::new();
    if let Some(description) = p.get("description") {
        metadata.push_str(",\"description\":");
        if description.is_null() {
            metadata.push_str("null");
        } else {
            metadata.push_str(&quote(description)?);
        }
    }
    if let Some(labels) = p.get("labels") {
        metadata.push_str(",\"labels\":");
        metadata.push_str(&strings(labels, true)?);
    }
    if let Some(seek) = p.get("seekPermission") {
        metadata.push_str(",\"seekPermission\":");
        metadata.push_str(match seek {
            Value::Bool(true) => "true",
            Value::Bool(false) => "false",
            Value::Null => "null",
            _ => return Err(UnsupportedInput),
        });
    }
    let recipients = m["recipients"].as_array().ok_or(UnsupportedInput)?;
    let ids = m["messageIds"].as_array().ok_or(UnsupportedInput)?;
    if recipients.len() != ids.len() {
        return Err(UnsupportedInput);
    }
    let bytes: Result<Vec<u8>, _> = p["tx"]
        .as_array()
        .ok_or(UnsupportedInput)?
        .iter()
        .map(|v| {
            v.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or(UnsupportedInput)
        })
        .collect();
    let beef = serde_json::to_string(&STANDARD.encode(bytes?)).map_err(|_| UnsupportedInput)?;
    let outputs = p["outputs"].as_array().ok_or(UnsupportedInput)?;
    if outputs.is_empty() {
        return Err(UnsupportedInput);
    }
    let mut encoded = Vec::with_capacity(outputs.len());
    for output in outputs {
        let output = object_with_optional(
            output,
            &["outputIndex", "protocol", "paymentRemittance"],
            &["customInstructions"],
        )?;
        let index = output["outputIndex"]
            .as_u64()
            .filter(|v| *v <= 9_007_199_254_740_991)
            .ok_or(UnsupportedInput)?;
        if string(&output["protocol"])? != "wallet payment" {
            return Err(UnsupportedInput);
        }
        let r = object_with_optional(
            &output["paymentRemittance"],
            &["derivationPrefix", "derivationSuffix", "senderIdentityKey"],
            &["customInstructions"],
        )?;
        encoded.push(format!("{{\"outputIndex\":{index},\"protocol\":\"wallet payment\",\"paymentRemittance\":{{\"derivationPrefix\":{},\"derivationSuffix\":{},\"senderIdentityKey\":{}{}}}{}}}",quote(&r["derivationPrefix"])?,quote(&r["derivationSuffix"])?,quote(&r["senderIdentityKey"])?,optional_instructions(r.get("customInstructions"))?,optional_instructions(output.get("customInstructions"))?));
    }
    let preimage = format!(
        "{{\"version\":1,\"sender\":{},\"message\":{{\"boxType\":{},\"recipients\":{},\"messageIds\":{},\"body\":{}}},\"payment\":{{\"transactionId\":{},\"atomicBEEF\":{},\"outputs\":[{}]{}}}}}",
        quote(&root["sender"])?,
        quote(&m["boxType"])?,
        strings(&m["recipients"], false)?,
        strings(&m["messageIds"], false)?,
        quote(&m["body"])?,
        quote(&p["transactionId"])?,
        beef,
        encoded.join(","),
        metadata
    );
    let sha256_hex = hex::encode(Sha256::digest(preimage.as_bytes()));
    Ok(IntentDigest {
        preimage,
        sha256_hex,
    })
}
