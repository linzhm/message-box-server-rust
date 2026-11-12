//! Fixed TS body-parser and auth-middleware request preparation. Business
//! handlers receive the same parsed values used to reconstruct the signed body.
use http::HeaderMap;
use serde::Serialize;
use serde_json::{Map, Number, Value, value::RawValue};

#[derive(Debug)]
pub(crate) enum JsonError {
    Invalid,
    Unsupported,
}

/// Express JSON's strict mode accepts objects/arrays, not root primitives.
/// `RawValue` separates malformed JSON from valid representations Rust's
/// Unicode-scalar/finite-number Value cannot hold (e.g. an unpaired surrogate).
pub(crate) fn parse_json(body: &[u8]) -> Result<Value, JsonError> {
    if body.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    // body-parser's UTF-8 decoder replaces malformed UTF-8 and strips a BOM.
    let text = String::from_utf8_lossy(body);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let raw: &RawValue = serde_json::from_str(text).map_err(|_| JsonError::Invalid)?;
    if !matches!(raw.get().as_bytes().first(), Some(b'{' | b'[')) {
        return Err(JsonError::Invalid);
    }
    let value = serde_json::from_str(raw.get()).map_err(|_| JsonError::Unsupported)?;
    normalize_json(value)
}

fn normalize_json(value: Value) -> Result<Value, JsonError> {
    Ok(match value {
        // JSON.parse uses IEEE-754 binary64 even for integer lexemes. Normalize
        // the consumed values too, so an unrounded integer cannot escape the
        // signature domain. The existing ryu-js formatter handles all finite
        // magnitudes, integral floats, exponent boundaries and negative zero.
        Value::Number(number) => Value::Number(
            number
                .as_f64()
                .and_then(Number::from_f64)
                .ok_or(JsonError::Unsupported)?,
        ),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(normalize_json)
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(values) => {
            // JS enumerates array-index keys numerically, then other keys in
            // insertion order. preserve_order also keeps the first insertion
            // position when JSON.parse's last duplicate value wins.
            let (mut indices, other): (Vec<_>, Vec<_>) = values
                .into_iter()
                .partition(|(key, _)| array_index(key).is_some());
            indices.sort_by_key(|(key, _)| array_index(key).unwrap());
            Value::Object(
                indices
                    .into_iter()
                    .chain(other)
                    .map(|(key, value)| Ok((key, normalize_json(value)?)))
                    .collect::<Result<_, JsonError>>()?,
            )
        }
        other => other,
    })
}

fn array_index(key: &str) -> Option<u32> {
    key.parse::<u32>()
        .ok()
        .filter(|index| *index < u32::MAX && index.to_string() == key)
}

pub(crate) fn signed_json_body(value: &Value) -> Result<Vec<u8>, JsonError> {
    // The pinned middleware gives dense root byte arrays precedence over JSON.
    // Other arrays are ordinary JSON and reach the business field validators.
    if let Value::Array(values) = value
        && let Some(bytes) = values
            .iter()
            .map(|value| {
                value
                    .as_f64()
                    .filter(|n| n.fract() == 0.0 && (0.0..=255.0).contains(n))
                    .map(|n| n as u8)
            })
            .collect::<Option<Vec<_>>>()
    {
        return Ok(bytes);
    }
    struct JsNumberFormatter;
    impl serde_json::ser::Formatter for JsNumberFormatter {
        fn write_f64<W>(&mut self, writer: &mut W, value: f64) -> std::io::Result<()>
        where
            W: ?Sized + std::io::Write,
        {
            writer.write_all(ryu_js::Buffer::new().format_finite(value).as_bytes())
        }
    }
    let mut bytes = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut bytes, JsNumberFormatter);
    value
        .serialize(&mut serializer)
        .map_err(|_| JsonError::Unsupported)?;
    Ok(bytes)
}

/// The pinned auth middleware's plain-data bound runs after JSON parsing and
/// after deciding that this is an authenticated request. In particular raw
/// negative zero is rejected there, although a client JSON.stringify(-0)
/// legitimately puts ordinary zero on the wire.
pub(crate) fn valid_auth_body(value: &Value) -> bool {
    let mut pending = vec![(value, 0)];
    let (mut nodes, mut bytes) = (0, 0);
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > 100_000 || depth > 64 {
            return false;
        }
        match value {
            Value::Null => bytes += 4,
            Value::Bool(_) => bytes += 16,
            Value::String(value) => bytes += value.len(),
            Value::Number(number) => {
                let Some(value) = number.as_f64() else {
                    return false;
                };
                if !value.is_finite() || (value == 0.0 && value.is_sign_negative()) {
                    return false;
                }
                bytes += 16;
            }
            Value::Array(values) => {
                if values.len() > 100_000 {
                    return false;
                }
                for (index, value) in values.iter().enumerate() {
                    bytes += index.to_string().len();
                    pending.push((value, depth + 1));
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    bytes += key.len();
                    pending.push((value, depth + 1));
                }
            }
        }
        if bytes > 8 * 1024 * 1024 {
            return false;
        }
    }
    true
}

/// Express 5's default simple query parser (Node querystring): strings,
/// repeated keys become arrays, unknown keys remain ordinary fields, and
/// at most 1000 pairs are parsed. The query's wire spelling is never rebuilt
/// from these business fields for authentication.
pub(crate) fn query_fields(query: &str) -> Value {
    let mut fields = Map::new();
    for pair in query.split('&').take(1000) {
        for (key, value) in url::form_urlencoded::parse(pair.as_bytes()) {
            let value = Value::String(value.into_owned());
            match fields.entry(key.into_owned()) {
                serde_json::map::Entry::Vacant(entry) => {
                    entry.insert(value);
                }
                serde_json::map::Entry::Occupied(mut entry) => match entry.get_mut() {
                    Value::Array(values) => values.push(value),
                    previous => *previous = Value::Array(vec![previous.take(), value]),
                },
            }
        }
    }
    Value::Object(fields)
}

/// Header names are lower-case ASCII HTTP tokens. This is the pinned Node
/// default localeCompare order on that finite alphabet, verified against the
/// actual SDK/middleware fixture (including every legal token character).
/// No Unicode collation implementation is needed for HTTP field names.
fn header_key_order(key: &str) -> impl Iterator<Item = usize> + '_ {
    const ORDER: &[u8] = b"_-!.'*&#%`^+|~$0123456789abcdefghijklmnopqrstuvwxyz";
    key.bytes()
        .map(|b| ORDER.iter().position(|c| *c == b).unwrap())
}

pub(crate) fn signed_headers(headers: &HeaderMap) -> Result<Vec<(&str, &str)>, ()> {
    let mut signed = Vec::new();
    for (key, value) in headers {
        let key = key.as_str();
        if (key.starts_with("x-bsv-") || key == "content-type" || key == "authorization")
            && !key.starts_with("x-bsv-auth")
        {
            let value = value.to_str().map_err(|_| ())?;
            let value = if key == "content-type" {
                value.split(';').next().unwrap_or("").trim()
            } else {
                value
            };
            signed.push((key, value));
        }
    }
    signed.sort_by(|a, b| header_key_order(a.0).cmp(header_key_order(b.0)));
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simple_query_matches_fixed_node_querystring_corpus() {
        let corpus: Value =
            serde_json::from_str(include_str!("../tests/fixtures/http-compat-sdk4-lock.json"))
                .unwrap();
        for vector in corpus["vectors"].as_array().unwrap() {
            let target = vector["target"].as_str().unwrap();
            let query = target.split_once('?').map(|(_, query)| query).unwrap_or("");
            assert_eq!(query_fields(query), vector["query"], "{}", vector["name"]);
        }
        for case in corpus["queryCases"].as_array().unwrap() {
            assert_eq!(
                query_fields(case["query"].as_str().unwrap()),
                case["parsed"]
            );
        }
    }
}
