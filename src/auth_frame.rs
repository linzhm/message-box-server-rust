//! Encoding only for an already-canonicalized BRC-104 HTTP request preimage.
//!
//! This module does not parse HTTP, canonicalize URLs/headers/bodies, verify
//! signatures or authenticate a caller. The transport must reconstruct the
//! precise request components from the actual request and enforce its limits.

/// Components that the embedding transport has already normalized exactly as
/// required by the pinned SDK/middleware. `headers` must already contain only
/// the signed headers in the SDK's order; `body` is the exact canonical body.
pub struct PreparedRequestFrame<'a> {
    pub request_id: [u8; 32],
    pub method: &'a str,
    pub path: Option<&'a str>,
    pub query: Option<&'a str>,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Option<&'a [u8]>,
}

#[derive(Debug)]
pub struct InvalidMethod;

/// SDK CompactSize encoding. `None` is the SDK's signed -1 sentinel.
pub fn encode_compact_size(value: Option<u64>) -> Vec<u8> {
    let Some(value) = value else {
        return vec![0xff; 9];
    };
    match value {
        0..=252 => vec![value as u8],
        253..=65535 => {
            let mut out = vec![0xfd];
            out.extend_from_slice(&(value as u16).to_le_bytes());
            out
        }
        65536..=4294967295 => {
            let mut out = vec![0xfe];
            out.extend_from_slice(&(value as u32).to_le_bytes());
            out
        }
        _ => {
            let mut out = vec![0xff];
            out.extend_from_slice(&value.to_le_bytes());
            out
        }
    }
}
fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&encode_compact_size(Some(bytes.len() as u64)));
    out.extend_from_slice(bytes);
}
fn write_optional(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => write_bytes(out, bytes),
        None => out.extend_from_slice(&encode_compact_size(None)),
    }
}

/// Encodes prevalidated components. The source server's method character set
/// is enforced here; this function does not independently validate the other
/// components or decide which headers and body bytes belong in the signature.
pub fn encode_request_frame(request: &PreparedRequestFrame<'_>) -> Result<Vec<u8>, InvalidMethod> {
    if request.method.is_empty()
        || request.method.len() > 32
        || !request
            .method
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b"!#$%&'*+.^_`|~-".contains(&b))
    {
        return Err(InvalidMethod);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&request.request_id);
    write_bytes(&mut out, request.method.as_bytes());
    write_optional(
        &mut out,
        request.path.filter(|s| !s.is_empty()).map(str::as_bytes),
    );
    write_optional(
        &mut out,
        request.query.filter(|s| !s.is_empty()).map(str::as_bytes),
    );
    out.extend_from_slice(&encode_compact_size(Some(request.headers.len() as u64)));
    for (name, value) in request.headers {
        write_bytes(&mut out, name.as_bytes());
        write_bytes(&mut out, value.as_bytes());
    }
    write_optional(&mut out, request.body);
    Ok(out)
}

/// Already-canonicalized response components. The caller selects and orders the
/// signed headers and validates status/limits; an empty body uses SDK's -1.
pub struct PreparedResponseFrame<'a> {
    pub request_id: [u8; 32],
    pub status: u16,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

/// Encodes the server's BRC-104 response preimage from prepared components.
pub fn encode_response_frame(response: &PreparedResponseFrame<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&response.request_id);
    out.extend_from_slice(&encode_compact_size(Some(response.status.into())));
    out.extend_from_slice(&encode_compact_size(Some(response.headers.len() as u64)));
    for (name, value) in response.headers {
        write_bytes(&mut out, name.as_bytes());
        write_bytes(&mut out, value.as_bytes());
    }
    write_optional(
        &mut out,
        (!response.body.is_empty()).then_some(response.body),
    );
    out
}
