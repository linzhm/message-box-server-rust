//! BRC-authenticated HTTP adapter for MessageBox application routes and the
//! no-certificate handshake. Request preparation follows the pinned TS middleware.
//!
//! This adapter accepts already-buffered requests. The listener must enforce a
//! streaming byte limit before buffering and provide TLS, edge controls and
//! lifecycle management. Unpaired JSON surrogates/nonfinite numbers and routes
//! outside the application contract remain unsupported; this is not a full server.
use crate::{
    ApiResponse, Identity, MessageBox,
    auth_frame::{PreparedRequestFrame, encode_request_frame},
    auth_responder::{AuthResponder, AuthSessionStore, AuthWallet},
    http_canonical::{
        JsonError, parse_json, query_fields, signed_headers, signed_json_body, valid_auth_body,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{
    HeaderMap, Request, Response, StatusCode,
    header::{CONTENT_TYPE, HOST},
};
use serde_json::{Value, json};
use std::{str::FromStr, sync::Arc};

pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Internal, authenticated post-commit notification metadata. This is carried
/// in response extensions and is not serialized into the HTTP response.
#[derive(Clone, Debug)]
pub struct CommittedDelivery {
    pub sender: String,
    pub recipient: String,
    pub message_box: String,
    pub message_id: String,
    pub body: Arc<str>,
}
#[derive(Clone, Debug)]
pub struct CommittedDeliveries(pub Vec<CommittedDelivery>);
/// Construct metadata only from a verified caller and an actual successful
/// send result. This helper does not authenticate the identity itself.
pub fn committed_deliveries(
    identity: &Identity,
    fields: &Value,
    result: &ApiResponse,
) -> Option<CommittedDeliveries> {
    // Upstream deliberately does not push paid messages: clients must list
    // them so their wallet can internalize the payment before acknowledgement.
    if fields.get("payment").is_some_and(|value| !value.is_null()) {
        return None;
    }
    if result.status != 200 || result.body["status"] != "success" {
        return None;
    }
    let message = &fields["message"];
    let message_box = message["messageBox"].as_str()?;
    let body: Arc<str> = Arc::from(message["body"].as_str()?);
    result.body["results"]
        .as_array()?
        .iter()
        .map(|entry| {
            Some(CommittedDelivery {
                sender: identity.as_str().to_owned(),
                recipient: entry["recipient"].as_str()?.to_owned(),
                message_box: message_box.to_owned(),
                message_id: entry["messageId"].as_str()?.to_owned(),
                body: Arc::clone(&body),
            })
        })
        .collect::<Option<Vec<_>>>()
        .map(CommittedDeliveries)
}
const AUTH_HEADERS: [&str; 6] = [
    "x-bsv-auth-version",
    "x-bsv-auth-identity-key",
    "x-bsv-auth-nonce",
    "x-bsv-auth-your-nonce",
    "x-bsv-auth-signature",
    "x-bsv-auth-request-id",
];

/// Normalize only an initial run of slashes for route matching. The original
/// request path must remain unchanged for authentication signature framing.
pub fn normalize_initial_slashes(path: &str) -> &str {
    let count = path.bytes().take_while(|byte| *byte == b'/').count();
    if count > 1 { &path[count - 1..] } else { path }
}

/// A restricted canonical route prefix. Empty means root routes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoutingPrefix(String);
impl RoutingPrefix {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if value.is_empty() {
            return Ok(Self::default());
        }
        if value.len() > 256 || !value.starts_with('/') {
            return Err("invalid routing prefix");
        }
        for segment in value[1..].split('/') {
            if segment.is_empty()
                || segment == "."
                || segment == ".."
                || !segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
            {
                return Err("invalid routing prefix");
            }
        }
        Ok(Self(value.to_owned()))
    }
    pub fn strip<'a>(&self, path: &'a str) -> Option<&'a str> {
        let remaining = path.strip_prefix(&self.0)?;
        remaining.starts_with('/').then_some(remaining)
    }
}
pub struct HttpAuthAdapter<'a, W, S> {
    app: &'a MessageBox,
    responder: AuthResponder<'a, W, S>,
    routing_prefix: Option<&'a RoutingPrefix>,
}
impl<'a, W: AuthWallet, S: AuthSessionStore> HttpAuthAdapter<'a, W, S> {
    pub fn new(app: &'a MessageBox, wallet: &'a W, store: &'a S) -> Self {
        Self {
            app,
            responder: AuthResponder::new(wallet, store),
            routing_prefix: None,
        }
    }
    pub fn with_routing_prefix(mut self, prefix: &'a RoutingPrefix) -> Self {
        self.routing_prefix = Some(prefix);
        self
    }
    /// Dispatch an already-buffered request. A caller must cap body bytes while
    /// reading the network stream, before invoking this method.
    pub async fn handle(&self, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
        if request.body().len() > MAX_BODY_BYTES {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "ERR_BODY_TOO_LARGE",
                "The request body exceeds the endpoint limit.",
            );
        }
        let (parts, body) = request.into_parts();
        if !valid_host(&parts.headers) {
            return error(StatusCode::BAD_REQUEST, "ERR_INVALID_HOST", "Invalid host.");
        }
        if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
            return error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_URI",
                "Only origin-form request targets are supported.",
            );
        }
        let target = parts.uri.path_and_query().map(|v| v.as_str()).unwrap_or("");
        let normalized_path = normalize_initial_slashes(parts.uri.path());
        if parts.method == http::Method::POST
            && parts.uri.query().is_none()
            && normalized_path == "/.well-known/auth"
        {
            let content = single(&parts.headers, "content-type").unwrap_or("");
            if !content
                .split(';')
                .next()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
            {
                return error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_BODY",
                    "The request body is invalid.",
                );
            }
            let message: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "ERR_INVALID_BODY",
                        "The request body is invalid.",
                    );
                }
            };
            if duplicate_bound_header(&parts.headers) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_AUTH",
                    "Invalid authentication headers.",
                );
            }
            return match self.responder.accept_initial(&message).await {
                Ok(response) => json_response(StatusCode::OK, &response.to_json()),
                Err(_) => error(
                    StatusCode::BAD_REQUEST,
                    "ERR_AUTH_FAILED",
                    "Authentication failed.",
                ),
            };
        }
        // Parse the body before authentication, just as body-parser does. Once
        // authenticated, business handlers consume these same normalized values.
        let content_type = single(&parts.headers, "content-type").unwrap_or("");
        let is_json = content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
        let parsed_body = if is_json {
            parse_json(&body)
        } else {
            Ok(json!({}))
        };
        if matches!(parsed_body, Err(JsonError::Invalid)) {
            return route_json_error(JsonError::Invalid);
        }
        let route_path = match self.routing_prefix {
            Some(prefix) => match prefix.strip(normalized_path) {
                Some(path) => path,
                None => return unsupported(),
            },
            None => normalized_path,
        };
        let method = parts.method.as_str();
        let supported = match method {
            "GET" => matches!(
                route_path,
                "/devices" | "/permissions/quote" | "/permissions/get" | "/permissions/list"
            ),
            "POST" => matches!(
                route_path,
                "/listMessages"
                    | "/sendMessage"
                    | "/acknowledgeMessage"
                    | "/registerDevice"
                    | "/permissions/set"
            ),
            _ => false,
        };
        if !supported {
            return unsupported();
        }
        let path = route_path;
        let any = parts
            .headers
            .keys()
            .any(|name| name.as_str().starts_with("x-bsv-auth-"));
        if !any {
            return error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Mutual-authentication failed!",
            );
        }
        if duplicate_bound_header(&parts.headers) {
            return error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_AUTH",
                "Invalid authentication headers.",
            );
        }
        let values: Option<Vec<&str>> = AUTH_HEADERS
            .iter()
            .map(|name| single(&parts.headers, name))
            .collect();
        let Some(values) = values else {
            return error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_AUTH",
                "Invalid authentication headers.",
            );
        };
        let Some(request_id) = canonical_id(values[5]) else {
            return error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_AUTH",
                "Invalid authentication headers.",
            );
        };
        if values[4].is_empty() || values[4].len() > 2048 || !values[4].len().is_multiple_of(2) {
            return error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_AUTH",
                "Invalid authentication headers.",
            );
        }
        let signature = match hex::decode(values[4]) {
            Ok(v) if !v.is_empty() && v.len() <= 1024 => v,
            _ => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_AUTH",
                    "Invalid authentication headers.",
                );
            }
        };
        let body_fields = match parsed_body {
            Ok(value) => value,
            Err(error) => return route_json_error(error),
        };
        if !valid_auth_body(&body_fields) {
            return error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_AUTH",
                "Invalid authentication body.",
            );
        }
        let signed_body =
            if is_json && (!body.is_empty() || parts.headers.contains_key("transfer-encoding")) {
                match signed_json_body(&body_fields) {
                    Ok(bytes) => Some(bytes),
                    Err(error) => return route_json_error(error),
                }
            } else {
                None
            };
        let fields = if method == "GET" {
            query_fields(parts.uri.query().unwrap_or(""))
        } else {
            body_fields
        };
        // The fixed middleware uses WHATWG URL on protocol + Host + originalUrl.
        // In particular a bare '?' is absent; nonempty searches retain their
        // original order/escapes rather than URLSearchParams reserialization.
        if target.len() > 8192 {
            return error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_AUTH",
                "Invalid authentication URL.",
            );
        }
        let parsed_url = match url::Url::parse(&format!(
            "http://{}{}",
            single(&parts.headers, "host").unwrap_or(""),
            target
        )) {
            Ok(url) => url,
            Err(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_AUTH",
                    "Invalid authentication URL.",
                );
            }
        };
        let raw_query = parsed_url
            .query()
            .filter(|query| !query.is_empty())
            .map(|query| format!("?{query}"));
        let signed_headers = match signed_headers(&parts.headers) {
            Ok(headers) => headers,
            Err(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_AUTH",
                    "Invalid authentication headers.",
                );
            }
        };
        let frame = match encode_request_frame(&PreparedRequestFrame {
            request_id,
            method,
            path: Some(parsed_url.path()),
            query: raw_query.as_deref(),
            headers: &signed_headers,
            body: signed_body.as_deref(),
        }) {
            Ok(v) => v,
            Err(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_AUTH",
                    "Invalid authentication headers.",
                );
            }
        };
        let message = json!({"version":values[0],"messageType":"general","identityKey":values[1],"nonce":values[2],"yourNonce":values[3],"signature":signature,"payload":frame});
        let verified = match self.responder.accept_general(&message, &frame).await {
            Ok(v) => v,
            Err(_) => {
                return error(
                    StatusCode::UNAUTHORIZED,
                    "ERR_AUTH_FAILED",
                    "Authentication failed.",
                );
            }
        };
        let identity = match Identity::from_verified_key(verified.identity_key()) {
            Ok(v) => v,
            Err(_) => {
                return error(
                    StatusCode::UNAUTHORIZED,
                    "ERR_AUTH_FAILED",
                    "Authentication failed.",
                );
            }
        };
        let empty = json!({});
        let (query_fields, body_fields) = if method == "GET" {
            (&fields, &empty)
        } else {
            (&empty, &fields)
        };
        let result = if parts.headers.contains_key("x-bsv-payment") {
            // Header authentication is not payment acceptance. Keep the
            // explicitly deferred payment boundary before any business writes.
            Some(ApiResponse {
                status: 501,
                body: json!({"status":"error","code":"ERR_PAYMENT_NOT_IMPLEMENTED","description":"Payment processing is not implemented."}),
            })
        } else {
            self.app
                .dispatch_http(method, path, Some(&identity), query_fields, body_fields)
                .await
        };
        let Some(result) = result else {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_INTERNAL",
                "An internal error has occurred.",
            );
        };
        let body = match serde_json::to_vec(&result.body) {
            Ok(v) => v,
            Err(_) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERR_INTERNAL",
                    "An internal error has occurred.",
                );
            }
        };
        let signed = match self
            .responder
            .sign_http_response(&verified, result.status, &[], &body)
            .await
        {
            Ok(v) => v,
            Err(_) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERR_INTERNAL",
                    "An internal error has occurred.",
                );
            }
        };
        let status =
            StatusCode::from_u16(result.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let committed = if path == "/sendMessage" {
            committed_deliveries(&identity, &fields, &result)
        } else {
            None
        };
        match Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .header("x-bsv-auth-version", "0.1")
            .header("x-bsv-auth-identity-key", signed.identity_key)
            .header("x-bsv-auth-nonce", signed.nonce)
            .header("x-bsv-auth-your-nonce", signed.your_nonce)
            .header("x-bsv-auth-signature", hex::encode(signed.signature))
            .header("x-bsv-auth-request-id", values[5])
            .body(body)
        {
            Ok(mut response) => {
                if let Some(committed) = committed {
                    response.extensions_mut().insert(committed);
                }
                response
            }
            Err(_) => error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_INTERNAL",
                "An internal error has occurred.",
            ),
        }
    }
}
fn route_json_error(error_kind: JsonError) -> Response<Vec<u8>> {
    match error_kind {
        JsonError::Invalid => error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_BODY",
            "The request body is invalid.",
        ),
        JsonError::Unsupported => unsupported(),
    }
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(first)
    }
}
fn duplicate_bound_header(headers: &HeaderMap) -> bool {
    headers.keys().any(|name| {
        let n = name.as_str();
        (n.starts_with("x-bsv-") || n == "authorization" || n == "content-type" || n == "host")
            && headers.get_all(name).iter().count() > 1
    })
}
fn valid_host(headers: &HeaderMap) -> bool {
    single(headers, HOST.as_str())
        .filter(|s| !s.is_empty() && s.len() <= 512)
        .and_then(|s| http::uri::Authority::from_str(s).ok())
        .filter(|a| !a.host().is_empty() && !a.as_str().contains('@'))
        .and_then(|a| url::Url::parse(&format!("http://{a}/")).ok())
        .is_some_and(|u| {
            u.host_str().is_some() && u.username().is_empty() && u.password().is_none()
        })
}

fn canonical_id(value: &str) -> Option<[u8; 32]> {
    if value.len() != 44 {
        return None;
    }
    let bytes = STANDARD.decode(value).ok()?;
    if STANDARD.encode(&bytes) != value {
        return None;
    }
    bytes.try_into().ok()
}
fn json_response(status: StatusCode, body: &Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(body).unwrap_or_default())
        .expect("static HTTP response")
}
fn error(status: StatusCode, code: &str, description: &str) -> Response<Vec<u8>> {
    json_response(
        status,
        &json!({"status":"error","code":code,"description":description}),
    )
}

fn unsupported() -> Response<Vec<u8>> {
    error(
        StatusCode::NOT_IMPLEMENTED,
        "ERR_NOT_IMPLEMENTED",
        "This HTTP route or request form is not implemented.",
    )
}
