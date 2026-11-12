//! Loopback HTTP resource tests. Authentication wallet/session are test doubles;
//! this exercises the real HTTP parser, auth adapter, and resource consumers,
//! not SDK cryptography or live identity verification.
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, MessageBox, PolicyError,
    auth_nonce::{HmacCheckError, NonceHmacRequest, NonceWallet},
    auth_responder::{AuthSession, AuthSessionStore, AuthWallet},
    http_auth::HttpAuthAdapter,
    http_stream::handle_http_stream,
    resource_config::{EnvironmentSnapshot, ResourceConfig},
    runtime_resources::RuntimeResources,
};
use serde_json::{Value, json};
use std::{convert::Infallible, sync::Arc};

const PEER: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
struct Wallet;
impl NonceWallet for Wallet {
    type Error = ();
    async fn create_hmac(&self, _: &NonceHmacRequest) -> Result<[u8; 32], ()> {
        Ok([0; 32])
    }
    async fn verify_hmac(
        &self,
        _: &NonceHmacRequest,
        _: &[u8; 32],
    ) -> Result<bool, HmacCheckError<()>> {
        Ok(true)
    }
}
impl AuthWallet for Wallet {
    async fn identity_key(&self) -> Result<String, ()> {
        Ok(PEER.to_owned())
    }
    async fn sign_auth(&self, _: &str, _: &str, _: &[u8]) -> Result<Vec<u8>, ()> {
        Ok(vec![1])
    }
    async fn verify_auth(&self, _: &str, _: &str, _: &[u8], _: &[u8]) -> Result<bool, ()> {
        Ok(true)
    }
}
struct Store;
impl AuthSessionStore for Store {
    type Error = ();
    async fn claim_initial(&self, _: &str, _: &str) -> Result<bool, ()> {
        Ok(true)
    }
    async fn add_session(&self, _: AuthSession) -> Result<(), ()> {
        Ok(())
    }
    async fn get_session(&self, nonce: &str) -> Result<Option<AuthSession>, ()> {
        Ok(Some(AuthSession {
            session_nonce: nonce.to_owned(),
            peer_nonce: STANDARD.encode([2; 48]),
            peer_identity: PEER.to_owned(),
            authenticated: true,
        }))
    }
    async fn claim_message(&self, _: &str, _: &str) -> Result<bool, ()> {
        Ok(true)
    }
    async fn mark_authenticated(&self, _: &str) -> Result<(), ()> {
        Ok(())
    }
}
struct Free;
impl DeliveryPolicy for Free {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
struct State {
    app: MessageBox,
    wallet: Wallet,
    store: Store,
}
async fn handle(
    req: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let adapter = HttpAuthAdapter::new(&state.app, &state.wallet, &state.store);
    let (parts, body) = handle_http_stream(&adapter, req).await.into_parts();
    Ok(Response::from_parts(parts, Full::new(Bytes::from(body))))
}
async fn server(settings: &[(&str, &str)]) -> (String, tokio::task::JoinHandle<()>) {
    let env: EnvironmentSnapshot = settings
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let resources = RuntimeResources::new(ResourceConfig::from_snapshot(&env).unwrap()).unwrap();
    let state = Arc::new(State {
        app: MessageBox::memory_with_resources(Arc::new(Free), resources)
            .await
            .unwrap(),
        wallet: Wallet,
        store: Store,
    });
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let service = service_fn(move |req| handle(req, Arc::clone(&state)));
                http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    });
    (format!("http://{addr}"), task)
}
async fn request(
    base: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut request = reqwest::Client::new()
        .request(method, format!("{base}{path}"))
        .header("x-bsv-auth-version", "0.1")
        .header("x-bsv-auth-identity-key", PEER)
        .header("x-bsv-auth-nonce", STANDARD.encode([1; 32]))
        .header("x-bsv-auth-your-nonce", STANDARD.encode([2; 48]))
        .header("x-bsv-auth-signature", "01")
        .header("x-bsv-auth-request-id", STANDARD.encode([3; 32]));
    if let Some(body) = body {
        request = request
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap());
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    (status, value)
}
fn public_key(index: u16) -> String {
    let mut secret = [0u8; 32];
    secret[30..].copy_from_slice(&index.to_be_bytes());
    let key = k256::SecretKey::from_slice(&secret).unwrap();
    hex::encode(key.public_key().to_encoded_point(true).as_bytes())
}
#[tokio::test]
async fn high_throughput_limits_reach_consumers_over_http() {
    let (base, server) = server(&[("MESSAGE_BOX_RESOURCE_PROFILE", "high-throughput")]).await;
    for path in [
        "/devices?limit=501&offset=100001",
        "/permissions/list?limit=501&offset=100001",
    ] {
        let (status, body) = request(&base, reqwest::Method::GET, path, None).await;
        assert_eq!(status, 200, "{path}: {body}");
    }
    for path in ["/devices?limit=1001", "/permissions/list?limit=1001"] {
        let (status, body) = request(&base, reqwest::Method::GET, path, None).await;
        assert_eq!(status, 400, "{path}: {body}");
        assert_eq!(body["code"], "ERR_INVALID_LIMIT");
    }
    let recipients: Vec<_> = (1..=101).map(public_key).collect();
    let ids: Vec<_> = (1..=101).map(|i| format!("wire-{i}")).collect();
    let body = json!({"message":{"recipient":recipients,"messageBox":"inbox","messageId":ids,"body":"hello"}});
    let (status, response) =
        request(&base, reqwest::Method::POST, "/sendMessage", Some(body)).await;
    assert_eq!(status, 200, "{response}");
    assert_eq!(response["results"].as_array().unwrap().len(), 101);
    let recipients: Vec<_> = (1..=251).map(public_key).collect();
    let ids: Vec<_> = (1..=251).map(|i| format!("overflow-{i}")).collect();
    let body = json!({"message":{"recipient":recipients,"messageBox":"inbox","messageId":ids,"body":"hello"}});
    let (status, response) =
        request(&base, reqwest::Method::POST, "/sendMessage", Some(body)).await;
    assert_eq!(status, 400, "{response}");
    assert_eq!(response["code"], "ERR_INVALID_REQUEST_DATA");
    server.abort();
}

#[tokio::test]
async fn unlimited_pagination_errors_match_fixed_ts_over_http() {
    let (base, server) = server(&[
        ("MESSAGE_BOX_DEVICE_LIST_MAX_LIMIT", "-1"),
        ("MESSAGE_BOX_DEVICE_LIST_MAX_OFFSET", "-1"),
        ("MESSAGE_BOX_PERMISSION_LIST_MAX_LIMIT", "-1"),
        ("MESSAGE_BOX_PERMISSION_LIST_MAX_OFFSET", "-1"),
        ("MESSAGE_BOX_LIST_MAX_LIMIT", "-1"),
        ("MESSAGE_BOX_LIST_MAX_OFFSET", "-1"),
        ("MESSAGE_BOX_MAX_RECIPIENTS", "-1"),
        ("MESSAGE_BOX_MAX_ACKNOWLEDGMENT_IDS", "-1"),
    ])
    .await;
    for prefix in ["/devices", "/permissions/list"] {
        for (query, expected) in [
            ("limit=0", "limit must be a positive safe integer."),
            (
                "offset=9007199254740992",
                "offset must be a non-negative safe integer.",
            ),
        ] {
            let (status, body) = request(
                &base,
                reqwest::Method::GET,
                &format!("{prefix}?{query}"),
                None,
            )
            .await;
            assert_eq!(status, 400, "{prefix}?{query}: {body}");
            assert_eq!(body["description"], expected);
        }
    }
    for (field, expected) in [
        (
            "limit",
            "limit must be an integer between 1 and the JavaScript safe-integer maximum.",
        ),
        (
            "offset",
            "offset must be an integer between 0 and the JavaScript safe-integer maximum.",
        ),
    ] {
        let mut body = json!({"messageBox":"inbox"});
        body[field] = if field == "limit" {
            json!(0)
        } else {
            json!(-1)
        };
        let (status, result) =
            request(&base, reqwest::Method::POST, "/listMessages", Some(body)).await;
        assert_eq!(status, 400, "{field}: {result}");
        assert_eq!(result["description"], expected);
    }
    let (status, body) = request(
        &base,
        reqwest::Method::POST,
        "/sendMessage",
        Some(json!({"message":{"recipient":[],"messageBox":"inbox","messageId":[],"body":"x"}})),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body["description"],
        "A message must include at least one recipient."
    );
    let (status, body) = request(
        &base,
        reqwest::Method::POST,
        "/acknowledgeMessage",
        Some(json!({"messageIds":[""]})),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body["description"],
        "Message IDs must be a non-empty array of exact, control-free strings no longer than 256 bytes each."
    );
    server.abort();
}
