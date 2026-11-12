//! Pinned middleware/SDK-generated request-frame corpus. The wallet and
//! store here are test doubles, not a real client/server acceptance run.
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{Request, StatusCode};
use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
    auth_nonce::{HmacCheckError, NonceHmacRequest, NonceWallet},
    auth_responder::{AuthSession, AuthSessionStore, AuthWallet},
    http_auth::HttpAuthAdapter,
};
use serde_json::Value;
use std::sync::{Arc, Mutex};

const PEER: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
struct Wallet {
    expected: Mutex<Vec<u8>>,
}
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
        Ok(PEER.into())
    }
    async fn sign_auth(&self, _: &str, _: &str, _: &[u8]) -> Result<Vec<u8>, ()> {
        Ok(vec![1])
    }
    async fn verify_auth(&self, _: &str, _: &str, frame: &[u8], _: &[u8]) -> Result<bool, ()> {
        Ok(frame == self.expected.lock().unwrap().as_slice())
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
            session_nonce: nonce.into(),
            peer_nonce: STANDARD.encode([2; 48]),
            peer_identity: PEER.into(),
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
fn request(path: &str, body: &str, auth: bool) -> Request<Vec<u8>> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "localhost")
        .header("content-type", "application/json");
    if auth {
        b = b
            .header("x-bsv-auth-version", "0.1")
            .header("x-bsv-auth-identity-key", PEER)
            .header("x-bsv-auth-nonce", STANDARD.encode([1; 32]))
            .header("x-bsv-auth-your-nonce", STANDARD.encode([2; 48]))
            .header("x-bsv-auth-signature", "01")
            .header("x-bsv-auth-request-id", STANDARD.encode([3; 32]));
    }
    b.body(body.as_bytes().to_vec()).unwrap()
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/http-compat-sdk4-lock.json")).unwrap()
}
fn vector_request(vector: &Value, auth: bool) -> Request<Vec<u8>> {
    let mut builder = Request::builder()
        .method(vector["method"].as_str().unwrap())
        .uri(vector["target"].as_str().unwrap())
        .header("host", "localhost");
    for (name, value) in vector["headers"].as_object().unwrap() {
        builder = builder.header(name, value.as_str().unwrap());
    }
    let body = vector["body"].as_str().unwrap();
    if !body.is_empty() {
        builder = builder.header("content-length", body.len());
    }
    if auth {
        for (name, value) in request("/unused", "", true).headers() {
            if name.as_str().starts_with("x-bsv-auth-") {
                builder = builder.header(name, value);
            }
        }
    }
    builder.body(body.as_bytes().to_vec()).unwrap()
}

#[tokio::test]
async fn fixed_middleware_frames_reach_the_business_contract() {
    for vector in vectors()["vectors"].as_array().unwrap() {
        let app = MessageBox::memory(Arc::new(Free), Limits::default())
            .await
            .unwrap();
        let wallet = Wallet {
            expected: Mutex::new(hex::decode(vector["frameHex"].as_str().unwrap()).unwrap()),
        };
        let adapter = HttpAuthAdapter::new(&app, &wallet, &Store);
        assert_eq!(
            adapter.handle(vector_request(vector, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned {}",
            vector["name"]
        );
        let response = adapter.handle(vector_request(vector, true)).await;
        assert_eq!(
            response.status().as_u16(),
            vector["status"].as_u64().unwrap() as u16,
            "{}: {}",
            vector["name"],
            String::from_utf8_lossy(response.body())
        );
        assert!(
            response.headers().contains_key("x-bsv-auth-signature"),
            "{}",
            vector["name"]
        );
        if !vector["code"].is_null() {
            assert_eq!(
                serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
                vector["code"]
            );
        }
        // A supported signed payment header is still explicitly deferred and
        // cannot cause the test message to be committed.
        if vector["name"] == "payment-deferred" {
            let owner = Identity::from_verified_key(PEER).unwrap();
            let listed = app
                .handle(
                    "/listMessages",
                    Some(&owner),
                    &serde_json::json!({"messageBox":"inbox"}),
                )
                .await;
            assert_eq!(listed.body["messages"], serde_json::json!([]));
        }
    }
}

#[tokio::test]
async fn sdk_raw_string_signature_is_not_mistaken_for_parsed_json_signature() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let adapter = HttpAuthAdapter::new(&app, &wallet, &Store);
    let mut checked = 0;
    for vector in vectors()["vectors"].as_array().unwrap() {
        if vector["frameHex"] == vector["sdkStringFrameHex"] {
            continue;
        }
        *wallet.expected.lock().unwrap() =
            hex::decode(vector["sdkStringFrameHex"].as_str().unwrap()).unwrap();
        assert_eq!(
            adapter.handle(vector_request(vector, true)).await.status(),
            StatusCode::UNAUTHORIZED,
            "{}",
            vector["name"]
        );
        checked += 1;
    }
    assert_eq!(checked, 9);
}

#[tokio::test]
async fn custom_headers_original_query_and_body_are_bound_before_any_write() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let all = vectors();
    let vector = all["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "send-custom")
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(hex::decode(vector["frameHex"].as_str().unwrap()).unwrap()),
    };
    let adapter = HttpAuthAdapter::new(&app, &wallet, &Store);
    for mutation in 0..5 {
        let mut req = vector_request(vector, true);
        match mutation {
            0 => {
                req.headers_mut()
                    .insert("x-bsv-extra", "tampered".parse().unwrap());
            }
            1 => {
                req.headers_mut().remove("x-bsv-extra");
            }
            2 => {
                *req.uri_mut() = "/sendMessage?extra=+".parse().unwrap();
            }
            3 => {
                *req.body_mut() = String::from_utf8(req.body().clone())
                    .unwrap()
                    .replace("untampered", "tampered")
                    .into_bytes();
            }
            4 => {
                req.headers_mut()
                    .insert("authorization", "Bearer extra".parse().unwrap());
            }
            _ => unreachable!(),
        }
        assert_eq!(
            adapter.handle(req).await.status(),
            StatusCode::UNAUTHORIZED,
            "mutation {mutation}"
        );
    }
    let owner = Identity::from_verified_key(PEER).unwrap();
    let listed = app
        .handle(
            "/listMessages",
            Some(&owner),
            &serde_json::json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(listed.body["messages"], serde_json::json!([]));
    assert_eq!(
        adapter.handle(vector_request(vector, true)).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn json_syntax_then_auth_then_business_validation_and_explicit_boundaries() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let adapter = HttpAuthAdapter::new(&app, &wallet, &Store);
    for body in [
        "{]",
        "{",
        "[1,]",
        "null",
        "1",
        "true",
        "\"x\"",
        "   ",
        r#"{"v":"\x"}"#,
    ] {
        for auth in [false, true] {
            let result = adapter.handle(request("/listMessages", body, auth)).await;
            assert_eq!(result.status(), StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(
                serde_json::from_slice::<Value>(result.body()).unwrap()["code"],
                "ERR_INVALID_BODY"
            );
        }
    }
    for body in [
        r#"{"messageBox":"inbox","v":-0}"#,
        r#"{"v":-0.0}"#,
        r#"{"v":-1e-999}"#,
    ] {
        assert_eq!(
            adapter
                .handle(request("/listMessages", body, false))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let result = adapter.handle(request("/listMessages", body, true)).await;
        assert_eq!(result.status(), StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            serde_json::from_slice::<Value>(result.body()).unwrap()["code"],
            "ERR_INVALID_AUTH"
        );
    }
    // Valid JS strings outside Rust's Unicode-scalar domain remain explicitly
    // unsupported. No alternate JSON representation has been introduced.
    for body in [r#"{"v":"\ud800"}"#, r#"{"v":1e400}"#] {
        assert_eq!(
            adapter
                .handle(request("/listMessages", body, false))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            adapter
                .handle(request("/listMessages", body, true))
                .await
                .status(),
            StatusCode::NOT_IMPLEMENTED
        );
    }
}

#[tokio::test]
async fn semantic_json_equivalence_uses_the_same_frame_and_consumed_fee() {
    use message_box_server_rust::auth_frame::{PreparedRequestFrame, encode_request_frame};
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let canonical = br#"{"messageBox":"inbox","recipientFee":1}"#;
    let expected = encode_request_frame(&PreparedRequestFrame {
        request_id: [3; 32],
        method: "POST",
        path: Some("/permissions/set"),
        query: None,
        headers: &[("content-type", "application/json")],
        body: Some(canonical),
    })
    .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(expected),
    };
    let adapter = HttpAuthAdapter::new(&app, &wallet, &Store);
    for body in [
        r#"{ "messageBox" : "inbox", "recipientFee": 1.0 }"#,
        r#"{"messageBox":"\u0069nbox","recipientFee":99,"recipientFee":1e0}"#,
        "\u{feff}{\"messageBox\":\"inbox\",\"recipientFee\":1}",
    ] {
        assert_eq!(
            adapter
                .handle(request("/permissions/set", body, true))
                .await
                .status(),
            StatusCode::OK,
            "{body}"
        );
    }
    let owner = Identity::from_verified_key(PEER).unwrap();
    let result = app
        .handle(
            "/permissions/get",
            Some(&owner),
            &serde_json::json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(result.body["permission"]["recipientFee"], 1);
}
