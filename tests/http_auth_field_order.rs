//! In-process adapter regression with a fake wallet and session store. No SDK,
//! network listener, cryptographic verification, or TS server is used here.
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
// Generated offline by the pinned Git SDK Writer and middleware helpers.
fn expected_frame(path: &str, body: &str) -> Vec<u8> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/field-order-sdk4.json")).unwrap();
    let vector = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["path"] == path && v["body"] == body)
        .unwrap();
    hex::decode(vector["frameHex"].as_str().unwrap()).unwrap()
}
#[tokio::test]
async fn business_shapes_are_checked_after_fake_auth_and_bound_to_frame() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (path, body, code) in [
        ("/listMessages", r#"{}"#, "ERR_MESSAGEBOX_REQUIRED"),
        (
            "/listMessages",
            r#"{"messageBox":1}"#,
            "ERR_INVALID_MESSAGEBOX",
        ),
        (
            "/sendMessage",
            r#"{"message":null}"#,
            "ERR_MESSAGE_REQUIRED",
        ),
        (
            "/acknowledgeMessage",
            r#"{"messageIds":[1]}"#,
            "ERR_INVALID_MESSAGE_ID",
        ),
        (
            "/registerDevice",
            r#"{"fcmToken":false}"#,
            "ERR_INVALID_FCM_TOKEN",
        ),
        (
            "/permissions/set",
            r#"{"messageBox":"inbox","recipientFee":"free"}"#,
            "ERR_INVALID_REQUEST",
        ),
    ] {
        let unsigned = adapter.handle(request(path, body, false)).await;
        assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED, "{path} {body}");
        *wallet.expected.lock().unwrap() = expected_frame(path, body);
        let response = adapter.handle(request(path, body, true)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path} {body}");
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
            code
        );
        // Same test proof, changed actual fields: auth must fail before business work.
        let changed = adapter
            .handle(request(path, r#"{"changed":true}"#, true))
            .await;
        assert_eq!(changed.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    let path = "/listMessages";
    let body = r#"{"messageBox":"inbox","extra":{"values":[true,null,2,"猫"]}}"#;
    *wallet.expected.lock().unwrap() = expected_frame(path, body);
    let response = adapter.handle(request(path, body, true)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ordinary_previously_restricted_shapes_require_auth() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for body in [
        r#"{"a":{"name":"x","1":"y"}}"#,
        r#"{"value":1.0}"#,
        r#"{"value":9007199254740992}"#,
        r#"{"a":1,"a":2}"#,
        r#"{ "a":1}"#,
        r#"[1,2]"#,
    ] {
        assert_eq!(
            adapter
                .handle(request("/listMessages", body, false))
                .await
                .status(),
            StatusCode::UNAUTHORIZED,
            "{body}"
        );
    }
    let response = adapter.handle(request("/listMessages", "{", false)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
        "ERR_INVALID_BODY"
    );
}

// Fixed SDK Writer and middleware vectors bind the exact canonical body; the
// wallet/session are test doubles and do not perform a real SDK handshake.
#[tokio::test]
async fn canonical_decimal_fields_reach_auth_with_original_body_bound() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let path = "/listMessages";
    for (body, expected_status) in [
        (
            r#"{"messageBox":"inbox","metadata":{"progress":1.5,"ratio":0.25}}"#,
            StatusCode::OK,
        ),
        (
            r#"{"messageBox":"inbox","limit":1.5}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            r#"{"messageBox":"inbox","metadata":{"values":[1.5,0.1,0.01,-0.25,999999999.99]}}"#,
            StatusCode::OK,
        ),
    ] {
        assert_eq!(
            adapter.handle(request(path, body, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned {body}"
        );
        *wallet.expected.lock().unwrap() = expected_frame(path, body);
        let response = adapter.handle(request(path, body, true)).await;
        assert_eq!(response.status(), expected_status, "authenticated {body}");
        if expected_status == StatusCode::BAD_REQUEST {
            assert_eq!(
                serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
                "ERR_INVALID_LIMIT"
            );
        }
        let changed = body.replace("1.5", "1.6");
        assert_eq!(
            adapter.handle(request(path, &changed, true)).await.status(),
            StatusCode::UNAUTHORIZED,
            "modified signed body {changed}"
        );
    }
    for body in [
        r#"{"value":1.0}"#,
        r#"{"value":-0.0}"#,
        r#"{"value":0.0000001}"#,
        r#"{"value":1000000000.5}"#,
        r#"{"value":1.50}"#,
    ] {
        assert_eq!(
            adapter.handle(request(path, body, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "authentication required: {body}"
        );
    }
}

// Fixed SDK/middleware-generated frames; the wallet/session are test doubles.
#[tokio::test]
async fn bounded_decimal_precision_reaches_auth_with_original_body_bound() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let path = "/listMessages";
    for (body, expected_status) in [
        (
            r#"{"messageBox":"inbox","metadata":{"values":[0.125,0.001,0.03125,-0.0625,1.000001,123.456789,999999999.125,999999999.000001,-999999999.000001]}}"#,
            StatusCode::OK,
        ),
        (
            r#"{"messageBox":"inbox","limit":0.125}"#,
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            adapter.handle(request(path, body, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned {body}"
        );
        *wallet.expected.lock().unwrap() = expected_frame(path, body);
        let response = adapter.handle(request(path, body, true)).await;
        assert_eq!(response.status(), expected_status, "authenticated {body}");
        if expected_status == StatusCode::BAD_REQUEST {
            assert_eq!(
                serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
                "ERR_INVALID_LIMIT"
            );
        }
        let changed = body.replace("0.125", "0.126");
        assert_eq!(
            adapter.handle(request(path, &changed, true)).await.status(),
            StatusCode::UNAUTHORIZED,
            "modified signed body {changed}"
        );
    }
    for body in [
        r#"{"value":1000000000.125}"#,
        r#"{"value":-0.0}"#,
        r#"{"value":1.25e0}"#,
    ] {
        assert_eq!(
            adapter.handle(request(path, body, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "authentication required: {body}"
        );
    }
}

// Pinned SDK/middleware vectors; fake authentication only, no network.
#[tokio::test]
async fn millionth_decimals_reach_auth_and_bind_the_canonical_body() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let path = "/listMessages";
    for (body, status) in [
        (
            r#"{"messageBox":"inbox","metadata":{"note":"literal 1e-6 \"quoted\"","values":[0.000001,0.000002,0.000003,0.000004,0.000005,0.000006,0.000007,0.000008,0.000009,-0.000001,-0.000002,-0.000003,-0.000004,-0.000005,-0.000006,-0.000007,-0.000008,-0.000009]}}"#,
            StatusCode::OK,
        ),
        (
            r#"{"messageBox":"inbox","limit":0.000001}"#,
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            adapter.handle(request(path, body, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned {body}"
        );
        *wallet.expected.lock().unwrap() = expected_frame(path, body);
        let response = adapter.handle(request(path, body, true)).await;
        assert_eq!(response.status(), status, "authenticated {body}");
        if status == StatusCode::BAD_REQUEST {
            assert_eq!(
                serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
                "ERR_INVALID_LIMIT"
            );
        }
        let changed = body.replacen("0.000001", "0.000002", 1);
        assert_eq!(
            adapter.handle(request(path, &changed, true)).await.status(),
            StatusCode::UNAUTHORIZED,
            "modified signed body {changed}"
        );
    }
    for body in [
        r#"{"value":1e-6}"#,
        r#"{"value":0.0000010}"#,
        r#"{"value":0.0000009}"#,
        r#"{"value":-0.0}"#,
    ] {
        assert_eq!(
            adapter.handle(request(path, body, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "authentication required: {body}"
        );
    }
}

#[tokio::test]
async fn all_pinned_post_frames_still_reach_business_processing() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/field-order-sdk4.json")).unwrap();
    let mut checked = 0;
    for vector in fixture["vectors"].as_array().unwrap() {
        let body = vector["body"].as_str().unwrap();
        if body.is_empty() {
            continue;
        }
        let path = vector["path"].as_str().unwrap();
        *wallet.expected.lock().unwrap() =
            hex::decode(vector["frameHex"].as_str().unwrap()).unwrap();
        let status = adapter.handle(request(path, body, true)).await.status();
        assert_ne!(status, StatusCode::NOT_IMPLEMENTED, "{path} {body}");
        assert_ne!(status, StatusCode::UNAUTHORIZED, "{path} {body}");
        checked += 1;
    }
    assert_eq!(checked, 26);
}

// Fixed SDK/middleware frames; fake wallet/session, not a real handshake.
#[tokio::test]
async fn ordinary_fractional_numbers_reach_auth_and_preserve_signed_body() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let path = "/listMessages";
    for (body, status) in [
        (
            r#"{"messageBox":"inbox","limit":3.141592653589793}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            r#"{"messageBox":"inbox","metadata":{"values":[3.141592653589793,0.12345678901234566,1.0000001,0.00001,0.000001,1e-7,-1e-7,-0.125]}}"#,
            StatusCode::OK,
        ),
        (
            r#"{"messageBox":"inbox","metadata":{"negativeZero":0,"safeInteger":9007199254740991}}"#,
            StatusCode::OK,
        ),
    ] {
        assert_eq!(
            adapter.handle(request(path, body, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned {body}"
        );
        *wallet.expected.lock().unwrap() = expected_frame(path, body);
        let response = adapter.handle(request(path, body, true)).await;
        assert_eq!(response.status(), status, "authenticated {body}");
        if status == StatusCode::BAD_REQUEST {
            assert_eq!(
                serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
                "ERR_INVALID_LIMIT"
            );
        }
        let changed = if body.contains("3.141592653589793") {
            body.replacen("3.141592653589793", "3.1415926535897927", 1)
        } else {
            body.replacen("9007199254740991", "9007199254740990", 1)
        };
        assert_eq!(
            adapter.handle(request(path, &changed, true)).await.status(),
            StatusCode::UNAUTHORIZED,
            "modified signed body {changed}"
        );
    }
    for body in [
        r#"{"value":9007199254740992}"#,
        r#"{"value":1e+21}"#,
        r#"{"value":-0}"#,
    ] {
        assert_eq!(
            adapter.handle(request(path, body, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "authentication required: {body}"
        );
    }
}

#[tokio::test]
async fn fee_integer_and_fraction_are_authenticated_before_validation() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let path = "/permissions/set";
    for (body, status, changed) in [
        (
            r#"{"messageBox":"inbox","recipientFee":0}"#,
            StatusCode::OK,
            r#"{"messageBox":"inbox","recipientFee":1}"#,
        ),
        (
            r#"{"messageBox":"inbox","recipientFee":3.141592653589793}"#,
            StatusCode::BAD_REQUEST,
            r#"{"messageBox":"inbox","recipientFee":3.14}"#,
        ),
    ] {
        assert_eq!(
            adapter.handle(request(path, body, false)).await.status(),
            StatusCode::UNAUTHORIZED
        );
        *wallet.expected.lock().unwrap() = expected_frame(path, body);
        let response = adapter.handle(request(path, body, true)).await;
        assert_eq!(response.status(), status, "{body}");
        if status == StatusCode::BAD_REQUEST {
            assert_eq!(
                serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
                "ERR_INVALID_FEE_VALUE"
            );
        }
        assert_eq!(
            adapter.handle(request(path, changed, true)).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

fn get_request(target: &str, auth: bool) -> Request<Vec<u8>> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(target)
        .header("host", "localhost");
    if auth {
        builder = builder
            .header("x-bsv-auth-version", "0.1")
            .header("x-bsv-auth-identity-key", PEER)
            .header("x-bsv-auth-nonce", STANDARD.encode([1; 32]))
            .header("x-bsv-auth-your-nonce", STANDARD.encode([2; 48]))
            .header("x-bsv-auth-signature", "01")
            .header("x-bsv-auth-request-id", STANDARD.encode([3; 32]));
    }
    builder.body(Vec::new()).unwrap()
}

#[tokio::test]
async fn pagination_values_are_authenticated_before_validation() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (target, status) in [
        ("/devices?limit=bad", StatusCode::BAD_REQUEST),
        ("/permissions/list?limit=bad", StatusCode::BAD_REQUEST),
        ("/devices?limit=01", StatusCode::OK),
    ] {
        assert_eq!(
            adapter.handle(get_request(target, false)).await.status(),
            StatusCode::UNAUTHORIZED
        );
        *wallet.expected.lock().unwrap() = expected_frame(target, "");
        let response = adapter.handle(get_request(target, true)).await;
        assert_eq!(response.status(), status, "{target}");
        if status == StatusCode::BAD_REQUEST {
            assert_eq!(
                serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
                "ERR_INVALID_LIMIT"
            );
        }
        assert_eq!(
            adapter
                .handle(get_request("/devices?limit=2", true))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

// Fixed TS route reads query fields by name; the SDK helper signs the original
// search bytes. This uses fake authentication, not an SDK handshake or server.
#[tokio::test]
async fn device_pagination_reordering_keeps_authentication_and_query_binding() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (target, status, code) in [
        ("/devices?offset=0&limit=1", StatusCode::OK, None),
        (
            "/devices?offset=bad&limit=1",
            StatusCode::BAD_REQUEST,
            Some("ERR_INVALID_OFFSET"),
        ),
    ] {
        assert_eq!(
            adapter.handle(get_request(target, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "{target}"
        );
        *wallet.expected.lock().unwrap() = expected_frame(target, "");
        let response = adapter.handle(get_request(target, true)).await;
        assert_eq!(response.status(), status, "{target}");
        if let Some(code) = code {
            assert_eq!(
                serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
                code
            );
        }
        let reordered = target
            .replace("offset=0&limit=1", "limit=1&offset=0")
            .replace("offset=bad&limit=1", "limit=1&offset=bad");
        assert_eq!(
            adapter.handle(get_request(&reordered, true)).await.status(),
            StatusCode::UNAUTHORIZED,
            "query reorder after signing must fail"
        );
    }
    assert_eq!(
        adapter
            .handle(get_request("/devices?offset=0&limit=1&limit=2", false))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

// The fixed TS routes read named query fields, and the fixed SDK Writer binds
// the original URL search. These tests use fake auth, not a live TS service.
#[tokio::test]
async fn permission_list_sort_order_is_authenticated_before_validation() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (first, second, status, code) in [
        (
            "/permissions/list?createdAtOrder=asc&limit=1&offset=0&messageBox=inbox",
            "/permissions/list?messageBox=inbox&offset=0&limit=1&createdAtOrder=asc",
            StatusCode::OK,
            None,
        ),
        (
            "/permissions/list?createdAtOrder=bad&limit=1",
            "/permissions/list?limit=1&createdAtOrder=bad",
            StatusCode::BAD_REQUEST,
            Some("ERR_INVALID_SORT_ORDER"),
        ),
    ] {
        for (target, reordered) in [(first, second), (second, first)] {
            assert_eq!(
                adapter.handle(get_request(target, false)).await.status(),
                StatusCode::UNAUTHORIZED,
                "unsigned {target}"
            );
            *wallet.expected.lock().unwrap() = expected_frame(target, "");
            let response = adapter.handle(get_request(target, true)).await;
            assert_eq!(response.status(), status, "authenticated {target}");
            if let Some(code) = code {
                assert_eq!(
                    serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
                    code
                );
            }
            assert_eq!(
                adapter.handle(get_request(reordered, true)).await.status(),
                StatusCode::UNAUTHORIZED,
                "reordered after signing {target}"
            );
        }
    }
}

#[tokio::test]
async fn post_query_is_signed_and_business_fields_remain_from_body() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (target, body) in [
        ("/listMessages?trace=1", r#"{"messageBox":"inbox"}"#),
        ("/sendMessage?trace=1", r#"{"message":null}"#),
        ("/acknowledgeMessage?trace=1", r#"{"messageIds":[1]}"#),
        ("/registerDevice?trace=1", r#"{"fcmToken":false}"#),
        (
            "/permissions/set?trace=1",
            r#"{"messageBox":"inbox","recipientFee":"free"}"#,
        ),
    ] {
        assert_eq!(
            adapter.handle(request(target, body, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned {target}"
        );
        *wallet.expected.lock().unwrap() = expected_frame(target, body);
        let response = adapter.handle(request(target, body, true)).await;
        assert_ne!(response.status(), StatusCode::NOT_IMPLEMENTED, "{target}");
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED, "{target}");
        assert_eq!(
            adapter
                .handle(request(&target.replace("trace=1", "trace=2"), body, true))
                .await
                .status(),
            StatusCode::UNAUTHORIZED,
            "modified query {target}"
        );
    }
}

#[tokio::test]
async fn content_type_is_included_and_case_preserved_in_all_application_frames() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/header-frames-sdk4.json")).unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 9);
    for vector in vectors {
        let method = vector["method"].as_str().unwrap();
        let target = vector["path"].as_str().unwrap();
        let body = vector["body"].as_str().unwrap();
        let content_type = vector["contentType"].as_str().unwrap();
        let make = |auth| {
            let mut req = if method == "GET" {
                get_request(target, auth)
            } else {
                request(target, body, auth)
            };
            req.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_str(content_type).unwrap(),
            );
            req
        };
        assert_eq!(
            adapter.handle(make(false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned {method} {target}"
        );
        *wallet.expected.lock().unwrap() =
            hex::decode(vector["frameHex"].as_str().unwrap()).unwrap();
        let response = adapter.handle(make(true)).await;
        assert_ne!(
            response.status(),
            StatusCode::NOT_IMPLEMENTED,
            "{method} {target}"
        );
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {target}"
        );
        let mut changed = make(true);
        changed.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        assert_eq!(
            adapter.handle(changed).await.status(),
            StatusCode::UNAUTHORIZED,
            "changed signed media type {method} {target}"
        );
    }
}

#[tokio::test]
async fn empty_query_delimiter_uses_fixed_url_signing_semantics() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (target, status) in [
        ("/devices?", StatusCode::OK),
        ("/permissions/list?", StatusCode::OK),
        ("/permissions/get?", StatusCode::BAD_REQUEST),
        ("/permissions/quote?", StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(
            adapter.handle(get_request(target, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned {target}"
        );
        *wallet.expected.lock().unwrap() = expected_frame(target, "");
        assert_eq!(
            adapter.handle(get_request(target, true)).await.status(),
            status,
            "authenticated {target}"
        );
    }
    let target = "/listMessages?";
    let body = r#"{"messageBox":"inbox"}"#;
    assert_eq!(
        adapter.handle(request(target, body, false)).await.status(),
        StatusCode::UNAUTHORIZED
    );
    *wallet.expected.lock().unwrap() = expected_frame(target, body);
    assert_eq!(
        adapter.handle(request(target, body, true)).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn quote_query_order_is_bound_before_business_validation() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (first, second, status, code) in [
        (
            format!("/permissions/quote?recipient={PEER}&messageBox=inbox"),
            format!("/permissions/quote?messageBox=inbox&recipient={PEER}"),
            StatusCode::OK,
            None,
        ),
        (
            "/permissions/quote?recipient=bad&messageBox=inbox".to_owned(),
            "/permissions/quote?messageBox=inbox&recipient=bad".to_owned(),
            StatusCode::BAD_REQUEST,
            Some("ERR_INVALID_PUBLIC_KEY"),
        ),
    ] {
        let mut observed = Vec::new();
        for (target, reordered) in [(&second, &first), (&first, &second)] {
            assert_eq!(
                adapter.handle(get_request(target, false)).await.status(),
                StatusCode::UNAUTHORIZED,
                "unsigned {target}"
            );
            *wallet.expected.lock().unwrap() = expected_frame(target, "");
            let response = adapter.handle(get_request(target, true)).await;
            assert_eq!(response.status(), status, "authenticated {target}");
            let body: Value = serde_json::from_slice(response.body()).unwrap();
            if let Some(code) = code {
                assert_eq!(body["code"], code);
            }
            observed.push(body);
            assert_eq!(
                adapter.handle(get_request(reordered, true)).await.status(),
                StatusCode::UNAUTHORIZED,
                "reordered after signing {target}"
            );
        }
        assert_eq!(observed[0], observed[1]);
    }
    let target = "/permissions/quote?recipient=bad&messageBox=inbox&recipient=alsoBad";
    *wallet.expected.lock().unwrap() = expected_frame(target, "");
    let response = adapter.handle(get_request(target, true)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
        "ERR_INVALID_PUBLIC_KEY"
    );
}

#[tokio::test]
async fn quote_missing_and_excess_fields_are_checked_after_authentication() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let excess = format!(
        "/permissions/quote?{}&messageBox=inbox",
        vec!["recipient=bad"; 101].join("&")
    );
    for (target, code) in [
        ("/permissions/quote", "ERR_MISSING_PARAMETERS"),
        ("/permissions/quote?recipient=bad", "ERR_MISSING_PARAMETERS"),
        (
            "/permissions/quote?messageBox=inbox",
            "ERR_MISSING_PARAMETERS",
        ),
        (excess.as_str(), "ERR_TOO_MANY_RECIPIENTS"),
    ] {
        assert_eq!(
            adapter.handle(get_request(target, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned {target}"
        );
        *wallet.expected.lock().unwrap() = expected_frame(target, "");
        let response = adapter.handle(get_request(target, true)).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "authenticated {target}"
        );
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
            code
        );
    }
}

#[tokio::test]
async fn permission_get_missing_message_box_is_checked_after_authentication() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for target in ["/permissions/get", "/permissions/get?sender=bad"] {
        assert_eq!(
            adapter.handle(get_request(target, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned {target}"
        );
        *wallet.expected.lock().unwrap() = expected_frame(target, "");
        let response = adapter.handle(get_request(target, true)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap()["code"],
            "ERR_INVALID_MESSAGE_BOX"
        );
    }
}

#[tokio::test]
async fn permission_query_order_get_is_bound_before_business_validation() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let cases = [
        (
            format!("/permissions/get?messageBox=inbox&sender={PEER}"),
            format!("/permissions/get?sender={PEER}&messageBox=inbox"),
            StatusCode::OK,
            None,
        ),
        (
            "/permissions/get?messageBox=inbox&sender=bad".to_owned(),
            "/permissions/get?sender=bad&messageBox=inbox".to_owned(),
            StatusCode::BAD_REQUEST,
            Some("ERR_INVALID_PUBLIC_KEY"),
        ),
    ];
    for (first, second, status, code) in cases {
        let mut observed = Vec::new();
        for (target, reordered) in [(&second, &first), (&first, &second)] {
            assert_eq!(
                adapter.handle(get_request(target, false)).await.status(),
                StatusCode::UNAUTHORIZED,
                "unsigned {target}"
            );
            *wallet.expected.lock().unwrap() = expected_frame(target, "");
            let response = adapter.handle(get_request(target, true)).await;
            assert_eq!(response.status(), status, "authenticated {target}");
            let body: Value = serde_json::from_slice(response.body()).unwrap();
            if let Some(code) = code {
                assert_eq!(body["code"], code);
            }
            observed.push(body);
            assert_eq!(
                adapter.handle(get_request(reordered, true)).await.status(),
                StatusCode::UNAUTHORIZED,
                "reorder after signing {target}"
            );
        }
        assert_eq!(observed[0], observed[1]);
    }
    for target in [
        "/permissions/get?sender=bad&sender=bad",
        "/permissions/get?messageBox=inbox&messageBox=inbox",
        "/permissions/get?sender=bad&messageBox=inbox&extra=x",
        "/permissions/get?sender=bad&messageBox=%69nbox",
    ] {
        assert_eq!(
            adapter.handle(get_request(target, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "authentication required {target}"
        );
    }
}

#[tokio::test]
async fn permission_query_order_list_is_bound_before_business_validation() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (first, second, status, code) in [
        (
            "/permissions/list?messageBox=inbox&limit=1&offset=0",
            "/permissions/list?offset=0&limit=1&messageBox=inbox",
            StatusCode::OK,
            None,
        ),
        (
            "/permissions/list?messageBox=inbox&limit=1&offset=bad",
            "/permissions/list?offset=bad&limit=1&messageBox=inbox",
            StatusCode::BAD_REQUEST,
            Some("ERR_INVALID_OFFSET"),
        ),
    ] {
        let mut observed = Vec::new();
        for (target, reordered) in [(second, first), (first, second)] {
            assert_eq!(
                adapter.handle(get_request(target, false)).await.status(),
                StatusCode::UNAUTHORIZED,
                "unsigned {target}"
            );
            *wallet.expected.lock().unwrap() = expected_frame(target, "");
            let response = adapter.handle(get_request(target, true)).await;
            assert_eq!(response.status(), status, "authenticated {target}");
            let body: Value = serde_json::from_slice(response.body()).unwrap();
            if let Some(code) = code {
                assert_eq!(body["code"], code);
            }
            observed.push(body);
            assert_eq!(
                adapter.handle(get_request(reordered, true)).await.status(),
                StatusCode::UNAUTHORIZED,
                "reorder after signing {target}"
            );
        }
        assert_eq!(observed[0], observed[1]);
    }
    // Exercise the other four permutations of the supported three fields.
    for target in [
        "/permissions/list?messageBox=inbox&offset=0&limit=1",
        "/permissions/list?limit=1&messageBox=inbox&offset=0",
        "/permissions/list?limit=1&offset=0&messageBox=inbox",
        "/permissions/list?offset=0&messageBox=inbox&limit=1",
    ] {
        assert_eq!(
            adapter.handle(get_request(target, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "unsigned {target}"
        );
        *wallet.expected.lock().unwrap() = expected_frame(target, "");
        assert_eq!(
            adapter.handle(get_request(target, true)).await.status(),
            StatusCode::OK,
            "authenticated {target}"
        );
        assert_eq!(
            adapter
                .handle(get_request(
                    "/permissions/list?messageBox=inbox&limit=1&offset=0",
                    true
                ))
                .await
                .status(),
            StatusCode::UNAUTHORIZED,
            "reordered after signing {target}"
        );
    }
    for target in [
        "/permissions/list?limit=1&limit=2",
        "/permissions/list?messageBox=%69nbox",
    ] {
        assert_eq!(
            adapter.handle(get_request(target, false)).await.status(),
            StatusCode::UNAUTHORIZED,
            "authentication required {target}"
        );
    }
}

// Real fixed-source SDK Writer/middleware frame, with fake wallet/session only.
#[tokio::test]
async fn canonical_index_keys_bind_exact_body_before_business() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet {
        expected: Mutex::new(Vec::new()),
    };
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let body = r#"{"messageBox":"inbox","metadata":{"0":"first","1":"second","name":"labels"}}"#;
    assert_eq!(
        adapter
            .handle(request("/listMessages", body, false))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    *wallet.expected.lock().unwrap() = expected_frame("/listMessages", body);
    assert_eq!(
        adapter
            .handle(request("/listMessages", body, true))
            .await
            .status(),
        StatusCode::OK
    );
    let changed = body.replace("first", "other");
    assert_eq!(
        adapter
            .handle(request("/listMessages", &changed, true))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // The last JS array index and the first non-index string remain distinct.
    let boundary = r#"{"messageBox":"inbox","metadata":{"0":"zero","4294967294":"last","4294967295":"ordinary"}}"#;
    assert_eq!(
        adapter
            .handle(request("/listMessages", boundary, false))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for unsupported in [
        r#"{"messageBox":"inbox","metadata":{"4294967295":"ordinary","4294967294":"last"}}"#,
        r#"{"messageBox":"inbox","metadata":{"1":"second","0":"first"}}"#,
        r#"{"messageBox":"inbox","metadata":{"name":"labels","0":"first"}}"#,
        r#"{"messageBox":"inbox","metadata":{"0":"first","0":"other"}}"#,
        r#"{ "messageBox":"inbox","metadata":{"0":"first"}}"#,
    ] {
        assert_eq!(
            adapter
                .handle(request("/listMessages", unsupported, false))
                .await
                .status(),
            StatusCode::UNAUTHORIZED,
            "{unsupported}"
        );
    }
}
