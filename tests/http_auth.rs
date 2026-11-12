use http::{Request, StatusCode};
use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
    auth_nonce::{HmacCheckError, NonceHmacRequest, NonceWallet},
    auth_responder::{AuthSession, AuthSessionStore, AuthWallet},
    http_auth::HttpAuthAdapter,
};
use serde_json::json;
use std::sync::Arc;
struct Wallet;
impl NonceWallet for Wallet {
    type Error = ();
    async fn create_hmac(&self, _: &NonceHmacRequest) -> Result<[u8; 32], ()> {
        panic!("unexpected wallet call")
    }
    async fn verify_hmac(
        &self,
        _: &NonceHmacRequest,
        _: &[u8; 32],
    ) -> Result<bool, HmacCheckError<()>> {
        panic!("unexpected wallet call")
    }
}
impl AuthWallet for Wallet {
    async fn identity_key(&self) -> Result<String, ()> {
        panic!("unexpected wallet call")
    }
    async fn sign_auth(&self, _: &str, _: &str, _: &[u8]) -> Result<Vec<u8>, ()> {
        panic!("unexpected wallet call")
    }
    async fn verify_auth(&self, _: &str, _: &str, _: &[u8], _: &[u8]) -> Result<bool, ()> {
        panic!("unexpected wallet call")
    }
}
struct Store;
impl AuthSessionStore for Store {
    type Error = ();
    async fn claim_initial(&self, _: &str, _: &str) -> Result<bool, ()> {
        panic!("unexpected store call")
    }
    async fn add_session(&self, _: AuthSession) -> Result<(), ()> {
        panic!("unexpected store call")
    }
    async fn get_session(&self, _: &str) -> Result<Option<AuthSession>, ()> {
        panic!("unexpected store call")
    }
    async fn claim_message(&self, _: &str, _: &str) -> Result<bool, ()> {
        panic!("unexpected store call")
    }
    async fn mark_authenticated(&self, _: &str) -> Result<(), ()> {
        panic!("unexpected store call")
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
#[tokio::test]
async fn rejects_unauthenticated_and_out_of_scope_requests_without_dispatch() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (method, path, body, expected) in [
        ("GET", "/devices", vec![], StatusCode::UNAUTHORIZED),
        ("GET", "/devices?limit=1", vec![], StatusCode::UNAUTHORIZED),
        ("POST", "/sendMessage", vec![], StatusCode::UNAUTHORIZED),
        ("GET", "/devices", vec![1], StatusCode::UNAUTHORIZED),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1:1234")
            .body(body)
            .unwrap();
        assert_eq!(adapter.handle(req).await.status(), expected);
    }
}
#[tokio::test]
async fn rejects_invalid_handshake_and_duplicate_headers() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let bad = Request::builder()
        .method("POST")
        .uri("/.well-known/auth")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(b"{".to_vec())
        .unwrap();
    assert_eq!(adapter.handle(bad).await.status(), StatusCode::BAD_REQUEST);
    let duplicate_handshake = Request::builder()
        .method("POST")
        .uri("/.well-known/auth")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("x-bsv-extra", "one")
        .header("x-bsv-extra", "two")
        .body(b"{}".to_vec())
        .unwrap();
    let response = adapter.handle(duplicate_handshake).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(response.body()).unwrap()["code"],
        "ERR_INVALID_AUTH"
    );
    let duplicate = Request::builder()
        .method("GET")
        .uri("/devices")
        .header("host", "localhost")
        .header("x-bsv-auth-version", "0.1")
        .header("x-bsv-auth-version", "0.1")
        .body(vec![])
        .unwrap();
    assert_eq!(
        adapter.handle(duplicate).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn handles_partial_auth_custom_signed_headers_and_oversized_body() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let partial = Request::builder()
        .method("GET")
        .uri("/devices")
        .header("host", "localhost")
        .header("x-bsv-auth-version", "0.1")
        .body(vec![])
        .unwrap();
    assert_eq!(
        adapter.handle(partial).await.status(),
        StatusCode::BAD_REQUEST
    );
    let custom = Request::builder()
        .method("GET")
        .uri("/devices")
        .header("host", "localhost")
        .header("x-bsv-extra", "value")
        .body(vec![])
        .unwrap();
    assert_eq!(
        adapter.handle(custom).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let big = Request::builder()
        .method("POST")
        .uri("/.well-known/auth")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(vec![0; 4 * 1024 * 1024 + 1])
        .unwrap();
    assert_eq!(
        adapter.handle(big).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let no_host = Request::builder()
        .method("GET")
        .uri("/devices")
        .body(vec![])
        .unwrap();
    assert_eq!(
        adapter.handle(no_host).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn rejects_oversized_or_malformed_signature_before_wallet_work() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let request_id = STANDARD.encode([1u8; 32]);
    for signature in ["aa".repeat(1025), "a".to_owned(), "".to_owned()] {
        let req = Request::builder()
            .method("GET")
            .uri("/devices")
            .header("host", "localhost")
            .header("x-bsv-auth-version", "0.1")
            .header("x-bsv-auth-identity-key", "key")
            .header("x-bsv-auth-nonce", "nonce")
            .header("x-bsv-auth-your-nonce", "yournonce")
            .header("x-bsv-auth-request-id", &request_id)
            .header("x-bsv-auth-signature", signature)
            .body(vec![])
            .unwrap();
        assert_eq!(adapter.handle(req).await.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn rejects_absolute_form_request_target() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let req = Request::builder()
        .method("GET")
        .uri("http://other.example/devices")
        .header("host", "localhost")
        .body(vec![])
        .unwrap();
    assert_eq!(adapter.handle(req).await.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_invalid_host_authority() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for host in [":abc", "localhost:99999", "localhost:abc"] {
        let req = Request::builder()
            .method("GET")
            .uri("/devices")
            .header("host", host)
            .body(vec![])
            .unwrap();
        assert_eq!(
            adapter.handle(req).await.status(),
            StatusCode::BAD_REQUEST,
            "{host}"
        );
    }
    for host in ["localhost:80", "[::1]:123"] {
        let req = Request::builder()
            .method("GET")
            .uri("/devices")
            .header("host", host)
            .body(vec![])
            .unwrap();
        assert_eq!(
            adapter.handle(req).await.status(),
            StatusCode::UNAUTHORIZED,
            "{host}"
        );
    }
}

#[tokio::test]
async fn list_messages_parses_ordinary_json_before_authentication() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (body, expected) in [
        (r#"{"messageBox":"inbox"}"#, StatusCode::UNAUTHORIZED),
        (
            r#"{"messageBox":"inbox","clientTag":"demo"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"clientTag":"猫","messageBox":"inbox"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","00":"demo"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","clientTag":null}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","clientTag":true}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","clientTag":false}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","clientTag":1}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","clientTag":{"x":"y"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","1":"demo"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","4294967294":"demo"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","4294967295":"demo"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":0}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":100001}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":100000}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":-1}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":1.0}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":"1"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"offset":0,"messageBox":"inbox"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (r#"{ "messageBox":"inbox"}"#, StatusCode::UNAUTHORIZED),
        (
            r#"{"messageBox":"inbox","messageBox":"inbox"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"0":"ignored","messageBox":"inbox"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":-0}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","limit":1}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":0,"limit":1000}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":0,"limit":0}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":0,"limit":1001}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":0,"limit":1.0}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","limit":1,"offset":0}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","limit":2,"skip":2}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","limit":null,"offset":null}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","limit":null,"skip":2}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","limit":9007199254740991}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","limit":9007199254740992}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","skip":null}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":2,"skip":2}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":2,"skip":3}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","skip":-1}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":0,"messageId":"id-1"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","offset":0,"limit":1,"messageId":"消息📨"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","messageId":1}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"messageBox":"inbox","messageId":"id-1","offset":0}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (r#"{"messageBox":"猫📨"}"#, StatusCode::UNAUTHORIZED),
        (r#"{"messageBox":"\u732b"}"#, StatusCode::UNAUTHORIZED),
        (r#"{"messageBox":"\ud800"}"#, StatusCode::UNAUTHORIZED),
    ] {
        let req = Request::builder()
            .method("POST")
            .uri("/listMessages")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(body.as_bytes().to_vec())
            .unwrap();
        assert_eq!(adapter.handle(req).await.status(), expected, "{body}");
    }
}

#[tokio::test]
async fn send_and_ack_shapes_reach_authentication() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (path, body, expected) in [
        (
            "/sendMessage",
            r#"{"message":{"recipient":"abc","messageBox":"inbox","messageId":"id-1","body":"hello"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"recipients":["abc","def"],"messageBox":"inbox","messageId":["id-1","id-2"],"body":"hello"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"recipient":["abc","def"],"messageBox":"inbox","messageId":["id-1","id-2"],"body":"hello"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"recipient":["abc"],"messageBox":"inbox","messageId":"id-1","body":"hello"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"recipients":"abc","messageBox":"inbox","messageId":["id-1"],"body":"hello"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"recipient":"abc","recipients":"def","messageBox":"inbox","messageId":"id-1","body":"hello"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"recipient":["abc",1],"messageBox":"inbox","messageId":["id-1","id-2"],"body":"hello"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"recipients":["abc",1],"messageBox":"inbox","messageId":["id-1","id-2"],"body":"hello"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"recipients":["abc","def"],"messageBox":"inbox","messageId":["id-1",2],"body":"hello"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"body":"hello","messageBox":"inbox","messageId":"id-1","recipient":"abc"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"recipient":"abc","messageBox":"通知📨","messageId":"消息-1","body":"你好📨"}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"recipient":"abc","messageBox":"inbox","messageId":"id-1","body":{}}}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/sendMessage",
            r#"{"message":{"recipient":"abc","messageBox":"inbox","messageId":"id-1","body":"hello"},"payment":null}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/acknowledgeMessage",
            r#"{"messageIds":["id-1","id-2"]}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/acknowledgeMessage",
            r#"{"messageIds":["消息-📨"]}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/acknowledgeMessage",
            r#"{"messageIds":[1]}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/acknowledgeMessage",
            r#"{"messageIds":["id-1"],"extra":true}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/acknowledgeMessage",
            r#"{ "messageIds":["id-1"]}"#,
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(body.as_bytes().to_vec())
            .unwrap();
        assert_eq!(
            adapter.handle(req).await.status(),
            expected,
            "{path} {body}"
        );
    }
}

#[tokio::test]
async fn batch_wire_shape_reaches_auth_independent_of_resource_limit() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (field, count, expected) in [
        ("recipient", 0, StatusCode::UNAUTHORIZED),
        ("recipient", 100, StatusCode::UNAUTHORIZED),
        ("recipient", 101, StatusCode::UNAUTHORIZED),
        ("recipients", 0, StatusCode::UNAUTHORIZED),
        ("recipients", 100, StatusCode::UNAUTHORIZED),
        ("recipients", 101, StatusCode::UNAUTHORIZED),
    ] {
        let recipients = serde_json::to_string(&vec!["recipient"; count]).unwrap();
        let ids = serde_json::to_string(&vec!["id"; count]).unwrap();
        let body = format!(
            r#"{{"message":{{"{field}":{recipients},"messageBox":"inbox","messageId":{ids},"body":"hello"}}}}"#
        );
        let req = Request::builder()
            .method("POST")
            .uri("/sendMessage")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(body.into_bytes())
            .unwrap();
        assert_eq!(
            adapter.handle(req).await.status(),
            expected,
            "field={field}, count={count}"
        );
    }
}

#[tokio::test]
async fn quote_accepts_simple_query_shapes() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (path, expected) in [
        (
            "/permissions/quote?recipient=abc&messageBox=inbox",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/permissions/quote?recipient=abc&messageBox=%E9%80%9A%E7%9F%A5%F0%9F%93%A8",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/permissions/quote?recipient=abc&messageBox=a+b%2Bc%2F%E4%B8%AD",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/permissions/quote?recipient=abc&messageBox=a%20b",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/permissions/quote?messageBox=inbox&recipient=abc",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/permissions/quote?recipient=abc&messageBox=inbox&extra=x",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/permissions/quote?recipient=abc&recipient=abc&messageBox=inbox",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/permissions/quote?recipient=abc&messageBox=inbox&recipient=def",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/permissions/quote?recipient=abc&messageBox=%69nbox",
            StatusCode::UNAUTHORIZED,
        ),
        ("/permissions/quote?recipient=abc", StatusCode::UNAUTHORIZED),
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(vec![])
            .unwrap();
        assert_eq!(adapter.handle(req).await.status(), expected, "{path}");
    }
    for (count, expected) in [
        (100, StatusCode::UNAUTHORIZED),
        (101, StatusCode::UNAUTHORIZED),
    ] {
        let query = format!(
            "{}&messageBox=inbox",
            vec!["recipient=abc"; count].join("&")
        );
        let req = Request::builder()
            .method("GET")
            .uri(format!("/permissions/quote?{query}"))
            .header("host", "localhost")
            .body(vec![])
            .unwrap();
        assert_eq!(adapter.handle(req).await.status(), expected);
    }
}

#[tokio::test]
async fn device_registration_accepts_only_client_wire_shape() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (body, expected) in [
        (r#"{"fcmToken":"fake-token"}"#, StatusCode::UNAUTHORIZED),
        (
            r#"{"fcmToken":"fake-token","deviceId":"桌面📱","platform":"ios"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"fcmToken":"fake-token","platform":"web"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"deviceId":"x","fcmToken":"fake-token"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"fcmToken":"fake-token","platform":null}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"fcmToken":"fake-token","extra":"x"}"#,
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let req = Request::builder()
            .method("POST")
            .uri("/registerDevice")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(body.as_bytes().to_vec())
            .unwrap();
        assert_eq!(adapter.handle(req).await.status(), expected, "{body}");
    }
}

#[tokio::test]
async fn device_list_query_shapes_reach_authentication() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (path, expected) in [
        ("/devices?limit=1&offset=0", StatusCode::UNAUTHORIZED),
        ("/devices?offset=1", StatusCode::UNAUTHORIZED),
        ("/devices?limit=100&offset=100000", StatusCode::UNAUTHORIZED),
        ("/devices?limit=0", StatusCode::UNAUTHORIZED),
        ("/devices?limit=101", StatusCode::UNAUTHORIZED),
        ("/devices?offset=100001", StatusCode::UNAUTHORIZED),
        ("/devices?offset=1&limit=1", StatusCode::UNAUTHORIZED),
        ("/devices?limit=1&limit=1", StatusCode::UNAUTHORIZED),
        ("/devices?limit=01", StatusCode::UNAUTHORIZED),
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(vec![])
            .unwrap();
        assert_eq!(adapter.handle(req).await.status(), expected, "{path}");
    }
}

#[tokio::test]
async fn permission_set_and_get_shapes_reach_authentication() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (method, path, body, expected) in [
        (
            "POST",
            "/permissions/set",
            r#"{"messageBox":"inbox","recipientFee":0}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/permissions/set",
            r#"{"messageBox":"通知","recipientFee":-1,"sender":"abc"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/permissions/set",
            r#"{"recipientFee":0,"messageBox":"inbox"}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/permissions/set",
            r#"{"messageBox":"inbox","recipientFee":1.0}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/permissions/set",
            r#"{"messageBox":"inbox","recipientFee":2147483648}"#,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "/permissions/get?messageBox=inbox",
            "",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "/permissions/get?messageBox=inbox&sender=abc",
            "",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "/permissions/get?sender=abc&messageBox=inbox",
            "",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "/permissions/get?messageBox=inbox&recipient=abc",
            "",
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost");
        if method == "POST" {
            req = req.header("content-type", "application/json");
        }
        assert_eq!(
            adapter
                .handle(req.body(body.as_bytes().to_vec()).unwrap())
                .await
                .status(),
            expected,
            "{path} {body}"
        );
    }
}

#[tokio::test]
async fn permission_list_query_shapes_reach_authentication() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    for (path, expected) in [
        ("/permissions/list", StatusCode::UNAUTHORIZED),
        (
            "/permissions/list?messageBox=inbox&limit=1&offset=0",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/permissions/list?limit=100&offset=100000",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/permissions/list?messageBox=%E9%80%9A%E7%9F%A5",
            StatusCode::UNAUTHORIZED,
        ),
        ("/permissions/list?limit=0", StatusCode::UNAUTHORIZED),
        ("/permissions/list?limit=101", StatusCode::UNAUTHORIZED),
        ("/permissions/list?offset=100001", StatusCode::UNAUTHORIZED),
        (
            "/permissions/list?offset=0&limit=1",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/permissions/list?limit=1&limit=1",
            StatusCode::UNAUTHORIZED,
        ),
        ("/permissions/list?limit=01", StatusCode::UNAUTHORIZED),
        (
            "/permissions/list?createdAtOrder=asc",
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(vec![])
            .unwrap();
        assert_eq!(adapter.handle(req).await.status(), expected, "{path}");
    }
}

#[tokio::test]
async fn routing_prefix_matches_complete_segments_before_authentication() {
    use message_box_server_rust::http_auth::RoutingPrefix;
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let prefix = RoutingPrefix::parse("/mb").unwrap();
    let adapter = HttpAuthAdapter::new(&app, &Wallet, &Store).with_routing_prefix(&prefix);
    for (path, expected) in [
        ("/mb/devices", StatusCode::UNAUTHORIZED),
        ("/devices", StatusCode::NOT_IMPLEMENTED),
        ("/mbextra/devices", StatusCode::NOT_IMPLEMENTED),
        ("/mb", StatusCode::NOT_IMPLEMENTED),
    ] {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(vec![])
            .unwrap();
        assert_eq!(adapter.handle(request).await.status(), expected, "{path}");
    }
}

#[tokio::test]
async fn truncated_json_is_rejected_before_authentication_on_supported_posts() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let adapter = HttpAuthAdapter::new(&app, &Wallet, &Store);
    for path in [
        "/sendMessage",
        "/listMessages",
        "/acknowledgeMessage",
        "/registerDevice",
        "/permissions/set",
    ] {
        for body in [
            b"{".as_slice(),
            b"{\"messageBox\":".as_slice(),
            b"[1,".as_slice(),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header("host", "localhost")
                .header("content-type", "application/json")
                .body(body.to_vec())
                .unwrap();
            let response = adapter.handle(request).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
                json!({"status":"error","code":"ERR_INVALID_BODY","description":"The request body is invalid."})
            );
        }
    }
    let owner = Identity::from_verified_key(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap();
    let listed = app
        .handle(
            "/listMessages",
            Some(&owner),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(listed.body["messages"], json!([]));
}

#[tokio::test]
async fn valid_but_unrepresented_json_reaches_auth_while_malformed_is_400() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let adapter = HttpAuthAdapter::new(&app, &Wallet, &Store);
    for (body, expected) in [
        ("", StatusCode::UNAUTHORIZED),
        (r#"{"messageBox":"\ud800"}"#, StatusCode::UNAUTHORIZED),
        (
            r#"{"messageBox":"inbox","extra":1e400}"#,
            StatusCode::UNAUTHORIZED,
        ),
        ("{]", StatusCode::BAD_REQUEST),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/listMessages")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(body.as_bytes().to_vec())
            .unwrap();
        assert_eq!(adapter.handle(request).await.status(), expected, "{body}");
    }
}

#[tokio::test]
async fn initial_slashes_normalize_for_routes_without_altering_internal_slashes() {
    use message_box_server_rust::http_auth::RoutingPrefix;
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let prefix = RoutingPrefix::parse("/mb").unwrap();
    let adapter = HttpAuthAdapter::new(&app, &Wallet, &Store).with_routing_prefix(&prefix);
    for (path, expected) in [
        ("//mb/devices", StatusCode::UNAUTHORIZED),
        ("///mb/devices", StatusCode::UNAUTHORIZED),
        ("/mb//devices", StatusCode::NOT_IMPLEMENTED),
        ("//mbextra/devices", StatusCode::NOT_IMPLEMENTED),
    ] {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(vec![])
            .unwrap();
        assert_eq!(adapter.handle(request).await.status(), expected, "{path}");
    }
}
