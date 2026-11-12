use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::Full;
use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
    auth_nonce::{HmacCheckError, NonceHmacRequest, NonceWallet},
    auth_responder::{AuthSession, AuthSessionStore, AuthWallet},
    http_auth::HttpAuthAdapter,
    http_stream::handle_http_stream,
};
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
struct Policy;
impl DeliveryPolicy for Policy {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
#[tokio::test]
async fn streams_are_bounded_before_buffered_adapter_dispatch() {
    let app = MessageBox::memory(Arc::new(Policy), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let request = |body: Bytes| {
        Request::builder()
            .method("GET")
            .uri("/devices")
            .header("host", "localhost")
            .body(Full::new(body))
            .unwrap()
    };
    assert_eq!(
        handle_http_stream(&adapter, request(Bytes::new()))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        handle_http_stream(&adapter, request(Bytes::from(vec![0; 4 * 1024 * 1024 + 1])))
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        handle_http_stream(&adapter, request(Bytes::from(vec![0; 4 * 1024 * 1024])))
            .await
            .status(),
        // At the exact streaming limit the body reaches the adapter. Without
        // a JSON content type it is not parsed into application fields.
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn counts_multiple_frames_and_distinguishes_stream_failure() {
    use futures_util::stream;
    use http_body::Frame;
    use http_body_util::StreamBody;
    let app = MessageBox::memory(Arc::new(Policy), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let frames = vec![
        Ok::<_, std::io::Error>(Frame::data(Bytes::from(vec![0; 4 * 1024 * 1024]))),
        Ok(Frame::data(Bytes::from_static(b"x"))),
    ];
    let req = Request::builder()
        .method("GET")
        .uri("/devices")
        .header("host", "localhost")
        .body(StreamBody::new(stream::iter(frames)))
        .unwrap();
    assert_eq!(
        handle_http_stream(&adapter, req).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let failing = vec![Err::<Frame<Bytes>, _>(std::io::Error::other(
        "test stream failure",
    ))];
    let req = Request::builder()
        .method("GET")
        .uri("/devices")
        .header("host", "localhost")
        .body(StreamBody::new(stream::iter(failing)))
        .unwrap();
    let response = handle_http_stream(&adapter, req).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["code"], "ERR_INVALID_BODY");
}
#[tokio::test]
async fn trailer_auth_headers_do_not_become_request_authentication() {
    use futures_util::stream;
    use http::{HeaderMap, HeaderValue};
    use http_body::Frame;
    use http_body_util::StreamBody;
    let app = MessageBox::memory(Arc::new(Policy), Limits::default())
        .await
        .unwrap();
    let wallet = Wallet;
    let store = Store;
    let adapter = HttpAuthAdapter::new(&app, &wallet, &store);
    let mut trailers = HeaderMap::new();
    trailers.insert("x-bsv-auth-version", HeaderValue::from_static("0.1"));
    let frames = vec![
        Ok::<_, std::io::Error>(Frame::data(Bytes::new())),
        Ok(Frame::trailers(trailers)),
    ];
    let req = Request::builder()
        .method("GET")
        .uri("/devices")
        .header("host", "localhost")
        .body(StreamBody::new(stream::iter(frames)))
        .unwrap();
    assert_eq!(
        handle_http_stream(&adapter, req).await.status(),
        StatusCode::UNAUTHORIZED
    );
}
