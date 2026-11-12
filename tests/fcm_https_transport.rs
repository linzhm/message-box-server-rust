use message_box_server_rust::{
    fcm_http_v1::{FcmHttpRequest, FcmHttpTransport},
    fcm_https::FcmHttpsTransport,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
};

async fn fixture(
    name: &str,
    response: Vec<u8>,
    trust: bool,
    delay: Duration,
    timeout: Duration,
) -> (FcmHttpsTransport, String, tokio::task::JoinHandle<Vec<u8>>) {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![name.to_owned()]).unwrap();
    let der = cert.der().to_vec();
    let key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(der.clone())], key.into())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(mut stream) = acceptor.accept(tcp).await else {
            return vec![];
        };
        let mut received = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
            if let Some(end) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&received[..end]);
                let len = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if received.len() >= end + 4 + len {
                    break;
                }
            }
        }
        tokio::time::sleep(delay).await;
        let _ = stream.write_all(&response).await;
        received
    });
    let ca = reqwest::Certificate::from_der(&der).unwrap();
    let builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .no_proxy()
        .resolve("fcm.googleapis.com", address);
    let builder = if trust {
        builder.add_root_certificate(ca)
    } else {
        builder
    };
    let transport = FcmHttpsTransport::with_trusted_builder(builder, timeout).unwrap();
    let url = "https://fcm.googleapis.com/v1/projects/fake/messages:send".to_owned();
    (transport, url, task)
}
fn request(url: String) -> FcmHttpRequest {
    FcmHttpRequest {
        method: http::Method::POST,
        content_type: "application/json",
        url,
        authorization: "Bearer fake-oauth".into(),
        body: json!({"message":{"token":"fake-device"}}),
    }
}
#[tokio::test]
async fn tls_post_to_synthetic_loopback_has_expected_body_and_auth() {
    let body = br#"{"name":"projects/fake/messages/id"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(body).unwrap()
    )
    .into_bytes();
    let (transport, url, server) = fixture(
        "fcm.googleapis.com",
        response,
        true,
        Duration::ZERO,
        Duration::from_secs(3),
    )
    .await;
    let result = transport.execute(request(url)).await.unwrap();
    assert_eq!(result.status, 200);
    assert_eq!(result.body, body);
    let captured = String::from_utf8(server.await.unwrap()).unwrap();
    assert!(
        captured.starts_with("POST /v1/projects/fake/messages:send HTTP/1.1\r\n"),
        "{captured}"
    );
    assert!(
        captured
            .to_ascii_lowercase()
            .contains("authorization: bearer fake-oauth")
    );
    assert!(captured.contains("fake-device"));
}
#[tokio::test]
async fn rejects_untrusted_hostname_and_other_destinations() {
    let (transport, url, server) = fixture(
        "wrong.invalid",
        vec![],
        true,
        Duration::ZERO,
        Duration::from_secs(3),
    )
    .await;
    assert!(transport.execute(request(url)).await.is_err());
    assert!(server.await.unwrap().is_empty());
    let result = transport
        .execute(request(
            "https://example.invalid/v1/projects/fake/messages:send".into(),
        ))
        .await;
    assert!(result.is_err());
    let result = transport
        .execute(request(
            "https://fcm.googleapis.com:444/v1/projects/fake/messages:send".into(),
        ))
        .await;
    assert!(result.is_err());
}
#[tokio::test]
async fn no_redirect_follow_and_bounded_streaming_response() {
    let response =
        b"HTTP/1.1 302 Found\r\nlocation: /leak\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            .to_vec();
    let (transport, url, server) = fixture(
        "fcm.googleapis.com",
        response,
        true,
        Duration::ZERO,
        Duration::from_secs(3),
    )
    .await;
    assert_eq!(transport.execute(request(url)).await.unwrap().status, 302);
    server.await.unwrap();
    let mut oversized =
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n10001\r\n"
            .to_vec();
    oversized.extend(vec![b'x'; 65_537]);
    oversized.extend_from_slice(b"\r\n0\r\n\r\n");
    let (transport, url, server) = fixture(
        "fcm.googleapis.com",
        oversized,
        true,
        Duration::ZERO,
        Duration::from_secs(3),
    )
    .await;
    assert!(transport.execute(request(url)).await.is_err());
    server.await.unwrap();
}

#[tokio::test]
async fn rejects_untrusted_certificate_and_honors_timeout() {
    let (transport, url, server) = fixture(
        "fcm.googleapis.com",
        vec![],
        false,
        Duration::ZERO,
        Duration::from_secs(3),
    )
    .await;
    assert!(transport.execute(request(url)).await.is_err());
    assert!(server.await.unwrap().is_empty());
    let response = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec();
    let (transport, url, server) = fixture(
        "fcm.googleapis.com",
        response,
        true,
        Duration::from_millis(500),
        Duration::from_millis(100),
    )
    .await;
    assert!(transport.execute(request(url)).await.is_err());
    assert!(
        !server.await.unwrap().is_empty(),
        "timeout fixture must receive the request"
    );
}

#[tokio::test]
async fn accepts_exact_response_limit_and_rejects_large_content_length() {
    let mut exact =
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n10000\r\n"
            .to_vec();
    exact.extend(vec![b'x'; 65_536]);
    exact.extend_from_slice(b"\r\n0\r\n\r\n");
    let (transport, url, server) = fixture(
        "fcm.googleapis.com",
        exact,
        true,
        Duration::ZERO,
        Duration::from_secs(3),
    )
    .await;
    assert_eq!(
        transport.execute(request(url)).await.unwrap().body.len(),
        65_536
    );
    server.await.unwrap();
    let large = b"HTTP/1.1 200 OK\r\ncontent-length: 65537\r\nconnection: close\r\n\r\n".to_vec();
    let (transport, url, server) = fixture(
        "fcm.googleapis.com",
        large,
        true,
        Duration::ZERO,
        Duration::from_secs(3),
    )
    .await;
    assert!(transport.execute(request(url)).await.is_err());
    server.await.unwrap();
}

struct FakeTokens;
impl message_box_server_rust::fcm_http_v1::OAuthTokenSource for FakeTokens {
    fn token<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>
    {
        Box::pin(async { Ok("fake-oauth".into()) })
    }
}
struct Free;
impl message_box_server_rust::DeliveryPolicy for Free {
    fn evaluate(
        &self,
        _: &message_box_server_rust::Identity,
        _: &str,
        _: &str,
    ) -> Result<message_box_server_rust::Decision, message_box_server_rust::PolicyError> {
        Ok(message_box_server_rust::Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, message_box_server_rust::PolicyError> {
        Ok(0)
    }
}
#[tokio::test]
async fn host_injection_persists_message_and_sends_via_synthetic_tls() {
    use message_box_server_rust::{
        Identity, Limits, MessageBox, fcm_delivery::FcmOptions, fcm_http_v1::FirebaseV1Provider,
    };
    const ALICE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const BOB: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let response_body = br#"{"name":"projects/fake/messages/id"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        std::str::from_utf8(response_body).unwrap()
    )
    .into_bytes();
    let (transport, _, server) = fixture(
        "fcm.googleapis.com",
        response,
        true,
        Duration::ZERO,
        Duration::from_secs(3),
    )
    .await;
    let provider = Arc::new(
        FirebaseV1Provider::new("fake", Arc::new(FakeTokens), Arc::new(transport)).unwrap(),
    );
    let dir = tempfile::tempdir().unwrap();
    let app = MessageBox::open(
        &dir.path().join("messages.sqlite"),
        Arc::new(Free),
        Limits::default(),
    )
    .await
    .unwrap()
    .with_fcm_provider(provider, FcmOptions::default(), 1)
    .unwrap();
    let alice = Identity::from_verified_key(ALICE).unwrap();
    let bob = Identity::from_verified_key(BOB).unwrap();
    assert_eq!(
        app.handle(
            "/registerDevice",
            Some(&bob),
            &json!({"fcmToken":"fake-device"})
        )
        .await
        .status,
        200
    );
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new().filename(dir.path().join("messages.sqlite")),
        )
        .await
        .unwrap();
    sqlx::query("UPDATE device_registrations SET last_used='2000-01-01T00:00:00.000Z' WHERE fcm_token='fake-device'").execute(&pool).await.unwrap();
    assert_eq!(
        app.handle(
            "/permissions/set",
            Some(&bob),
            &json!({"messageBox":"notifications","recipientFee":0,"sender":ALICE})
        )
        .await
        .status,
        200
    );
    assert_eq!(app.handle("/sendMessage", Some(&alice), &json!({"message":{"recipient":BOB,"messageBox":"notifications","messageId":"id3","body":"fake-private-body"}})).await.status, 200);
    let listed = app
        .handle(
            "/listMessages",
            Some(&bob),
            &json!({"messageBox":"notifications"}),
        )
        .await;
    assert_eq!(listed.status, 200);
    assert_eq!(listed.body["messages"][0]["messageId"], "id3");
    let captured = String::from_utf8(
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("synthetic server did not receive request")
            .unwrap(),
    )
    .unwrap();
    assert!(
        captured
            .to_ascii_lowercase()
            .contains("authorization: bearer fake-oauth")
    );
    let body = captured.split_once("\r\n\r\n").unwrap().1;
    let message: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(message["message"]["token"], "fake-device");
    assert_eq!(message["message"]["android"]["data"]["messageId"], "id3");
    assert!(!body.contains("fake-private-body"));
    let last_used: String = sqlx::query_scalar(
        "SELECT last_used FROM device_registrations WHERE fcm_token='fake-device'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_ne!(last_used, "2000-01-01T00:00:00.000Z");
    pool.close().await;
    app.close().await;
}
