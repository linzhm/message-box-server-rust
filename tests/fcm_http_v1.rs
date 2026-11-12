use message_box_server_rust::{
    fcm_delivery::FcmProvider,
    fcm_http_v1::{
        FcmHttpRequest, FcmHttpResponse, FcmHttpTransport, FirebaseV1Provider, OAuthTokenSource,
    },
};
use serde_json::{Value, json};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
struct Tokens {
    calls: AtomicUsize,
    token: String,
}
impl OAuthTokenSource for Tokens {
    fn token<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.token.clone())
        })
    }
}
struct Transport {
    requests: Mutex<Vec<FcmHttpRequest>>,
    responses: Mutex<Vec<FcmHttpResponse>>,
}
impl FcmHttpTransport for Transport {
    fn execute<'a>(
        &'a self,
        request: FcmHttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<FcmHttpResponse, String>> + Send + 'a>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(request);
            Ok(self.responses.lock().unwrap().remove(0))
        })
    }
}
fn response(status: u16, value: Value) -> FcmHttpResponse {
    FcmHttpResponse {
        status,
        body: serde_json::to_vec(&value).unwrap(),
    }
}
#[tokio::test]
async fn sends_v1_request_and_retrieves_token_for_each_attempt() {
    let tokens = Arc::new(Tokens {
        calls: AtomicUsize::new(0),
        token: "fake-access-token".into(),
    });
    let transport = Arc::new(Transport {
        requests: Mutex::new(Vec::new()),
        responses: Mutex::new(vec![
            response(200, json!({"name":"projects/example/messages/one"})),
            response(200, json!({"name":"projects/example/messages/two"})),
        ]),
    });
    let provider =
        FirebaseV1Provider::new("example-project", tokens.clone(), transport.clone()).unwrap();
    let message = json!({"token":"fake-device","notification":{"title":"New Message","body":"Open the app to view this message."}});
    assert!(provider.send(message.clone()).await.is_ok());
    assert!(provider.send(message.clone()).await.is_ok());
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 2);
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].url,
        "https://fcm.googleapis.com/v1/projects/example-project/messages:send"
    );
    assert_eq!(requests[0].method, http::Method::POST);
    assert_eq!(requests[0].content_type, "application/json");
    assert_eq!(requests[0].authorization, "Bearer fake-access-token");
    assert_eq!(requests[0].body, json!({"message":message}));
}
#[tokio::test]
async fn only_structured_unregistered_maps_to_invalid_token_and_errors_are_sanitized() {
    let tokens = Arc::new(Tokens {
        calls: AtomicUsize::new(0),
        token: "fake-token".into(),
    });
    let transport = Arc::new(Transport {
        requests: Mutex::new(Vec::new()),
        responses: Mutex::new(vec![
            response(
                404,
                json!({"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}),
            ),
            response(
                400,
                json!({"error":{"status":"INVALID_ARGUMENT","message":"invalid-registration-token fake secret"}}),
            ),
            response(
                404,
                json!({"error":{"message":"registration-token-not-registered"}}),
            ),
            response(200, json!({})),
        ]),
    });
    let provider = FirebaseV1Provider::new("example-project", tokens, transport).unwrap();
    assert_eq!(
        provider.send(json!({"token":"fake"})).await.unwrap_err(),
        "registration-token-not-registered"
    );
    for _ in 0..3 {
        let error = provider.send(json!({"token":"fake"})).await.unwrap_err();
        assert_eq!(error, "FCM request failed");
    }
}
#[tokio::test]
async fn rejects_bad_project_or_token_without_transport() {
    let bad = Arc::new(Tokens {
        calls: AtomicUsize::new(0),
        token: "fake\nheader".into(),
    });
    let transport = Arc::new(Transport {
        requests: Mutex::new(Vec::new()),
        responses: Mutex::new(Vec::new()),
    });
    assert!(FirebaseV1Provider::new("project/other", bad.clone(), transport.clone()).is_err());
    let provider = FirebaseV1Provider::new("valid-project", bad, transport.clone()).unwrap();
    assert_eq!(
        provider.send(json!({"token":"fake"})).await.unwrap_err(),
        "FCM request failed"
    );
    assert!(transport.requests.lock().unwrap().is_empty());
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
async fn structured_unregistered_reaches_sqlite_but_ambiguous_failure_does_not() {
    use message_box_server_rust::{
        Limits, MessageBox,
        fcm_delivery::{FcmOptions, FcmPayload},
    };
    use sqlx::{
        Row,
        sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    };
    for (response, expected_active) in [
        (
            response(
                404,
                json!({"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}),
            ),
            false,
        ),
        (
            response(
                400,
                json!({"error":{"status":"INVALID_ARGUMENT","message":"invalid-registration-token fake-secret"}}),
            ),
            true,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.sqlite");
        let app = MessageBox::open(&path, Arc::new(Free), Limits::default())
            .await
            .unwrap();
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
        sqlx::query("INSERT INTO device_registrations(identity_key,fcm_token,active,created_at,updated_at,last_used) VALUES('alice','fake-device',1,'2020','2020','2020')").execute(&pool).await.unwrap();
        let token_source = Arc::new(Tokens {
            calls: AtomicUsize::new(0),
            token: "fake-oauth".into(),
        });
        let transport = Arc::new(Transport {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(vec![response]),
        });
        let provider =
            Arc::new(FirebaseV1Provider::new("example-project", token_source, transport).unwrap());
        let result = app
            .send_fcm_notification(
                "alice",
                &FcmPayload {
                    title: "New Message",
                    message_id: "id-1",
                    originator: None,
                },
                Some(provider),
                FcmOptions {
                    max_devices: 100,
                    concurrency: 1,
                },
            )
            .await;
        assert!(!result.success);
        assert!(!result.to_json().to_string().contains("fake-secret"));
        let row =
            sqlx::query("SELECT active FROM device_registrations WHERE fcm_token='fake-device'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.get::<bool, _>("active"), expected_active);
        pool.close().await;
        app.close().await;
    }
}

struct BrokenTokens;
impl OAuthTokenSource for BrokenTokens {
    fn token<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async { Err("invalid-registration-token fake-oauth-secret".into()) })
    }
}
struct BrokenTransport;
impl FcmHttpTransport for BrokenTransport {
    fn execute<'a>(
        &'a self,
        _: FcmHttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<FcmHttpResponse, String>> + Send + 'a>> {
        Box::pin(async { Err("registration-token-not-registered fake-device-secret".into()) })
    }
}
#[tokio::test]
async fn host_failures_are_sanitized_without_token_invalidation_marker() {
    let tokens = Arc::new(Tokens {
        calls: AtomicUsize::new(0),
        token: "fake-oauth".into(),
    });
    let provider =
        FirebaseV1Provider::new("example", Arc::new(BrokenTokens), Arc::new(BrokenTransport))
            .unwrap();
    assert_eq!(
        provider.send(json!({})).await.unwrap_err(),
        "FCM request failed"
    );
    let provider = FirebaseV1Provider::new("example", tokens, Arc::new(BrokenTransport)).unwrap();
    assert_eq!(
        provider.send(json!({})).await.unwrap_err(),
        "FCM request failed"
    );
}
