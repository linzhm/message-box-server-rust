use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
    fcm_delivery::{FcmOptions, FcmProvider},
    fcm_http_v1::{
        FcmHttpRequest, FcmHttpResponse, FcmHttpTransport, FirebaseV1Provider, OAuthTokenSource,
    },
    firebase_init::{FirebaseBackend, FirebaseBackendError, FirebaseConfig, FirebaseInitializer},
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
const ALICE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const BOB: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
struct Free;
impl DeliveryPolicy for Free {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
struct FakeProvider(AtomicUsize);
impl FcmProvider for FakeProvider {
    fn send<'a>(
        &'a self,
        _: Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}
struct FakeHost {
    provider: Arc<dyn FcmProvider>,
    calls: usize,
}
impl FirebaseBackend for FakeHost {
    type App = Arc<dyn FcmProvider>;
    type Credential = ();
    fn read_service_account(&mut self, _: &str) -> Result<String, FirebaseBackendError> {
        Err(FirebaseBackendError)
    }
    fn certificate(&mut self, _: &str, _: &str, _: &str) -> Result<(), FirebaseBackendError> {
        Err(FirebaseBackendError)
    }
    fn default_credential(&mut self) -> Result<(), FirebaseBackendError> {
        self.calls += 1;
        Ok(())
    }
    fn has_apps(&mut self) -> Result<bool, FirebaseBackendError> {
        Ok(false)
    }
    fn get_app(&mut self) -> Result<Self::App, FirebaseBackendError> {
        Err(FirebaseBackendError)
    }
    fn initialize_app(&mut self, _: &str, _: ()) -> Result<Self::App, FirebaseBackendError> {
        Ok(self.provider.clone())
    }
}
#[tokio::test]
async fn host_can_inject_initialized_fake_provider_into_messagebox() {
    let provider = Arc::new(FakeProvider(AtomicUsize::new(0)));
    let mut initializer = FirebaseInitializer::new(FakeHost {
        provider: provider.clone(),
        calls: 0,
    });
    let disabled = FirebaseConfig {
        enabled: None,
        project: None,
        service_account_json: None,
        service_account_path: None,
    };
    assert!(initializer.initialize(&disabled).unwrap().is_none());
    assert_eq!(initializer.backend().calls, 0);
    let enabled = FirebaseConfig {
        enabled: Some("true"),
        project: Some("fake-project"),
        ..disabled
    };
    let ready = initializer.initialize(&enabled).unwrap().unwrap();
    assert_eq!(provider.0.load(Ordering::SeqCst), 0);
    let dir = tempfile::tempdir().unwrap();
    let app = MessageBox::open(
        &dir.path().join("messages.sqlite"),
        Arc::new(Free),
        Limits::default(),
    )
    .await
    .unwrap()
    .with_fcm_provider(ready, FcmOptions::default(), 1)
    .unwrap();
    let alice = Identity::from_verified_key(ALICE).unwrap();
    let bob = Identity::from_verified_key(BOB).unwrap();
    assert_eq!(
        app.handle(
            "/registerDevice",
            Some(&bob),
            &json!({"fcmToken":"fake-token"})
        )
        .await
        .status,
        200
    );
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
    assert_eq!(app.handle("/sendMessage", Some(&alice), &json!({"message":{"recipient":BOB,"messageBox":"notifications","messageId":"id","body":"fake"}})).await.status, 200);
    assert_eq!(provider.0.load(Ordering::SeqCst), 1);
    app.close().await;
}

struct FakeOAuth(AtomicUsize);
impl OAuthTokenSource for FakeOAuth {
    fn token<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok("fake-oauth".into())
        })
    }
}
struct FakeHttp(Mutex<Vec<FcmHttpRequest>>);
impl FcmHttpTransport for FakeHttp {
    fn execute<'a>(
        &'a self,
        request: FcmHttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<FcmHttpResponse, String>> + Send + 'a>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(request);
            Ok(FcmHttpResponse {
                status: 200,
                body: br#"{"name":"projects/fake-project/messages/id"}"#.to_vec(),
            })
        })
    }
}
#[tokio::test]
async fn initializer_can_inject_http_v1_adapter_with_fake_oauth_and_transport() {
    let oauth = Arc::new(FakeOAuth(AtomicUsize::new(0)));
    let transport = Arc::new(FakeHttp(Mutex::new(Vec::new())));
    let adapter = Arc::new(
        FirebaseV1Provider::new("fake-project", oauth.clone(), transport.clone()).unwrap(),
    );
    let mut initializer = FirebaseInitializer::new(FakeHost {
        provider: adapter,
        calls: 0,
    });
    let initialized = initializer
        .initialize(&FirebaseConfig {
            enabled: Some("true"),
            project: Some("fake-project"),
            service_account_json: None,
            service_account_path: None,
        })
        .unwrap()
        .unwrap();
    assert_eq!(oauth.0.load(Ordering::SeqCst), 0);
    assert!(transport.0.lock().unwrap().is_empty());
    let dir = tempfile::tempdir().unwrap();
    let app = MessageBox::open(
        &dir.path().join("messages.sqlite"),
        Arc::new(Free),
        Limits::default(),
    )
    .await
    .unwrap()
    .with_fcm_provider(initialized, FcmOptions::default(), 1)
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
    assert_eq!(app.handle("/sendMessage", Some(&alice), &json!({"message":{"recipient":BOB,"messageBox":"notifications","messageId":"id2","body":"fake-private-body"}})).await.status, 200);
    assert_eq!(oauth.0.load(Ordering::SeqCst), 1);
    {
        let requests = transport.0.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, http::Method::POST);
        assert_eq!(requests[0].authorization, "Bearer fake-oauth");
        assert_eq!(requests[0].body["message"]["token"], "fake-device");
        assert_eq!(
            requests[0].body["message"]["android"]["data"]["messageId"],
            "id2"
        );
        assert!(!requests[0].body.to_string().contains("fake-private-body"));
    }
    app.close().await;
}
