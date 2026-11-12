use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
    fcm_delivery::{FcmOptions, FcmProvider},
    fcm_http_v1::{
        FcmHttpRequest, FcmHttpResponse, FcmHttpTransport, FirebaseV1Provider, OAuthTokenSource,
    },
    firebase_init::{
        FirebaseAssemblyError, FirebaseBackend, FirebaseBackendError, FirebaseInitError,
        UnavailableFirebaseBackend, assemble_firebase,
    },
    resource_config::{EnvironmentSnapshot, ResourceConfig},
    runtime_resources::RuntimeResources,
};
use serde_json::{Value, json};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
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
const CAROL: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
struct Free;
impl DeliveryPolicy for Free {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
fn id(s: &str) -> Identity {
    Identity::from_verified_key(s).unwrap()
}
fn env(pairs: &[(&str, &str)]) -> EnvironmentSnapshot {
    pairs
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect()
}
async fn memory() -> MessageBox {
    MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap()
}

struct FakeBackend {
    provider: Arc<dyn FcmProvider>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}
impl FirebaseBackend for FakeBackend {
    type App = Arc<dyn FcmProvider>;
    type Credential = ();
    fn read_service_account(&mut self, _: &str) -> Result<String, FirebaseBackendError> {
        self.calls.lock().unwrap().push("read");
        Err(FirebaseBackendError)
    }
    fn certificate(&mut self, _: &str, _: &str, _: &str) -> Result<(), FirebaseBackendError> {
        self.calls.lock().unwrap().push("cert");
        Ok(())
    }
    fn default_credential(&mut self) -> Result<(), FirebaseBackendError> {
        self.calls.lock().unwrap().push("default");
        Ok(())
    }
    fn has_apps(&mut self) -> Result<bool, FirebaseBackendError> {
        Ok(false)
    }
    fn get_app(&mut self) -> Result<Self::App, FirebaseBackendError> {
        Err(FirebaseBackendError)
    }
    fn initialize_app(&mut self, _: &str, _: ()) -> Result<Self::App, FirebaseBackendError> {
        self.calls.lock().unwrap().push("initialize");
        Ok(self.provider.clone())
    }
}
struct Tokens {
    calls: AtomicUsize,
    fail: bool,
}
impl OAuthTokenSource for Tokens {
    fn token<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err("fake-secret-oauth-error".into())
            } else {
                Ok("fake-oauth".into())
            }
        })
    }
}
struct Transport {
    pool: Option<SqlitePool>,
    requests: Mutex<Vec<FcmHttpRequest>>,
    active: AtomicUsize,
    peak: AtomicUsize,
}
impl FcmHttpTransport for Transport {
    fn execute<'a>(
        &'a self,
        req: FcmHttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<FcmHttpResponse, String>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(pool) = &self.pool {
                let mid = req.body["message"]["android"]["data"]["messageId"]
                    .as_str()
                    .unwrap();
                let exists: Option<i64> =
                    sqlx::query_scalar("SELECT 1 FROM messages WHERE message_id=?")
                        .bind(mid)
                        .fetch_optional(pool)
                        .await
                        .unwrap();
                assert_eq!(exists, Some(1), "notification must follow commit");
            }
            let n = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(n, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.requests.lock().unwrap().push(req);
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(FcmHttpResponse {
                status: 200,
                body: br#"{"name":"projects/fake-project/messages/id"}"#.to_vec(),
            })
        })
    }
}
type FakeParts = (
    Arc<Tokens>,
    Arc<Transport>,
    Arc<dyn FcmProvider>,
    Arc<Mutex<Vec<&'static str>>>,
);
fn make(pool: Option<SqlitePool>, fail: bool) -> FakeParts {
    let tokens = Arc::new(Tokens {
        calls: AtomicUsize::new(0),
        fail,
    });
    let transport = Arc::new(Transport {
        pool,
        requests: Mutex::new(vec![]),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
    });
    let provider: Arc<dyn FcmProvider> = Arc::new(
        FirebaseV1Provider::new("fake-project", tokens.clone(), transport.clone()).unwrap(),
    );
    (tokens, transport, provider, Arc::new(Mutex::new(vec![])))
}
fn backend(provider: Arc<dyn FcmProvider>, calls: Arc<Mutex<Vec<&'static str>>>) -> FakeBackend {
    FakeBackend { provider, calls }
}

#[tokio::test]
async fn disabled_and_invalid_configuration_do_not_silently_enable_or_fallback() {
    let (tokens, transport, provider, calls) = make(None, false);
    let factory_calls = AtomicUsize::new(0);
    for enabled in [None, Some("false"), Some("TRUE")] {
        let mut settings = EnvironmentSnapshot::new();
        if let Some(v) = enabled {
            settings.insert("ENABLE_FIREBASE".into(), v.into());
        }
        let app = assemble_firebase(memory().await, &settings, || {
            factory_calls.fetch_add(1, Ordering::SeqCst);
            backend(provider.clone(), calls.clone())
        })
        .unwrap();
        let alice = id(ALICE);
        let bob = id(BOB);
        register(&app, &bob, "fake-disabled-device").await;
        assert_eq!(
            app.handle(
                "/sendMessage",
                Some(&alice),
                &send("notifications", "disabled-id", BOB)
            )
            .await
            .status,
            200
        );
        app.close().await;
    }
    assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 0);
    assert!(transport.requests.lock().unwrap().is_empty());
    assert!(calls.lock().unwrap().is_empty());
    let missing = env(&[("ENABLE_FIREBASE", "true")]);
    assert!(matches!(
        assemble_firebase(memory().await, &missing, || backend(
            provider.clone(),
            calls.clone()
        )),
        Err(FirebaseAssemblyError::Initialization(
            FirebaseInitError::MissingProject
        ))
    ));
    let unavailable = env(&[
        ("ENABLE_FIREBASE", "true"),
        ("FIREBASE_PROJECT_ID", "fake-project"),
    ]);
    assert!(matches!(
        assemble_firebase(memory().await, &unavailable, || UnavailableFirebaseBackend),
        Err(FirebaseAssemblyError::Initialization(
            FirebaseInitError::Backend
        ))
    ));
    let invalid = env(&[
        ("ENABLE_FIREBASE", "true"),
        ("FIREBASE_PROJECT_ID", "fake-project"),
        ("FIREBASE_SERVICE_ACCOUNT_JSON", "invalid"),
        ("FIREBASE_SERVICE_ACCOUNT_PATH", "fake-path"),
    ]);
    assert!(matches!(
        assemble_firebase(memory().await, &invalid, || backend(
            provider.clone(),
            calls.clone()
        )),
        Err(FirebaseAssemblyError::Initialization(
            FirebaseInitError::InvalidCredential
        ))
    ));
    assert!(calls.lock().unwrap().is_empty());
    let valid = env(&[
        ("ENABLE_FIREBASE", "true"),
        ("FIREBASE_PROJECT_ID", "fake-project"),
        (
            "FIREBASE_SERVICE_ACCOUNT_JSON",
            r#"{"private_key":"fake","client_email":"fake@example.test","project_id":"fake-project"}"#,
        ),
        ("FIREBASE_SERVICE_ACCOUNT_PATH", "fake-path"),
    ]);
    let app =
        assemble_firebase(memory().await, &valid, || backend(provider, calls.clone())).unwrap();
    assert_eq!(*calls.lock().unwrap(), vec!["cert", "initialize"]);
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 0);
    assert!(transport.requests.lock().unwrap().is_empty());
    app.close().await;
}

#[tokio::test]
async fn disabled_assembly_removes_preinstalled_provider() {
    for enabled in [None, Some("false"), Some("TRUE")] {
        let (tokens, transport, provider, calls) = make(None, false);
        let app = memory()
            .await
            .with_fcm_provider(provider.clone(), FcmOptions::default(), 4)
            .unwrap();
        let mut settings = EnvironmentSnapshot::new();
        if let Some(value) = enabled {
            settings.insert("ENABLE_FIREBASE".into(), value.into());
        }
        let factory_calls = AtomicUsize::new(0);
        let app = assemble_firebase(app, &settings, || {
            factory_calls.fetch_add(1, Ordering::SeqCst);
            backend(provider, calls.clone())
        })
        .unwrap();
        let alice = id(ALICE);
        let bob = id(BOB);
        register(&app, &bob, "fake-disabled-device").await;
        assert_eq!(
            app.handle(
                "/sendMessage",
                Some(&alice),
                &send("notifications", "preinstalled-disabled", BOB),
            )
            .await
            .status,
            200
        );
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(tokens.calls.load(Ordering::SeqCst), 0);
        assert!(transport.requests.lock().unwrap().is_empty());
        app.close().await;
    }
}

async fn register(app: &MessageBox, who: &Identity, token: &str) {
    assert_eq!(
        app.handle("/registerDevice", Some(who), &json!({"fcmToken":token}))
            .await
            .status,
        200
    );
    assert_eq!(
        app.handle(
            "/permissions/set",
            Some(who),
            &json!({"messageBox":"notifications","recipientFee":0,"sender":ALICE})
        )
        .await
        .status,
        200
    );
}
fn send(box_name: &str, mid: &str, recipient: &str) -> Value {
    json!({"message":{"recipient":recipient,"messageBox":box_name,"messageId":mid,"body":"private-body"}})
}

#[tokio::test]
async fn same_assembly_path_notifies_after_commit_and_preserves_messages_on_token_failure() {
    for fail in [false, true] {
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
        let (tokens, transport, provider, calls) = make(Some(pool.clone()), fail);
        let app = assemble_firebase(
            app,
            &env(&[
                ("ENABLE_FIREBASE", "true"),
                ("FIREBASE_PROJECT_ID", "fake-project"),
            ]),
            || backend(provider, calls),
        )
        .unwrap();
        assert_eq!(tokens.calls.load(Ordering::SeqCst), 0);
        let alice = id(ALICE);
        let bob = id(BOB);
        register(&app, &bob, "fake-device").await;
        assert_eq!(
            app.handle(
                "/sendMessage",
                Some(&alice),
                &send("inbox", "inbox-id", BOB)
            )
            .await
            .status,
            200
        );
        let response = app
            .handle(
                "/sendMessage",
                Some(&alice),
                &send("notifications", "notice-id", BOB),
            )
            .await;
        assert_eq!(response.status, 200);
        assert!(!response.body.to_string().contains("fake-secret"));
        assert_eq!(tokens.calls.load(Ordering::SeqCst), 1);
        {
            let requests = transport.requests.lock().unwrap();
            assert_eq!(requests.len(), usize::from(!fail));
            if !fail {
                assert_eq!(requests[0].body["message"]["token"], "fake-device");
                assert!(!requests[0].body.to_string().contains("private-body"));
            }
        }
        assert_eq!(
            app.handle(
                "/sendMessage",
                Some(&alice),
                &send("notifications", "notice-id", BOB)
            )
            .await
            .status,
            400
        );
        let mut rejected = send("notifications", "rejected", BOB);
        rejected["payment"] = Value::Null;
        assert_eq!(
            app.handle("/sendMessage", Some(&alice), &rejected)
                .await
                .status,
            501
        );
        assert_eq!(tokens.calls.load(Ordering::SeqCst), 1);
        let listed = app
            .handle(
                "/listMessages",
                Some(&bob),
                &json!({"messageBox":"notifications"}),
            )
            .await;
        assert_eq!(listed.body["messages"][0]["messageId"], "notice-id");
        pool.close().await;
        app.close().await;
    }
}

#[tokio::test]
async fn resource_limits_survive_assembly() {
    for (max_devices, recipient_concurrency, expected_calls) in [(1, 2, 2), (3, 1, 4)] {
        let settings = env(&[
            (
                "MESSAGE_BOX_MAX_NOTIFICATION_DEVICES",
                &max_devices.to_string(),
            ),
            ("MESSAGE_BOX_FCM_SEND_CONCURRENCY", "1"),
            (
                "MESSAGE_BOX_NOTIFICATION_RECIPIENT_CONCURRENCY",
                &recipient_concurrency.to_string(),
            ),
        ]);
        let resources =
            RuntimeResources::new(ResourceConfig::from_snapshot(&settings).unwrap()).unwrap();
        let app = MessageBox::memory_with_resources(Arc::new(Free), resources)
            .await
            .unwrap();
        let (tokens, transport, provider, calls) = make(None, false);
        let app = assemble_firebase(
            app,
            &env(&[
                ("ENABLE_FIREBASE", "true"),
                ("FIREBASE_PROJECT_ID", "fake-project"),
            ]),
            || backend(provider, calls),
        )
        .unwrap();
        let alice = id(ALICE);
        let bob = id(BOB);
        let carol = id(CAROL);
        for (owner, token) in [(&bob, "b1"), (&bob, "b2"), (&bob, "b3"), (&carol, "c1")] {
            register(&app, owner, token).await;
        }
        let request = json!({"message":{"recipients":[BOB,CAROL],"messageBox":"notifications","messageId":["resource-b","resource-c"],"body":"private-body"}});
        assert_eq!(
            app.handle("/sendMessage", Some(&alice), &request)
                .await
                .status,
            200
        );
        assert_eq!(tokens.calls.load(Ordering::SeqCst), expected_calls);
        if recipient_concurrency == 1 {
            assert_eq!(transport.peak.load(Ordering::SeqCst), 1);
        }
        app.close().await;
    }
}
