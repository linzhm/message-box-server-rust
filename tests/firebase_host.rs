use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
    fcm_http_v1::{FcmHttpRequest, FcmHttpResponse, FcmHttpTransport, OAuthTokenSource},
    firebase_host::{AccessToken, FirebaseHostBackend, ServiceAccountTokenSource, TokenExchange},
    firebase_init::{FirebaseAssemblyError, FirebaseInitError, assemble_firebase},
    resource_config::EnvironmentSnapshot,
};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};
use serde_json::{Value, json};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

const KEY: &[u8] = include_bytes!("../tests/fixtures/fcm-synthetic-rsa.pk8");
const ALICE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const BOB: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

struct Exchange {
    assertions: Mutex<Vec<String>>,
    lifetime: u64,
    fail: AtomicBool,
}
impl TokenExchange for Exchange {
    fn exchange<'a>(
        &'a self,
        assertion: String,
    ) -> Pin<Box<dyn Future<Output = Result<AccessToken, String>> + Send + 'a>> {
        Box::pin(async move {
            self.assertions.lock().unwrap().push(assertion);
            if self.fail.load(Ordering::SeqCst) {
                Err("synthetic-private-error".into())
            } else {
                Ok(AccessToken {
                    value: "synthetic-access".into(),
                    expires_in: self.lifetime,
                })
            }
        })
    }
}
struct Transport(Mutex<Vec<FcmHttpRequest>>);
impl FcmHttpTransport for Transport {
    fn execute<'a>(
        &'a self,
        request: FcmHttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<FcmHttpResponse, String>> + Send + 'a>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(request);
            Ok(FcmHttpResponse {
                status: 200,
                body: br#"{"name":"projects/fake-project/messages/one"}"#.to_vec(),
            })
        })
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
fn exchange(lifetime: u64) -> Arc<Exchange> {
    Arc::new(Exchange {
        assertions: Mutex::new(Vec::new()),
        lifetime,
        fail: AtomicBool::new(false),
    })
}
fn config() -> EnvironmentSnapshot {
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(KEY)
    );
    let raw = json!({"private_key":pem,"client_email":"synthetic@example.test","project_id":"fake-project"}).to_string();
    [
        ("ENABLE_FIREBASE".to_owned(), "true".to_owned()),
        ("FIREBASE_PROJECT_ID".to_owned(), "fake-project".to_owned()),
        ("FIREBASE_SERVICE_ACCOUNT_JSON".to_owned(), raw),
    ]
    .into_iter()
    .collect()
}

#[tokio::test]
async fn signed_assertion_and_refresh_use_real_service_account_code() {
    let ex = exchange(3600);
    let source =
        ServiceAccountTokenSource::from_pkcs8("synthetic@example.test", KEY, ex.clone()).unwrap();
    assert_eq!(source.token().await.unwrap(), "synthetic-access");
    assert_eq!(source.token().await.unwrap(), "synthetic-access");
    {
        let assertions = ex.assertions.lock().unwrap();
        assert_eq!(assertions.len(), 1);
        let parts: Vec<_> = assertions[0].split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "synthetic@example.test");
        assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
        assert_eq!(
            claims["scope"],
            "https://www.googleapis.com/auth/firebase.messaging"
        );
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            3600
        );
        let key = RsaKeyPair::from_pkcs8(KEY).unwrap();
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public().as_ref())
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
            )
            .unwrap();
    }
    let short = exchange(1);
    let source =
        ServiceAccountTokenSource::from_pkcs8("synthetic@example.test", KEY, short.clone())
            .unwrap();
    source.token().await.unwrap();
    source.token().await.unwrap();
    assert_eq!(short.assertions.lock().unwrap().len(), 2);
    short.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        source.token().await.unwrap_err(),
        "Firebase credential operation failed"
    );
}

#[tokio::test]
async fn explicit_service_account_assembles_and_sends_through_fakes() {
    let ex = exchange(3600);
    let transport = Arc::new(Transport(Mutex::new(vec![])));
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let app = assemble_firebase(app, &config(), || {
        FirebaseHostBackend::with_transports(
            &EnvironmentSnapshot::new(),
            std::env::current_dir().unwrap(),
            ex.clone(),
            transport.clone(),
        )
    })
    .unwrap();
    assert!(ex.assertions.lock().unwrap().is_empty());
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
    assert_eq!(app.handle("/sendMessage", Some(&alice), &json!({"message":{"recipient":BOB,"messageBox":"notifications","messageId":"id","body":"private-body"}})).await.status, 200);
    let requests = transport.0.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].authorization, "Bearer synthetic-access");
    assert_eq!(requests[0].body["message"]["token"], "fake-device");
    assert!(!requests[0].body.to_string().contains("private-body"));
}

#[tokio::test]
async fn explicit_missing_adc_file_and_invalid_key_fail_without_network() {
    let ex = exchange(3600);
    let transport = Arc::new(Transport(Mutex::new(vec![])));
    let dir = tempfile::tempdir().unwrap();
    let adc = EnvironmentSnapshot::from([(
        "GOOGLE_APPLICATION_CREDENTIALS".into(),
        "missing.json".into(),
    )]);
    let make = || {
        FirebaseHostBackend::with_transports(
            &adc,
            dir.path().to_owned(),
            ex.clone(),
            transport.clone(),
        )
    };
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let env = [
        ("ENABLE_FIREBASE".into(), "true".into()),
        ("FIREBASE_PROJECT_ID".into(), "fake-project".into()),
    ]
    .into_iter()
    .collect();
    assert!(matches!(
        assemble_firebase(app, &env, make),
        Err(FirebaseAssemblyError::Initialization(
            FirebaseInitError::Backend
        ))
    ));
    assert!(
        ServiceAccountTokenSource::from_pkcs8("synthetic@example.test", b"invalid", ex.clone())
            .is_err()
    );
    assert!(ex.assertions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reads_only_explicit_synthetic_file_and_disabled_skips_factory() {
    let ex = exchange(3600);
    let transport = Arc::new(Transport(Mutex::new(vec![])));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-service-account.json");
    std::fs::write(&path, config()["FIREBASE_SERVICE_ACCOUNT_JSON"].as_bytes()).unwrap();
    let env: EnvironmentSnapshot = [
        ("ENABLE_FIREBASE".into(), "true".into()),
        ("FIREBASE_PROJECT_ID".into(), "fake-project".into()),
        (
            "FIREBASE_SERVICE_ACCOUNT_PATH".into(),
            path.to_str().unwrap().into(),
        ),
    ]
    .into_iter()
    .collect();
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let app = assemble_firebase(app, &env, || {
        FirebaseHostBackend::with_transports(
            &EnvironmentSnapshot::new(),
            std::env::current_dir().unwrap(),
            ex.clone(),
            transport.clone(),
        )
    })
    .unwrap();
    app.close().await;
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let disabled = EnvironmentSnapshot::new();
    let app = assemble_firebase(app, &disabled, || -> FirebaseHostBackend {
        panic!("disabled must skip factory")
    })
    .unwrap();
    app.close().await;
    assert!(ex.assertions.lock().unwrap().is_empty());
    assert!(transport.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn adc_service_accounts_use_oauth_exchange_for_explicit_and_gcloud_files() {
    use message_box_server_rust::firebase_init::FirebaseBackend;
    let dir = tempfile::tempdir().unwrap();
    let mut json: Value = serde_json::from_str(&config()["FIREBASE_SERVICE_ACCOUNT_JSON"]).unwrap();
    json["type"] = "service_account".into();
    std::fs::write(dir.path().join("adc.json"), json.to_string()).unwrap();
    std::fs::create_dir_all(dir.path().join(".config/gcloud")).unwrap();
    std::fs::write(
        dir.path()
            .join(".config/gcloud/application_default_credentials.json"),
        json.to_string(),
    )
    .unwrap();
    for env in [
        EnvironmentSnapshot::from([("GOOGLE_APPLICATION_CREDENTIALS".into(), "adc.json".into())]),
        EnvironmentSnapshot::from([("HOME".into(), dir.path().to_str().unwrap().into())]),
    ] {
        let ex = exchange(3600);
        let mut host = FirebaseHostBackend::with_transports(
            &env,
            dir.path().to_owned(),
            ex.clone(),
            Arc::new(Transport(Mutex::new(vec![]))),
        );
        let token = host.default_credential().unwrap();
        assert!(ex.assertions.lock().unwrap().is_empty());
        assert_eq!(token.token().await.unwrap(), "synthetic-access");
        assert_eq!(token.token().await.unwrap(), "synthetic-access");
        assert_eq!(ex.assertions.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn explicit_json_precedes_broken_file_and_adc_and_oauth_failure_keeps_message() {
    let dir = tempfile::tempdir().unwrap();
    let mut env = config();
    env.insert(
        "FIREBASE_SERVICE_ACCOUNT_PATH".into(),
        "missing-service.json".into(),
    );
    env.insert(
        "GOOGLE_APPLICATION_CREDENTIALS".into(),
        "missing-adc.json".into(),
    );
    let ex = exchange(3600);
    ex.fail.store(true, Ordering::SeqCst);
    let transport = Arc::new(Transport(Mutex::new(vec![])));
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let app = assemble_firebase(app, &env, || {
        FirebaseHostBackend::with_transports(
            &env,
            dir.path().to_owned(),
            ex.clone(),
            transport.clone(),
        )
    })
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
    let response = app.handle("/sendMessage", Some(&alice), &json!({"message":{"recipient":BOB,"messageBox":"notifications","messageId":"token-failed","body":"private-body"}})).await;
    assert_eq!(response.status, 200);
    assert!(
        !response
            .body
            .to_string()
            .contains("synthetic-private-error")
    );
    let listed = app
        .handle(
            "/listMessages",
            Some(&bob),
            &json!({"messageBox":"notifications"}),
        )
        .await;
    assert_eq!(listed.status, 200);
    assert!(listed.body.to_string().contains("token-failed"));
    assert!(transport.0.lock().unwrap().is_empty());
    assert_eq!(ex.assertions.lock().unwrap().len(), 1);
}
