//! Test-only signed HTTP fixture with a fake FCM provider. Never deploy.
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
    auth_store::{AuthStoreOptions, SqliteAuthSessionStore},
    fcm_delivery::{FcmOptions, FcmProvider},
    http_auth::HttpAuthAdapter,
    http_stream::handle_http_stream,
    local_auth_wallet::LocalAuthWallet,
};
use serde_json::{Value, json};
use std::{convert::Infallible, future::Future, pin::Pin, sync::Arc};
struct Free;
impl DeliveryPolicy for Free {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
struct Fake;
impl FcmProvider for Fake {
    fn send<'a>(
        &'a self,
        message: Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            println!("{}", json!({"fakeFcm":message}));
            Ok(())
        })
    }
}
struct State {
    app: MessageBox,
    wallet: LocalAuthWallet,
    store: SqliteAuthSessionStore,
}
async fn handle(
    req: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let adapter = HttpAuthAdapter::new(&state.app, &state.wallet, &state.store);
    let result = handle_http_stream(&adapter, req).await;
    let (parts, body) = result.into_parts();
    Ok(Response::from_parts(parts, Full::new(Bytes::from(body))))
}
#[tokio::main]
async fn main() {
    let dir = std::env::var("FCM_TEST_DIR").expect("test directory");
    let app = MessageBox::open(
        std::path::Path::new(&dir).join("messages.sqlite"),
        Arc::new(Free),
        Limits::default(),
    )
    .await
    .unwrap()
    .with_fcm_provider(Arc::new(Fake), FcmOptions::default(), 4)
    .unwrap();
    let bob = Identity::from_verified_key(
        "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
    )
    .unwrap();
    assert_eq!(
        app.handle(
            "/registerDevice",
            Some(&bob),
            &json!({"fcmToken":"fake-fcm-token"})
        )
        .await
        .status,
        200
    );
    assert_eq!(
        app.handle(
            "/permissions/set",
            Some(&bob),
            &json!({"messageBox":"notifications","recipientFee":0})
        )
        .await
        .status,
        200
    );
    let store = SqliteAuthSessionStore::open(
        std::path::Path::new(&dir).join("auth.sqlite"),
        AuthStoreOptions::default(),
    )
    .await
    .unwrap();
    let mut bytes = [0u8; 32];
    bytes[31] = 3;
    let wallet = LocalAuthWallet::new(k256::SecretKey::from_slice(&bytes).unwrap());
    let state = Arc::new(State { app, wallet, store });
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    println!("{}", listener.local_addr().unwrap().port());
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(req, Arc::clone(&state)));
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
