//! Test-only loopback HTTP harness with public test keys. Never deploy.
#![allow(dead_code)]
mod fixture {
    #![allow(dead_code, unused_imports)]
    include!("../tests/auth_responder.rs");
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use message_box_server_rust::{
        Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
        auth_store::{AuthStoreOptions, SqliteAuthSessionStore},
        http_auth::HttpAuthAdapter,
        http_stream::handle_http_stream,
        local_auth_wallet::LocalAuthWallet,
    };
    use std::{convert::Infallible, sync::Arc};
    struct Free;
    impl DeliveryPolicy for Free {
        fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
            Ok(Decision::Free)
        }
        fn delivery_fee(&self, message_box: &str) -> Result<i64, PolicyError> {
            Ok(if message_box == "paidbox" { 7 } else { 0 })
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
    pub async fn run() {
        let path = std::env::var("AUTH_TEST_DB").expect("test database path");
        let app = MessageBox::open(&path, Arc::new(Free), Limits::default())
            .await
            .unwrap();
        let owner = Identity::from_verified_key(&key(&secret(2))).unwrap();
        let other = Identity::from_verified_key(&key(&secret(4))).unwrap();
        assert_eq!(
            app.handle(
                "/registerDevice",
                Some(&owner),
                &json!({"fcmToken":"client-secret-token","platform":"web"})
            )
            .await
            .status,
            200
        );
        assert_eq!(
            app.handle(
                "/registerDevice",
                Some(&other),
                &json!({"fcmToken":"other-secret-token"})
            )
            .await
            .status,
            200
        );
        assert_eq!(app.handle("/sendMessage",Some(&other),&json!({"message":{"recipient":key(&secret(2)),"messageBox":"inbox","messageId":"sdk-message-1","body":"hello from test"}})).await.status,200);
        let store = SqliteAuthSessionStore::open(&path, AuthStoreOptions::default())
            .await
            .unwrap();
        let state = Arc::new(State {
            app,
            wallet: LocalAuthWallet::new(secret(3)),
            store,
        });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        println!("{}", listener.local_addr().unwrap().port());
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let state = state.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| handle(req, state.clone()));
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    }
}
#[tokio::main]
async fn main() {
    fixture::run().await;
}
