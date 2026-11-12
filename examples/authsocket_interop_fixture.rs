//! Test-only one-connection AuthSocket echo. Not a MessageBox server.
use futures_util::{SinkExt, StreamExt};
use k256::SecretKey;
use message_box_server_rust::{
    auth_responder::AuthResponder,
    auth_store::{AuthStoreOptions, SqliteAuthSessionStore},
    authsocket_payload::{encode_event_payload, parse_event_payload},
    local_auth_wallet::LocalAuthWallet,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
    },
};

#[tokio::main]
async fn main() {
    tokio::time::timeout(std::time::Duration::from_secs(15), run())
        .await
        .expect("fixture timeout");
}
async fn run() {
    let temp = tempfile::tempdir().unwrap();
    let store =
        SqliteAuthSessionStore::open(temp.path().join("auth.sqlite"), AuthStoreOptions::default())
            .await
            .unwrap();
    let mut secret = [0u8; 32];
    secret[31] = 3;
    let wallet = LocalAuthWallet::new(SecretKey::from_slice(&secret).unwrap());
    let responder = AuthResponder::new(&wallet, &store);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    println!("{}", listener.local_addr().unwrap().port());
    let (stream, _) = listener.accept().await.unwrap();
    let mut ws = accept_hdr_async(stream, check).await.unwrap();
    ws.send(Message::Text(r#"0{"sid":"auth-test","upgrades":[],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}"#.into())).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap().into_text().unwrap(), "40");
    ws.send(Message::Text(r#"40{"sid":"auth-socket"}"#.into()))
        .await
        .unwrap();
    let mut connection_nonce = None;
    loop {
        let text = ws.next().await.unwrap().unwrap().into_text().unwrap();
        let value: Value =
            serde_json::from_str(text.strip_prefix("42").expect("Socket.IO event frame")).unwrap();
        assert_eq!(value[0], "authMessage");
        let message = &value[1];
        let answer = match message["messageType"].as_str() {
            Some("initialRequest") => {
                assert!(connection_nonce.is_none());
                let initial = responder.accept_initial(message).await.unwrap();
                connection_nonce = Some(initial.initial_nonce.clone());
                initial.to_json()
            }
            Some("general") => {
                assert_eq!(
                    message["yourNonce"].as_str(),
                    connection_nonce.as_deref(),
                    "session must have been established on this connection"
                );
                assert!(connection_nonce.is_some());
                let payload: Vec<u8> = message["payload"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
                    .collect();
                let verified = responder.accept_general(message, &payload).await.unwrap();
                let event = parse_event_payload(verified.payload(), 1_048_576).unwrap();
                assert_eq!(event.event_name, "probe");
                assert_eq!(event.data, Some(json!({"text":"hello"})));
                let reply =
                    encode_event_payload("reply", Some(&json!({"echo":"hello"})), 1_048_576)
                        .unwrap();
                let signed = responder
                    .sign_general_payload(&verified, &reply)
                    .await
                    .unwrap();
                ws.send(Message::Text(format!(
                    "42{}",
                    json!(["authMessage", signed.to_json()])
                )))
                .await
                .unwrap();
                break;
            }
            other => panic!("unexpected auth message {other:?}"),
        };
        ws.send(Message::Text(format!(
            "42{}",
            json!(["authMessage", answer])
        )))
        .await
        .unwrap();
    }
    let _ = ws.next().await;
}
#[expect(
    clippy::result_large_err,
    reason = "required by tungstenite callback signature"
)]
fn check(request: &Request, response: Response) -> Result<Response, ErrorResponse> {
    assert_eq!(request.uri().path(), "/socket.io/");
    let pairs: Vec<_> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes()).collect();
    assert!(pairs.iter().any(|(k, v)| k == "EIO" && v == "4"));
    assert!(
        pairs
            .iter()
            .any(|(k, v)| k == "transport" && v == "websocket")
    );
    Ok(response)
}
