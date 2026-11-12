//! Test-only Engine.IO/Socket.IO WebSocket framing probe. No authentication,
//! rooms, application dispatch or production listener. Never deploy.
use futures_util::{SinkExt, StreamExt};
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
    if tokio::time::timeout(std::time::Duration::from_secs(10), probe())
        .await
        .is_err()
    {
        eprintln!("probe timed out");
        std::process::exit(1);
    }
}
async fn probe() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    println!("{}", listener.local_addr().unwrap().port());
    let (stream, _) = listener.accept().await.unwrap();
    let mut ws = accept_hdr_async(stream, check_request).await.unwrap();
    ws.send(Message::Text(r#"0{"sid":"test-probe","upgrades":[],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}"#.into())).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap().into_text().unwrap(), "40");
    ws.send(Message::Text(r#"40{"sid":"test-namespace"}"#.into()))
        .await
        .unwrap();
    ws.send(Message::Text("2".into())).await.unwrap();
    let (mut pong, mut event) = (false, false);
    while !pong || !event {
        let text = ws.next().await.unwrap().unwrap().into_text().unwrap();
        if text == "3" {
            pong = true;
            continue;
        }
        if let Some(json) = text.strip_prefix("42") {
            let value: serde_json::Value = serde_json::from_str(json).unwrap();
            assert_eq!(
                value,
                serde_json::json!(["probe",{"text":"hello","count":2}])
            );
            event = true;
        } else {
            panic!("unexpected test fixture frame");
        }
    }
    ws.send(Message::Text(
        r#"42["reply",{"echo":"hello","count":2}]"#.into(),
    ))
    .await
    .unwrap();
    let _ = ws.next().await;
}

// Tungstenite's callback fixes its error type to an HTTP response value.
#[expect(
    clippy::result_large_err,
    reason = "required by tungstenite callback signature"
)]
fn check_request(request: &Request, response: Response) -> Result<Response, ErrorResponse> {
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
