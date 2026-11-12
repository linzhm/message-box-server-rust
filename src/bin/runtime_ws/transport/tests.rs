//! HTTP and WebSocket wire tests over Tokio duplex streams; no bind/listen or network.
use super::*;
use crate::{State, handle};
use message_box_server_rust::{
    Limits, MessageBox,
    auth_nonce::create_nonce,
    auth_responder::AuthWallet,
    auth_store::{AuthStoreOptions, SqliteAuthSessionStore},
    authsocket_payload::{encode_event_payload, parse_event_payload},
    http_auth::RoutingPrefix,
    local_auth_wallet::LocalAuthWallet,
    resource_config::ResourceConfig,
    runtime_config::{CorsConfig, CorsMode, FreeBoxPolicy},
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    task::JoinHandle,
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
fn wallet(n: u8) -> LocalAuthWallet {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    LocalAuthWallet::new(k256::SecretKey::from_slice(&bytes).unwrap())
}
struct Rig {
    state: Arc<State>,
    stop: watch::Sender<bool>,
    worker: JoinHandle<()>,
    _dir: tempfile::TempDir,
}
impl Drop for Rig {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.worker.abort();
    }
}
impl Rig {
    async fn new(mode: CorsMode) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let wallet = Arc::new(wallet(3));
        let app = Arc::new(
            MessageBox::memory(
                Arc::new(FreeBoxPolicy::new(["inbox".into()])),
                Limits::default(),
            )
            .await
            .unwrap(),
        );
        let ctx = Arc::new(Context {
            wallet: wallet.clone(),
            app: app.clone(),
            sessions: SqliteAuthSessionStore::open(
                dir.path().join("ws.db"),
                AuthStoreOptions::default(),
            )
            .await
            .unwrap(),
            routing: Mutex::new(Default::default()),
            resources: ResourceConfig::from_snapshot(&Default::default()).unwrap(),
            transports: Default::default(),
        });
        let (jobs, mut receiver) = mpsc::channel(32);
        let (stop, shutdown) = watch::channel(false);
        let worker_ctx = ctx.clone();
        let worker = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {Some(job)=receiver.recv()=>{let ctx=worker_ctx.clone();let shutdown=shutdown.clone();tasks.spawn(async move {super::super::serve(job,ctx,shutdown).await;});},Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},else=>break}
            }
        });
        let state = Arc::new(State {
            app,
            wallet,
            sessions: SqliteAuthSessionStore::open(
                dir.path().join("http.db"),
                AuthStoreOptions::default(),
            )
            .await
            .unwrap(),
            network_label: "test".into(),
            routing_prefix: RoutingPrefix::parse("").unwrap(),
            ws: Some(ctx),
            ws_jobs: jobs,
            permits: Arc::new(Semaphore::new(100)),
            cors: CorsConfig {
                mode,
                allowed_headers: None,
                exposed_headers: None,
            },
        });
        Self {
            state,
            stop,
            worker,
            _dir: dir,
        }
    }
    fn stream(&self) -> DuplexStream {
        let (client, server) = tokio::io::duplex(2 * MAX_PAYLOAD);
        let state = self.state.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| handle(req, state.clone()));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server), service)
                .with_upgrades()
                .await;
        });
        client
    }
    async fn http(
        &self,
        method: &str,
        path: &str,
        origin: Option<&str>,
        body: &str,
    ) -> (u16, String, String) {
        let mut io = self.stream();
        let origin = origin
            .map(|o| format!("Origin: {o}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{origin}Content-Type: text/plain;charset=UTF-8\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        io.write_all(request.as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), io.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        (
            head.split_whitespace().nth(1).unwrap().parse().unwrap(),
            head.to_owned(),
            body.to_owned(),
        )
    }
    async fn poll(&self, sid: &str) -> String {
        let (status, _, body) = self
            .http(
                "GET",
                &format!("/socket.io/?EIO=4&transport=polling&sid={sid}"),
                Some("https://client.test"),
                "",
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }
    async fn post(&self, sid: &str, packet: &str) {
        let (status, _, body) = self
            .http(
                "POST",
                &format!("/socket.io/?EIO=4&transport=polling&sid={sid}"),
                Some("https://client.test"),
                packet,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body, "ok");
    }
    async fn connect(&self) -> String {
        let (status, headers, body) = self
            .http(
                "GET",
                "/socket.io/?EIO=4&transport=polling",
                Some("https://client.test"),
                "",
            )
            .await;
        assert_eq!(status, 200);
        assert!(
            headers
                .to_lowercase()
                .contains("access-control-allow-origin:")
        );
        let open: Value = serde_json::from_str(body.strip_prefix('0').unwrap()).unwrap();
        assert_eq!(open["upgrades"], json!(["websocket"]));
        let sid = open["sid"].as_str().unwrap().to_owned();
        self.post(&sid, "40").await;
        assert!(self.poll(&sid).await.starts_with("40"));
        sid
    }
    async fn websocket(&self, sid: Option<&str>) -> WebSocketStream<DuplexStream> {
        let suffix = sid.map(|id| format!("&sid={id}")).unwrap_or_default();
        let mut req = format!("ws://localhost/socket.io/?EIO=4&transport=websocket{suffix}")
            .into_client_request()
            .unwrap();
        req.headers_mut().insert(
            "Origin",
            http::HeaderValue::from_static("https://client.test"),
        );
        let (socket, response) = tokio_tungstenite::client_async(req, self.stream())
            .await
            .unwrap();
        assert!(
            response
                .headers()
                .contains_key("access-control-allow-origin")
        );
        socket
    }
    async fn clean(&self, id: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let ctx = self.state.ws.as_ref().unwrap();
                if !ctx.transports.0.lock().await.contains_key(id)
                    && !ctx.routing.lock().await.registry.sockets().contains(&id)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
fn auth_packet(value: Value) -> String {
    format!("42{}", json!(["authMessage", value]))
}
fn reply(packet: &str) -> Value {
    serde_json::from_str::<Value>(packet.strip_prefix("42").unwrap()).unwrap()[1].clone()
}
fn event(packet: &str) -> (String, Value) {
    let reply = reply(packet);
    let bytes: Vec<u8> = serde_json::from_value(reply["payload"].clone()).unwrap();
    let event = parse_event_payload(&bytes, MAX_PAYLOAD).unwrap();
    (event.event_name, event.data.unwrap_or(Value::Null))
}
async fn initial(rig: &Rig, sid: &str, client: &LocalAuthWallet) -> String {
    let nonce = create_nonce(client, "self", None).await.unwrap();
    rig.post(sid,&auth_packet(json!({"version":"0.1","messageType":"initialRequest","identityKey":client.identity_key().await.unwrap(),"initialNonce":nonce,"requestedCertificates":{"certifiers":[],"types":{}}}))).await;
    reply(&rig.poll(sid).await)["initialNonce"]
        .as_str()
        .unwrap()
        .to_owned()
}
async fn signed(
    client: &LocalAuthWallet,
    server: &str,
    session: &str,
    event: &str,
    data: Value,
) -> String {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).unwrap();
    let nonce = STANDARD.encode(random);
    let payload = encode_event_payload(event, Some(&data), MAX_PAYLOAD).unwrap();
    let signature = client
        .sign_auth(server, &format!("{nonce} {session}"), &payload)
        .await
        .unwrap();
    auth_packet(
        json!({"version":"0.1","messageType":"general","identityKey":client.identity_key().await.unwrap(),"nonce":nonce,"yourNonce":session,"payload":payload,"signature":signature}),
    )
}
async fn ws_text(ws: &mut WebSocketStream<DuplexStream>) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match ws.next().await.unwrap().unwrap() {
                Message::Text(t) => return t,
                Message::Ping(_) => ws.flush().await.unwrap(),
                p => panic!("unexpected {p:?}"),
            }
        }
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn polling_upgrade_preserves_auth_room_delivery_and_resumed_reconnect() {
    let rig = Rig::new(CorsMode::Public).await;
    let client = wallet(2);
    let identity = client.identity_key().await.unwrap();
    let server = rig.state.wallet.identity_key().await.unwrap();
    let room = format!("{identity}-inbox");
    let sid = rig.connect().await;
    let session = initial(&rig, &sid, &client).await;
    rig.post(
        &sid,
        &signed(
            &client,
            &server,
            &session,
            "authenticated",
            json!({"identityKey":identity}),
        )
        .await,
    )
    .await;
    assert_eq!(event(&rig.poll(&sid).await).0, "authenticationSuccess");
    rig.post(
        &sid,
        &signed(&client, &server, &session, "joinRoom", json!(room)).await,
    )
    .await;
    assert_eq!(
        event(&rig.poll(&sid).await),
        ("joinedRoom".into(), json!({"roomId":room}))
    );
    let mut ws = rig.websocket(Some(&sid)).await;
    ws.send(Message::Text("2probe".into())).await.unwrap();
    assert_eq!(ws_text(&mut ws).await, "3probe");
    assert_eq!(rig.poll(&sid).await, "6");
    ws.send(Message::Text("5".into())).await.unwrap();
    // A queued announcement must arrive once on the upgraded transport, still signed for this peer.
    rig.state
        .ws
        .as_ref()
        .unwrap()
        .announce(&identity, &identity, "inbox", "live-1", Arc::from("hello"))
        .await;
    assert_eq!(
        event(&ws_text(&mut ws).await),
        (
            format!("sendMessage-{room}"),
            json!({"sender":identity,"messageId":"live-1","body":"hello"})
        )
    );
    ws.send(Message::Text(
        signed(
            &client,
            &server,
            &session,
            "joinRoom",
            json!("another-inbox"),
        )
        .await,
    ))
    .await
    .unwrap();
    assert_eq!(
        event(&ws_text(&mut ws).await).1["code"],
        "ERR_WEBSOCKET_ROOM_NOT_OWNED"
    );
    ws.close(None).await.unwrap();
    drop(ws);
    rig.clean(&sid).await;
    let new_sid = rig.connect().await;
    assert_ne!(sid, new_sid);
    // Fixed AuthSocketClient retains its Peer and session on one automatic reconnect.
    rig.post(
        &new_sid,
        &signed(
            &client,
            &server,
            &session,
            "authenticated",
            json!({"identityKey":identity}),
        )
        .await,
    )
    .await;
    assert_eq!(event(&rig.poll(&new_sid).await).0, "authenticationSuccess");
    assert_eq!(
        rig.state
            .ws
            .as_ref()
            .unwrap()
            .routing
            .lock()
            .await
            .registry
            .room_count(&new_sid),
        0
    );
    rig.post(
        &new_sid,
        &signed(&client, &server, &session, "joinRoom", json!(room)).await,
    )
    .await;
    assert_eq!(event(&rig.poll(&new_sid).await).0, "joinedRoom");
    rig.post(&new_sid, "41").await;
    rig.clean(&new_sid).await;
}
#[tokio::test]
async fn origin_denial_and_preflight_precede_transport_allocation() {
    let rig = Rig::new(CorsMode::Allowlist(vec!["https://client.test".into()])).await;
    for method in ["GET", "POST", "OPTIONS"] {
        let (status, _, body) = rig
            .http(
                method,
                "/socket.io/?EIO=4&transport=polling",
                Some("https://denied.test"),
                "",
            )
            .await;
        assert_eq!(status, 403);
        assert!(body.contains("ERR_ORIGIN_NOT_ALLOWED"));
    }
    let (status, _, _) = rig
        .http(
            "OPTIONS",
            "/socket.io/?EIO=bogus",
            Some("https://client.test"),
            "",
        )
        .await;
    assert_eq!(status, 204);
    assert!(
        rig.state
            .ws
            .as_ref()
            .unwrap()
            .transports
            .0
            .lock()
            .await
            .is_empty()
    );
    let sid = rig.connect().await;
    rig.post(&sid, "1").await;
    rig.clean(&sid).await;
}
#[tokio::test]
async fn direct_websocket_origin_and_engine_heartbeat_frames() {
    let rig = Rig::new(CorsMode::Public).await;
    let mut ws = rig.websocket(None).await;
    let open: Value = serde_json::from_str(&ws_text(&mut ws).await[1..]).unwrap();
    assert_eq!(open["upgrades"], json!([]));
    ws.send(Message::Text("40".into())).await.unwrap();
    assert!(ws_text(&mut ws).await.starts_with("40"));
    ws.send(Message::Ping(vec![1, 2])).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::Pong(vec![1, 2]));
    ws.send(Message::Text("41".into())).await.unwrap();
}
#[tokio::test]
async fn invalid_query_unknown_sid_and_payload_limit() {
    let rig = Rig::new(CorsMode::Public).await;
    for query in [
        "EIO=4&EIO=4&transport=polling",
        "EIO=3&transport=polling",
        "EIO=4&transport=other",
        "EIO=4&transport=polling&sid=unknown",
        "EIO=4&transport=polling&sid=a&sid=b",
    ] {
        assert_eq!(
            rig.http("GET", &format!("/socket.io/?{query}"), None, "")
                .await
                .0,
            400
        );
    }
    let sid = rig.connect().await;
    assert_eq!(
        rig.http(
            "POST",
            &format!("/socket.io/?EIO=4&transport=polling&sid={sid}"),
            None,
            &"x".repeat(MAX_PAYLOAD + 1)
        )
        .await
        .0,
        400
    );
    rig.post(&sid, "1").await;
    rig.clean(&sid).await;
}

#[tokio::test]
async fn two_same_identity_connections_keep_reply_sessions_and_cleanup_independent() {
    use message_box_server_rust::auth_responder::AuthSessionStore;
    let rig = Rig::new(CorsMode::Public).await;
    let client = wallet(2);
    let identity = client.identity_key().await.unwrap();
    let server = rig.state.wallet.identity_key().await.unwrap();
    let room = format!("{identity}-inbox");
    let a = rig.connect().await;
    let sa = initial(&rig, &a, &client).await;
    let b = rig.connect().await;
    let sb = initial(&rig, &b, &client).await;
    assert_ne!(sa, sb);
    for (id, session) in [(&a, &sa), (&b, &sb)] {
        // The fixed server activates on any first valid signed event, not its claimed key.
        rig.post(
            id,
            &signed(&client, &server, session, "joinRoom", json!(room)).await,
        )
        .await;
        assert_eq!(event(&rig.poll(id).await).0, "authenticationSuccess");
        assert_eq!(event(&rig.poll(id).await).0, "joinedRoom");
    }
    let ctx = rig.state.ws.as_ref().unwrap();
    ctx.announce(&identity, &identity, "inbox", "both", Arc::from("two tabs"))
        .await;
    for (id, session) in [(&a, &sa), (&b, &sb)] {
        let packet = rig.poll(id).await;
        let response = reply(&packet);
        let stored = ctx.sessions.get_session(session).await.unwrap().unwrap();
        assert_eq!(response["yourNonce"], stored.peer_nonce);
        let payload: Vec<u8> = serde_json::from_value(response["payload"].clone()).unwrap();
        let signature: Vec<u8> = serde_json::from_value(response["signature"].clone()).unwrap();
        assert!(
            client
                .verify_auth(
                    &server,
                    &format!(
                        "{} {}",
                        response["nonce"].as_str().unwrap(),
                        stored.peer_nonce
                    ),
                    &payload,
                    &signature
                )
                .await
                .unwrap()
        );
        assert_eq!(event(&packet).0, format!("sendMessage-{room}"));
    }
    rig.post(&a, "1").await;
    rig.clean(&a).await;
    assert_eq!(ctx.routing.lock().await.registry.connection_count(), 1);
    assert_eq!(ctx.routing.lock().await.registry.room_count(&b), 1);
    // A second live connection cannot change its negotiated session to the first tab's.
    rig.post(
        &b,
        &signed(&client, &server, &sa, "joinRoom", json!(room)).await,
    )
    .await;
    rig.clean(&b).await;
}

#[tokio::test]
async fn failed_upgrade_keeps_polling_and_pending_get_is_released_by_probe() {
    let rig = Rig::new(CorsMode::Public).await;
    let sid = rig.connect().await;
    let mut ws = rig.websocket(Some(&sid)).await;
    ws.send(Message::Text("wrong-probe".into())).await.unwrap();
    drop(ws);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if rig.state.ws.as_ref().unwrap().transports.0.lock().await[&sid]
                .state
                .load(Ordering::SeqCst)
                == POLLING
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let session = rig.state.ws.as_ref().unwrap().transports.0.lock().await[&sid].clone();
    let pending = tokio::spawn(async move { poll(&session).await });
    tokio::task::yield_now().await;
    let mut ws = rig.websocket(Some(&sid)).await;
    ws.send(Message::Text("2probe".into())).await.unwrap();
    assert_eq!(ws_text(&mut ws).await, "3probe");
    let response = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "6"
    );
    ws.send(Message::Text("5".into())).await.unwrap();
    ws.send(Message::Text("41".into())).await.unwrap();
    rig.clean(&sid).await;
}
