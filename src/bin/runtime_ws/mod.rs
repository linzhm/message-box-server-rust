//! Engine.IO v4 polling and WebSocket transport with authenticated Socket.IO events.
mod transport;
use message_box_server_rust::{
    Identity, MessageBox,
    auth_responder::{AuthResponder, VerifiedGeneral},
    auth_store::SqliteAuthSessionStore,
    authsocket_payload::{encode_event_payload, parse_event_payload},
    local_auth_wallet::LocalAuthWallet,
    websocket_policy::{is_identity_owned_room, message_box_from_recipient_room},
    websocket_registry::{MinuteRateLimiter, WebSocketRegistry},
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use transport::Endpoint;
pub use transport::{Job, TransportSessions, request};

pub struct Context {
    pub transports: TransportSessions,
    pub wallet: Arc<LocalAuthWallet>,
    pub sessions: SqliteAuthSessionStore,
    pub app: Arc<MessageBox>,
    pub routing: Mutex<Routing>,
    pub resources: message_box_server_rust::resource_config::ResourceConfig,
}
#[derive(Default)]
pub struct Routing {
    registry: WebSocketRegistry,
    senders: HashMap<String, mpsc::Sender<Arc<LiveMessage>>>,
}
struct LiveMessage {
    room: String,
    sender: String,
    message_id: String,
    body: Arc<str>,
}
impl Context {
    pub async fn announce(
        &self,
        sender: &str,
        recipient: &str,
        message_box: &str,
        message_id: &str,
        body: Arc<str>,
    ) {
        let room = format!("{recipient}-{message_box}");
        let targets = {
            let routing = self.routing.lock().await;
            routing
                .registry
                .recipient_sockets(
                    recipient,
                    &room,
                    signed(self.resources.websocket_max_recipient_connections),
                )
                .into_iter()
                .filter_map(|id| routing.senders.get(id).cloned())
                .collect::<Vec<_>>()
        };
        let live = Arc::new(LiveMessage {
            room,
            sender: sender.to_owned(),
            message_id: message_id.to_owned(),
            body,
        });
        for target in targets {
            let _ = target.try_send(Arc::clone(&live));
        }
    }
}
fn signed(limit: message_box_server_rust::resource_config::ResourceLimit) -> i64 {
    message_box_server_rust::runtime_resources::RuntimeResources::signed(limit)
}
fn js_trim(value: &str) -> &str {
    value.trim_matches(|c| matches!(c,'\u{0009}'..='\u{000d}'|'\u{0020}'|'\u{00a0}'|'\u{1680}'|'\u{2000}'..='\u{200a}'|'\u{2028}'|'\u{2029}'|'\u{202f}'|'\u{205f}'|'\u{3000}'|'\u{feff}'))
}
fn js_blank(value: &str) -> bool {
    js_trim(value).is_empty()
}
fn valid_message_body(
    value: &str,
    limit: message_box_server_rust::resource_config::ResourceLimit,
) -> bool {
    use message_box_server_rust::resource_config::ResourceLimit;
    !js_blank(value)
        && match limit {
            ResourceLimit::Finite(max) => u64::try_from(value.len()).is_ok_and(|size| size <= max),
            ResourceLimit::Unlimited => true,
        }
}
fn valid_message_id(value: &str) -> bool {
    !value.is_empty()
        && js_trim(value) == value
        && value.len() <= 256
        && !value
            .chars()
            .any(|c| c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&c))
}
async fn send_event(
    ws: &mut Endpoint,
    ctx: &Context,
    verified: &VerifiedGeneral,
    event: &str,
    data: &Value,
) -> Result<(), ()> {
    let payload = encode_event_payload(event, Some(data), 1_048_576).map_err(|_| ())?;
    let reply = AuthResponder::new(ctx.wallet.as_ref(), &ctx.sessions)
        .sign_general_payload(verified, &payload)
        .await
        .map_err(|_| ())?;
    ws.send(Message::Text(format!(
        "42{}",
        json!(["authMessage", reply.to_json()])
    )))
    .await
    .map_err(|_| ())
}
pub async fn serve(job: Job, ctx: Arc<Context>, mut shutdown: watch::Receiver<bool>) {
    let Some((mut endpoint, id, _permit)) = job.open(&mut shutdown).await else {
        return;
    };
    let _ = handle(&mut endpoint, &ctx, &mut shutdown, &id).await;
    endpoint.close().await;
    ctx.transports.remove(&id).await;
    let mut routing = ctx.routing.lock().await;
    routing.registry.remove(&id);
    routing.senders.remove(&id);
}
async fn handle(
    ws: &mut Endpoint,
    ctx: &Context,
    shutdown: &mut watch::Receiver<bool>,
    id: &str,
) -> Result<(), ()> {
    ws.send(Message::Text(format!("0{}",json!({"sid":id,"upgrades":ws.upgrades(),"pingInterval":25000,"pingTimeout":20000,"maxPayload":1048576})))).await.map_err(|_|())?;
    let namespace = async {
        loop {
            match ws.next().await.ok_or(())?.map_err(|_| ())? {
                Message::Text(text) if text == "40" => return Ok(()),
                Message::Ping(_) => ws.flush().await.map_err(|_| ())?,
                Message::Pong(_) => {}
                _ => return Err(()),
            }
        }
    };
    tokio::select! {
        result=namespace=>result?,
        _=shutdown.changed()=>return Ok(()),
        _=tokio::time::sleep(Duration::from_secs(20))=>return Err(()),
    }
    ws.send(Message::Text(format!("40{}", json!({"sid":id}))))
        .await
        .map_err(|_| ())?;
    let mut peer: Option<String> = None;
    let mut session_nonce: Option<String> = None;
    let mut last_verified: Option<VerifiedGeneral> = None;
    let (sender, mut incoming) = mpsc::channel::<Arc<LiveMessage>>(32);
    let mut control = (
        MinuteRateLimiter::new(signed(ctx.resources.websocket_control_rate_limit), 0),
        tokio::time::Instant::now(),
    );
    let mut sends = (
        MinuteRateLimiter::new(signed(ctx.resources.websocket_send_rate_limit), 0),
        tokio::time::Instant::now(),
    );
    let mut heartbeat = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(25),
        Duration::from_secs(25),
    );
    let mut pong_deadline: Option<tokio::time::Instant> = None;
    loop {
        let next = tokio::select! {
            _=shutdown.changed()=>return Ok(()),
            _=heartbeat.tick()=>{
                if pong_deadline.is_some(){return Err(());}
                ws.send(Message::Text("2".into())).await.map_err(|_|())?;
                pong_deadline=Some(tokio::time::Instant::now()+Duration::from_secs(20));continue;
            },
            _=async {if let Some(deadline)=pong_deadline {tokio::time::sleep_until(deadline).await} else {std::future::pending::<()>().await}}=>return Err(()),
            Some(live)=incoming.recv()=>{
                let verified=last_verified.as_ref().ok_or(())?;
                send_event(ws,ctx,verified,&format!("sendMessage-{}",live.room),&json!({"sender":live.sender,"messageId":live.message_id,"body":live.body.as_ref()})).await?;
                continue;
            },
            message=ws.next()=>message,
        };
        let frame = next.ok_or(())?.map_err(|_| ())?;
        let text = match frame {
            Message::Text(text) => text,
            Message::Ping(_) => {
                ws.flush().await.map_err(|_| ())?;
                continue;
            }
            Message::Pong(_) => continue,
            Message::Close(_) => return Ok(()),
            _ => return Err(()),
        };
        if text == "1" || text == "41" {
            return Ok(());
        }
        if text == "3" {
            pong_deadline = None;
            continue;
        }
        if text.len() > 1_048_576 {
            return Err(());
        }
        let packet: Value =
            serde_json::from_str(text.strip_prefix("42").ok_or(())?).map_err(|_| ())?;
        let items = packet.as_array().filter(|a| a.len() == 2).ok_or(())?;
        if items[0] != "authMessage" {
            return Err(());
        }
        let message = &items[1];
        let responder = AuthResponder::new(ctx.wallet.as_ref(), &ctx.sessions);
        match message["messageType"].as_str() {
            Some("initialRequest") => {
                if session_nonce.is_some() {
                    return Err(());
                }
                let response = responder.accept_initial(message).await.map_err(|_| ())?;
                session_nonce = Some(response.initial_nonce.clone());
                ws.send(Message::Text(format!(
                    "42{}",
                    json!(["authMessage", response.to_json()])
                )))
                .await
                .map_err(|_| ())?;
            }
            Some("general") => {
                if session_nonce
                    .as_deref()
                    .is_some_and(|nonce| message["yourNonce"].as_str() != Some(nonce))
                {
                    return Err(());
                }
                let payload: Vec<u8> = message["payload"]
                    .as_array()
                    .ok_or(())?
                    .iter()
                    .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()).ok_or(()))
                    .collect::<Result<_, _>>()?;
                let verified = responder
                    .accept_general(message, &payload)
                    .await
                    .map_err(|_| ())?;
                // Shared store permits the fixed client's reconnect to resume its Peer.
                // Once verified, pin that session on this connection; replies use VerifiedGeneral.
                session_nonce = message["yourNonce"].as_str().map(str::to_owned);
                if let Some(bound) = &peer {
                    if bound != verified.identity_key() {
                        return Err(());
                    }
                } else {
                    let mut routing = ctx.routing.lock().await;
                    if !routing
                        .registry
                        .register(id, signed(ctx.resources.websocket_max_connections))
                        || !routing.registry.authenticate(
                            id,
                            verified.identity_key(),
                            signed(ctx.resources.websocket_max_connections_per_identity),
                        )
                    {
                        return Err(());
                    }
                    routing.senders.insert(id.to_owned(), sender.clone());
                    drop(routing);
                    peer = Some(verified.identity_key().to_owned());
                    send_event(
                        ws,
                        ctx,
                        &verified,
                        "authenticationSuccess",
                        &json!({"status":"success"}),
                    )
                    .await?;
                }
                let event = parse_event_payload(verified.payload(), 1_048_576).map_err(|_| ())?;
                if matches!(event.event_name.as_str(), "joinRoom" | "leaveRoom") {
                    let (limiter, start) = &mut control;
                    let now = i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX);
                    if !limiter.consume(now) {
                        let mut body = json!({"reason":"WebSocket control-event rate limit exceeded","code":"ERR_WEBSOCKET_CONTROL_RATE_LIMITED"});
                        let name = if event.event_name == "joinRoom" {
                            if let Some(room) = event
                                .data
                                .as_ref()
                                .and_then(Value::as_str)
                                .filter(|r| !js_blank(r))
                            {
                                body["roomId"] = json!(room);
                            }
                            "joinFailed"
                        } else {
                            "leaveFailed"
                        };
                        send_event(ws, ctx, &verified, name, &body).await?;
                        last_verified = Some(verified);
                        continue;
                    }
                }
                match event.event_name.as_str() {
                    "authenticated" => {}
                    "sendMessage" => {
                        let (limiter, start) = &mut sends;
                        if !limiter
                            .consume(i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX))
                        {
                            send_event(ws,ctx,&verified,"messageFailed",&json!({"reason":"WebSocket send rate limit exceeded","code":"ERR_WEBSOCKET_RATE_LIMITED"})).await?;
                            last_verified = Some(verified);
                            continue;
                        }
                        let data = event.data.as_ref();
                        if data.is_some_and(Value::is_object)
                            && signed(ctx.resources.websocket_max_concurrent_sends) == 0
                        {
                            send_event(ws,ctx,&verified,"messageFailed",&json!({"reason":"Too many concurrent WebSocket sends","code":"ERR_WEBSOCKET_CONCURRENCY_LIMIT"})).await?;
                            last_verified = Some(verified);
                            continue;
                        }
                        let failure = if !data.is_some_and(Value::is_object) {
                            Some("Invalid data object")
                        } else if data
                            .and_then(|d| d.get("roomId"))
                            .and_then(Value::as_str)
                            .is_none_or(js_blank)
                        {
                            Some("Invalid room ID")
                        } else if !data
                            .and_then(|d| d.get("message"))
                            .is_some_and(Value::is_object)
                        {
                            Some("Invalid message object")
                        } else {
                            let message = &data.ok_or(())?["message"];
                            let body = message.get("body").and_then(Value::as_str);
                            let recipient = message.get("recipient").and_then(Value::as_str);
                            let identity =
                                recipient.and_then(|r| Identity::from_verified_key(r).ok());
                            let message_id = message.get("messageId").and_then(Value::as_str);
                            let room = data.ok_or(())?["roomId"].as_str().ok_or(())?;
                            if body.is_none_or(|b| {
                                !valid_message_body(b, ctx.resources.max_message_body_bytes)
                            }) {
                                Some("Invalid message body")
                            } else if identity.is_none() {
                                Some("Invalid recipient identity key")
                            } else if identity.as_ref().map(Identity::as_str) != recipient {
                                Some("Recipient identity key must use canonical encoding")
                            } else if message_id.is_none_or(|id| !valid_message_id(id)) {
                                Some("Invalid message ID")
                            } else if message_box_from_recipient_room(
                                recipient.ok_or(())?,
                                Some(&json!(room)),
                            )
                            .is_none()
                            {
                                Some("Room does not match canonical recipient and message box")
                            } else {
                                None
                            }
                        };
                        if let Some(reason) = failure {
                            send_event(
                                ws,
                                ctx,
                                &verified,
                                "messageFailed",
                                &json!({"reason":reason}),
                            )
                            .await?;
                            last_verified = Some(verified);
                            continue;
                        }
                        let data = data.ok_or(())?;
                        let room = data["roomId"].as_str().ok_or(())?;
                        let message = &data["message"];
                        let recipient = message["recipient"].as_str().ok_or(())?;
                        let message_id = message["messageId"].as_str().ok_or(())?;
                        let body = message["body"].as_str().ok_or(())?;
                        let box_name =
                            message_box_from_recipient_room(recipient, Some(&json!(room)))
                                .ok_or(())?;
                        let identity =
                            Identity::from_verified_key(verified.identity_key()).map_err(|_| ())?;
                        let result=ctx.app.handle("/sendMessage",Some(&identity),&json!({"message":{"recipient":recipient,"messageBox":box_name,"messageId":message_id,"body":body}})).await;
                        if result.status != 200 || result.body["status"] != "success" {
                            send_event(ws,ctx,&verified,&format!("sendMessageAck-{room}"),&json!({"status":"error","code":result.body["code"].as_str().unwrap_or("ERR_MESSAGE_REJECTED")})).await?;
                        } else {
                            send_event(
                                ws,
                                ctx,
                                &verified,
                                &format!("sendMessageAck-{room}"),
                                &json!({"status":"success","messageId":message_id}),
                            )
                            .await?;
                            ctx.announce(
                                identity.as_str(),
                                recipient,
                                &box_name,
                                message_id,
                                Arc::from(body),
                            )
                            .await;
                        }
                    }
                    "joinRoom" => {
                        let room = event.data.as_ref();
                        let raw = room.and_then(Value::as_str);
                        let (event, data) = if raw.is_none_or(js_blank) {
                            (
                                "joinFailed",
                                json!({"reason":"Invalid room ID","code":"ERR_WEBSOCKET_INVALID_ROOM"}),
                            )
                        } else if !is_identity_owned_room(verified.identity_key(), room) {
                            (
                                "joinFailed",
                                json!({"roomId":raw,"reason":"Room is not owned by authenticated identity","code":"ERR_WEBSOCKET_ROOM_NOT_OWNED"}),
                            )
                        } else if !ctx.routing.lock().await.registry.join(
                            id,
                            raw.ok_or(())?,
                            signed(ctx.resources.websocket_max_rooms_per_connection),
                        ) {
                            (
                                "joinFailed",
                                json!({"roomId":raw,"reason":"WebSocket room limit exceeded","code":"ERR_WEBSOCKET_ROOM_LIMIT"}),
                            )
                        } else {
                            ("joinedRoom", json!({"roomId":raw}))
                        };
                        send_event(ws, ctx, &verified, event, &data).await?;
                    }
                    "leaveRoom" => {
                        let room = event.data.as_ref();
                        let raw = room.and_then(Value::as_str);
                        let (event, data) = if raw.is_none_or(js_blank) {
                            ("leaveFailed", json!({"reason":"Invalid room ID"}))
                        } else if !is_identity_owned_room(verified.identity_key(), room) {
                            (
                                "leaveFailed",
                                json!({"reason":"Room is not owned by authenticated identity"}),
                            )
                        } else {
                            ctx.routing.lock().await.registry.leave(id, raw.ok_or(())?);
                            ("leftRoom", json!({"roomId":raw}))
                        };
                        send_event(ws, ctx, &verified, event, &data).await?;
                    }
                    _ => {}
                }
                last_verified = Some(verified);
            }
            _ => return Err(()),
        }
    }
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    use message_box_server_rust::resource_config::ResourceLimit;

    #[test]
    fn websocket_body_uses_configured_utf8_byte_limit() {
        assert!(valid_message_body("é", ResourceLimit::Finite(2)));
        assert!(!valid_message_body("é", ResourceLimit::Finite(1)));
        assert!(valid_message_body("éé", ResourceLimit::Unlimited));
        assert!(!valid_message_body(" ", ResourceLimit::Unlimited));
    }
}
