//! One bounded Engine.IO session survives polling -> WebSocket upgrade.
//! Application authentication and rooms belong to that session, never an HTTP request.
use super::Context;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Incoming,
    upgrade::{OnUpgrade, Upgraded},
};
use hyper_util::rt::TokioIo;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        protocol::{Role, WebSocketConfig},
    },
};

const MAX_PAYLOAD: usize = 1_048_576;
const POLLING: u8 = 0;
const PROBING: u8 = 1;
const UPGRADED: u8 = 2;
const CLOSED: u8 = 3;
type Socket = WebSocketStream<TokioIo<Upgraded>>;
#[derive(Default)]
pub struct TransportSessions(Mutex<HashMap<String, Arc<PollSession>>>);
pub struct PollSession {
    input: mpsc::Sender<Message>,
    output: Mutex<mpsc::Receiver<Message>>,
    posting: Mutex<()>,
    upgrade: mpsc::Sender<Socket>,
    state: AtomicU8,
    changed: Notify,
}
impl TransportSessions {
    pub async fn remove(&self, id: &str) {
        if let Some(session) = self.0.lock().await.remove(id) {
            session.state.store(CLOSED, Ordering::SeqCst);
            session.changed.notify_waiters();
        }
    }
}
pub enum Job {
    Poll {
        endpoint: Box<Endpoint>,
        id: String,
        permit: OwnedSemaphorePermit,
    },
    WebSocket {
        upgrade: OnUpgrade,
        id: String,
        session: Option<Arc<PollSession>>,
        permit: OwnedSemaphorePermit,
    },
}
pub struct Endpoint {
    socket: Option<Socket>,
    polling: Option<Arc<PollSession>>,
    input: mpsc::Receiver<Message>,
    output: mpsc::Sender<Message>,
    upgrade: mpsc::Receiver<Socket>,
}
fn channels() -> (Endpoint, Arc<PollSession>) {
    let (input_tx, input) = mpsc::channel(32);
    let (output, output_rx) = mpsc::channel(32);
    let (upgrade_tx, upgrade) = mpsc::channel(1);
    let session = Arc::new(PollSession {
        input: input_tx,
        output: Mutex::new(output_rx),
        posting: Mutex::new(()),
        upgrade: upgrade_tx,
        state: AtomicU8::new(POLLING),
        changed: Notify::new(),
    });
    (
        Endpoint {
            socket: None,
            polling: Some(session.clone()),
            input,
            output,
            upgrade,
        },
        session,
    )
}
impl Job {
    pub async fn open(
        self,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Option<(Endpoint, String, OwnedSemaphorePermit)> {
        match self {
            Self::Poll {
                endpoint,
                id,
                permit,
            } => Some((*endpoint, id, permit)),
            Self::WebSocket {
                upgrade,
                id,
                session,
                permit,
            } => {
                let result = tokio::select! { result=tokio::time::timeout(Duration::from_secs(10), upgrade)=>result, _=shutdown.changed()=>return None };
                let socket = match result {
                    Ok(Ok(upgraded)) => {
                        WebSocketStream::from_raw_socket(
                            TokioIo::new(upgraded),
                            Role::Server,
                            Some(WebSocketConfig {
                                max_message_size: Some(MAX_PAYLOAD),
                                max_frame_size: Some(MAX_PAYLOAD),
                                ..Default::default()
                            }),
                        )
                        .await
                    }
                    _ => {
                        if let Some(session) = session {
                            session
                                .state
                                .compare_exchange(
                                    PROBING,
                                    POLLING,
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                )
                                .ok();
                        }
                        return None;
                    }
                };
                if let Some(session) = session {
                    let result = tokio::select! { result=tokio::time::timeout(Duration::from_secs(10), probe(socket, &session))=>matches!(result,Ok(Ok(()))), _=shutdown.changed()=>false };
                    if !result {
                        session
                            .state
                            .compare_exchange(PROBING, POLLING, Ordering::SeqCst, Ordering::SeqCst)
                            .ok();
                    }
                    None
                } else {
                    let (mut endpoint, _) = channels();
                    endpoint.polling = None;
                    endpoint.socket = Some(socket);
                    Some((endpoint, id, permit))
                }
            }
        }
    }
}
async fn probe(mut socket: Socket, session: &PollSession) -> Result<(), ()> {
    match socket.next().await {
        Some(Ok(Message::Text(packet))) if packet == "2probe" => {}
        _ => return Err(()),
    }
    socket
        .send(Message::Text("3probe".into()))
        .await
        .map_err(|_| ())?;
    // Release an outstanding long poll so the client can pause polling before sending 5.
    session.changed.notify_waiters();
    match socket.next().await {
        Some(Ok(Message::Text(packet))) if packet == "5" => {}
        _ => return Err(()),
    }
    session.upgrade.try_send(socket).map_err(|_| ())?;
    Ok(())
}
impl Endpoint {
    pub fn upgrades(&self) -> Vec<&str> {
        if self.polling.is_some() {
            vec!["websocket"]
        } else {
            vec![]
        }
    }
    pub async fn send(&mut self, packet: Message) -> Result<(), ()> {
        self.flush_pending().await?;
        if let Some(socket) = &mut self.socket {
            socket.send(packet).await.map_err(|_| ())
        } else {
            self.output.try_send(packet).map_err(|_| ())
        }
    }
    pub async fn flush(&mut self) -> Result<(), ()> {
        if let Some(socket) = &mut self.socket {
            socket.flush().await.map_err(|_| ())
        } else {
            Ok(())
        }
    }
    async fn flush_pending(&mut self) -> Result<(), ()> {
        if let (Some(socket), Some(session)) = (&mut self.socket, &self.polling) {
            let mut queued = session.output.lock().await;
            while let Ok(packet) = queued.try_recv() {
                socket.send(packet).await.map_err(|_| ())?;
            }
        }
        Ok(())
    }
    pub async fn next(&mut self) -> Option<Result<Message, ()>> {
        if self.flush_pending().await.is_err() {
            return Some(Err(()));
        }
        if let Some(socket) = &mut self.socket {
            // POST acknowledgement can precede application processing during upgrade.
            if let Ok(packet) = self.input.try_recv() {
                return Some(Ok(packet));
            }
            return socket.next().await.map(|r| r.map_err(|_| ()));
        }
        let session = self.polling.as_ref()?;
        let changed = session.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if session.state.load(Ordering::SeqCst) == CLOSED {
            return None;
        }
        tokio::select! {
            packet=self.input.recv()=>packet.map(Ok),
            _=&mut changed=>Some(Ok(Message::Pong(Vec::new()))),
            socket=self.upgrade.recv()=>{
                self.socket=Some(socket?);
                session.state.store(UPGRADED,Ordering::SeqCst);
                session.changed.notify_waiters();
                // Store the socket before yielding: next() is cancellation-safe in select!.
                Some(Ok(Message::Pong(Vec::new())))
            }
        }
    }
    pub async fn close(&mut self) {
        if let Some(session) = &self.polling {
            session.state.store(CLOSED, Ordering::SeqCst);
            session.changed.notify_waiters();
        }
        if let Some(socket) = &mut self.socket {
            let _ = tokio::time::timeout(Duration::from_secs(1), socket.close(None)).await;
        }
    }
}
fn response(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=UTF-8")
        .header("cache-control", "no-store")
        .body(Full::new(body.into()))
        .expect("static response")
}
fn bad() -> Response<Full<Bytes>> {
    response(StatusCode::BAD_REQUEST, "invalid Engine.IO request")
}
fn new_id() -> Result<String, ()> {
    let mut bytes = [0u8; 18];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}
fn query(uri: &http::Uri) -> Option<(String, Option<String>)> {
    let pairs: Vec<_> = url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()).collect();
    let one = |key: &str| {
        let values: Vec<_> = pairs.iter().filter(|(k, _)| k == key).collect();
        if values.len() == 1 {
            Some(values[0].1.to_string())
        } else {
            None
        }
    };
    if one("EIO").as_deref() != Some("4") {
        return None;
    }
    let transport = one("transport")?;
    if !matches!(transport.as_str(), "polling" | "websocket") {
        return None;
    }
    let sid = if pairs.iter().any(|(k, _)| k == "sid") {
        Some(one("sid").filter(|s| !s.is_empty())?)
    } else {
        None
    };
    Some((transport, sid))
}
// The caller applies its existing CORS decision before calling this function,
// and decorates every response (including errors and 101) afterward.
pub async fn request(
    mut req: Request<Incoming>,
    ctx: &Arc<Context>,
    jobs: &mpsc::Sender<Job>,
    permits: &Arc<Semaphore>,
) -> Response<Full<Bytes>> {
    let Some((transport, sid)) = query(req.uri()) else {
        return bad();
    };
    let existing = if let Some(id) = &sid {
        match ctx.transports.0.lock().await.get(id).cloned() {
            Some(session) => Some(session),
            None => return bad(),
        }
    } else {
        None
    };
    if transport == "websocket" {
        let mut keys = req.headers().get_all("sec-websocket-key").iter();
        let valid = keys.next().and_then(|v| v.to_str().ok()).is_some_and(|v| {
            STANDARD
                .decode(v)
                .ok()
                .is_some_and(|b| b.len() == 16 && STANDARD.encode(b) == v)
        }) && keys.next().is_none();
        if !valid {
            return bad();
        }
        let mut head = Request::builder()
            .method(req.method())
            .uri(req.uri())
            .version(req.version())
            .body(())
            .expect("request");
        *head.headers_mut() = req.headers().clone();
        let Ok(reply) = tokio_tungstenite::tungstenite::handshake::server::create_response(&head)
        else {
            return bad();
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            return response(StatusCode::SERVICE_UNAVAILABLE, "capacity");
        };
        let id = match sid {
            Some(id) => id,
            None => match new_id() {
                Ok(id) => id,
                Err(()) => return bad(),
            },
        };
        if let Some(session) = &existing
            && session
                .state
                .compare_exchange(POLLING, PROBING, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return bad();
        }
        let job = Job::WebSocket {
            upgrade: hyper::upgrade::on(&mut req),
            id,
            session: existing.clone(),
            permit,
        };
        if jobs.try_send(job).is_err() {
            if let Some(session) = existing {
                session.state.store(POLLING, Ordering::SeqCst);
            }
            return response(StatusCode::SERVICE_UNAVAILABLE, "capacity");
        }
        let (parts, _) = reply.into_parts();
        return Response::from_parts(parts, Full::new(Bytes::new()));
    }
    let session = if let Some(session) = existing {
        session
    } else {
        if req.method() != Method::GET {
            return bad();
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            return response(StatusCode::SERVICE_UNAVAILABLE, "capacity");
        };
        let Ok(id) = new_id() else {
            return bad();
        };
        let (endpoint, session) = channels();
        ctx.transports
            .0
            .lock()
            .await
            .insert(id.clone(), session.clone());
        if jobs
            .try_send(Job::Poll {
                endpoint: Box::new(endpoint),
                id: id.clone(),
                permit,
            })
            .is_err()
        {
            ctx.transports.remove(&id).await;
            return response(StatusCode::SERVICE_UNAVAILABLE, "capacity");
        }
        session
    };
    if session.state.load(Ordering::SeqCst) >= UPGRADED {
        return bad();
    }
    match *req.method() {
        Method::GET => poll(&session).await,
        Method::POST => {
            let Ok(_posting) = session.posting.try_lock() else {
                session.state.store(CLOSED, Ordering::SeqCst);
                session.changed.notify_waiters();
                return bad();
            };
            let data = tokio::time::timeout(
                Duration::from_secs(20),
                Limited::new(req.into_body(), MAX_PAYLOAD).collect(),
            )
            .await;
            let Ok(Ok(data)) = data else {
                return bad();
            };
            let bytes = data.to_bytes();
            let Ok(text) = std::str::from_utf8(&bytes) else {
                return bad();
            };
            if text.is_empty() {
                return bad();
            }
            for packet in text.split('\u{1e}') {
                if packet.is_empty()
                    || session
                        .input
                        .try_send(Message::Text(packet.to_owned()))
                        .is_err()
                {
                    return bad();
                }
            }
            response(StatusCode::OK, "ok")
        }
        _ => bad(),
    }
}
async fn poll(session: &PollSession) -> Response<Full<Bytes>> {
    let Ok(mut output) = session.output.try_lock() else {
        session.state.store(CLOSED, Ordering::SeqCst);
        session.changed.notify_waiters();
        return bad();
    };
    let changed = session.changed.notified();
    tokio::pin!(changed);
    changed.as_mut().enable();
    if session.state.load(Ordering::SeqCst) >= UPGRADED {
        return bad();
    }
    if session.state.load(Ordering::SeqCst) == PROBING {
        return response(StatusCode::OK, "6");
    }
    let packet = tokio::select! {
        packet=output.recv()=>packet,
        _=&mut changed=>return response(StatusCode::OK,if session.state.load(Ordering::SeqCst)==CLOSED {"1"} else {"6"}),
        _=tokio::time::sleep(Duration::from_secs(30))=>return response(StatusCode::OK,"6"),
    };
    match packet {
        Some(Message::Text(text)) => response(StatusCode::OK, text),
        _ => response(StatusCode::OK, "1"),
    }
}

#[cfg(test)]
mod tests;
