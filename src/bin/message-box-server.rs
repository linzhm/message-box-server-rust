//! Explicitly configured loopback-only MessageBox HTTP runtime.
//! This is not an upstream-compatible production deployment: the optional
//! Socket.IO supports default text events; listener TLS, certificates and payment are not implemented.
mod runtime_cors;
mod runtime_ws;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use message_box_server_rust::{
    MessageBox,
    auth_responder::AuthWallet,
    auth_store::{AuthStoreOptions, SqliteAuthSessionStore},
    firebase_host::assemble_host_firebase,
    http_auth::{CommittedDeliveries, HttpAuthAdapter, RoutingPrefix, normalize_initial_slashes},
    http_stream::read_limited_http_body,
    local_auth_wallet::LocalAuthWallet,
    public_health::{health_response_with_websockets, readiness_response},
    resource_config::{EnvironmentSnapshot, ResourceConfig},
    runtime_config::{
        FreeBoxPolicy, PricingMode, RuntimeConfig, TsTableAdmission, load_identity_key,
        prepare_private_database, prepare_private_directory,
    },
    runtime_resources::RuntimeResources,
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
};
struct State {
    app: Arc<MessageBox>,
    wallet: Arc<LocalAuthWallet>,
    sessions: SqliteAuthSessionStore,
    network_label: String,
    routing_prefix: RoutingPrefix,
    ws: Option<Arc<runtime_ws::Context>>,
    ws_jobs: mpsc::Sender<runtime_ws::Job>,
    permits: Arc<Semaphore>,
    cors: message_box_server_rust::runtime_config::CorsConfig,
}
async fn handle(
    req: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let cors = match runtime_cors::CorsResponse::from_request(&req, &state.cors) {
        runtime_cors::Decision::NoOrigin => None,
        runtime_cors::Decision::Allowed(cors) => Some(cors),
        runtime_cors::Decision::Denied => {
            let body = br#"{"status":"error","code":"ERR_ORIGIN_NOT_ALLOWED","description":"The request origin is not allowed."}"#;
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(
                    http::header::CONTENT_TYPE,
                    "application/json; charset=utf-8",
                )
                .body(Full::new(Bytes::from_static(body)))
                .expect("static response"));
        }
    };
    if let Some(response) = cors
        .as_ref()
        .and_then(|cors| cors.preflight(req.method(), Full::new(Bytes::new())))
    {
        return Ok(response);
    }
    if let Some(ws) = &state.ws
        && req.uri().path() == "/socket.io/"
    {
        let mut response = runtime_ws::request(req, ws, &state.ws_jobs, &state.permits).await;
        if let Some(cors) = &cors {
            cors.apply(&mut response);
        }
        return Ok(response);
    }
    let adapter = HttpAuthAdapter::new(&state.app, state.wallet.as_ref(), &state.sessions)
        .with_routing_prefix(&state.routing_prefix);
    let mut response =
        match tokio::time::timeout(Duration::from_secs(60), read_limited_http_body(req)).await {
            Ok(Ok(request)) => {
                let head = request.method() == http::Method::HEAD;
                let health_method = request.method() == http::Method::GET || head;
                let health_path = state
                    .routing_prefix
                    .strip(normalize_initial_slashes(request.uri().path()));
                if health_method && matches!(health_path, Some("/health" | "/healthz" | "/ready")) {
                    let mut response = match health_path.unwrap_or("") {
                        "/health" | "/healthz" => health_response_with_websockets(
                            &state.network_label,
                            state.ws.is_some(),
                        ),
                        "/ready" => readiness_response(state.app.database_ready().await),
                        _ => unreachable!(),
                    };
                    if head {
                        let length = response.body().len();
                        response.headers_mut().insert(
                            http::header::CONTENT_LENGTH,
                            http::HeaderValue::from_str(&length.to_string())
                                .expect("length is a valid header"),
                        );
                        response.body_mut().clear();
                    }
                    response
                } else {
                    adapter.handle(request).await
                }
            }
            Ok(Err(response)) => response,
            Err(_) => Response::builder()
                .status(StatusCode::REQUEST_TIMEOUT)
                .body(Vec::new())
                .expect("static timeout response is valid"),
        };
    if let Some(deliveries) = response.extensions_mut().remove::<CommittedDeliveries>()
        && let Some(ws) = &state.ws
    {
        for delivery in deliveries.0 {
            ws.announce(
                &delivery.sender,
                &delivery.recipient,
                &delivery.message_box,
                &delivery.message_id,
                delivery.body,
            )
            .await;
        }
    }
    if let Some(cors) = cors {
        cors.apply(&mut response);
    }
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, Full::new(Bytes::from(body))))
}
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("MessageBox startup or runtime failed; check configuration and data access.");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let path = args.next().ok_or("configuration path required")?;
    if args.next().is_some() {
        return Err("unexpected arguments".into());
    }
    let bytes = std::fs::read(path)?;
    if bytes.len() > 1024 * 1024 {
        return Err("configuration too large".into());
    }
    let value = serde_json::from_slice(&bytes)?;
    // Parse and validate one immutable startup snapshot before creating any files.
    let environment: EnvironmentSnapshot = std::env::vars().collect();
    let config = RuntimeConfig::parse_with_environment(&value, &environment)
        .map_err(|_| "invalid configuration")?;
    let resources = RuntimeResources::new(ResourceConfig::from_snapshot(&environment)?)?;
    let maintenance_config =
        message_box_server_rust::runtime_resources::MaintenanceConfig::from_snapshot(&environment)?;
    let key = load_identity_key(&config.identity_key_file)
        .map_err(|_| "identity key unavailable or invalid")?;
    prepare_private_directory(&config.data_dir)?;
    prepare_private_database(&config.data_dir.join("messages.sqlite"))?;
    prepare_private_database(&config.data_dir.join("auth.sqlite"))?;
    let wallet = Arc::new(LocalAuthWallet::new(key));
    let identity = wallet
        .identity_key()
        .await
        .map_err(|_| "identity unavailable")?;
    let policy: Arc<dyn message_box_server_rust::DeliveryPolicy> = match config.pricing_mode {
        PricingMode::FreeBoxes => Arc::new(FreeBoxPolicy::new(config.free_boxes)),
        PricingMode::TsTable => Arc::new(TsTableAdmission),
    };
    let app = MessageBox::open_with_resources(
        config.data_dir.join("messages.sqlite"),
        policy,
        resources.clone(),
    )
    .await?;
    let app = match config.pricing_mode {
        PricingMode::FreeBoxes => app,
        PricingMode::TsTable => app.with_sqlite_server_fees().await?,
    };
    let app = assemble_host_firebase(app, &environment)?;
    let app = Arc::new(app);
    let sessions = SqliteAuthSessionStore::open(
        config.data_dir.join("auth.sqlite"),
        AuthStoreOptions::default(),
    )
    .await
    .map_err(|_| "session store unavailable")?;
    let ws = if config.enable_websockets {
        prepare_private_database(&config.data_dir.join("ws-auth.sqlite"))?;
        let sessions = SqliteAuthSessionStore::open(
            config.data_dir.join("ws-auth.sqlite"),
            AuthStoreOptions::default(),
        )
        .await
        .map_err(|_| "websocket session store unavailable")?;
        Some(Arc::new(runtime_ws::Context {
            transports: Default::default(),
            wallet: Arc::clone(&wallet),
            sessions,
            app: Arc::clone(&app),
            routing: tokio::sync::Mutex::new(Default::default()),
            resources: resources.config.clone(),
        }))
    } else {
        None
    };
    let permits = Arc::new(Semaphore::new(1_000));
    let (ws_jobs, mut ws_receiver) = mpsc::channel(1000);
    let state = Arc::new(State {
        app,
        wallet,
        sessions,
        network_label: std::env::var("BSV_NETWORK").unwrap_or_else(|_| "mainnet".to_owned()),
        routing_prefix: config.routing_prefix,
        ws,
        ws_jobs,
        permits: Arc::clone(&permits),
        cors: config.cors,
    });
    let listener = TcpListener::bind(config.bind).await?;
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    #[cfg(not(unix))]
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(not(unix))]
    tokio::pin!(interrupt);
    println!(
        "{}",
        serde_json::json!({"status":"ready","address":listener.local_addr()?.to_string(),"identityKey":identity})
    );
    // TS runs once at startup even when the periodic timer is disabled.
    let mut maintenance = maintenance_config
        .timer_duration()
        .map(tokio::time::interval);
    let mut initial_maintenance = true;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            result = async {
                #[cfg(unix)]
                { interrupt.recv().await.ok_or_else(|| std::io::Error::other("interrupt stream closed")) }
                #[cfg(not(unix))]
                { interrupt.as_mut().await }
            } => { result?; break; }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { drop(stream); continue; };
                let state = Arc::clone(&state);
                let mut shutdown = shutdown_rx.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let service = service_fn(move |request| handle(request, Arc::clone(&state)));
                    let mut builder = http1::Builder::new();
                    builder.max_headers(1000).timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(15));
                    let connection = builder.serve_connection(TokioIo::new(stream), service).with_upgrades();
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {}
                        changed = shutdown.changed() => {
                            if changed.is_ok() && *shutdown.borrow() {
                                connection.as_mut().graceful_shutdown();
                                let _ = connection.await;
                            }
                        }
                    }
                });
            }
            Some(job)=ws_receiver.recv()=>{
                if let Some(ws)=&state.ws {
                    let ws=Arc::clone(ws);let shutdown=shutdown_rx.clone();
                    connections.spawn(async move {runtime_ws::serve(job,ws,shutdown).await;});
                }
            }
            _ = async {
                if initial_maintenance { return; }
                match &mut maintenance {
                    Some(timer) => { timer.tick().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                if initial_maintenance {
                    initial_maintenance = false;
                    if let Some(timer) = &mut maintenance { timer.reset(); }
                }
                if state.app.purge_expired_batch(maintenance_config.batch_size).await.is_err() { eprintln!("Message expiration cleanup failed."); }
                if state.sessions.prune_expired_batch(maintenance_config.batch_size).await.is_err() { eprintln!("Authentication expiration cleanup failed."); }
                if let Some(ws)=&state.ws && ws.sessions.prune_expired_batch(maintenance_config.batch_size).await.is_err(){eprintln!("WebSocket authentication expiration cleanup failed.");}
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    drop(listener);
    let _ = shutdown_tx.send(true);
    if tokio::time::timeout(Duration::from_secs(5), async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    let state = Arc::try_unwrap(state).map_err(|_| "connections did not release state")?;
    state.sessions.close().await;
    if let Some(ws) = state.ws {
        let ws = Arc::try_unwrap(ws).map_err(|_| "WebSocket tasks did not release state")?;
        ws.sessions.close().await;
        drop(ws.app);
    }
    Arc::try_unwrap(state.app)
        .map_err(|_| "WebSocket tasks did not release app")?
        .close()
        .await;
    Ok(())
}
