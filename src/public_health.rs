//! Public health response shapes for the restricted local runtime.
//! Readiness reflects only the message SQLite `SELECT 1` result, not wallet,
//! chain, Firebase, WebSocket, or overall production readiness.
use http::{
    Response, StatusCode,
    header::{CACHE_CONTROL, CONTENT_TYPE},
};
use serde_json::{Value, json};
fn response(status: StatusCode, body: Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(CACHE_CONTROL, "no-store")
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(serde_json::to_vec(&body).expect("static health JSON serializes"))
        .expect("static health headers are valid")
}
/// Compatibility helper for a runtime without WebSockets.
pub fn health_response(network: &str) -> Response<Vec<u8>> {
    health_response_with_websockets(network, false)
}
/// Report whether the configured WebSocket listener is enabled.
pub fn health_response_with_websockets(network: &str, websockets: bool) -> Response<Vec<u8>> {
    response(
        StatusCode::OK,
        json!({"ok":true,"status":"ok","service":"messagebox-server","network":network,"websockets":websockets}),
    )
}
/// Mirrors the pinned source's DB-only ready / not-ready response shape.
pub fn readiness_response(database_ready: bool) -> Response<Vec<u8>> {
    if database_ready {
        response(StatusCode::OK, json!({"status":"ready"}))
    } else {
        response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status":"error","code":"ERR_NOT_READY","description":"Message Box dependencies are not ready."}),
        )
    }
}
