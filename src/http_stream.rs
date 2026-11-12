//! Bounded streaming request adapter for the existing restricted HTTP handler.
//!
//! This function does not open a socket, impose connection/header timeouts,
//! configure TLS, authenticate by itself, or make the application production
//! ready. The host owns listener, request-header limits, timeouts, concurrency,
//! shutdown, TLS and trusted wallet/session-store lifecycles. Only bounded body
//! bytes are passed to the existing authentication adapter.
use crate::{
    auth_responder::{AuthSessionStore, AuthWallet},
    http_auth::{HttpAuthAdapter, MAX_BODY_BYTES},
};
use bytes::Buf;
use futures_util::TryStreamExt;
use http::{Request, Response, StatusCode, header::CONTENT_TYPE};
use http_body::Body;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use std::error::Error;
/// Collect at most [`MAX_BODY_BYTES`] of body data and dispatch the buffered
/// request. Length overrun is 413; other stream failures return 400. Trailers
/// are not used as authentication or application fields.
pub async fn handle_http_stream<W, S, B>(
    adapter: &HttpAuthAdapter<'_, W, S>,
    request: Request<B>,
) -> Response<Vec<u8>>
where
    W: AuthWallet,
    S: AuthSessionStore,
    B: Body,
    B::Data: Buf,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    match read_limited_http_body(request).await {
        Ok(request) => adapter.handle(request).await,
        Err(response) => response,
    }
}
/// Collect bounded DATA before any application dispatch. The caller may apply
/// a body-read timeout around this future without cancelling a committed write.
pub async fn read_limited_http_body<B>(
    request: Request<B>,
) -> Result<Request<Vec<u8>>, Response<Vec<u8>>>
where
    B: Body,
    B::Data: Buf,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let (parts, body) = request.into_parts();
    let body = match Limited::new(body, MAX_BODY_BYTES)
        .into_data_stream()
        .try_fold(Vec::new(), |mut collected, mut data| async move {
            while data.has_remaining() {
                let chunk = data.chunk();
                let len = chunk.len();
                collected.extend_from_slice(chunk);
                data.advance(len);
            }
            Ok(collected)
        })
        .await
    {
        Ok(value) => value,
        Err(error) => {
            let (status, message) = if error.is::<LengthLimitError>() {
                (StatusCode::PAYLOAD_TOO_LARGE,br#"{"status":"error","code":"ERR_BODY_TOO_LARGE","description":"The request body exceeds the endpoint limit."}"#.as_slice())
            } else {
                (StatusCode::BAD_REQUEST,br#"{"status":"error","code":"ERR_INVALID_BODY","description":"The request body is invalid."}"#.as_slice())
            };
            return Err(Response::builder()
                .status(status)
                .header(CONTENT_TYPE, "application/json")
                .body(message.to_vec())
                .expect("static response is valid"));
        }
    };
    Ok(Request::from_parts(parts, body))
}
