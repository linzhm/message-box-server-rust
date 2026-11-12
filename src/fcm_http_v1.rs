//! Restricted FCM HTTP v1 provider with host-injected OAuth token source and
//! HTTPS transport. This module does not read credentials, refresh tokens,
//! open sockets, initialize Firebase, or configure itself in the runtime.
//! The host must protect tokens, verify TLS/host, limit response streaming,
//! and authorize any actual data transmission to Firebase.
use crate::fcm_delivery::FcmProvider;
use serde_json::{Value, json};
use std::{future::Future, pin::Pin, sync::Arc};

/// Contains an OAuth bearer credential: do not log, persist, or expose it.
pub struct FcmHttpRequest {
    pub method: http::Method,
    pub content_type: &'static str,
    pub url: String,
    pub authorization: String,
    pub body: Value,
}
pub struct FcmHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}
/// The source owns OAuth acquisition, expiry, refresh and credential protection.
pub trait OAuthTokenSource: Send + Sync {
    fn token<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;
}
/// The host must perform a POST to the given HTTPS endpoint using JSON content
/// type and the supplied authorization header, with TLS and bounded streaming.
pub trait FcmHttpTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: FcmHttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<FcmHttpResponse, String>> + Send + 'a>>;
}
pub struct FirebaseV1Provider {
    url: String,
    tokens: Arc<dyn OAuthTokenSource>,
    transport: Arc<dyn FcmHttpTransport>,
}
impl FirebaseV1Provider {
    /// Construct a provider for a restricted ASCII project ID/number.
    pub fn new(
        project: &str,
        tokens: Arc<dyn OAuthTokenSource>,
        transport: Arc<dyn FcmHttpTransport>,
    ) -> Result<Self, &'static str> {
        if project.is_empty()
            || project.len() > 128
            || !project
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err("invalid Firebase project identifier");
        }
        Ok(Self {
            url: format!("https://fcm.googleapis.com/v1/projects/{project}/messages:send"),
            tokens,
            transport,
        })
    }
}
impl FcmProvider for FirebaseV1Provider {
    fn send<'a>(
        &'a self,
        message: Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            const FAILURE: &str = "FCM request failed";
            let token = self.tokens.token().await.map_err(|_| FAILURE.to_owned())?;
            if token.is_empty()
                || !token.bytes().all(|b| b.is_ascii_graphic())
                || http::HeaderValue::from_str(&format!("Bearer {token}")).is_err()
            {
                return Err(FAILURE.into());
            }
            let response = self
                .transport
                .execute(FcmHttpRequest {
                    method: http::Method::POST,
                    content_type: "application/json",
                    url: self.url.clone(),
                    authorization: format!("Bearer {token}"),
                    body: json!({"message":message}),
                })
                .await
                .map_err(|_| FAILURE.to_owned())?;
            if response.body.len() > 65_536 {
                return Err(FAILURE.into());
            }
            let value: Value =
                serde_json::from_slice(&response.body).map_err(|_| FAILURE.to_owned())?;
            if response.status == 200
                && value
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| !name.is_empty())
            {
                return Ok(());
            }
            let error = &value["error"];
            let unregistered = response.status == 404
                && error["code"].as_u64() == Some(404)
                && error["status"].as_str() == Some("NOT_FOUND")
                && error["details"].as_array().is_some_and(|details| {
                    details.iter().any(|item| {
                        item["@type"] == "type.googleapis.com/google.firebase.fcm.v1.FcmError"
                            && item["errorCode"] == "UNREGISTERED"
                    })
                });
            if unregistered {
                Err("registration-token-not-registered".into())
            } else {
                Err(FAILURE.into())
            }
        })
    }
}
