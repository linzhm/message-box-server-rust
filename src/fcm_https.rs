//! FCM HTTP v1 HTTPS transport with a host-owned client and no credential source.
use crate::fcm_http_v1::{FcmHttpRequest, FcmHttpResponse, FcmHttpTransport};
use std::{future::Future, pin::Pin};

/// HTTPS transport for the HTTP v1 adapter. No credentials are acquired here.
/// Its default client verifies TLS, disallows redirects and uses a total timeout.
pub struct FcmHttpsTransport {
    client: reqwest::Client,
}
impl FcmHttpsTransport {
    pub fn new(timeout: std::time::Duration) -> Result<Self, &'static str> {
        Self::with_trusted_builder(reqwest::Client::builder(), timeout)
    }
    /// The caller must trust its builder's TLS roots, DNS and proxy settings.
    /// Rustls, certificate and hostname verification, HTTPS-only, no redirects,
    /// and the total timeout are enforced by this method.
    pub fn with_trusted_builder(
        builder: reqwest::ClientBuilder,
        timeout: std::time::Duration,
    ) -> Result<Self, &'static str> {
        if timeout.is_zero() {
            return Err("invalid FCM timeout");
        }
        let client = builder
            .use_rustls_tls()
            .danger_accept_invalid_certs(false)
            .danger_accept_invalid_hostnames(false)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| "FCM HTTP client unavailable")?;
        Ok(Self { client })
    }
}
impl FcmHttpTransport for FcmHttpsTransport {
    fn execute<'a>(
        &'a self,
        request: FcmHttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<FcmHttpResponse, String>> + Send + 'a>> {
        Box::pin(async move {
            const FAILURE: &str = "FCM request failed";
            const LIMIT: usize = 65_536;
            let url = url::Url::parse(&request.url).map_err(|_| FAILURE.to_owned())?;
            let project = url
                .path()
                .strip_prefix("/v1/projects/")
                .and_then(|s| s.strip_suffix("/messages:send"))
                .ok_or_else(|| FAILURE.to_owned())?;
            if request.method != http::Method::POST
                || request.content_type != "application/json"
                || url.scheme() != "https"
                || url.host_str() != Some("fcm.googleapis.com")
                || url.port().is_some()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || project.is_empty()
                || project.len() > 128
                || !project
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                return Err(FAILURE.into());
            }
            let body = serde_json::to_vec(&request.body).map_err(|_| FAILURE.to_owned())?;
            let mut response = self
                .client
                .post(url)
                .header(reqwest::header::AUTHORIZATION, request.authorization)
                .header(reqwest::header::CONTENT_TYPE, request.content_type)
                .body(body)
                .send()
                .await
                .map_err(|_| FAILURE.to_owned())?;
            if response
                .content_length()
                .is_some_and(|length| length > LIMIT as u64)
            {
                return Err(FAILURE.into());
            }
            let status = response.status().as_u16();
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| FAILURE.to_owned())? {
                if chunk.len() > LIMIT - body.len() {
                    return Err(FAILURE.into());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(FcmHttpResponse { status, body })
        })
    }
}
