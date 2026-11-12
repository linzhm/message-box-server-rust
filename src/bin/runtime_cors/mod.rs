//! Fixed public HTTP CORS profile from MessageBox TS 52d36a5 edgePolicy.ts.
//! Explicit runtime JSON modes select the TS public, allowlist or disabled behavior.
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use message_box_server_rust::runtime_config::{CorsConfig, CorsMode, normalize_cors_origin};

const ALLOWED: &str = "Accept, Authorization, Content-Type, If-None-Match, X-BSV-Action-Batch-Encoding, X-BSV-Auth-Identity-Key, X-BSV-Auth-Message-Type, X-BSV-Auth-Nonce, X-BSV-Auth-Request-ID, X-BSV-Auth-Requested-Certificates, X-BSV-Auth-Signature, X-BSV-Auth-Version, X-BSV-Auth-Your-Nonce, X-BSV-Binary-Encoding, X-BSV-Binary-Request-Encoding, X-BSV-Payment, X-BSV-Topic, X-Aggregation, X-Callback-Token, X-Includes-Off-Chain-Values, X-Topics";
const EXPOSED: &str = "ETag, RateLimit, RateLimit-Policy, Retry-After, X-BSV-Auth-Identity-Key, X-BSV-Auth-Message-Type, X-BSV-Auth-Nonce, X-BSV-Auth-Request-ID, X-BSV-Auth-Requested-Certificates, X-BSV-Auth-Signature, X-BSV-Auth-Version, X-BSV-Auth-Your-Nonce, X-BSV-Binary-Encoding, X-BSV-Payment-Derivation-Prefix, X-BSV-Payment-Satoshis-Paid, X-BSV-Payment-Satoshis-Required, X-BSV-Payment-Version";

pub struct CorsResponse {
    allowed: HeaderValue,
    origin: HeaderValue,
    vary: bool,
    exposed: HeaderValue,
}

pub enum Decision {
    NoOrigin,
    Allowed(CorsResponse),
    Denied,
}
impl CorsResponse {
    pub fn from_request<B>(request: &Request<B>, config: &CorsConfig) -> Decision {
        let Some(origin) = request.headers().get(http::header::ORIGIN) else {
            return Decision::NoOrigin;
        };
        if origin.is_empty() {
            return Decision::NoOrigin;
        }
        let (origin, vary) = match &config.mode {
            CorsMode::Public => (HeaderValue::from_static("*"), false),
            CorsMode::Disabled => return Decision::Denied,
            CorsMode::Allowlist(origins) => {
                let Some(normalized) = origin.to_str().ok().and_then(normalize_cors_origin) else {
                    return Decision::Denied;
                };
                let Some(configured) = origins.iter().find(|candidate| **candidate == normalized)
                else {
                    return Decision::Denied;
                };
                (
                    HeaderValue::from_str(configured).expect("normalized origin"),
                    true,
                )
            }
        };
        let mut names: Vec<&str> = config
            .allowed_headers
            .as_deref()
            .unwrap_or(ALLOWED)
            .split(", ")
            .collect();
        if config.allowed_headers.is_none()
            && let Some(requested) = request
                .headers()
                .get(http::header::ACCESS_CONTROL_REQUEST_HEADERS)
                .and_then(|h| h.to_str().ok())
        {
            for name in requested.split(',').map(str::trim) {
                if HeaderName::from_bytes(name.as_bytes()).is_ok()
                    && !names
                        .iter()
                        .any(|existing| existing.eq_ignore_ascii_case(name))
                {
                    names.push(name);
                }
            }
        }
        Decision::Allowed(Self {
            allowed: HeaderValue::from_str(&names.join(", ")).expect("validated header names"),
            origin,
            vary,
            exposed: HeaderValue::from_str(config.exposed_headers.as_deref().unwrap_or(EXPOSED))
                .expect("validated headers"),
        })
    }
    pub fn apply<B>(&self, response: &mut Response<B>) {
        let headers: &mut HeaderMap = response.headers_mut();
        headers.insert(
            http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            self.origin.clone(),
        );
        if self.vary {
            headers.append(http::header::VARY, HeaderValue::from_static("Origin"));
        }
        headers.insert(
            http::header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        headers.insert(
            http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            self.allowed.clone(),
        );
        headers.insert(
            http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
            self.exposed.clone(),
        );
        headers.insert(
            http::header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
    }
    pub fn preflight<B>(&self, method: &Method, body: B) -> Option<Response<B>> {
        if method != Method::OPTIONS {
            return None;
        }
        let mut response = Response::new(body);
        *response.status_mut() = StatusCode::NO_CONTENT;
        self.apply(&mut response);
        Some(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use message_box_server_rust::runtime_config::{CorsConfig, CorsMode};

    #[test]
    fn strict_headers_do_not_reflect_and_custom_exposure_is_used() {
        let config = CorsConfig {
            mode: CorsMode::Public,
            allowed_headers: Some("X-Allowed".into()),
            exposed_headers: Some("X-Reply".into()),
        };
        let request = Request::builder()
            .method(Method::OPTIONS)
            .header("origin", "null")
            .header("access-control-request-headers", "X-Other")
            .body(())
            .unwrap();
        let Decision::Allowed(cors) = CorsResponse::from_request(&request, &config) else {
            panic!("expected allowed")
        };
        let response = cors.preflight(request.method(), ()).unwrap();
        assert_eq!(
            response.headers()[http::header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "*"
        );
        assert_eq!(
            response.headers()[http::header::ACCESS_CONTROL_ALLOW_HEADERS],
            "X-Allowed"
        );
        assert_eq!(
            response.headers()[http::header::ACCESS_CONTROL_EXPOSE_HEADERS],
            "X-Reply"
        );
        assert!(
            !response
                .headers()
                .contains_key(http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
        );
    }

    #[test]
    fn default_reflection_is_case_insensitive_and_validates_tokens() {
        let config = CorsConfig {
            mode: CorsMode::Public,
            allowed_headers: None,
            exposed_headers: None,
        };
        let request = Request::builder()
            .header("origin", "https://example.test")
            .header(
                "access-control-request-headers",
                "authorization, X-New, x-new, bad name",
            )
            .body(())
            .unwrap();
        let Decision::Allowed(cors) = CorsResponse::from_request(&request, &config) else {
            panic!("expected allowed")
        };
        let mut response = Response::new(());
        cors.apply(&mut response);
        let value = response.headers()[http::header::ACCESS_CONTROL_ALLOW_HEADERS]
            .to_str()
            .unwrap();
        assert!(value.contains("X-New"));
        assert!(!value.contains("x-new"));
        assert!(!value.contains("bad name"));
        assert_eq!(
            value.to_ascii_lowercase().matches("authorization").count(),
            1
        );
    }

    #[test]
    fn allowlist_request_accepts_empty_delimiters_and_rejects_nonempty_values() {
        let config = CorsConfig {
            mode: CorsMode::Allowlist(vec!["https://example.test".into()]),
            allowed_headers: None,
            exposed_headers: None,
        };
        for origin in [
            "https://example.test?",
            "https://example.test#",
            "https://example.test?#",
        ] {
            let request = Request::builder()
                .header("origin", origin)
                .body(())
                .unwrap();
            let Decision::Allowed(cors) = CorsResponse::from_request(&request, &config) else {
                panic!("{origin}")
            };
            let mut response = Response::new(());
            cors.apply(&mut response);
            assert_eq!(
                response.headers()[http::header::ACCESS_CONTROL_ALLOW_ORIGIN],
                "https://example.test"
            );
        }
        for origin in ["https://example.test?x", "https://example.test#x"] {
            let request = Request::builder()
                .header("origin", origin)
                .body(())
                .unwrap();
            assert!(
                matches!(
                    CorsResponse::from_request(&request, &config),
                    Decision::Denied
                ),
                "{origin}"
            );
        }
    }
}
