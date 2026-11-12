//! Firebase host adapter with service-account OAuth and standard ADC discovery.
//! Never log or persist credential material or access tokens.
use crate::{
    MessageBox,
    fcm_delivery::FcmProvider,
    fcm_http_v1::{FcmHttpTransport, FirebaseV1Provider, OAuthTokenSource},
    fcm_https::FcmHttpsTransport,
    firebase_adc::{AdcSource, FCM_SCOPE, GoogleTokenSource, discover},
    firebase_init::{
        FirebaseAssemblyError, FirebaseBackend, FirebaseBackendError, FirebaseInitError,
        assemble_firebase,
    },
    resource_config::EnvironmentSnapshot,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::{Value, json};
use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const FAILURE: &str = "Firebase credential operation failed";

/// The exchange is injectable for tests; implementations must not log assertions.
pub trait TokenExchange: Send + Sync {
    fn exchange<'a>(
        &'a self,
        assertion: String,
    ) -> Pin<Box<dyn Future<Output = Result<AccessToken, String>> + Send + 'a>>;
}
pub struct AccessToken {
    pub value: String,
    pub expires_in: u64,
}

/// Google OAuth endpoint transport. No network request occurs at construction.
pub struct GoogleTokenExchange {
    client: reqwest::Client,
}
fn token_request_body(assertion: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
        .append_pair("assertion", assertion)
        .finish()
}
fn parse_token_response(bytes: &[u8]) -> Result<AccessToken, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| FAILURE.to_owned())?;
    let token = value["access_token"]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| FAILURE.to_owned())?;
    let expires_in = value["expires_in"]
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or_else(|| FAILURE.to_owned())?;
    if !value["token_type"]
        .as_str()
        .is_some_and(|v| v.eq_ignore_ascii_case("bearer"))
    {
        return Err(FAILURE.into());
    }
    Ok(AccessToken {
        value: token.to_owned(),
        expires_in,
    })
}
impl GoogleTokenExchange {
    pub fn new(timeout: Duration) -> Result<Self, &'static str> {
        if timeout.is_zero() {
            return Err(FAILURE);
        }
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| FAILURE)?;
        Ok(Self { client })
    }
}
impl TokenExchange for GoogleTokenExchange {
    fn exchange<'a>(
        &'a self,
        assertion: String,
    ) -> Pin<Box<dyn Future<Output = Result<AccessToken, String>> + Send + 'a>> {
        Box::pin(async move {
            let body = token_request_body(&assertion);
            let mut response = self
                .client
                .post(TOKEN_URL)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(body)
                .send()
                .await
                .map_err(|_| FAILURE.to_owned())?;
            if !response.status().is_success()
                || response.content_length().is_some_and(|n| n > 65_536)
            {
                return Err(FAILURE.into());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| FAILURE.to_owned())? {
                if chunk.len() > 65_536 - bytes.len() {
                    return Err(FAILURE.into());
                }
                bytes.extend_from_slice(&chunk);
            }
            parse_token_response(&bytes)
        })
    }
}

struct CachedToken {
    value: String,
    refresh_at: Instant,
}
/// RS256 assertion and cached OAuth token for an explicit service account.
pub struct ServiceAccountTokenSource {
    email: String,
    key: RsaKeyPair,
    exchange: Arc<dyn TokenExchange>,
    cached: Mutex<Option<CachedToken>>,
}
impl ServiceAccountTokenSource {
    pub fn from_pkcs8(
        email: &str,
        pkcs8: &[u8],
        exchange: Arc<dyn TokenExchange>,
    ) -> Result<Self, &'static str> {
        if email.is_empty() {
            return Err(FAILURE);
        }
        let key = RsaKeyPair::from_pkcs8(pkcs8).map_err(|_| FAILURE)?;
        Ok(Self {
            email: email.into(),
            key,
            exchange,
            cached: Mutex::new(None),
        })
    }
    fn assertion(&self) -> Result<String, &'static str> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| FAILURE)?
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = json!({"iss":self.email,"scope":FCM_SCOPE,"aud":TOKEN_URL,"iat":now,"exp":now.checked_add(3600).ok_or(FAILURE)?});
        let input = format!(
            "{header}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).map_err(|_| FAILURE)?)
        );
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| FAILURE)?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}
impl OAuthTokenSource for ServiceAccountTokenSource {
    fn token<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            let mut cache = self.cached.lock().await;
            if let Some(token) = cache.as_ref().filter(|t| Instant::now() < t.refresh_at) {
                return Ok(token.value.clone());
            }
            let assertion = self.assertion().map_err(str::to_owned)?;
            let result = self
                .exchange
                .exchange(assertion)
                .await
                .map_err(|_| FAILURE.to_owned())?;
            if result.value.is_empty() || result.expires_in == 0 {
                return Err(FAILURE.into());
            }
            let refresh_at = Instant::now()
                .checked_add(Duration::from_secs(result.expires_in.saturating_sub(60)))
                .ok_or_else(|| FAILURE.to_owned())?;
            let value = result.value;
            *cache = Some(CachedToken {
                value: value.clone(),
                refresh_at,
            });
            Ok(value)
        })
    }
}

fn private_key_from_pem(pem: &str) -> Result<Vec<u8>, FirebaseBackendError> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN PRIVATE KEY-----")
        .and_then(|v| v.strip_suffix("-----END PRIVATE KEY-----"))
        .ok_or(FirebaseBackendError)?;
    let text: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD.decode(text).map_err(|_| FirebaseBackendError)
}

/// Host backend using explicit service-account configuration or ADC.
/// Construct only with trusted startup configuration, never request fields.
pub struct FirebaseHostBackend {
    environment: EnvironmentSnapshot,
    cwd: PathBuf,
    exchange: Arc<dyn TokenExchange>,
    transport: Arc<dyn FcmHttpTransport>,
    app: Option<Arc<dyn FcmProvider>>,
}
impl FirebaseHostBackend {
    pub fn new(
        environment: &EnvironmentSnapshot,
        cwd: PathBuf,
        timeout: Duration,
    ) -> Result<Self, &'static str> {
        Ok(Self::with_transports(
            environment,
            cwd,
            Arc::new(GoogleTokenExchange::new(timeout)?),
            Arc::new(FcmHttpsTransport::new(timeout)?),
        ))
    }
    pub fn with_transports(
        environment: &EnvironmentSnapshot,
        cwd: PathBuf,
        exchange: Arc<dyn TokenExchange>,
        transport: Arc<dyn FcmHttpTransport>,
    ) -> Self {
        Self {
            environment: environment
                .iter()
                .filter(|(name, _)| {
                    matches!(
                        name.as_str(),
                        "HOME"
                            | "APPDATA"
                            | "CLOUDSDK_CONFIG"
                            | "GOOGLE_APPLICATION_CREDENTIALS"
                            | "google_application_credentials"
                            | "GCE_METADATA_HOST"
                    )
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            cwd,
            exchange,
            transport,
            app: None,
        }
    }
}
impl FirebaseBackend for FirebaseHostBackend {
    type App = Arc<dyn FcmProvider>;
    type Credential = Arc<dyn OAuthTokenSource>;
    fn read_service_account(&mut self, path: &str) -> Result<String, FirebaseBackendError> {
        std::fs::read_to_string(self.cwd.join(path)).map_err(|_| FirebaseBackendError)
    }
    fn certificate(
        &mut self,
        private_key: &str,
        email: &str,
        project: &str,
    ) -> Result<Self::Credential, FirebaseBackendError> {
        if project.is_empty() {
            return Err(FirebaseBackendError);
        }
        let bytes = private_key_from_pem(private_key)?;
        Ok(Arc::new(
            ServiceAccountTokenSource::from_pkcs8(email, &bytes, self.exchange.clone())
                .map_err(|_| FirebaseBackendError)?,
        ))
    }
    fn default_credential(&mut self) -> Result<Self::Credential, FirebaseBackendError> {
        let source = discover(&self.environment, &self.cwd)?;
        if let AdcSource::File(json) = &source
            && json.get("type").and_then(Value::as_str) == Some("service_account")
        {
            let field = |name: &str| {
                json.get(name)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or(FirebaseBackendError)
            };
            return self.certificate(
                field("private_key")?,
                field("client_email")?,
                field("project_id")?,
            );
        }
        Ok(Arc::new(GoogleTokenSource::build(
            source,
            &self.environment,
        )?))
    }
    fn has_apps(&mut self) -> Result<bool, FirebaseBackendError> {
        Ok(self.app.is_some())
    }
    fn get_app(&mut self) -> Result<Self::App, FirebaseBackendError> {
        self.app.clone().ok_or(FirebaseBackendError)
    }
    fn initialize_app(
        &mut self,
        project: &str,
        credential: Self::Credential,
    ) -> Result<Self::App, FirebaseBackendError> {
        let app: Arc<dyn FcmProvider> = Arc::new(
            FirebaseV1Provider::new(project, credential, self.transport.clone())
                .map_err(|_| FirebaseBackendError)?,
        );
        self.app = Some(app.clone());
        Ok(app)
    }
}

/// Executable startup entry. Disabled Firebase does not construct clients,
/// inspect ADC paths, or contact metadata/OAuth. Enabled initialization errors
/// stop startup instead of silently dropping notifications. Token acquisition
/// errors after startup remain notification failures and never undo a message.
pub fn assemble_host_firebase(
    app: MessageBox,
    environment: &EnvironmentSnapshot,
) -> Result<MessageBox, FirebaseAssemblyError> {
    if environment.get("ENABLE_FIREBASE").map(String::as_str) != Some("true") {
        return assemble_firebase::<FirebaseHostBackend, _>(app, environment, || {
            unreachable!("disabled assembly skips the backend")
        });
    }
    let failure = || FirebaseAssemblyError::Initialization(FirebaseInitError::Backend);
    let cwd = std::env::current_dir().map_err(|_| failure())?;
    let backend = FirebaseHostBackend::new(environment, cwd, Duration::from_secs(30))
        .map_err(|_| failure())?;
    assemble_firebase(app, environment, || backend)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oauth_form_and_response_contract() {
        let encoded = token_request_body("a+b/=");
        let fields: std::collections::HashMap<_, _> =
            url::form_urlencoded::parse(encoded.as_bytes())
                .into_owned()
                .collect();
        assert_eq!(
            fields["grant_type"],
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        );
        assert_eq!(fields["assertion"], "a+b/=");
        let token = parse_token_response(
            br#"{"access_token":"fake","expires_in":3600,"token_type":"Bearer"}"#,
        )
        .unwrap();
        assert_eq!(token.value, "fake");
        assert_eq!(token.expires_in, 3600);
        for value in [
            br#"{}"#.as_slice(),
            br#"{"access_token":"fake","expires_in":0,"token_type":"Bearer"}"#,
            br#"{"access_token":"fake","expires_in":3600,"token_type":"other"}"#,
        ] {
            assert!(parse_token_response(value).is_err());
        }
    }
}
