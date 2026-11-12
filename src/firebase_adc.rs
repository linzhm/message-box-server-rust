//! Application Default Credentials discovery for the Firebase host.
//!
//! Only the host calls this module, with its startup environment and working
//! directory. Tests supply isolated paths; no process-global environment is
//! changed. Credential files are trusted operator configuration, never request
//! input. Google owns non-service-account token exchange, caching and refresh.
use crate::{
    fcm_http_v1::OAuthTokenSource, firebase_init::FirebaseBackendError,
    resource_config::EnvironmentSnapshot,
};
use google_cloud_auth::credentials::{
    AccessTokenCredentials, external_account, impersonated, mds, user_account,
};
use serde_json::Value;
use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};

pub(crate) const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

// Never derive Debug: a JSON value can contain private keys or refresh tokens.
pub(crate) enum AdcSource {
    File(Value),
    Metadata,
}

fn nonempty<'a>(environment: &'a EnvironmentSnapshot, name: &str) -> Option<&'a str> {
    environment
        .get(name)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
}

/// The standard explicit-file, gcloud well-known-file, metadata order. A broken
/// explicit file or malformed existing well-known file never falls back.
pub(crate) fn discover(
    environment: &EnvironmentSnapshot,
    cwd: &Path,
) -> Result<AdcSource, FirebaseBackendError> {
    let explicit = nonempty(environment, "GOOGLE_APPLICATION_CREDENTIALS")
        .or_else(|| nonempty(environment, "google_application_credentials"));
    let path = explicit
        .map(PathBuf::from)
        .or_else(|| well_known_path(environment));
    let Some(path) = path else {
        return Ok(AdcSource::Metadata);
    };
    let path = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw)
            .map(AdcSource::File)
            .map_err(|_| FirebaseBackendError),
        Err(error) if explicit.is_none() && error.kind() == std::io::ErrorKind::NotFound => {
            Ok(AdcSource::Metadata)
        }
        Err(_) => Err(FirebaseBackendError),
    }
}

fn well_known_path(environment: &EnvironmentSnapshot) -> Option<PathBuf> {
    if let Some(config) = nonempty(environment, "CLOUDSDK_CONFIG") {
        return Some(PathBuf::from(config).join("application_default_credentials.json"));
    }
    #[cfg(windows)]
    let root = PathBuf::from(nonempty(environment, "APPDATA")?).join("gcloud");
    #[cfg(not(windows))]
    let root = PathBuf::from(nonempty(environment, "HOME")?).join(".config/gcloud");
    Some(root.join("application_default_credentials.json"))
}

pub(crate) struct GoogleTokenSource(AccessTokenCredentials);
impl GoogleTokenSource {
    /// Builds official credentials in the host's Tokio runtime. Their cache may
    /// begin fetching immediately. Do not call this with real configuration in
    /// an offline test. Service-account files are handled by the host's OAuth
    /// JWT-bearer exchange, because this Google version returns self-signed JWTs
    /// for service-account access_token(), rather than FCM OAuth access tokens.
    pub(crate) fn build(
        source: AdcSource,
        environment: &EnvironmentSnapshot,
    ) -> Result<Self, FirebaseBackendError> {
        tokio::runtime::Handle::try_current().map_err(|_| FirebaseBackendError)?;
        // This dependency is built without its default AWS-LC provider. Keep an
        // embedding application's installed provider, or select the same ring
        // provider already used by this executable's HTTPS transports.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let credentials = match source {
            AdcSource::Metadata => {
                let endpoint = nonempty(environment, "GCE_METADATA_HOST")
                    .map(|host| format!("http://{host}"))
                    .unwrap_or_else(|| "http://metadata.google.internal".into());
                mds::Builder::default()
                    .with_endpoint(endpoint)
                    .with_scopes([FCM_SCOPE])
                    .build_access_token_credentials()
            }
            AdcSource::File(json) => match json.get("type").and_then(Value::as_str) {
                Some("authorized_user") => user_account::Builder::new(json)
                    .with_scopes([FCM_SCOPE])
                    .build_access_token_credentials(),
                Some("impersonated_service_account") => impersonated::Builder::new(json)
                    .with_scopes([FCM_SCOPE])
                    .build_access_token_credentials(),
                Some("external_account") => external_account::Builder::new(json)
                    .with_scopes([FCM_SCOPE])
                    .build_access_token_credentials(),
                _ => return Err(FirebaseBackendError),
            },
        }
        .map_err(|_| FirebaseBackendError)?;
        Ok(Self(credentials))
    }
}

impl OAuthTokenSource for GoogleTokenSource {
    fn token<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            // SDK retry/cache policy owns refresh. Bound the caller's wait and
            // expose no provider error text or credential details.
            tokio::time::timeout(Duration::from_secs(30), self.0.access_token())
                .await
                .map_err(|_| "OAuth token unavailable".to_owned())?
                .map(|token| token.token)
                .map_err(|_| "OAuth token unavailable".to_owned())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn adc_file_precedence_and_error_paths_use_only_isolated_files() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path();
        let home = cwd.join("home");
        std::fs::create_dir_all(home.join(".config/gcloud")).unwrap();
        let known = home.join(".config/gcloud/application_default_credentials.json");
        std::fs::write(
            &known,
            r#"{"type":"authorized_user","marker":"well-known"}"#,
        )
        .unwrap();
        std::fs::write(
            cwd.join("explicit.json"),
            r#"{"type":"service_account","marker":"explicit"}"#,
        )
        .unwrap();
        let mut env = EnvironmentSnapshot::from([("HOME".into(), home.to_str().unwrap().into())]);
        let selected = |source| match source {
            AdcSource::File(v) => v["marker"].clone(),
            AdcSource::Metadata => json!("metadata"),
        };
        assert_eq!(selected(discover(&env, cwd).unwrap()), "well-known");
        env.insert(
            "GOOGLE_APPLICATION_CREDENTIALS".into(),
            "explicit.json".into(),
        );
        assert_eq!(selected(discover(&env, cwd).unwrap()), "explicit");
        env.insert(
            "GOOGLE_APPLICATION_CREDENTIALS".into(),
            "missing.json".into(),
        );
        assert!(discover(&env, cwd).is_err());
        std::fs::write(cwd.join("broken.json"), "{fake-secret").unwrap();
        env.insert(
            "GOOGLE_APPLICATION_CREDENTIALS".into(),
            "broken.json".into(),
        );
        assert!(discover(&env, cwd).is_err());
        env.remove("GOOGLE_APPLICATION_CREDENTIALS");
        std::fs::write(&known, "broken-fake-secret").unwrap();
        assert!(discover(&env, cwd).is_err());
        std::fs::remove_file(known).unwrap();
        assert_eq!(selected(discover(&env, cwd).unwrap()), "metadata");
        assert_eq!(
            selected(discover(&EnvironmentSnapshot::new(), cwd).unwrap()),
            "metadata"
        );
    }

    #[test]
    fn adc_sdk_config_and_lowercase_env_are_respected() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path();
        std::fs::create_dir(cwd.join("gcloud")).unwrap();
        std::fs::write(
            cwd.join("gcloud/application_default_credentials.json"),
            r#"{"marker":"config"}"#,
        )
        .unwrap();
        let mut env = EnvironmentSnapshot::from([("CLOUDSDK_CONFIG".into(), "gcloud".into())]);
        let AdcSource::File(value) = discover(&env, cwd).unwrap() else {
            panic!("file expected")
        };
        assert_eq!(value["marker"], "config");
        env.insert("GOOGLE_APPLICATION_CREDENTIALS".into(), "".into());
        env.insert(
            "google_application_credentials".into(),
            "missing.json".into(),
        );
        assert!(discover(&env, cwd).is_err());
    }
}

#[cfg(test)]
mod google_tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    // Only synthetic credentials and loopback are used. These tests are run
    // with GCE_METADATA_HOST and proxy variables unset, and an isolated HOME.
    async fn server(
        responses: Vec<(u16, Value)>,
    ) -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let captured = seen.clone();
        let job = tokio::spawn(async move {
            for (status, response) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                loop {
                    let mut buf = [0; 4096];
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0 && data.len() + n <= 65536);
                    data.extend_from_slice(&buf[..n]);
                    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&data[..pos]).unwrap();
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if data.len() >= pos + 4 + length {
                            break;
                        }
                    }
                }
                captured
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(data).unwrap());
                let body = response.to_string();
                let bytes = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nMetadata-Flavor: Google\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(bytes.as_bytes()).await.unwrap();
            }
        });
        (url, seen, job)
    }

    fn user(endpoint: &str) -> Value {
        json!({"type":"authorized_user", "client_id":"fake-client", "client_secret":"fake-secret", "refresh_token":"fake-refresh", "token_uri":endpoint})
    }
    fn response(token: &str, expiry: u64) -> (u16, Value) {
        (
            200,
            json!({"access_token":token,"expires_in":expiry,"token_type":"Bearer"}),
        )
    }

    #[tokio::test]
    async fn official_user_refresh_token_exchange_cache_and_refresh() {
        let (url, seen, task) = server(vec![
            response("fake-first", 12),
            response("fake-refreshed", 3600),
        ])
        .await;
        let tokens =
            GoogleTokenSource::build(AdcSource::File(user(&url)), &EnvironmentSnapshot::new())
                .unwrap();
        assert_eq!(tokens.token().await.unwrap(), "fake-first");
        assert_eq!(tokens.token().await.unwrap(), "fake-first");
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "official cache must be reused"
        );
        tokio::time::timeout(Duration::from_secs(15), task)
            .await
            .unwrap()
            .unwrap();
        for _ in 0..100 {
            if tokens.token().await.unwrap() == "fake-refreshed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(tokens.token().await.unwrap(), "fake-refreshed");
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            let body: Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(body["grant_type"], "refresh_token");
            assert_eq!(body["refresh_token"], "fake-refresh");
            assert!(request.contains("firebase.messaging"));
        }
    }

    #[tokio::test]
    async fn official_user_error_is_redacted_and_invalid_config_fails() {
        let (url, _, task) = server(vec![(
            400,
            json!({"error":"invalid_grant", "error_description":"fake-secret-do-not-return"}),
        )])
        .await;
        let tokens =
            GoogleTokenSource::build(AdcSource::File(user(&url)), &EnvironmentSnapshot::new())
                .unwrap();
        assert_eq!(tokens.token().await.unwrap_err(), "OAuth token unavailable");
        task.await.unwrap();
        for json in [
            json!({}),
            json!({"type":"unknown"}),
            json!({"type":"authorized_user"}),
            json!({"type":"impersonated_service_account"}),
            json!({"type":"external_account"}),
        ] {
            assert!(
                GoogleTokenSource::build(AdcSource::File(json), &EnvironmentSnapshot::new())
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn official_metadata_tokens_use_fake_endpoint_and_scope() {
        let (url, seen, task) = server(vec![response("fake-metadata", 3600)]).await;
        let environment = EnvironmentSnapshot::from([(
            "GCE_METADATA_HOST".into(),
            url.strip_prefix("http://").unwrap().into(),
        )]);
        let tokens = GoogleTokenSource::build(AdcSource::Metadata, &environment).unwrap();
        assert_eq!(tokens.token().await.unwrap(), "fake-metadata");
        assert_eq!(tokens.token().await.unwrap(), "fake-metadata");
        task.await.unwrap();
        let request = &seen.lock().unwrap()[0];
        assert!(
            request.starts_with("GET /computeMetadata/v1/instance/service-accounts/default/token?")
        );
        assert!(request.contains("firebase.messaging"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("metadata-flavor: google")
        );
    }

    #[tokio::test]
    async fn official_external_account_exchanges_isolated_file_subject_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subject-token");
        std::fs::write(&path, "fake-subject-token").unwrap();
        let (url, seen, task) = server(vec![(200, json!({"access_token":"fake-federated", "token_type":"Bearer", "expires_in":3600, "issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}))]).await;
        let config = json!({"type":"external_account", "audience":"//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/test/providers/test", "subject_token_type":"urn:ietf:params:oauth:token-type:jwt", "token_url":url, "credential_source":{"file":path}});
        let tokens =
            GoogleTokenSource::build(AdcSource::File(config), &EnvironmentSnapshot::new()).unwrap();
        assert_eq!(tokens.token().await.unwrap(), "fake-federated");
        task.await.unwrap();
        let request = &seen.lock().unwrap()[0];
        assert!(request.contains("subject_token=fake-subject-token"));
        assert!(request.contains("firebase.messaging"));
        assert!(request.contains("token-exchange"));
    }

    #[tokio::test]
    async fn official_impersonated_account_uses_source_then_target_token() {
        let expiry = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let (url, seen, task) = server(vec![
            response("fake-source", 3600),
            (
                200,
                json!({"accessToken":"fake-impersonated", "expireTime":expiry}),
            ),
        ])
        .await;
        let config = json!({"type":"impersonated_service_account", "service_account_impersonation_url":format!("{url}/v1/projects/-/serviceAccounts/fake@example.test:generateAccessToken"), "source_credentials":user(&format!("{url}/token"))});
        let tokens =
            GoogleTokenSource::build(AdcSource::File(config), &EnvironmentSnapshot::new()).unwrap();
        assert_eq!(tokens.token().await.unwrap(), "fake-impersonated");
        task.await.unwrap();
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("Bearer fake-source"));
        assert!(requests[1].contains("firebase.messaging"));
        assert!(requests[1].contains(":generateAccessToken"));
    }
}
