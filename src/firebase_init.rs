//! Firebase initialization control flow, using a trusted, host-supplied backend.
//!
//! This module does not read process environment, access files, initialize the
//! Firebase Admin SDK, acquire credentials, or use a network. The startup
//! assembly entry point accepts explicit configuration and a host backend;
//! the host owns credential operations and any associated consent.
//! Do not log config or credentials. Backend details are deliberately redacted.
use crate::{
    MessageBox,
    fcm_delivery::{FcmOptions, FcmProvider},
    resource_config::EnvironmentSnapshot,
};
use serde_json::Value;
use std::sync::Arc;

/// Supplied explicitly by the host; may contain a private credential.
/// Never log or persist this value.
pub struct FirebaseConfig<'a> {
    pub enabled: Option<&'a str>,
    pub project: Option<&'a str>,
    pub service_account_json: Option<&'a str>,
    pub service_account_path: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirebaseBackendError;

/// Trusted host operations. `read_service_account` must resolve relative paths
/// against the intended working directory, as Node's path.resolve does. A host
/// must protect the secret returned by that operation and passed to certificate.
pub trait FirebaseBackend {
    type App: Clone;
    type Credential;
    fn read_service_account(&mut self, path: &str) -> Result<String, FirebaseBackendError>;
    fn certificate(
        &mut self,
        private_key: &str,
        client_email: &str,
        project: &str,
    ) -> Result<Self::Credential, FirebaseBackendError>;
    fn default_credential(&mut self) -> Result<Self::Credential, FirebaseBackendError>;
    fn has_apps(&mut self) -> Result<bool, FirebaseBackendError>;
    fn get_app(&mut self) -> Result<Self::App, FirebaseBackendError>;
    fn initialize_app(
        &mut self,
        project: &str,
        credential: Self::Credential,
    ) -> Result<Self::App, FirebaseBackendError>;
}

/// Categories only; the original JS exception details are intentionally not exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirebaseInitError {
    MissingProject,
    InvalidCredential,
    FileRead,
    Backend,
}

/// Error categories for startup assembly; no credential or backend detail is exposed.
#[derive(Debug, PartialEq, Eq)]
pub enum FirebaseAssemblyError {
    Initialization(FirebaseInitError),
    ProviderConfiguration,
}
impl std::fmt::Display for FirebaseAssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Firebase startup configuration is unavailable or invalid"
        )
    }
}
impl std::error::Error for FirebaseAssemblyError {}

/// Select Firebase configuration from the same explicit startup snapshot and
/// attach the host-created provider before the MessageBox is shared. A disabled
/// configuration removes any provider already installed on this MessageBox and
/// never constructs the backend. The host owns credential access and any actual
/// token source and transport.
pub fn assemble_firebase<B, F>(
    mut app: MessageBox,
    environment: &EnvironmentSnapshot,
    make_backend: F,
) -> Result<MessageBox, FirebaseAssemblyError>
where
    B: FirebaseBackend<App = Arc<dyn FcmProvider>>,
    F: FnOnce() -> B,
{
    let get = |key: &str| environment.get(key).map(String::as_str);
    let config = FirebaseConfig {
        enabled: get("ENABLE_FIREBASE"),
        project: get("FIREBASE_PROJECT_ID"),
        service_account_json: get("FIREBASE_SERVICE_ACCOUNT_JSON"),
        service_account_path: get("FIREBASE_SERVICE_ACCOUNT_PATH"),
    };
    if config.enabled != Some("true") {
        app.fcm = None;
        return Ok(app);
    }
    let mut initializer = FirebaseInitializer::new(make_backend());
    let provider = initializer
        .initialize(&config)
        .map_err(FirebaseAssemblyError::Initialization)?
        .ok_or(FirebaseAssemblyError::Initialization(
            FirebaseInitError::Backend,
        ))?;
    // Legacy hosts without a resource snapshot use the standard-profile default;
    // MessageBox replaces these values when it has explicit runtime resources.
    app.with_fcm_provider(provider, FcmOptions::default(), 4)
        .map_err(|_| FirebaseAssemblyError::ProviderConfiguration)
}

/// Fail-closed backend for embedding hosts without a Firebase implementation.
/// The executable uses `firebase_host::assemble_host_firebase` instead.
pub struct UnavailableFirebaseBackend;
impl FirebaseBackend for UnavailableFirebaseBackend {
    type App = Arc<dyn FcmProvider>;
    type Credential = ();
    fn read_service_account(&mut self, _: &str) -> Result<String, FirebaseBackendError> {
        Err(FirebaseBackendError)
    }
    fn certificate(&mut self, _: &str, _: &str, _: &str) -> Result<(), FirebaseBackendError> {
        Err(FirebaseBackendError)
    }
    fn default_credential(&mut self) -> Result<(), FirebaseBackendError> {
        Err(FirebaseBackendError)
    }
    fn has_apps(&mut self) -> Result<bool, FirebaseBackendError> {
        Err(FirebaseBackendError)
    }
    fn get_app(&mut self) -> Result<Self::App, FirebaseBackendError> {
        Err(FirebaseBackendError)
    }
    fn initialize_app(&mut self, _: &str, _: ()) -> Result<Self::App, FirebaseBackendError> {
        Err(FirebaseBackendError)
    }
}

pub struct FirebaseInitializer<B: FirebaseBackend> {
    backend: B,
    app: Option<B::App>,
}
impl<B: FirebaseBackend> FirebaseInitializer<B> {
    pub fn new(backend: B) -> Self {
        Self { backend, app: None }
    }
    pub fn backend(&self) -> &B {
        &self.backend
    }
    /// Cached app, if a previous initialization succeeded. Disabling later does
    /// not clear it, matching TS getFirebaseMessaging's cache semantics.
    pub fn app(&self) -> Option<&B::App> {
        self.app.as_ref()
    }
    pub fn initialize(
        &mut self,
        config: &FirebaseConfig<'_>,
    ) -> Result<Option<B::App>, FirebaseInitError> {
        if config.enabled != Some("true") {
            return Ok(None);
        }
        if let Some(app) = &self.app {
            return Ok(Some(app.clone()));
        }
        let project = config
            .project
            .filter(|s| !s.is_empty())
            .ok_or(FirebaseInitError::MissingProject)?;
        let credential = if let Some(raw) = config.service_account_json.filter(|s| !s.is_empty()) {
            self.credential(raw)?
        } else if let Some(path) = config.service_account_path.filter(|s| !s.is_empty()) {
            let raw = self
                .backend
                .read_service_account(path)
                .map_err(|_| FirebaseInitError::FileRead)?;
            self.credential(&raw)?
        } else {
            self.backend
                .default_credential()
                .map_err(|_| FirebaseInitError::Backend)?
        };
        let app = if self
            .backend
            .has_apps()
            .map_err(|_| FirebaseInitError::Backend)?
        {
            self.backend
                .get_app()
                .map_err(|_| FirebaseInitError::Backend)?
        } else {
            self.backend
                .initialize_app(project, credential)
                .map_err(|_| FirebaseInitError::Backend)?
        };
        self.app = Some(app.clone());
        Ok(Some(app))
    }
    fn credential(&mut self, raw: &str) -> Result<B::Credential, FirebaseInitError> {
        let json: Value =
            serde_json::from_str(raw).map_err(|_| FirebaseInitError::InvalidCredential)?;
        let field = |name: &str| {
            json.get(name)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or(FirebaseInitError::InvalidCredential)
        };
        self.backend
            .certificate(
                field("private_key")?,
                field("client_email")?,
                field("project_id")?,
            )
            .map_err(|_| FirebaseInitError::InvalidCredential)
    }
}
