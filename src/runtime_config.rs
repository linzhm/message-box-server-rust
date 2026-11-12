//! Explicit configuration for a restricted local, non-payment service.
//!
//! The caller chooses paths and a stable private key. This configuration never
//! defaults to a public key or an all-box free policy. It is not TS environment
//! profile compatibility and must not be treated as production deployment setup.
use crate::{
    Decision, DeliveryPolicy, Identity, PolicyError, http_auth::RoutingPrefix,
    resource_config::EnvironmentSnapshot,
};
use serde_json::Value;
use std::{collections::HashSet, net::SocketAddr, path::PathBuf};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PricingMode {
    FreeBoxes,
    TsTable,
}
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub identity_key_file: PathBuf,
    pub free_boxes: Vec<String>,
    pub pricing_mode: PricingMode,
    pub enable_websockets: bool,
    pub routing_prefix: RoutingPrefix,
    pub cors: CorsConfig,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorsMode {
    Public,
    Allowlist(Vec<String>),
    Disabled,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorsConfig {
    pub mode: CorsMode,
    pub allowed_headers: Option<String>,
    pub exposed_headers: Option<String>,
}

fn csv(value: Option<&String>) -> Result<Option<Vec<String>>, InvalidRuntimeConfig> {
    let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
        return Ok(None);
    };
    let mut result = Vec::new();
    for item in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        if item == "*" {
            return Err(InvalidRuntimeConfig);
        }
        if !result.iter().any(|existing| existing == item) {
            result.push(item.to_owned());
        }
    }
    Ok(Some(result))
}

fn header_setting(
    environment: &EnvironmentSnapshot,
    key: &str,
) -> Result<Option<String>, InvalidRuntimeConfig> {
    csv(environment.get(key))?
        .map(|values| {
            let result = values.join(", ");
            http::HeaderValue::from_str(&result).map_err(|_| InvalidRuntimeConfig)?;
            Ok(result)
        })
        .transpose()
}

pub fn normalize_cors_origin(origin: &str) -> Option<String> {
    if origin == "null" {
        return None;
    }
    let url = url::Url::parse(origin).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        // WHATWG URL's search/hash accessors are empty for bare '?' and '#'.
        || url.query().is_some_and(|query| !query.is_empty())
        || url.fragment().is_some_and(|fragment| !fragment.is_empty())
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}
#[derive(Debug)]
pub struct InvalidRuntimeConfig;
impl RuntimeConfig {
    pub fn parse(value: &Value) -> Result<Self, InvalidRuntimeConfig> {
        Self::parse_with_environment(value, &EnvironmentSnapshot::new())
    }

    pub fn parse_with_environment(
        value: &Value,
        environment: &EnvironmentSnapshot,
    ) -> Result<Self, InvalidRuntimeConfig> {
        let object = value.as_object().ok_or(InvalidRuntimeConfig)?;
        let keys = ["bind", "dataDir", "identityKeyFile"];
        if keys.iter().any(|key| !object.contains_key(*key))
            || object.keys().any(|key| {
                !keys.contains(&key.as_str())
                    && key != "enableWebSockets"
                    && key != "routingPrefix"
                    && key != "pricingMode"
                    && key != "freeBoxes"
                    && key != "corsMode"
                    && key != "corsAllowedOrigins"
            })
        {
            return Err(InvalidRuntimeConfig);
        }
        let routing_prefix = match object.get("routingPrefix") {
            None => RoutingPrefix::default(),
            Some(value) => RoutingPrefix::parse(value.as_str().ok_or(InvalidRuntimeConfig)?)
                .map_err(|_| InvalidRuntimeConfig)?,
        };
        let enable_websockets = match object.get("enableWebSockets") {
            None => false,
            Some(value) => value.as_bool().ok_or(InvalidRuntimeConfig)?,
        };
        let explicit_cors =
            object.contains_key("corsMode") || object.contains_key("corsAllowedOrigins");
        let origins = match object.get("corsAllowedOrigins") {
            None if !explicit_cors => {
                let source = environment
                    .get("MESSAGE_BOX_CORS_ALLOWED_ORIGINS")
                    .filter(|v| !v.trim().is_empty())
                    .or_else(|| environment.get("CORS_ALLOWED_ORIGINS"));
                csv(source)?
                    .unwrap_or_default()
                    .iter()
                    .map(|v| normalize_cors_origin(v).ok_or(InvalidRuntimeConfig))
                    .collect::<Result<Vec<_>, _>>()?
            }
            None => Vec::new(),
            Some(value) => value
                .as_array()
                .ok_or(InvalidRuntimeConfig)?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .and_then(normalize_cors_origin)
                        .ok_or(InvalidRuntimeConfig)
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        let configured_mode = object
            .get("corsMode")
            .map(|value| value.as_str().ok_or(InvalidRuntimeConfig))
            .transpose()?;
        let env_mode = environment
            .get("MESSAGE_BOX_CORS_MODE")
            .filter(|v| !v.trim().is_empty())
            .or_else(|| environment.get("CORS_MODE"))
            .map(|s| s.trim().to_ascii_lowercase());
        let auto_mode = if origins.is_empty() {
            "public"
        } else {
            "allowlist"
        };
        let mode = if explicit_cors {
            configured_mode.unwrap_or(auto_mode)
        } else {
            env_mode
                .as_deref()
                .filter(|v| !v.is_empty())
                .unwrap_or(auto_mode)
        };
        let mode = match mode {
            "public" if origins.is_empty() => CorsMode::Public,
            "disabled" if origins.is_empty() => CorsMode::Disabled,
            "allowlist" if !origins.is_empty() => CorsMode::Allowlist(origins),
            _ => return Err(InvalidRuntimeConfig),
        };
        let cors = CorsConfig {
            mode,
            allowed_headers: header_setting(environment, "MESSAGE_BOX_CORS_ALLOWED_HEADERS")?,
            exposed_headers: header_setting(environment, "MESSAGE_BOX_CORS_EXPOSED_HEADERS")?,
        };
        let bind: SocketAddr = object["bind"]
            .as_str()
            .ok_or(InvalidRuntimeConfig)?
            .parse()
            .map_err(|_| InvalidRuntimeConfig)?;
        if !bind.ip().is_loopback() {
            return Err(InvalidRuntimeConfig);
        }
        let data_dir = PathBuf::from(
            object["dataDir"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or(InvalidRuntimeConfig)?,
        );
        let identity_key_file = PathBuf::from(
            object["identityKeyFile"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or(InvalidRuntimeConfig)?,
        );
        if !data_dir.is_absolute() || !identity_key_file.is_absolute() {
            return Err(InvalidRuntimeConfig);
        }
        let pricing_mode = match object.get("pricingMode") {
            None => PricingMode::FreeBoxes,
            Some(value) if value.as_str() == Some("ts-table") => PricingMode::TsTable,
            _ => return Err(InvalidRuntimeConfig),
        };
        let empty = Vec::new();
        let boxes = match (pricing_mode, object.get("freeBoxes")) {
            (PricingMode::FreeBoxes, Some(value)) => value
                .as_array()
                .filter(|v| !v.is_empty())
                .ok_or(InvalidRuntimeConfig)?,
            (PricingMode::TsTable, None) => &empty,
            (PricingMode::TsTable, Some(value)) => value
                .as_array()
                .filter(|v| v.is_empty())
                .ok_or(InvalidRuntimeConfig)?,
            _ => return Err(InvalidRuntimeConfig),
        };
        let mut unique = HashSet::new();
        let mut free_boxes = Vec::with_capacity(boxes.len());
        for b in boxes {
            let value = b
                .as_str()
                .filter(|s| crate::exact_text(s, 128))
                .ok_or(InvalidRuntimeConfig)?;
            if !unique.insert(value) {
                return Err(InvalidRuntimeConfig);
            }
            free_boxes.push(value.to_owned());
        }
        Ok(Self {
            bind,
            data_dir,
            identity_key_file,
            free_boxes,
            pricing_mode,
            enable_websockets,
            routing_prefix,
            cors,
        })
    }
}
pub struct FreeBoxPolicy {
    boxes: HashSet<String>,
}
impl FreeBoxPolicy {
    pub fn new(boxes: impl IntoIterator<Item = String>) -> Self {
        Self {
            boxes: boxes.into_iter().collect(),
        }
    }
}
impl DeliveryPolicy for FreeBoxPolicy {
    fn evaluate(&self, _: &Identity, _: &str, message_box: &str) -> Result<Decision, PolicyError> {
        if self.boxes.contains(message_box) {
            Ok(Decision::Free)
        } else {
            Err(PolicyError)
        }
    }
    fn delivery_fee(&self, message_box: &str) -> Result<i64, PolicyError> {
        if self.boxes.contains(message_box) {
            Ok(0)
        } else {
            Err(PolicyError)
        }
    }
}
/// Read a host-provided 32-byte secp256k1 identity secret in hex. The caller
/// must protect the file and keep the same identity across restarts. This
/// function never creates, prints or persists a key.
pub fn load_identity_key(path: &std::path::Path) -> Result<k256::SecretKey, InvalidRuntimeConfig> {
    check_private_file(path).map_err(|_| InvalidRuntimeConfig)?;
    let text = std::fs::read_to_string(path).map_err(|_| InvalidRuntimeConfig)?;
    let encoded = text.trim();
    if encoded.len() != 64 {
        return Err(InvalidRuntimeConfig);
    }
    let bytes = hex::decode(encoded).map_err(|_| InvalidRuntimeConfig)?;
    k256::SecretKey::from_slice(&bytes).map_err(|_| InvalidRuntimeConfig)
}

#[cfg(unix)]
fn check_private_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.mode() & 0o077 != 0 {
        return Err(std::io::Error::other("file must be private and regular"));
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_private_file(_path: &std::path::Path) -> std::io::Result<()> {
    Err(std::io::Error::other("private runtime files require Unix"))
}
/// Create a private directory if absent; reject existing non-private paths
/// rather than changing their permissions. The host must protect parent paths.
#[cfg(unix)]
pub fn prepare_private_directory(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(std::io::Error::other("data directory must be private"));
    }
    Ok(())
}
#[cfg(not(unix))]
pub fn prepare_private_directory(_path: &std::path::Path) -> std::io::Result<()> {
    Err(std::io::Error::other("private runtime files require Unix"))
}
/// Create an empty private database if absent, or reject an existing
/// non-private or non-regular file without changing its permissions.
#[cfg(unix)]
pub fn prepare_private_database(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => drop(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    check_private_file(path)
}
#[cfg(not(unix))]
pub fn prepare_private_database(_path: &std::path::Path) -> std::io::Result<()> {
    Err(std::io::Error::other("private runtime files require Unix"))
}

/// Runtime admission for explicit TS-fee-table mode. The fee itself must come
/// from the separately enabled SQLite table; the default trait fee fails closed.
pub struct TsTableAdmission;
impl DeliveryPolicy for TsTableAdmission {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
}

/// Pinned TS PORT / HTTP_PORT selection for hosts assembling a listener.
/// The explicit JSON bind contract remains authoritative in the local binary.
pub fn resolve_http_port(environment: &EnvironmentSnapshot) -> Result<u16, String> {
    for name in ["PORT", "HTTP_PORT"] {
        if let Some(raw) = environment.get(name) {
            let value = crate::resource_config::trim_js(raw);
            if value.is_empty() {
                continue;
            }
            if value.bytes().all(|b| b.is_ascii_digit()) {
                // Leading zeroes are accepted by Number(), even for long strings.
                if let Ok(port) = value.trim_start_matches('0').parse::<u16>()
                    && port != 0
                {
                    return Ok(port);
                }
            }
            return Err(format!("{name} must be an integer between 1 and 65535."));
        }
    }
    Ok(8080)
}
