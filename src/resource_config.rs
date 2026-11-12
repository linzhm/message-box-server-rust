//! Pure parser for the pinned TypeScript MessageBox resource configuration.
//!
//! This module only parses a caller-provided environment snapshot. It does not
//! read or modify process-global environment state, change `Limits`, or wire
//! these values into the current runtime.

use std::{collections::BTreeMap, error::Error, fmt};

/// Environment variables captured by the caller for one immutable parse.
pub type EnvironmentSnapshot = BTreeMap<String, String>;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// A positive, finite TypeScript resource limit or its explicit `-1` opt-out.
///
/// The sentinel is not represented as a negative integer, so it cannot be
/// mistaken for a finite bound by downstream code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceLimit {
    Finite(u64),
    Unlimited,
}

/// The selected MessageBox profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceProfile {
    Small,
    Standard,
    HighThroughput,
}

impl ResourceProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Standard => "standard",
            Self::HighThroughput => "high-throughput",
        }
    }
}

/// Parsed limits from the pinned TypeScript `readMessageBoxResourceConfig`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceConfig {
    pub profile: ResourceProfile,
    pub max_message_body_bytes: ResourceLimit,
    pub max_recipients: ResourceLimit,
    pub list_default_limit: ResourceLimit,
    pub list_max_limit: ResourceLimit,
    pub list_max_offset: ResourceLimit,
    pub list_max_response_bytes: ResourceLimit,
    pub max_inbox_messages: ResourceLimit,
    pub max_inbox_bytes: ResourceLimit,
    pub max_sender_messages: ResourceLimit,
    pub max_sender_bytes: ResourceLimit,
    pub max_acknowledgment_ids: ResourceLimit,
    pub device_list_default_limit: ResourceLimit,
    pub device_list_max_limit: ResourceLimit,
    pub device_list_max_offset: ResourceLimit,
    pub max_notification_devices: ResourceLimit,
    pub notification_recipient_concurrency: ResourceLimit,
    pub fcm_send_concurrency: ResourceLimit,
    pub websocket_max_connections: ResourceLimit,
    pub websocket_max_connections_per_identity: ResourceLimit,
    pub websocket_max_rooms_per_connection: ResourceLimit,
    pub websocket_control_rate_limit: ResourceLimit,
    pub websocket_max_concurrent_sends: ResourceLimit,
    pub websocket_send_rate_limit: ResourceLimit,
    pub websocket_max_recipient_connections: ResourceLimit,
    pub permission_list_default_limit: ResourceLimit,
    pub permission_list_max_limit: ResourceLimit,
    pub permission_list_max_offset: ResourceLimit,
    pub retention_days: ResourceLimit,
}

/// A TypeScript-compatible configuration parse error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceConfigError(String);

impl fmt::Display for ResourceConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ResourceConfigError {}

impl ResourceConfig {
    /// Parse a snapshot without reading or changing `std::env`.
    pub fn from_snapshot(environment: &EnvironmentSnapshot) -> Result<Self, ResourceConfigError> {
        let profile = read_profile(environment)?;

        // Keep source evaluation order: the TypeScript config reads these
        // fields first, before constructing each legacy-batch fallback.
        let max_message_body_bytes = configured(
            environment,
            "MAX_MESSAGE_BODY_BYTES",
            profile,
            256 * 1024,
            1024 * 1024,
            4 * 1024 * 1024,
        )?;
        let max_recipients = configured(environment, "MAX_RECIPIENTS", profile, 25, 100, 250)?;

        let list_default_fallback = ProfileValues {
            small: read_legacy_batch_size(environment, 250)?,
            standard: read_legacy_batch_size(environment, 1_000)?,
            high_throughput: read_legacy_batch_size(environment, 1_000)?,
        };
        let list_default_limit = configured_with_fallback(
            environment,
            "LIST_DEFAULT_LIMIT",
            profile,
            list_default_fallback,
        )?;

        let list_max_fallback = ProfileValues {
            small: read_legacy_batch_size(environment, 500)?,
            standard: read_legacy_batch_size(environment, 1_000)?,
            high_throughput: read_legacy_batch_size(environment, 5_000)?,
        };
        let list_max_limit =
            configured_with_fallback(environment, "LIST_MAX_LIMIT", profile, list_max_fallback)?;

        let list_max_offset = configured(
            environment,
            "LIST_MAX_OFFSET",
            profile,
            25_000,
            100_000,
            1_000_000,
        )?;
        let list_max_response_bytes = configured(
            environment,
            "LIST_MAX_RESPONSE_BYTES",
            profile,
            4 * 1024 * 1024,
            8 * 1024 * 1024,
            32 * 1024 * 1024,
        )?;
        let max_inbox_messages = configured(
            environment,
            "MAX_INBOX_MESSAGES",
            profile,
            5_000,
            10_000,
            100_000,
        )?;
        let max_inbox_bytes = configured(
            environment,
            "MAX_INBOX_BYTES",
            profile,
            256 * 1024 * 1024,
            1024 * 1024 * 1024,
            16 * 1024 * 1024 * 1024,
        )?;
        let max_sender_messages = configured(
            environment,
            "MAX_SENDER_MESSAGES",
            profile,
            5_000,
            10_000,
            100_000,
        )?;
        let max_sender_bytes = configured(
            environment,
            "MAX_SENDER_BYTES",
            profile,
            256 * 1024 * 1024,
            1024 * 1024 * 1024,
            16 * 1024 * 1024 * 1024,
        )?;
        let max_acknowledgment_ids = configured(
            environment,
            "MAX_ACKNOWLEDGMENT_IDS",
            profile,
            500,
            1_000,
            5_000,
        )?;
        let device_list_default_limit = configured(
            environment,
            "DEVICE_LIST_DEFAULT_LIMIT",
            profile,
            50,
            100,
            500,
        )?;
        let device_list_max_limit = configured(
            environment,
            "DEVICE_LIST_MAX_LIMIT",
            profile,
            100,
            100,
            1_000,
        )?;
        let device_list_max_offset = configured(
            environment,
            "DEVICE_LIST_MAX_OFFSET",
            profile,
            10_000,
            100_000,
            1_000_000,
        )?;
        let max_notification_devices = configured(
            environment,
            "MAX_NOTIFICATION_DEVICES",
            profile,
            25,
            100,
            500,
        )?;
        let notification_recipient_concurrency = configured(
            environment,
            "NOTIFICATION_RECIPIENT_CONCURRENCY",
            profile,
            2,
            4,
            16,
        )?;
        let fcm_send_concurrency =
            configured(environment, "FCM_SEND_CONCURRENCY", profile, 4, 10, 50)?;
        let websocket_max_connections = configured(
            environment,
            "WEBSOCKET_MAX_CONNECTIONS",
            profile,
            250,
            1_000,
            10_000,
        )?;
        let websocket_max_connections_per_identity = configured(
            environment,
            "WEBSOCKET_MAX_CONNECTIONS_PER_IDENTITY",
            profile,
            5,
            25,
            100,
        )?;
        let websocket_max_rooms_per_connection = configured(
            environment,
            "WEBSOCKET_MAX_ROOMS_PER_CONNECTION",
            profile,
            32,
            128,
            512,
        )?;
        let websocket_control_rate_limit = configured(
            environment,
            "WEBSOCKET_CONTROL_RATE_LIMIT",
            profile,
            120,
            600,
            2_400,
        )?;
        let websocket_max_concurrent_sends = configured(
            environment,
            "WEBSOCKET_MAX_CONCURRENT_SENDS",
            profile,
            2,
            4,
            16,
        )?;
        let websocket_send_rate_limit = configured(
            environment,
            "WEBSOCKET_SEND_RATE_LIMIT",
            profile,
            60,
            300,
            1_200,
        )?;
        let websocket_max_recipient_connections = configured(
            environment,
            "WEBSOCKET_MAX_RECIPIENT_CONNECTIONS",
            profile,
            10,
            25,
            100,
        )?;
        let permission_list_default_limit = configured(
            environment,
            "PERMISSION_LIST_DEFAULT_LIMIT",
            profile,
            50,
            100,
            500,
        )?;
        let permission_list_max_limit = configured(
            environment,
            "PERMISSION_LIST_MAX_LIMIT",
            profile,
            100,
            100,
            1_000,
        )?;
        let permission_list_max_offset = configured(
            environment,
            "PERMISSION_LIST_MAX_OFFSET",
            profile,
            10_000,
            100_000,
            1_000_000,
        )?;
        let retention_days = configured(environment, "RETENTION_DAYS", profile, 14, 30, 90)?;

        validate_default_max_pair(
            "MESSAGE_BOX_LIST_DEFAULT_LIMIT",
            list_default_limit,
            "MESSAGE_BOX_LIST_MAX_LIMIT",
            list_max_limit,
        )?;
        validate_default_max_pair(
            "MESSAGE_BOX_DEVICE_LIST_DEFAULT_LIMIT",
            device_list_default_limit,
            "MESSAGE_BOX_DEVICE_LIST_MAX_LIMIT",
            device_list_max_limit,
        )?;
        validate_default_max_pair(
            "MESSAGE_BOX_PERMISSION_LIST_DEFAULT_LIMIT",
            permission_list_default_limit,
            "MESSAGE_BOX_PERMISSION_LIST_MAX_LIMIT",
            permission_list_max_limit,
        )?;

        Ok(Self {
            profile,
            max_message_body_bytes,
            max_recipients,
            list_default_limit,
            list_max_limit,
            list_max_offset,
            list_max_response_bytes,
            max_inbox_messages,
            max_inbox_bytes,
            max_sender_messages,
            max_sender_bytes,
            max_acknowledgment_ids,
            device_list_default_limit,
            device_list_max_limit,
            device_list_max_offset,
            max_notification_devices,
            notification_recipient_concurrency,
            fcm_send_concurrency,
            websocket_max_connections,
            websocket_max_connections_per_identity,
            websocket_max_rooms_per_connection,
            websocket_control_rate_limit,
            websocket_max_concurrent_sends,
            websocket_send_rate_limit,
            websocket_max_recipient_connections,
            permission_list_default_limit,
            permission_list_max_limit,
            permission_list_max_offset,
            retention_days,
        })
    }
}

#[derive(Clone, Copy)]
struct ProfileValues {
    small: ResourceLimit,
    standard: ResourceLimit,
    high_throughput: ResourceLimit,
}

impl ProfileValues {
    fn finite(small: u64, standard: u64, high_throughput: u64) -> Self {
        Self {
            small: ResourceLimit::Finite(small),
            standard: ResourceLimit::Finite(standard),
            high_throughput: ResourceLimit::Finite(high_throughput),
        }
    }

    fn select(self, profile: ResourceProfile) -> ResourceLimit {
        match profile {
            ResourceProfile::Small => self.small,
            ResourceProfile::Standard => self.standard,
            ResourceProfile::HighThroughput => self.high_throughput,
        }
    }
}

fn read_profile(environment: &EnvironmentSnapshot) -> Result<ResourceProfile, ResourceConfigError> {
    let prefixed = environment.get("MESSAGE_BOX_RESOURCE_PROFILE");
    let selected = match prefixed {
        Some(value) if !trim_js(value).is_empty() => Some(value.as_str()),
        _ => environment
            .get("RESOURCE_PROFILE")
            .map(std::string::String::as_str),
    };
    let normalized = selected.map(|value| lowercase_js(trim_js(value)));
    match normalized.as_deref().unwrap_or("standard") {
        "small" => Ok(ResourceProfile::Small),
        "standard" => Ok(ResourceProfile::Standard),
        "high-throughput" => Ok(ResourceProfile::HighThroughput),
        _ => Err(ResourceConfigError(
            "MESSAGE_BOX_RESOURCE_PROFILE must be small, standard, or high-throughput".into(),
        )),
    }
}

fn configured(
    environment: &EnvironmentSnapshot,
    suffix: &str,
    profile: ResourceProfile,
    small: u64,
    standard: u64,
    high_throughput: u64,
) -> Result<ResourceLimit, ResourceConfigError> {
    configured_with_fallback(
        environment,
        suffix,
        profile,
        ProfileValues::finite(small, standard, high_throughput),
    )
}

fn configured_with_fallback(
    environment: &EnvironmentSnapshot,
    suffix: &str,
    profile: ResourceProfile,
    fallbacks: ProfileValues,
) -> Result<ResourceLimit, ResourceConfigError> {
    let name = format!("MESSAGE_BOX_{suffix}");
    read_resource_limit(environment, &name, fallbacks.select(profile))
}

pub(crate) fn read_resource_limit(
    environment: &EnvironmentSnapshot,
    name: &str,
    fallback: ResourceLimit,
) -> Result<ResourceLimit, ResourceConfigError> {
    let Some(raw) = environment.get(name) else {
        return Ok(fallback);
    };
    let trimmed = trim_js(raw);
    if trimmed.is_empty() {
        return Ok(fallback);
    }

    let normalized = lowercase_js(trimmed);
    if normalized == "-1" || normalized == "unlimited" {
        return Ok(ResourceLimit::Unlimited);
    }
    if !is_positive_decimal(&normalized) {
        return Err(ResourceConfigError(format!(
            "{name} must be -1, unlimited, or a positive integer"
        )));
    }
    let Some(value) = parse_safe_integer(&normalized) else {
        return Err(ResourceConfigError(format!(
            "{name} must not exceed {MAX_SAFE_INTEGER}"
        )));
    };
    Ok(ResourceLimit::Finite(value))
}

fn read_legacy_batch_size(
    environment: &EnvironmentSnapshot,
    fallback: u64,
) -> Result<ResourceLimit, ResourceConfigError> {
    let Some(raw) = environment.get("MESSAGE_LIST_BATCH_SIZE") else {
        return Ok(ResourceLimit::Finite(fallback));
    };
    let trimmed = trim_js(raw);
    if trimmed.is_empty() {
        return Ok(ResourceLimit::Finite(fallback));
    }

    let normalized = lowercase_js(trimmed);
    if normalized == "-1" || normalized == "unlimited" {
        return Ok(ResourceLimit::Unlimited);
    }
    if !is_positive_decimal(&normalized) {
        return Err(ResourceConfigError(
            "MESSAGE_LIST_BATCH_SIZE must be -1, unlimited, or a positive integer".into(),
        ));
    }
    let Some(value) = parse_safe_integer(&normalized) else {
        return Err(ResourceConfigError(
            "MESSAGE_LIST_BATCH_SIZE must be a safe integer".into(),
        ));
    };
    Ok(ResourceLimit::Finite(value))
}

fn parse_safe_integer(value: &str) -> Option<u64> {
    let parsed = value.parse::<u64>().ok()?;
    (parsed <= MAX_SAFE_INTEGER).then_some(parsed)
}

fn is_positive_decimal(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'1'..=b'9')) && bytes[1..].iter().all(u8::is_ascii_digit)
}

fn validate_default_max_pair(
    default_name: &str,
    default: ResourceLimit,
    max_name: &str,
    maximum: ResourceLimit,
) -> Result<(), ResourceConfigError> {
    if let (ResourceLimit::Finite(default), ResourceLimit::Finite(maximum)) = (default, maximum)
        && default > maximum
    {
        return Err(ResourceConfigError(format!(
            "{default_name} must not exceed {max_name}"
        )));
    }
    Ok(())
}

fn lowercase_js(value: &str) -> String {
    value.chars().flat_map(char::to_lowercase).collect()
}

pub(crate) fn trim_js(value: &str) -> &str {
    let start = value
        .char_indices()
        .find(|(_, character)| !is_js_trim_whitespace(*character))
        .map_or(value.len(), |(index, _)| index);
    let end = value
        .char_indices()
        .rev()
        .find(|(_, character)| !is_js_trim_whitespace(*character))
        .map_or(start, |(index, character)| index + character.len_utf8());
    &value[start..end]
}

fn is_js_trim_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}
