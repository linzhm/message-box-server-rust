//! Checked conversion from a single startup resource snapshot to local consumers.
use crate::{
    Limits,
    resource_config::{ResourceConfig, ResourceLimit},
};
use std::{error::Error, fmt};

#[derive(Debug)]
pub struct UnsupportedResource(pub &'static str);
impl fmt::Display for UnsupportedResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "resource {} is not representable by the local runtime",
            self.0
        )
    }
}
impl Error for UnsupportedResource {}
fn finite(limit: ResourceLimit, name: &'static str) -> Result<u64, UnsupportedResource> {
    match limit {
        ResourceLimit::Finite(n) => Ok(n),
        ResourceLimit::Unlimited => Err(UnsupportedResource(name)),
    }
}
fn usize_limit(limit: ResourceLimit, name: &'static str) -> Result<usize, UnsupportedResource> {
    usize::try_from(finite(limit, name)?).map_err(|_| UnsupportedResource(name))
}
fn i64_limit(limit: ResourceLimit, name: &'static str) -> Result<i64, UnsupportedResource> {
    match limit {
        ResourceLimit::Finite(n) => i64::try_from(n).map_err(|_| UnsupportedResource(name)),
        ResourceLimit::Unlimited => Ok(-1),
    }
}
/// Local implementation limits and the original immutable profile.
#[derive(Clone, Debug)]
pub struct RuntimeResources {
    pub config: ResourceConfig,
    pub limits: Limits,
}
impl RuntimeResources {
    pub fn new(config: ResourceConfig) -> Result<Self, UnsupportedResource> {
        let n = |v, name| usize_limit(v, name);
        let q = |v, name| i64_limit(v, name);
        let unbounded_usize = |v, name| match v {
            ResourceLimit::Unlimited => Ok(usize::MAX),
            ResourceLimit::Finite(_) => usize_limit(v, name),
        };
        // TypeScript uses Number.MAX_SAFE_INTEGER for an unlimited list bound.
        let list_limit = |v, name| match v {
            ResourceLimit::Unlimited => {
                usize::try_from(9_007_199_254_740_991u64).map_err(|_| UnsupportedResource(name))
            }
            ResourceLimit::Finite(_) => usize_limit(v, name),
        };
        let limits = Limits {
            max_body_bytes: unbounded_usize(
                config.max_message_body_bytes,
                "MAX_MESSAGE_BODY_BYTES",
            )?,
            max_recipients: match config.max_recipients {
                ResourceLimit::Unlimited => usize::try_from(i64::MAX).unwrap_or(usize::MAX),
                finite => n(finite, "MAX_RECIPIENTS")?,
            },
            default_list_limit: list_limit(config.list_default_limit, "LIST_DEFAULT_LIMIT")?,
            max_list_limit: list_limit(config.list_max_limit, "LIST_MAX_LIMIT")?,
            max_list_offset: list_limit(config.list_max_offset, "LIST_MAX_OFFSET")?,
            max_list_response_bytes: unbounded_usize(
                config.list_max_response_bytes,
                "LIST_MAX_RESPONSE_BYTES",
            )?,
            max_ack_ids: unbounded_usize(config.max_acknowledgment_ids, "MAX_ACKNOWLEDGMENT_IDS")?,
            max_inbox_messages: q(config.max_inbox_messages, "MAX_INBOX_MESSAGES")?,
            max_inbox_bytes: q(config.max_inbox_bytes, "MAX_INBOX_BYTES")?,
            max_sender_messages: q(config.max_sender_messages, "MAX_SENDER_MESSAGES")?,
            max_sender_bytes: q(config.max_sender_bytes, "MAX_SENDER_BYTES")?,
            // Legacy Limits retains u32 storage. Resource-aware sends always use
            // the typed config; this fallback never determines their expiry.
            retention_days: match config.retention_days {
                ResourceLimit::Finite(n) => u32::try_from(n).unwrap_or(30),
                ResourceLimit::Unlimited => 30,
            },
        };
        // These fields enter SQLite LIMIT/OFFSET or the existing registry's i64 sentinel API.
        for (v, name) in [
            (
                config.device_list_default_limit,
                "DEVICE_LIST_DEFAULT_LIMIT",
            ),
            (config.device_list_max_limit, "DEVICE_LIST_MAX_LIMIT"),
            (config.device_list_max_offset, "DEVICE_LIST_MAX_OFFSET"),
            (
                config.permission_list_default_limit,
                "PERMISSION_LIST_DEFAULT_LIMIT",
            ),
            (
                config.permission_list_max_limit,
                "PERMISSION_LIST_MAX_LIMIT",
            ),
            (
                config.permission_list_max_offset,
                "PERMISSION_LIST_MAX_OFFSET",
            ),
            (config.max_notification_devices, "MAX_NOTIFICATION_DEVICES"),
            (
                config.notification_recipient_concurrency,
                "NOTIFICATION_RECIPIENT_CONCURRENCY",
            ),
            (config.fcm_send_concurrency, "FCM_SEND_CONCURRENCY"),
            (
                config.websocket_max_connections,
                "WEBSOCKET_MAX_CONNECTIONS",
            ),
            (
                config.websocket_max_connections_per_identity,
                "WEBSOCKET_MAX_CONNECTIONS_PER_IDENTITY",
            ),
            (
                config.websocket_max_rooms_per_connection,
                "WEBSOCKET_MAX_ROOMS_PER_CONNECTION",
            ),
            (
                config.websocket_control_rate_limit,
                "WEBSOCKET_CONTROL_RATE_LIMIT",
            ),
            (
                config.websocket_send_rate_limit,
                "WEBSOCKET_SEND_RATE_LIMIT",
            ),
            (
                config.websocket_max_recipient_connections,
                "WEBSOCKET_MAX_RECIPIENT_CONNECTIONS",
            ),
        ] {
            i64_limit(v, name)?;
        }
        // Existing Limits validates practical arithmetic and SQLite bounds before any DB is opened.
        limits
            .validate(true)
            .map_err(|_| UnsupportedResource("core limits"))?;
        Ok(Self { config, limits })
    }
    pub fn signed(limit: ResourceLimit) -> i64 {
        match limit {
            ResourceLimit::Finite(n) => i64::try_from(n).expect("checked at startup"),
            ResourceLimit::Unlimited => -1,
        }
    }
}

/// TS maintenance settings are independent of the selected resource profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintenanceConfig {
    pub interval_ms: ResourceLimit,
    pub batch_size: ResourceLimit,
}
impl MaintenanceConfig {
    pub fn from_snapshot(
        env: &crate::resource_config::EnvironmentSnapshot,
    ) -> Result<Self, crate::resource_config::ResourceConfigError> {
        use crate::resource_config::read_resource_limit;
        Ok(Self {
            interval_ms: read_resource_limit(
                env,
                "MESSAGE_BOX_RETENTION_CLEANUP_INTERVAL_MS",
                ResourceLimit::Finite(900_000),
            )?,
            batch_size: read_resource_limit(
                env,
                "MESSAGE_BOX_RETENTION_CLEANUP_BATCH_SIZE",
                ResourceLimit::Finite(1_000),
            )?,
        })
    }
    /// Node setInterval clamps delays beyond signed 32-bit milliseconds to 1ms.
    pub fn timer_duration(&self) -> Option<std::time::Duration> {
        match self.interval_ms {
            ResourceLimit::Unlimited => None,
            ResourceLimit::Finite(n) => {
                Some(std::time::Duration::from_millis(if n > i32::MAX as u64 {
                    1
                } else {
                    n.max(1)
                }))
            }
        }
    }
}

impl RuntimeResources {
    /// Matches messageExpiresAt's binary64 arithmetic and ECMAScript TimeClip.
    /// An invalid Date is an error, never the NULL used for unlimited retention.
    pub fn expires_at_ms(&self, now_ms: i64) -> Result<Option<i64>, UnsupportedResource> {
        match self.config.retention_days {
            ResourceLimit::Unlimited => Ok(None),
            ResourceLimit::Finite(days) => {
                let expiry = now_ms as f64 + days as f64 * 24.0 * 60.0 * 60.0 * 1_000.0;
                if !expiry.is_finite() || expiry.abs() > 8_640_000_000_000_000.0 {
                    return Err(UnsupportedResource("RETENTION_DAYS invalid Date"));
                }
                Ok(Some(expiry.trunc() as i64))
            }
        }
    }
}

impl crate::MessageBox {
    /// Delete at most one TS-configured batch; NULL expiry remains untouched.
    pub async fn purge_expired_batch(&self, batch: ResourceLimit) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query("DELETE FROM messages WHERE message_id IN (SELECT message_id FROM messages WHERE expires_at<=? LIMIT ?)")
            .bind(chrono::Utc::now().timestamp_millis())
            .bind(RuntimeResources::signed(batch))
            .execute(&self.pool).await?.rows_affected())
    }
}
