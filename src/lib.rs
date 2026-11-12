//! Experimental, transport-neutral MessageBox application core.
//!
//! This is not a BRC-103 authentication implementation or a drop-in server.
//! An embedding application must verify authentication before constructing an
//! [`Identity`], and supply its authoritative [`DeliveryPolicy`]. No identity
//! header, wallet, payment processing, MCAP bypass, or network listener exists.

pub mod auth_frame;
pub mod auth_nonce;
pub mod auth_responder;
pub mod auth_store;
pub mod authsocket_payload;
pub mod beef_bump;
pub mod beef_subset;
pub mod brc29_recipient_script;
pub mod brc42;
pub mod compact_size;
pub mod delivery_remittance;
mod devices;
pub mod fcm_delivery;
pub mod fcm_http_v1;
pub mod fcm_https;
pub mod fcm_payload;
mod firebase_adc;
pub mod firebase_host;
pub mod firebase_init;
pub mod http_auth;
mod http_canonical;
mod http_routing;
pub mod http_stream;
pub mod legacy_delivery_amount;
pub mod local_auth_wallet;
pub mod payment_candidate;
pub mod payment_header;
mod payment_index;
pub mod payment_intent_digest;
pub mod payment_intents;
pub mod payment_replay;
pub mod payment_stage;
mod permissions;
pub mod public_health;
pub mod recipient_allocation;
pub mod recipient_output_check;
pub mod regular_bump;
pub mod resource_config;
pub mod runtime_config;
pub mod runtime_resources;
mod server_fees;
pub mod transaction_frame;
pub mod websocket_policy;
pub mod websocket_registry;

use chrono::{SecondsFormat, Utc};
use futures_util::{StreamExt, TryStreamExt};
use k256::{PublicKey, elliptic_curve::sec1::ToEncodedPoint};
use serde_json::{Value, json};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{collections::HashSet, path::Path, sync::Arc};

/// Canonical secp256k1 public identity, already verified by the embedding app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity(String);

impl Identity {
    /// Canonicalizes a key. **Does not authenticate it.** Call only after an
    /// SDK/transport has verified the request's proof of this identity.
    pub fn from_verified_key(key: &str) -> Result<Self, InvalidIdentity> {
        canonical_key(key).map(Self).ok_or(InvalidIdentity)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub struct InvalidIdentity;

fn canonical_key(key: &str) -> Option<String> {
    let bytes = hex::decode(key).ok()?;
    let key = PublicKey::from_sec1_bytes(&bytes).ok()?;
    Some(hex::encode(key.to_encoded_point(true).as_bytes()))
}

/// Decision of an authoritative policy adapter, including server delivery fees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Free,
    Blocked,
    PaymentRequired,
}
#[derive(Debug)]
pub struct PolicyError;

/// Plug in server delivery fees and additional application admission policy.
/// `with_sqlite_server_fees` explicitly replaces this policy's fee source, but
/// does not replace its admission decision. Stored recipient permissions are enforced independently and cannot be
/// overridden by this adapter. There is no permissive production default.
/// A policy error fails closed before any storage mutation.
pub trait DeliveryPolicy: Send + Sync {
    fn evaluate(
        &self,
        sender: &Identity,
        recipient: &str,
        message_box: &str,
    ) -> Result<Decision, PolicyError>;

    /// Returns the authoritative per-recipient server fee in satoshis for a
    /// quote and send admission, in the range 0..=2_147_483_647. An adapter reading upstream-like
    /// state should return zero for a missing or null fee and the stored value
    /// otherwise. Existing adapters fail closed until they implement this method.
    fn delivery_fee(&self, _message_box: &str) -> Result<i64, PolicyError> {
        Err(PolicyError)
    }
}

/// Runtime limits for the embedded core. Quota fields accept -1 for unlimited.
/// Use `RuntimeResources` for a checked environment-derived startup profile.
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_body_bytes: usize,
    pub max_recipients: usize,
    pub default_list_limit: usize,
    pub max_list_limit: usize,
    pub max_list_offset: usize,
    pub max_list_response_bytes: usize,
    pub max_ack_ids: usize,
    pub max_inbox_messages: i64,
    pub max_inbox_bytes: i64,
    pub max_sender_messages: i64,
    pub max_sender_bytes: i64,
    pub retention_days: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024,
            max_recipients: 100,
            default_list_limit: 1000,
            max_list_limit: 1000,
            max_list_offset: 100_000,
            max_list_response_bytes: 8 * 1024 * 1024,
            max_ack_ids: 1000,
            max_inbox_messages: 10_000,
            max_inbox_bytes: 1024 * 1024 * 1024,
            max_sender_messages: 10_000,
            max_sender_bytes: 1024 * 1024 * 1024,
            retention_days: 30,
        }
    }
}
impl Limits {
    fn validate(&self, resource_profile: bool) -> Result<(), sqlx::Error> {
        if (!resource_profile
            && (self.max_recipients > 1_000
                || self.max_list_limit > 100_000
                || self.max_list_offset > 1_000_000
                || self.max_list_response_bytes < 256
                || self.max_ack_ids > 10_000
                || self.max_inbox_messages <= 0
                || self.max_inbox_bytes <= 0
                || self.max_sender_messages <= 0
                || self.max_sender_bytes <= 0
                || self.retention_days > 36_500))
            || self.max_body_bytes == 0
            || self.max_recipients == 0
            || i64::try_from(self.max_recipients).is_err()
            || self.default_list_limit == 0
            || (!resource_profile && self.default_list_limit > self.max_list_limit)
            || i64::try_from(self.max_list_limit).is_err()
            || self.max_list_limit == i64::MAX as usize
            || i64::try_from(self.max_list_offset).is_err()
            || self.max_list_response_bytes == 0
            || self.max_ack_ids == 0
            || self.max_inbox_messages == 0
            || self.max_inbox_messages < -1
            || self.max_inbox_bytes == 0
            || self.max_inbox_bytes < -1
            || self.max_sender_messages == 0
            || self.max_sender_messages < -1
            || self.max_sender_bytes == 0
            || self.max_sender_bytes < -1
            || self.retention_days == 0
        {
            return Err(sqlx::Error::Configuration(
                "invalid bounded MessageBox resource limits".into(),
            ));
        }
        Ok(())
    }
}

// Existing databases used NOT NULL. Rebuild only that known table once, in a
// transaction, preserving its rows; indexes are recreated by connect().
async fn migrate_nullable_expiry(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let columns = sqlx::query("PRAGMA table_info(messages)")
        .fetch_all(pool)
        .await?;
    let old = columns
        .iter()
        .any(|r| r.get::<String, _>("name") == "expires_at" && r.get::<i64, _>("notnull") != 0);
    if !old {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    sqlx::query("CREATE TABLE messages_nullable (message_id TEXT PRIMARY KEY NOT NULL, recipient TEXT NOT NULL, sender TEXT NOT NULL, message_box TEXT NOT NULL, body TEXT NOT NULL, body_bytes INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at INTEGER)").execute(&mut *tx).await?;
    sqlx::query("INSERT INTO messages_nullable SELECT message_id, recipient, sender, message_box, body, body_bytes, created_at, expires_at FROM messages").execute(&mut *tx).await?;
    sqlx::query("DROP TABLE messages").execute(&mut *tx).await?;
    sqlx::query("ALTER TABLE messages_nullable RENAME TO messages")
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

#[derive(Debug)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Value,
}
impl ApiResponse {
    fn ok(body: Value) -> Self {
        Self { status: 200, body }
    }
    fn error(status: u16, code: &str, description: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({"status":"error","code":code,"description":description.into()}),
        }
    }
}
type ApiResult<T> = Result<T, ApiResponse>;

pub struct MessageBox {
    pool: SqlitePool,
    policy: Arc<dyn DeliveryPolicy>,
    fee_source: server_fees::DeliveryFeeSource,
    limits: Limits,
    fcm: Option<fcm_delivery::FcmConfiguration>,
    resources: Option<runtime_resources::RuntimeResources>,
}
impl MessageBox {
    /// Opens this port's SQLite schema. This does not migrate an upstream MySQL DB.
    pub async fn open(
        path: impl AsRef<Path>,
        policy: Arc<dyn DeliveryPolicy>,
        limits: Limits,
    ) -> Result<Self, sqlx::Error> {
        Self::connect(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true),
            policy,
            limits,
            false,
        )
        .await
    }
    /// Opens with a checked, immutable resource profile.
    pub async fn open_with_resources(
        path: impl AsRef<Path>,
        policy: Arc<dyn DeliveryPolicy>,
        resources: runtime_resources::RuntimeResources,
    ) -> Result<Self, sqlx::Error> {
        let mut app = Self::connect(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true),
            policy,
            resources.limits.clone(),
            true,
        )
        .await?;
        app.resources = Some(resources);
        Ok(app)
    }
    /// In-memory variant for embedded hosts and tests.
    pub async fn memory_with_resources(
        policy: Arc<dyn DeliveryPolicy>,
        resources: runtime_resources::RuntimeResources,
    ) -> Result<Self, sqlx::Error> {
        let mut app = Self::connect(
            SqliteConnectOptions::new().in_memory(true),
            policy,
            resources.limits.clone(),
            true,
        )
        .await?;
        app.resources = Some(resources);
        Ok(app)
    }
    pub async fn memory(
        policy: Arc<dyn DeliveryPolicy>,
        limits: Limits,
    ) -> Result<Self, sqlx::Error> {
        Self::connect(
            SqliteConnectOptions::new().in_memory(true),
            policy,
            limits,
            false,
        )
        .await
    }
    async fn connect(
        options: SqliteConnectOptions,
        policy: Arc<dyn DeliveryPolicy>,
        limits: Limits,
        resource_profile: bool,
    ) -> Result<Self, sqlx::Error> {
        limits.validate(resource_profile)?;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS messages (message_id TEXT PRIMARY KEY NOT NULL, recipient TEXT NOT NULL, sender TEXT NOT NULL, message_box TEXT NOT NULL, body TEXT NOT NULL, body_bytes INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at INTEGER)").execute(&pool).await?;
        migrate_nullable_expiry(&pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS inbox_order ON messages(recipient, message_box, created_at, message_id)").execute(&pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS sender_usage ON messages(sender, expires_at)")
            .execute(&pool)
            .await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS device_registrations (id INTEGER PRIMARY KEY AUTOINCREMENT, identity_key TEXT NOT NULL, fcm_token TEXT NOT NULL UNIQUE, device_id TEXT, platform TEXT, active INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_used TEXT NOT NULL)").execute(&pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS devices_owner ON device_registrations(identity_key, updated_at DESC)").execute(&pool).await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS message_permissions (recipient TEXT NOT NULL, message_box TEXT NOT NULL, sender_scope TEXT NOT NULL, recipient_fee INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(recipient, message_box, sender_scope))").execute(&pool).await?;
        payment_replay::initialize_schema(&pool).await?;
        payment_intents::initialize_schema(&pool).await?;
        Ok(Self {
            pool,
            policy,
            fee_source: server_fees::DeliveryFeeSource::default(),
            limits,
            fcm: None,
            resources: None,
        })
    }
    /// Probe only the application SQLite connection, as the upstream readiness
    /// route does. This is not a wallet, authentication or chain health check.
    pub async fn database_ready(&self) -> bool {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }
    /// Deletes expired messages. The embedding app must schedule maintenance.
    /// This is not an HTTP route and never touches unexpired messages.
    pub async fn purge_expired(&self) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query("DELETE FROM messages WHERE expires_at<=?")
            .bind(Utc::now().timestamp_millis())
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    pub async fn close(self) {
        self.pool.close().await;
    }

    /// Applies a supported route to parsed fields and a **verified** caller.
    /// For permission get/list, `request` contains parsed query fields, not a body.
    /// Route names/JSON shapes are modeled after upstream; this is not HTTP I/O.
    pub async fn handle(
        &self,
        path: &str,
        identity: Option<&Identity>,
        request: &Value,
    ) -> ApiResponse {
        if !matches!(
            path,
            "/sendMessage"
                | "/listMessages"
                | "/acknowledgeMessage"
                | "/permissions/set"
                | "/permissions/get"
                | "/permissions/list"
                | "/permissions/quote"
                | "/registerDevice"
                | "/devices"
        ) {
            return ApiResponse::error(
                501,
                "ERR_NOT_IMPLEMENTED",
                "This route is not implemented by the Rust core.",
            );
        }
        let Some(identity) = identity else {
            return if path == "/sendMessage" {
                ApiResponse::error(401, "ERR_AUTH_REQUIRED", "Authentication required")
            } else if path == "/permissions/list" {
                ApiResponse::error(401, "ERR_UNAUTHORIZED", "Authentication required")
            } else {
                ApiResponse::error(
                    401,
                    "ERR_AUTHENTICATION_REQUIRED",
                    "Authentication required.",
                )
            };
        };
        // TS listMessages reads req.body.messageBox from arrays as undefined.
        if !(request.is_object() || path == "/listMessages" && request.is_array()) {
            return ApiResponse::error(
                400,
                "ERR_INVALID_REQUEST_DATA",
                "Request fields must be own JSON data.",
            );
        }
        let result = match path {
            "/sendMessage" => self.send(identity, request).await,
            "/listMessages" => self.list(identity, request).await,
            "/acknowledgeMessage" => self.ack(identity, request).await,
            "/permissions/set" => self.set_permission(identity, request).await,
            "/permissions/get" => self.get_permission(identity, request).await,
            "/permissions/list" => self.list_permissions(identity, request).await,
            "/permissions/quote" => self.quote_permission(identity, request).await,
            "/registerDevice" => self.register_device(identity, request).await,
            _ => self.list_devices(identity, request).await,
        };
        match result {
            Ok(body) => ApiResponse::ok(body),
            Err(error) => error,
        }
    }

    async fn send(&self, sender: &Identity, request: &Value) -> ApiResult<Value> {
        // The pinned TS handler snapshots every known message field before
        // validating it, even fields shadowed by another recipient field.
        const SNAPSHOT_ARRAY_MAX: usize = 101;
        if request
            .get("message")
            .and_then(Value::as_object)
            .is_some_and(|message| {
                ["recipient", "recipients", "messageBox", "messageId", "body"]
                    .iter()
                    .filter_map(|field| message.get(*field).and_then(Value::as_array))
                    .any(|array| array.len() > SNAPSHOT_ARRAY_MAX)
            })
        {
            return Err(ApiResponse::error(
                400,
                "ERR_INVALID_REQUEST_DATA",
                "Request fields must be own JSON data.",
            ));
        }
        let message = validate_message(
            request,
            &self.limits,
            self.resources.as_ref().is_some_and(|r| {
                matches!(
                    r.config.max_recipients,
                    resource_config::ResourceLimit::Unlimited
                )
            }),
        )?;
        // No payment field is ignored or reported as accepted, including null.
        if request.get("payment").is_some() {
            return Err(ApiResponse::error(
                501,
                "ERR_PAYMENT_NOT_IMPLEMENTED",
                "Payment processing is not implemented by the Rust core.",
            ));
        }
        // The fixed TS route reads its legacy server fee before recipient
        // permissions. Keep existing host-policy ordering in the default mode.
        let table_fee = match self.fee_source {
            server_fees::DeliveryFeeSource::Sqlite => Some(
                self.server_delivery_fee(&message.message_box)
                    .await
                    .map_err(|_| internal("send"))?,
            ),
            server_fees::DeliveryFeeSource::HostPolicy => None,
        };
        let mut blocked = vec![];
        let mut requires_payment = false;
        for recipient in &message.recipients {
            let server_decision = self
                .policy
                .evaluate(sender, recipient, &message.message_box)
                .map_err(|_| {
                    ApiResponse::error(
                        503,
                        "ERR_POLICY_UNAVAILABLE",
                        "Delivery policy is unavailable.",
                    )
                })?;
            let recipient_decision = self
                .recipient_decision(sender, recipient, &message.message_box)
                .await?;
            // Both policies apply. A stored allow can never bypass a server
            // restriction, nor can a server allow bypass the recipient's block.
            if server_decision == Decision::Blocked || recipient_decision == Decision::Blocked {
                blocked.push(recipient.clone());
            } else if server_decision == Decision::PaymentRequired
                || recipient_decision == Decision::PaymentRequired
            {
                requires_payment = true;
            }
        }
        if !blocked.is_empty() {
            let mut error = ApiResponse::error(
                403,
                "ERR_DELIVERY_BLOCKED",
                format!("Blocked recipients: {}", blocked.join(", ")),
            );
            error.body["blockedRecipients"] = json!(blocked);
            return Err(error);
        }
        // The delivery fee is authoritative independently of the additional
        // admission policy. Fail closed if the host cannot supply a valid fee;
        // this core does not yet verify or accept payment.
        let delivery_fee = match table_fee {
            Some(fee) => fee,
            None => self
                .server_delivery_fee(&message.message_box)
                .await
                .map_err(|_| {
                    ApiResponse::error(
                        503,
                        "ERR_POLICY_UNAVAILABLE",
                        "Delivery policy is unavailable.",
                    )
                })?,
        };
        if requires_payment || delivery_fee > 0 {
            return Err(ApiResponse::error(
                501,
                "ERR_PAYMENT_NOT_IMPLEMENTED",
                "Delivery requires payment, which is not implemented by the Rust core.",
            ));
        }
        let body = json!({"message":message.body}).to_string();
        let body_bytes = i64::try_from(body.len()).map_err(|_| internal("send"))?;
        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        let expires = match &self.resources {
            Some(resources) => resources
                .expires_at_ms(now_ms)
                .map_err(|_| internal("send"))?,
            None => Some(
                now_ms
                    .checked_add(i64::from(self.limits.retention_days) * 86_400_000)
                    .ok_or_else(|| internal("send"))?,
            ),
        };
        let created_at = now.to_rfc3339_opts(SecondsFormat::Millis, true);
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| internal("send"))?;
        let (count, bytes): (i64,i64) = sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(body_bytes),0) FROM messages WHERE sender=? AND (expires_at IS NULL OR expires_at>?)")
            .bind(sender.as_str()).bind(now_ms).fetch_one(&mut *tx).await.map_err(|_| internal("send"))?;
        quota(
            count,
            bytes,
            message.recipients.len() as i64,
            body_bytes
                .checked_mul(i64::try_from(message.recipients.len()).map_err(|_| internal("send"))?)
                .ok_or_else(|| internal("send"))?,
            self.limits.max_sender_messages,
            self.limits.max_sender_bytes,
            true,
        )?;
        for (recipient, message_id) in message.recipients.iter().zip(&message.ids) {
            let (count,bytes): (i64,i64) = sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(body_bytes),0) FROM messages WHERE recipient=? AND (expires_at IS NULL OR expires_at>?)")
                .bind(recipient).bind(now_ms).fetch_one(&mut *tx).await.map_err(|_| internal("send"))?;
            quota(
                count,
                bytes,
                1,
                body_bytes,
                self.limits.max_inbox_messages,
                self.limits.max_inbox_bytes,
                false,
            )?;
            let result = sqlx::query("INSERT INTO messages(message_id, recipient, sender, message_box, body, body_bytes, created_at, expires_at) VALUES(?,?,?,?,?,?,?,?)")
                .bind(message_id).bind(recipient).bind(sender.as_str()).bind(&message.message_box).bind(&body).bind(body_bytes).bind(&created_at).bind(expires)
                .execute(&mut *tx).await;
            if let Err(error) = result {
                if error
                    .as_database_error()
                    .is_some_and(|e| e.is_unique_violation())
                {
                    return Err(ApiResponse::error(
                        400,
                        "ERR_DUPLICATE_MESSAGE",
                        "Duplicate message.",
                    ));
                }
                return Err(internal("send"));
            }
        }
        tx.commit().await.map_err(|_| internal("send"))?;
        if message.message_box == "notifications"
            && let Some(fcm) = &self.fcm
        {
            let concurrency = if fcm.recipient_concurrency == -1 {
                message.recipients.len()
            } else {
                usize::try_from(fcm.recipient_concurrency)
                    .unwrap_or(usize::MAX)
                    .min(message.recipients.len())
            };
            let recipients: Vec<_> = message
                .recipients
                .iter()
                .cloned()
                .zip(message.ids.iter().cloned())
                .collect();
            futures_util::stream::iter(recipients.into_iter().map(|(recipient, id)| async move {
                let payload = fcm_delivery::FcmPayload {
                    title: "New Message",
                    message_id: &id,
                    originator: None,
                };
                self.send_fcm_notification(
                    &recipient,
                    &payload,
                    Some(Arc::clone(&fcm.provider)),
                    fcm.options,
                )
                .await
            }))
            .buffer_unordered(concurrency)
            .collect::<Vec<_>>()
            .await;
        }
        let results: Vec<_> = message
            .recipients
            .iter()
            .zip(&message.ids)
            .map(|(r, id)| json!({"recipient":r,"messageId":id}))
            .collect();
        Ok(
            json!({"status":"success","message":format!("Your message has been sent to {} recipient(s).",results.len()),"results":results}),
        )
    }

    async fn list(&self, identity: &Identity, request: &Value) -> ApiResult<Value> {
        let value = &request["messageBox"];
        if value.is_null() || value.as_str().is_some_and(|s| js_trim(s).is_empty()) {
            return Err(ApiResponse::error(
                400,
                "ERR_MESSAGEBOX_REQUIRED",
                "Please provide the name of a valid MessageBox!",
            ));
        }
        let message_box = value.as_str().ok_or_else(|| {
            ApiResponse::error(
                400,
                "ERR_INVALID_MESSAGEBOX",
                "MessageBox name must be a string!",
            )
        })?;
        if !exact_text(message_box, 128) {
            return Err(ApiResponse::error(
                400,
                "ERR_INVALID_MESSAGEBOX",
                "MessageBox names must be exact, control-free strings of at most 128 bytes.",
            ));
        }
        let message_id = match request.get("messageId") {
            None => None,
            Some(value) => Some(value.as_str().filter(|s| exact_text(s, 256)).ok_or_else(
                || {
                    ApiResponse::error(
                        400,
                        "ERR_INVALID_MESSAGE_ID",
                        "messageId must be an exact bounded control-free string.",
                    )
                },
            )?),
        };
        let offset = request.get("offset").filter(|v| !v.is_null());
        let skip = request.get("skip").filter(|v| !v.is_null());
        if let (Some(offset), Some(skip)) = (offset, skip)
            && (offset.as_f64().is_none() || offset.as_f64() != skip.as_f64())
        {
            return Err(ApiResponse::error(
                400,
                "ERR_INVALID_OFFSET",
                "offset and skip must match when both are provided.",
            ));
        }
        let limit = bounded_integer(
            request.get("limit"),
            self.limits.default_list_limit,
            1,
            self.limits.max_list_limit,
            "ERR_INVALID_LIMIT",
            "limit",
            self.resources.as_ref().is_some_and(|r| {
                matches!(
                    r.config.list_max_limit,
                    resource_config::ResourceLimit::Unlimited
                )
            }),
        )?;
        let offset = bounded_integer(
            offset.or(skip),
            0,
            0,
            self.limits.max_list_offset,
            "ERR_INVALID_OFFSET",
            "offset",
            self.resources.as_ref().is_some_and(|r| {
                matches!(
                    r.config.list_max_offset,
                    resource_config::ResourceLimit::Unlimited
                )
            }),
        )?;
        let mut rows = sqlx::query("SELECT message_id, body, sender, created_at FROM messages WHERE recipient=? AND message_box=? AND (expires_at IS NULL OR expires_at>?) AND (? IS NULL OR message_id=?) ORDER BY created_at ASC, message_id ASC LIMIT ? OFFSET ?")
            .bind(identity.as_str()).bind(message_box).bind(Utc::now().timestamp_millis()).bind(message_id).bind(message_id)
            .bind((limit+1) as i64).bind(offset as i64).fetch(&self.pool);
        let mut messages = vec![];
        let mut bytes = 256;
        let mut has_more = false;
        while let Some(row) = rows.try_next().await.map_err(|_| internal("list"))? {
            if messages.len() >= limit {
                has_more = true;
                break;
            }
            let message = json!({"messageId":row.get::<String,_>("message_id"),"body":row.get::<String,_>("body"),"sender":row.get::<String,_>("sender"),"createdAt":row.get::<String,_>("created_at"),"updatedAt":row.get::<String,_>("created_at")});
            let item_bytes = message.to_string().len() + 1;
            if bytes + item_bytes > self.limits.max_list_response_bytes {
                if messages.is_empty() {
                    return Err(ApiResponse::error(
                        413,
                        "ERR_MESSAGE_RESPONSE_TOO_LARGE",
                        "The oldest message exceeds the configured listing response budget.",
                    ));
                }
                has_more = true;
                break;
            }
            bytes += item_bytes;
            messages.push(message);
        }
        Ok(
            json!({"status":"success","limit":limit,"offset":offset,"nextOffset":offset+messages.len(),"hasMore":has_more,"messages":messages}),
        )
    }

    async fn ack(&self, identity: &Identity, request: &Value) -> ApiResult<Value> {
        let value = &request["messageIds"];
        if value.is_null() || value.as_array().is_some_and(|v| v.is_empty()) {
            return Err(ApiResponse::error(
                400,
                "ERR_MESSAGE_ID_REQUIRED",
                "Please provide the ID of the message(s) to acknowledge!",
            ));
        }
        let invalid = || {
            ApiResponse::error(
                400,
                "ERR_INVALID_MESSAGE_ID",
                if self.resources.as_ref().is_some_and(|r| {
                    matches!(
                        r.config.max_acknowledgment_ids,
                        resource_config::ResourceLimit::Unlimited
                    )
                }) {
                    "Message IDs must be a non-empty array of exact, control-free strings no longer than 256 bytes each.".to_owned()
                } else {
                    format!(
                        "Message IDs must be a non-empty array of at most {} of exact, control-free strings no longer than 256 bytes each.",
                        self.limits.max_ack_ids
                    )
                },
            )
        };
        let ids = value
            .as_array()
            .filter(|v| v.len() <= self.limits.max_ack_ids)
            .ok_or_else(invalid)?;
        let ids: HashSet<&str> = ids
            .iter()
            .map(|v| {
                v.as_str()
                    .filter(|s| exact_text(s, 256))
                    .ok_or_else(invalid)
            })
            .collect::<Result<_, _>>()?;
        let mut tx = self.pool.begin().await.map_err(|_| internal("ack"))?;
        let mut deleted = 0;
        for id in ids {
            deleted += sqlx::query("DELETE FROM messages WHERE recipient=? AND message_id=?")
                .bind(identity.as_str())
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(|_| internal("ack"))?
                .rows_affected();
        }
        if deleted == 0 {
            return Err(ApiResponse::error(
                400,
                "ERR_INVALID_ACKNOWLEDGMENT",
                "Message not found!",
            ));
        }
        tx.commit().await.map_err(|_| internal("ack"))?;
        Ok(json!({"status":"success"}))
    }
}

fn internal(operation: &str) -> ApiResponse {
    match operation {
        "send" => ApiResponse::error(500, "ERR_INTERNAL", "An internal error has occurred."),
        "list" => ApiResponse::error(
            500,
            "ERR_INTERNAL_ERROR",
            "An internal error has occurred while listing messages.",
        ),
        _ => ApiResponse::error(
            500,
            "ERR_INTERNAL_ERROR",
            "An internal error has occurred while acknowledging the message",
        ),
    }
}
fn quota(
    count: i64,
    bytes: i64,
    add_count: i64,
    add_bytes: i64,
    max_count: i64,
    max_bytes: i64,
    sender: bool,
) -> ApiResult<()> {
    let exceeded = if max_count != -1
        && i128::from(count) + i128::from(add_count) > i128::from(max_count)
    {
        Some(("messages", max_count))
    } else if max_bytes != -1 && i128::from(bytes) + i128::from(add_bytes) > i128::from(max_bytes) {
        Some(("bytes", max_bytes))
    } else {
        None
    };
    if let Some((resource, limit)) = exceeded {
        let (code, description) = if sender {
            (
                "ERR_SENDER_QUOTA_EXCEEDED",
                "The sender storage quota has been reached. Retry after messages expire.",
            )
        } else {
            (
                "ERR_INBOX_QUOTA_EXCEEDED",
                "The recipient inbox storage quota has been reached. Retry after messages are acknowledged or expire.",
            )
        };
        let mut error = ApiResponse::error(429, code, description);
        error.body["resource"] = json!(resource);
        error.body["limit"] = json!(limit);
        Err(error)
    } else {
        Ok(())
    }
}

// ECMAScript WhiteSpace + LineTerminator, deliberately not Rust's broader trim.
fn js_whitespace(c: char) -> bool {
    matches!(c,'\u{0009}'..='\u{000d}'|'\u{0020}'|'\u{00a0}'|'\u{1680}'|'\u{2000}'..='\u{200a}'|'\u{2028}'|'\u{2029}'|'\u{202f}'|'\u{205f}'|'\u{3000}'|'\u{feff}')
}
fn js_trim(s: &str) -> &str {
    s.trim_matches(js_whitespace)
}
fn exact_text(s: &str, max: usize) -> bool {
    !s.is_empty()
        && js_trim(s) == s
        && s.len() <= max
        && !s
            .chars()
            .any(|c| c <= '\u{001f}' || ('\u{007f}'..='\u{009f}').contains(&c))
}
fn bounded_integer(
    value: Option<&Value>,
    default: usize,
    min: usize,
    max: usize,
    code: &str,
    name: &str,
    unlimited: bool,
) -> ApiResult<usize> {
    let default_value = json!(default);
    let value = value.filter(|v| !v.is_null()).unwrap_or(&default_value);
    if let Some(value) = value.as_f64()
        && value.fract() == 0.0
        && value >= min as f64
        && value <= max as f64
    {
        return Ok(value as usize);
    }
    Err(ApiResponse::error(
        400,
        code,
        format!(
            "{name} must be an integer between {min} and {}.",
            if unlimited {
                "the JavaScript safe-integer maximum".to_owned()
            } else {
                max.to_string()
            }
        ),
    ))
}

struct Message {
    message_box: String,
    body: String,
    recipients: Vec<String>,
    ids: Vec<String>,
}
fn validate_message(
    request: &Value,
    limits: &Limits,
    unlimited_recipients: bool,
) -> ApiResult<Message> {
    let message = &request["message"];
    if message.is_null() {
        return Err(ApiResponse::error(
            400,
            "ERR_MESSAGE_REQUIRED",
            "Please provide a valid message to send!",
        ));
    }
    let message_box = message["messageBox"]
        .as_str()
        .filter(|s| !js_trim(s).is_empty())
        .ok_or_else(|| ApiResponse::error(400, "ERR_INVALID_MESSAGEBOX", "Invalid message box."))?;
    if message_box.len() > 128 {
        return Err(ApiResponse::error(
            400,
            "ERR_MESSAGEBOX_TOO_LARGE",
            "Message box names must not exceed 128 bytes.",
        ));
    }
    if !exact_text(message_box, 128) {
        return Err(ApiResponse::error(
            400,
            "ERR_INVALID_MESSAGEBOX",
            "Message box names must be exact and control-free.",
        ));
    }
    let body = message["body"]
        .as_str()
        .filter(|s| !js_trim(s).is_empty())
        .ok_or_else(|| {
            ApiResponse::error(400, "ERR_INVALID_MESSAGE_BODY", "Invalid message body.")
        })?;
    if body.len() > limits.max_body_bytes {
        return Err(ApiResponse::error(
            413,
            "ERR_MESSAGE_BODY_TOO_LARGE",
            format!(
                "Message bodies must not exceed {} bytes.",
                limits.max_body_bytes
            ),
        ));
    }
    let recipients = message
        .get("recipients")
        .filter(|v| !v.is_null())
        .unwrap_or(&message["recipient"]);
    if recipients.is_null() {
        return Err(ApiResponse::error(
            400,
            "ERR_RECIPIENT_REQUIRED",
            "Missing recipient(s). Provide \"recipient\" or \"recipients\".",
        ));
    }
    let recipients: Vec<&Value> = recipients
        .as_array()
        .map(|v| v.iter().collect())
        .unwrap_or(vec![recipients]);
    if recipients.is_empty() || recipients.len() > limits.max_recipients {
        return Err(ApiResponse::error(
            400,
            "ERR_TOO_MANY_RECIPIENTS",
            if unlimited_recipients {
                "A message must include at least one recipient.".to_owned()
            } else {
                format!(
                    "A message may include at most {} recipients.",
                    limits.max_recipients
                )
            },
        ));
    }
    let recipients: Vec<String> = recipients
        .iter()
        .map(|v| {
            v.as_str()
                .and_then(|s| canonical_key(js_trim(s)))
                .ok_or_else(|| {
                    ApiResponse::error(400, "ERR_INVALID_RECIPIENT_KEY", "Invalid recipient key.")
                })
        })
        .collect::<Result<_, _>>()?;
    if recipients.iter().collect::<HashSet<_>>().len() != recipients.len() {
        return Err(ApiResponse::error(
            400,
            "ERR_DUPLICATE_RECIPIENT",
            "Each recipient may appear only once in a batch.",
        ));
    }
    let ids = &message["messageId"];
    if ids.is_null() {
        return Err(ApiResponse::error(
            400,
            "ERR_MESSAGEID_REQUIRED",
            "Missing messageId.",
        ));
    }
    let ids: Vec<&Value> = ids
        .as_array()
        .map(|v| v.iter().collect())
        .unwrap_or(vec![ids]);
    if recipients.len() > 1 && ids.len() == 1 {
        return Err(ApiResponse::error(
            400,
            "ERR_MESSAGEID_COUNT_MISMATCH",
            format!(
                "Provided 1 messageId for {} recipients. Provide one messageId per recipient (same order).",
                recipients.len()
            ),
        ));
    }
    if ids.len() != recipients.len() {
        return Err(ApiResponse::error(
            400,
            "ERR_MESSAGEID_COUNT_MISMATCH",
            format!(
                "Recipients ({}) and messageId count ({}) must match.",
                recipients.len(),
                ids.len()
            ),
        ));
    }
    let ids:Vec<String> = ids.iter().map(|v|v.as_str().filter(|s|exact_text(s,256)).map(str::to_owned).ok_or_else(||ApiResponse::error(400,"ERR_INVALID_MESSAGEID","Each messageId must be an exact, control-free string of at most 256 bytes."))).collect::<Result<_,_>>()?;
    Ok(Message {
        message_box: message_box.to_owned(),
        body: body.to_owned(),
        recipients,
        ids,
    })
}
