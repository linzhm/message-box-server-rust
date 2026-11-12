//! Offline durable state for legacy message payment intents.
//!
//! This is not connected to the message route or any wallet. The caller must
//! derive the canonical lowercase transaction ID from the verified transaction
//! and derive the digest from an authenticated, validated request using the pinned
//! upstream serialization, not trust a digest supplied by a client. The caller
//! must generate a fresh cryptographically random attempt token for every new
//! request, reusing it only for that same owned attempt; identical tokens cannot
//! be distinguished by this store. The caller must release a prepared intent
//! only if the wallet was never attempted, and
//! mark completion only after the message and replay transaction commits. These
//! records alone do not verify payment or automatically recover wallet effects.
//! The Rust-owned schema is not the upstream migration schema.
use chrono::Utc;
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{io, path::Path};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub transaction_id: String,
    pub request_digest: String,
    pub attempt_token: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntentStatus {
    Prepared,
    WalletAccepted,
    Completed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedIntent {
    pub binding: Binding,
    pub status: IntentStatus,
}
#[derive(Debug)]
pub enum IntentError {
    DifferentRequest,
    InProgress,
    InvalidState,
    Database(sqlx::Error),
}
impl From<sqlx::Error> for IntentError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}
pub struct SqlitePaymentIntentStore {
    pool: SqlitePool,
}
impl SqlitePaymentIntentStore {
    /// Open a Rust-owned database file. The embedding app is responsible for
    /// using its intended durable MessageBox database and SQLite filesystem.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, sqlx::Error> {
        let path = path.as_ref();
        let text = path.as_os_str().to_string_lossy();
        if text.is_empty() || text == ":memory:" || text.to_ascii_lowercase().starts_with("file:") {
            return Err(sqlx::Error::Configuration(Box::new(io::Error::other(
                "intent store requires a filesystem path",
            ))));
        }
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(path)
                    .create_if_missing(true),
            )
            .await?;
        initialize_schema(&pool).await?;
        Ok(Self { pool })
    }
    pub async fn prepare(&self, binding: &Binding) -> Result<PreparedIntent, IntentError> {
        let now = Utc::now().timestamp_millis();
        sqlx::query("INSERT INTO rust_message_payment_intents(transaction_id,request_digest,status,attempt_token,created_at_ms,updated_at_ms) VALUES(?,?,'prepared',?,?,?) ON CONFLICT(transaction_id) DO NOTHING").bind(&binding.transaction_id).bind(&binding.request_digest).bind(&binding.attempt_token).bind(now).bind(now).execute(&self.pool).await?;
        let row = sqlx::query("SELECT request_digest,status,attempt_token FROM rust_message_payment_intents WHERE transaction_id=?").bind(&binding.transaction_id).fetch_optional(&self.pool).await?.ok_or(IntentError::InvalidState)?;
        let digest: String = row.try_get("request_digest")?;
        let token: String = row.try_get("attempt_token")?;
        let raw: String = row.try_get("status")?;
        if digest != binding.request_digest {
            return Err(IntentError::DifferentRequest);
        }
        let status = match raw.as_str() {
            "prepared" => IntentStatus::Prepared,
            "wallet_accepted" => IntentStatus::WalletAccepted,
            "completed" => IntentStatus::Completed,
            _ => return Err(IntentError::InvalidState),
        };
        if status == IntentStatus::Prepared && token != binding.attempt_token {
            return Err(IntentError::InProgress);
        }
        Ok(PreparedIntent {
            binding: Binding {
                transaction_id: binding.transaction_id.clone(),
                request_digest: digest,
                attempt_token: token,
            },
            status,
        })
    }
    pub async fn mark_wallet_accepted(&self, binding: &Binding) -> Result<bool, sqlx::Error> {
        self.update(binding, false).await
    }
    pub async fn mark_completed(&self, binding: &Binding) -> Result<bool, sqlx::Error> {
        self.update(binding, true).await
    }
    async fn update(&self, b: &Binding, completed: bool) -> Result<bool, sqlx::Error> {
        let (target, statuses) = if completed {
            ("completed", "('prepared','wallet_accepted','completed')")
        } else {
            ("wallet_accepted", "('prepared','wallet_accepted')")
        };
        let query = format!(
            "UPDATE rust_message_payment_intents SET status=?, updated_at_ms=? WHERE transaction_id=? AND request_digest=? AND attempt_token=? AND status IN {statuses}"
        );
        let updated = sqlx::query(&query)
            .bind(target)
            .bind(Utc::now().timestamp_millis())
            .bind(&b.transaction_id)
            .bind(&b.request_digest)
            .bind(&b.attempt_token)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if updated == 1 {
            return Ok(true);
        }
        if completed {
            return Ok(false);
        }
        let status: Option<String> = sqlx::query_scalar("SELECT status FROM rust_message_payment_intents WHERE transaction_id=? AND request_digest=? AND attempt_token=?").bind(&b.transaction_id).bind(&b.request_digest).bind(&b.attempt_token).fetch_optional(&self.pool).await?;
        Ok(status.as_deref() == Some("completed"))
    }
    /// Only call if the wallet was not attempted for this prepared binding.
    pub async fn release_prepared(&self, b: &Binding) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM rust_message_payment_intents WHERE transaction_id=? AND request_digest=? AND attempt_token=? AND status='prepared'").bind(&b.transaction_id).bind(&b.request_digest).bind(&b.attempt_token).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }
    pub async fn close(self) {
        self.pool.close().await;
    }
}

pub(crate) async fn initialize_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("CREATE TABLE IF NOT EXISTS rust_message_payment_intents (transaction_id TEXT PRIMARY KEY NOT NULL, request_digest TEXT NOT NULL, status TEXT NOT NULL, attempt_token TEXT NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL)").execute(pool).await?;
    Ok(())
}
