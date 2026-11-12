//! Standalone SQLite BRC-105 replay claims, not connected to online payment.
//!
//! The caller supplies the database path and is responsible for the applicable
//! payment validation. The BRC-105 header path requires a newly accepted wallet
//! result; legacy recipient-only payments follow different upstream checks.
//! This store does not verify payments, authenticate callers, or coordinate with a
//! wallet or message delivery. A permanent claim can be inserted in a supplied
//! SQLite transaction, but no legacy body-payment route invokes it.
use chrono::Utc;
use sqlx::{
    Sqlite, SqlitePool, Transaction,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{io, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRetention {
    Days(u32),
    Forever,
}
impl Default for ReplayRetention {
    fn default() -> Self {
        Self::Days(365)
    }
}

pub struct SqlitePaymentReplayStore {
    pool: SqlitePool,
    retention: ReplayRetention,
}
impl SqlitePaymentReplayStore {
    /// Open an explicitly chosen Rust-owned filesystem database. Memory,
    /// temporary and SQLite URI targets are rejected. The host must supply a
    /// persistent filesystem with correct SQLite locking. Zero days is invalid.
    pub async fn open(
        path: impl AsRef<Path>,
        retention: ReplayRetention,
    ) -> Result<Self, sqlx::Error> {
        let path = path.as_ref();
        let text = path.as_os_str().to_string_lossy();
        if text.is_empty() || text == ":memory:" || text.to_ascii_lowercase().starts_with("file:") {
            return Err(config_error(
                "replay store requires a regular filesystem path, not a SQLite URI or memory target",
            ));
        }
        if retention == ReplayRetention::Days(0) {
            return Err(config_error("replay retention must be positive or forever"));
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        initialize_schema(&pool).await?;
        Ok(Self { pool, retention })
    }
    /// Atomically insert one claim. An existing claim returns false even if its
    /// TTL has elapsed, until explicit pruning removes it. Transaction IDs are
    /// opaque here; the caller must compute them from a verified transaction
    /// and use one canonical encoding (for example, lowercase transaction hex).
    pub async fn claim(&self, transaction_id: &str) -> Result<bool, sqlx::Error> {
        let now = Utc::now().timestamp_millis();
        let expiry = match self.retention {
            ReplayRetention::Forever => None,
            ReplayRetention::Days(days) => {
                let millis = i64::from(days)
                    .checked_mul(86_400_000)
                    .ok_or_else(|| config_error("replay expiration overflow"))?;
                let value = now
                    .checked_add(millis)
                    .filter(|v| *v <= 8_640_000_000_000_000)
                    .ok_or_else(|| config_error("replay expiration outside date range"))?;
                Some(value)
            }
        };
        let result=sqlx::query("INSERT INTO brc105_replay_claims(transaction_id,created_at_ms,expires_at_ms) VALUES(?,?,?) ON CONFLICT(transaction_id) DO NOTHING")
            .bind(transaction_id).bind(now).bind(expiry).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }
    /// Insert a permanent claim into an existing SQLite transaction. The caller
    /// must ensure that the transaction belongs to the same database used for
    /// ordinary claims and containing this Rust-owned schema; this method cannot
    /// verify that precondition. The caller must commit or roll back the entire
    /// transaction itself. A false result reports an existing claim; other SQL
    /// failures are returned as errors. The caller must roll back its other
    /// writes if a false result or error makes its operation invalid. This
    /// operation does not verify payment
    /// or establish atomicity with a wallet.
    pub async fn claim_permanent_in_transaction(
        transaction: &mut Transaction<'_, Sqlite>,
        transaction_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("INSERT INTO brc105_replay_claims(transaction_id,created_at_ms,expires_at_ms) VALUES(?,?,NULL) ON CONFLICT(transaction_id) DO NOTHING")
            .bind(transaction_id)
            .bind(Utc::now().timestamp_millis())
            .execute(&mut **transaction)
            .await?;
        Ok(result.rows_affected() == 1)
    }
    /// Explicitly remove expired, non-permanent claims at the supplied time.
    /// Scheduling and the authoritative clock are the host's responsibility.
    pub async fn prune_expired_at(&self, now_ms: i64) -> Result<u64, sqlx::Error> {
        let result=sqlx::query("DELETE FROM brc105_replay_claims WHERE expires_at_ms IS NOT NULL AND expires_at_ms <= ?").bind(now_ms).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }
    pub async fn close(self) {
        self.pool.close().await;
    }
}
pub(crate) async fn initialize_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("CREATE TABLE IF NOT EXISTS brc105_replay_claims (transaction_id TEXT PRIMARY KEY NOT NULL, created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER)").execute(pool).await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS brc105_replay_expiry ON brc105_replay_claims(expires_at_ms)",
    )
    .execute(pool)
    .await?;
    Ok(())
}
fn config_error(message: &str) -> sqlx::Error {
    sqlx::Error::Configuration(Box::new(io::Error::other(message.to_owned())))
}
