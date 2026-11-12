//! SQLite session/replay store for the no-certificate responder subset.
//!
//! The caller chooses the database path and schedules `prune_expired`. This
//! schema is private to this port, not an upstream MySQL migration. SQLite VFS,
//! filesystem locking and crash recovery must be validated in the host.
use crate::auth_responder::{AuthSession, AuthSessionStore};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::path::Path;

const MAX_JS_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
// SQLite evaluates this at statement execution, after connection/lock waits.
const NOW_MS: &str = "CAST(unixepoch('subsec') * 1000 AS INTEGER)";

#[derive(Clone, Debug)]
pub struct AuthStoreOptions {
    pub ttl_ms: i64,
    pub max_message_nonces_per_session: i64,
    pub max_initial_total: i64,
    pub max_initial_per_identity: i64,
}
impl Default for AuthStoreOptions {
    fn default() -> Self {
        Self {
            ttl_ms: 86_400_000,
            max_message_nonces_per_session: 100_000,
            max_initial_total: 100_000,
            max_initial_per_identity: 100_000,
        }
    }
}
#[derive(Debug)]
pub enum StoreError {
    Database(sqlx::Error),
    InvalidInput,
    InvalidConfig,
    Clock,
    SessionMissing,
    Capacity,
}
impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

pub struct SqliteAuthSessionStore {
    pool: SqlitePool,
    options: AuthStoreOptions,
}
impl SqliteAuthSessionStore {
    pub async fn open(
        path: impl AsRef<Path>,
        options: AuthStoreOptions,
    ) -> Result<Self, StoreError> {
        if options.ttl_ms <= 0
            || options.max_message_nonces_per_session <= 0
            || options.max_initial_total <= 0
            || options.max_initial_per_identity <= 0
            || options.ttl_ms > MAX_JS_SAFE_INTEGER
            || options.max_message_nonces_per_session > MAX_JS_SAFE_INTEGER
            || options.max_initial_total > MAX_JS_SAFE_INTEGER
            || options.max_initial_per_identity > MAX_JS_SAFE_INTEGER
        {
            return Err(StoreError::InvalidConfig);
        }
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(path)
                    .create_if_missing(true)
                    .foreign_keys(true),
            )
            .await?;
        let clock: Option<i64> = sqlx::query_scalar(&format!("SELECT {NOW_MS}"))
            .fetch_one(&pool)
            .await?;
        if clock.is_none_or(|now| now < 0 || now > MAX_JS_SAFE_INTEGER - options.ttl_ms) {
            return Err(StoreError::Clock);
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS auth_sessions (session_nonce TEXT PRIMARY KEY NOT NULL, peer_nonce TEXT NOT NULL, peer_identity TEXT NOT NULL, authenticated INTEGER NOT NULL, expires_at INTEGER NOT NULL)").execute(&pool).await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS auth_message_nonces (session_nonce TEXT NOT NULL, message_nonce TEXT NOT NULL, PRIMARY KEY(session_nonce,message_nonce), FOREIGN KEY(session_nonce) REFERENCES auth_sessions(session_nonce) ON DELETE CASCADE)").execute(&pool).await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS auth_initial_claims (identity_key TEXT NOT NULL, initial_nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(identity_key,initial_nonce))").execute(&pool).await?;
        Ok(Self { pool, options })
    }
    pub async fn close(self) {
        self.pool.close().await;
    }
    /// Reclaims expired sessions and initial claims; message claims cascade.
    pub async fn prune_expired(&self) -> Result<u64, StoreError> {
        self.prune_expired_batch(crate::resource_config::ResourceLimit::Unlimited)
            .await
    }
    pub async fn prune_expired_batch(
        &self,
        batch: crate::resource_config::ResourceLimit,
    ) -> Result<u64, StoreError> {
        let bound = crate::runtime_resources::RuntimeResources::signed(batch);
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let removed = sqlx::query(&format!(
            "DELETE FROM auth_sessions WHERE rowid IN (SELECT rowid FROM auth_sessions WHERE expires_at<={NOW_MS} LIMIT ?)"
        ))
        .bind(bound)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        sqlx::query(&format!(
            "DELETE FROM auth_initial_claims WHERE rowid IN (SELECT rowid FROM auth_initial_claims WHERE expires_at<={NOW_MS} LIMIT ?)"
        ))
        .bind(bound)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(removed)
    }
}
fn valid(value: &str, max: usize) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > max {
        Err(StoreError::InvalidInput)
    } else {
        Ok(())
    }
}

impl AuthSessionStore for SqliteAuthSessionStore {
    type Error = StoreError;
    async fn claim_initial(&self, identity: &str, nonce: &str) -> Result<bool, Self::Error> {
        valid(identity, 66)?;
        valid(nonce, 64)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(&format!(
            "DELETE FROM auth_initial_claims WHERE expires_at<={NOW_MS}"
        ))
        .execute(&mut *tx)
        .await?;
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_initial_claims WHERE identity_key=? AND initial_nonce=?)").bind(identity).bind(nonce).fetch_one(&mut *tx).await?;
        if exists {
            tx.commit().await?;
            return Ok(false);
        }
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM auth_initial_claims WHERE identity_key=?")
                .bind(identity)
                .fetch_one(&mut *tx)
                .await?;
        let evict = (count - self.options.max_initial_per_identity + 1).max(0);
        if evict > 0 {
            sqlx::query("DELETE FROM auth_initial_claims WHERE rowid IN (SELECT rowid FROM auth_initial_claims WHERE identity_key=? ORDER BY expires_at,identity_key,initial_nonce LIMIT ?)").bind(identity).bind(evict).execute(&mut *tx).await?;
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_initial_claims")
            .fetch_one(&mut *tx)
            .await?;
        let evict = (count - self.options.max_initial_total + 1).max(0);
        if evict > 0 {
            sqlx::query("DELETE FROM auth_initial_claims WHERE rowid IN (SELECT rowid FROM auth_initial_claims ORDER BY expires_at,identity_key,initial_nonce LIMIT ?)").bind(evict).execute(&mut *tx).await?;
        }
        let inserted = sqlx::query(&format!("INSERT INTO auth_initial_claims(identity_key,initial_nonce,expires_at) SELECT ?,?,{NOW_MS}+? WHERE {NOW_MS} BETWEEN 0 AND ?"))
            .bind(identity).bind(nonce).bind(self.options.ttl_ms)
            .bind(MAX_JS_SAFE_INTEGER-self.options.ttl_ms).execute(&mut *tx).await?;
        if inserted.rows_affected() != 1 {
            return Err(StoreError::Clock);
        }
        tx.commit().await?;
        Ok(true)
    }
    async fn add_session(&self, session: AuthSession) -> Result<(), Self::Error> {
        valid(&session.session_nonce, 64)?;
        valid(&session.peer_nonce, 64)?;
        valid(&session.peer_identity, 66)?;
        let inserted=sqlx::query(&format!("INSERT INTO auth_sessions(session_nonce,peer_nonce,peer_identity,authenticated,expires_at) SELECT ?,?,?,?,{NOW_MS}+? WHERE {NOW_MS} BETWEEN 0 AND ?"))
            .bind(session.session_nonce).bind(session.peer_nonce).bind(session.peer_identity).bind(session.authenticated)
            .bind(self.options.ttl_ms).bind(MAX_JS_SAFE_INTEGER-self.options.ttl_ms).execute(&self.pool).await?;
        if inserted.rows_affected() != 1 {
            return Err(StoreError::Clock);
        }
        Ok(())
    }
    async fn get_session(&self, nonce: &str) -> Result<Option<AuthSession>, Self::Error> {
        valid(nonce, 64)?;
        let row=sqlx::query(&format!("SELECT session_nonce,peer_nonce,peer_identity,authenticated FROM auth_sessions WHERE session_nonce=? AND expires_at>{NOW_MS} AND {NOW_MS} BETWEEN 0 AND {MAX_JS_SAFE_INTEGER}"))
            .bind(nonce).fetch_optional(&self.pool).await?;
        row.map(|r| {
            Ok(AuthSession {
                session_nonce: r.try_get("session_nonce")?,
                peer_nonce: r.try_get("peer_nonce")?,
                peer_identity: r.try_get("peer_identity")?,
                authenticated: r.try_get("authenticated")?,
            })
        })
        .transpose()
    }
    async fn claim_message(&self, session: &str, nonce: &str) -> Result<bool, Self::Error> {
        valid(session, 64)?;
        valid(nonce, 64)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let active: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM auth_sessions WHERE session_nonce=? AND expires_at>{NOW_MS} AND {NOW_MS} BETWEEN 0 AND {MAX_JS_SAFE_INTEGER})",
        ))
        .bind(session)
        .fetch_one(&mut *tx)
        .await?;
        if !active {
            return Err(StoreError::SessionMissing);
        }
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_message_nonces WHERE session_nonce=? AND message_nonce=?)").bind(session).bind(nonce).fetch_one(&mut *tx).await?;
        if exists {
            tx.commit().await?;
            return Ok(false);
        }
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM auth_message_nonces WHERE session_nonce=?")
                .bind(session)
                .fetch_one(&mut *tx)
                .await?;
        if count >= self.options.max_message_nonces_per_session {
            return Err(StoreError::Capacity);
        }
        sqlx::query("INSERT INTO auth_message_nonces(session_nonce,message_nonce) VALUES(?,?)")
            .bind(session)
            .bind(nonce)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }
    async fn mark_authenticated(&self, nonce: &str) -> Result<(), Self::Error> {
        valid(nonce, 64)?;
        let result=sqlx::query(&format!("UPDATE auth_sessions SET authenticated=1,expires_at=MAX(expires_at,{NOW_MS}+?) WHERE session_nonce=? AND expires_at>{NOW_MS} AND {NOW_MS} BETWEEN 0 AND ?"))
            .bind(self.options.ttl_ms).bind(nonce).bind(MAX_JS_SAFE_INTEGER-self.options.ttl_ms).execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            return Err(StoreError::SessionMissing);
        }
        Ok(())
    }
}
