//! Optional SQLite-backed server delivery fees, modeled on the fixed TS fee
//! migration and read helper. This is not an upstream MySQL migration.
use crate::{MessageBox, PolicyError};
use chrono::{SecondsFormat, Utc};
use sqlx::Row;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum DeliveryFeeSource {
    #[default]
    HostPolicy,
    Sqlite,
}
impl MessageBox {
    /// Enable the optional persistent fee table. The initial TS fee rows are
    /// inserted once, without replacing existing values or restoring deletions.
    /// The SQLite table replaces `DeliveryPolicy::delivery_fee` as the sole
    /// server-fee source for both quotes and sends. The host's separate
    /// `DeliveryPolicy::evaluate` admission decision still applies to every send.
    pub async fn with_sqlite_server_fees(mut self) -> Result<Self, sqlx::Error> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS server_fees (message_box TEXT PRIMARY KEY NOT NULL, delivery_fee INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)").execute(&mut *tx).await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS rust_server_fee_migrations (version INTEGER PRIMARY KEY NOT NULL)").execute(&mut *tx).await?;
        let migration =
            sqlx::query("INSERT OR IGNORE INTO rust_server_fee_migrations(version) VALUES(1)")
                .execute(&mut *tx)
                .await?;
        if migration.rows_affected() == 1 {
            let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            for (message_box, fee) in [
                ("notifications", 10_i64),
                ("inbox", 0),
                ("payment_inbox", 0),
            ] {
                sqlx::query("INSERT OR IGNORE INTO server_fees(message_box,delivery_fee,created_at,updated_at) VALUES(?,?,?,?)").bind(message_box).bind(fee).bind(&now).bind(&now).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
        self.fee_source = DeliveryFeeSource::Sqlite;
        Ok(self)
    }
    pub(crate) async fn server_delivery_fee(&self, message_box: &str) -> Result<i64, PolicyError> {
        let fee = match self.fee_source {
            DeliveryFeeSource::HostPolicy => self.policy.delivery_fee(message_box)?,
            DeliveryFeeSource::Sqlite => {
                let row = sqlx::query("SELECT delivery_fee, typeof(delivery_fee) AS storage_type FROM server_fees WHERE message_box=?").bind(message_box).fetch_optional(&self.pool).await.map_err(|_| PolicyError)?;
                match row {
                    None => 0,
                    Some(row) => match row
                        .try_get::<String, _>("storage_type")
                        .map_err(|_| PolicyError)?
                        .as_str()
                    {
                        "null" => 0,
                        "integer" => row
                            .try_get::<i64, _>("delivery_fee")
                            .map_err(|_| PolicyError)?,
                        _ => return Err(PolicyError),
                    },
                }
            }
        };
        if (0..=i64::from(i32::MAX)).contains(&fee) {
            Ok(fee)
        } else {
            Err(PolicyError)
        }
    }
}
