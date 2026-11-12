use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
    payment_replay::SqlitePaymentReplayStore,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::sync::Arc;
struct Policy;
impl DeliveryPolicy for Policy {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
#[tokio::test]
async fn message_database_initializes_payment_tables_and_supports_atomic_claim() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("message.sqlite");
    let app = MessageBox::open(&path, Arc::new(Policy), Limits::default())
        .await
        .unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('messages','brc105_replay_claims','rust_message_payment_intents')").fetch_one(&pool).await.unwrap();
    assert_eq!(count, 3);
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO messages VALUES ('id','recipient','sender','inbox','{}',2,'now',9999999999999)").execute(&mut *tx).await.unwrap();
    assert!(
        SqlitePaymentReplayStore::claim_permanent_in_transaction(&mut tx, "txid")
            .await
            .unwrap()
    );
    tx.rollback().await.unwrap();
    let n: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM messages)+(SELECT COUNT(*) FROM brc105_replay_claims)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(n, 0);
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO messages VALUES ('id','recipient','sender','inbox','{}',2,'now',9999999999999)").execute(&mut *tx).await.unwrap();
    assert!(
        SqlitePaymentReplayStore::claim_permanent_in_transaction(&mut tx, "txid")
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    let n: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM messages)+(SELECT COUNT(*) FROM brc105_replay_claims)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(n, 2);
    pool.close().await;
    app.close().await;
    let reopened = MessageBox::open(&path, Arc::new(Policy), Limits::default())
        .await
        .unwrap();
    let read = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    let count:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM messages)+(SELECT COUNT(*) FROM brc105_replay_claims WHERE expires_at_ms IS NULL)").fetch_one(&read).await.unwrap();
    assert_eq!(count, 2);
    read.close().await;
    reopened.close().await;
}
