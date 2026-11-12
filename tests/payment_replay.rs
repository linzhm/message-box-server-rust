use message_box_server_rust::payment_replay::{ReplayRetention, SqlitePaymentReplayStore};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::sync::Arc;
async fn store(path: &std::path::Path, retention: ReplayRetention) -> SqlitePaymentReplayStore {
    SqlitePaymentReplayStore::open(path, retention)
        .await
        .unwrap()
}
async fn db(path: &std::path::Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(path))
        .await
        .unwrap()
}
#[tokio::test]
async fn concurrent_claims_across_pools_have_one_winner_and_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replay.sqlite");
    let mut stores = Vec::new();
    for _ in 0..4 {
        stores.push(Arc::new(store(&path, ReplayRetention::Days(365)).await));
    }
    let mut tasks = Vec::new();
    for s in &stores {
        let s = Arc::clone(s);
        tasks.push(tokio::spawn(
            async move { s.claim("tx-one").await.unwrap() },
        ));
    }
    let mut winners = 0;
    for t in tasks {
        winners += usize::from(t.await.unwrap());
    }
    assert_eq!(winners, 1);
    drop(stores);
    let reopened = store(&path, ReplayRetention::Days(365)).await;
    assert!(!reopened.claim("tx-one").await.unwrap());
}
#[tokio::test]
async fn ttl_is_explicitly_pruned_and_permanent_claims_survive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replay.sqlite");
    let finite = store(&path, ReplayRetention::Days(1)).await;
    let forever = store(&path, ReplayRetention::Forever).await;
    assert!(finite.claim("expiring").await.unwrap());
    assert!(forever.claim("permanent").await.unwrap());
    let pool = db(&path).await;
    let (created,expires):(i64,i64)=sqlx::query_as("SELECT created_at_ms,expires_at_ms FROM brc105_replay_claims WHERE transaction_id='expiring'").fetch_one(&pool).await.unwrap();
    assert_eq!(expires - created, 86_400_000);
    sqlx::query(
        "UPDATE brc105_replay_claims SET expires_at_ms=100 WHERE transaction_id='expiring'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(!finite.claim("expiring").await.unwrap());
    assert_eq!(finite.prune_expired_at(99).await.unwrap(), 0);
    assert_eq!(finite.prune_expired_at(100).await.unwrap(), 1);
    assert!(finite.claim("expiring").await.unwrap());
    assert!(!forever.claim("permanent").await.unwrap());
    pool.close().await;
}
#[tokio::test]
async fn rejects_zero_retention_and_propagates_schema_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replay.sqlite");
    assert!(
        SqlitePaymentReplayStore::open(&path, ReplayRetention::Days(0))
            .await
            .is_err()
    );
    let store = store(&path, ReplayRetention::Days(1)).await;
    let pool = db(&path).await;
    sqlx::query("DROP TABLE brc105_replay_claims")
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.claim("tx").await.is_err());
    pool.close().await;
}

#[tokio::test]
async fn non_duplicate_constraint_errors_are_not_treated_as_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("constraints.sqlite");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    sqlx::query("CREATE TABLE brc105_replay_claims (transaction_id TEXT PRIMARY KEY NOT NULL CHECK(transaction_id <> 'bad'), created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER)").execute(&pool).await.unwrap();
    let store = store(&path, ReplayRetention::Days(1)).await;
    assert!(store.claim("bad").await.is_err());
    assert!(store.claim("good").await.unwrap());
    assert!(!store.claim("good").await.unwrap());
    pool.close().await;
}

#[tokio::test]
async fn rejects_memory_temporary_and_uri_targets() {
    for target in [
        "",
        ":memory:",
        "file::memory:?cache=shared",
        "file:replay?mode=memory&cache=shared",
        "file:ordinary.sqlite?mode=rwc",
    ] {
        assert!(
            SqlitePaymentReplayStore::open(target, ReplayRetention::Days(1))
                .await
                .is_err(),
            "{target:?}"
        );
    }
}

#[tokio::test]
async fn permanent_claim_and_synthetic_messages_share_the_callers_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("combined.sqlite");
    let store = store(&path, ReplayRetention::Days(1)).await;
    let pool = db(&path).await;
    sqlx::query("CREATE TABLE synthetic_messages (id TEXT PRIMARY KEY NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO synthetic_messages VALUES ('committed')")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        SqlitePaymentReplayStore::claim_permanent_in_transaction(&mut tx, "permanent")
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    assert!(!store.claim("permanent").await.unwrap());
    assert_eq!(store.prune_expired_at(i64::MAX).await.unwrap(), 0);
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO synthetic_messages VALUES ('rolled-back')")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        !SqlitePaymentReplayStore::claim_permanent_in_transaction(&mut tx, "permanent")
            .await
            .unwrap()
    );
    tx.rollback().await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM synthetic_messages WHERE id='rolled-back'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    assert!(store.claim("header-first").await.unwrap());
    let mut tx = pool.begin().await.unwrap();
    assert!(
        !SqlitePaymentReplayStore::claim_permanent_in_transaction(&mut tx, "header-first")
            .await
            .unwrap()
    );
    assert!(
        SqlitePaymentReplayStore::claim_permanent_in_transaction(&mut tx, "rolled-claim")
            .await
            .unwrap()
    );
    tx.rollback().await.unwrap();
    assert!(store.claim("rolled-claim").await.unwrap());
    pool.close().await;
}

#[tokio::test]
async fn duplicate_message_or_other_sql_error_does_not_commit_a_claim() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("combined-errors.sqlite");
    let store = store(&path, ReplayRetention::Days(1)).await;
    let pool = db(&path).await;
    sqlx::query("CREATE TABLE synthetic_messages (id TEXT PRIMARY KEY NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO synthetic_messages VALUES ('existing')")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert!(
        SqlitePaymentReplayStore::claim_permanent_in_transaction(&mut tx, "unclaimed")
            .await
            .unwrap()
    );
    assert!(
        sqlx::query("INSERT INTO synthetic_messages VALUES ('existing')")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert!(store.claim("unclaimed").await.unwrap());
    sqlx::query("DROP TABLE brc105_replay_claims")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert!(
        SqlitePaymentReplayStore::claim_permanent_in_transaction(&mut tx, "error")
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    pool.close().await;
}
