use message_box_server_rust::payment_intents::{
    Binding, IntentError, IntentStatus, SqlitePaymentIntentStore,
};
fn binding(tx: &str, digest: &str, token: &str) -> Binding {
    Binding {
        transaction_id: tx.into(),
        request_digest: digest.into(),
        attempt_token: token.into(),
    }
}
#[tokio::test]
async fn prepare_binds_transaction_digest_and_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("intent.sqlite");
    let store = SqlitePaymentIntentStore::open(&path).await.unwrap();
    let first = binding("tx", "digest", "token-a");
    assert_eq!(
        store.prepare(&first).await.unwrap().status,
        IntentStatus::Prepared
    );
    assert_eq!(store.prepare(&first).await.unwrap().binding, first);
    assert!(matches!(
        store.prepare(&binding("tx", "other", "token-b")).await,
        Err(IntentError::DifferentRequest)
    ));
    assert!(matches!(
        store.prepare(&binding("tx", "digest", "token-b")).await,
        Err(IntentError::InProgress)
    ));
    assert!(store.mark_wallet_accepted(&first).await.unwrap());
    let retry = store
        .prepare(&binding("tx", "digest", "token-b"))
        .await
        .unwrap();
    assert_eq!(retry.status, IntentStatus::WalletAccepted);
    assert_eq!(retry.binding, first);
    store.close().await;
    let reopened = SqlitePaymentIntentStore::open(&path).await.unwrap();
    assert_eq!(
        reopened
            .prepare(&binding("tx", "digest", "token-c"))
            .await
            .unwrap()
            .binding,
        first
    );
}
#[tokio::test]
async fn updates_are_bound_and_never_downgrade_completed() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqlitePaymentIntentStore::open(dir.path().join("intent.sqlite"))
        .await
        .unwrap();
    let first = binding("tx", "digest", "token");
    store.prepare(&first).await.unwrap();
    assert!(
        !store
            .mark_completed(&binding("tx", "digest", "wrong"))
            .await
            .unwrap()
    );
    assert!(store.mark_completed(&first).await.unwrap());
    assert!(store.mark_completed(&first).await.unwrap());
    assert!(store.mark_wallet_accepted(&first).await.unwrap());
    assert_eq!(
        store.prepare(&first).await.unwrap().status,
        IntentStatus::Completed
    );
    assert!(!store.release_prepared(&first).await.unwrap());
}
#[tokio::test]
async fn release_requires_all_binding_fields_and_prepared_status() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqlitePaymentIntentStore::open(dir.path().join("intent.sqlite"))
        .await
        .unwrap();
    let first = binding("tx", "digest", "token");
    store.prepare(&first).await.unwrap();
    assert!(
        !store
            .release_prepared(&binding("tx", "digest", "other"))
            .await
            .unwrap()
    );
    assert!(store.release_prepared(&first).await.unwrap());
    assert_eq!(
        store
            .prepare(&binding("tx", "other", "new"))
            .await
            .unwrap()
            .status,
        IntentStatus::Prepared
    );
}
#[tokio::test]
async fn concurrent_prepare_has_one_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("intent.sqlite");
    let a = SqlitePaymentIntentStore::open(&path).await.unwrap();
    let b = SqlitePaymentIntentStore::open(&path).await.unwrap();
    let first = binding("tx", "digest", "a");
    let second = binding("tx", "digest", "b");
    let (x, y) = tokio::join!(a.prepare(&first), b.prepare(&second));
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
    assert!(matches!(x, Err(IntentError::InProgress)) || matches!(y, Err(IntentError::InProgress)));
}
#[tokio::test]
async fn corrupt_state_and_missing_table_fail_closed() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("intent.sqlite");
    let store = SqlitePaymentIntentStore::open(&path).await.unwrap();
    let b = binding("tx", "digest", "token");
    store.prepare(&b).await.unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("UPDATE rust_message_payment_intents SET status='bogus'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store.prepare(&b).await,
        Err(IntentError::InvalidState)
    ));
    assert!(!store.mark_completed(&b).await.unwrap());
    sqlx::query("DROP TABLE rust_message_payment_intents")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store.prepare(&b).await,
        Err(IntentError::Database(_))
    ));
    assert!(store.mark_completed(&b).await.is_err());
    pool.close().await;
}
