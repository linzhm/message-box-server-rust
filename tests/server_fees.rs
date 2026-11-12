use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
};
use serde_json::{Value, json};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::sync::Arc;
const A: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const B: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
struct Allow;
impl DeliveryPolicy for Allow {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
}
async fn quote(app: &MessageBox, sender: &Identity, box_name: &str) -> (u16, Value) {
    let response = app
        .handle(
            "/permissions/quote",
            Some(sender),
            &json!({"recipient":B,"messageBox":box_name}),
        )
        .await;
    (response.status, response.body)
}
async fn send(app: &MessageBox, sender: &Identity, box_name: &str, id: &str) -> u16 {
    app.handle(
        "/sendMessage",
        Some(sender),
        &json!({"message":{"recipient":B,"messageBox":box_name,"messageId":id,"body":"fake"}}),
    )
    .await
    .status
}
#[tokio::test]
async fn stored_fee_defaults_and_missing_rows_match_fixed_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let app = MessageBox::open(&path, Arc::new(Allow), Limits::default())
        .await
        .unwrap()
        .with_sqlite_server_fees()
        .await
        .unwrap();
    let alice = Identity::from_verified_key(A).unwrap();
    for (name, fee) in [
        ("notifications", 10),
        ("inbox", 0),
        ("payment_inbox", 0),
        ("orders", 0),
    ] {
        let (status, body) = quote(&app, &alice, name).await;
        assert_eq!(status, 200, "{name}");
        assert_eq!(body["quote"]["deliveryFee"], fee, "{name}");
    }
    assert_eq!(send(&app, &alice, "orders", "orders-id").await, 200);
    assert_eq!(send(&app, &alice, "notifications", "paid-id").await, 501);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM server_fees WHERE message_box='orders'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows, 0,
        "reading or sending an unknown box must not insert a fee row"
    );
    pool.close().await;
    app.close().await;
}
#[tokio::test]
async fn fees_persist_and_migration_does_not_restore_deleted_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let app = MessageBox::open(&path, Arc::new(Allow), Limits::default())
        .await
        .unwrap()
        .with_sqlite_server_fees()
        .await
        .unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("UPDATE server_fees SET delivery_fee=17 WHERE message_box='inbox'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM server_fees WHERE message_box='notifications'")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    app.close().await;
    let app = MessageBox::open(&path, Arc::new(Allow), Limits::default())
        .await
        .unwrap()
        .with_sqlite_server_fees()
        .await
        .unwrap();
    let alice = Identity::from_verified_key(A).unwrap();
    assert_eq!(
        quote(&app, &alice, "inbox").await.1["quote"]["deliveryFee"],
        17
    );
    assert_eq!(
        quote(&app, &alice, "notifications").await.1["quote"]["deliveryFee"],
        0
    );
    assert_eq!(send(&app, &alice, "inbox", "paid-id").await, 501);
    app.close().await;
}
#[tokio::test]
async fn invalid_or_unavailable_stored_fee_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let app = MessageBox::open(&path, Arc::new(Allow), Limits::default())
        .await
        .unwrap()
        .with_sqlite_server_fees()
        .await
        .unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    let alice = Identity::from_verified_key(A).unwrap();
    for invalid in ["-1", "2147483648", "1.5", "'not-an-integer'"] {
        sqlx::query(&format!(
            "UPDATE server_fees SET delivery_fee={invalid} WHERE message_box='inbox'"
        ))
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(quote(&app, &alice, "inbox").await.0, 500, "{invalid}");
        assert_eq!(
            send(&app, &alice, "inbox", "bad-id").await,
            500,
            "{invalid}"
        );
    }
    sqlx::query("UPDATE server_fees SET delivery_fee=NULL WHERE message_box='inbox'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        quote(&app, &alice, "inbox").await.1["quote"]["deliveryFee"],
        0
    );
    sqlx::query("DROP TABLE server_fees")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(quote(&app, &alice, "inbox").await.0, 500);
    assert_eq!(send(&app, &alice, "inbox", "bad-id").await, 500);
    let bob = Identity::from_verified_key(B).unwrap();
    let listed = app
        .handle("/listMessages", Some(&bob), &json!({"messageBox":"inbox"}))
        .await;
    assert_eq!(listed.body["messages"], json!([]));
    pool.close().await;
    app.close().await;
}

#[tokio::test]
async fn migration_preserves_preexisting_fee_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let app = MessageBox::open(&path, Arc::new(Allow), Limits::default())
        .await
        .unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("CREATE TABLE server_fees (message_box TEXT PRIMARY KEY NOT NULL, delivery_fee INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO server_fees(message_box,delivery_fee,created_at,updated_at) VALUES('notifications',7,'2020','2020')").execute(&pool).await.unwrap();
    pool.close().await;
    let app = app.with_sqlite_server_fees().await.unwrap();
    let alice = Identity::from_verified_key(A).unwrap();
    assert_eq!(
        quote(&app, &alice, "notifications").await.1["quote"]["deliveryFee"],
        7
    );
    assert_eq!(
        quote(&app, &alice, "inbox").await.1["quote"]["deliveryFee"],
        0
    );
    app.close().await;
}

struct FeeTen;
impl DeliveryPolicy for FeeTen {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(10)
    }
}
struct Block;
impl DeliveryPolicy for Block {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Blocked)
    }
}
#[tokio::test]
async fn explicit_table_replaces_host_fee_but_never_host_admission() {
    let alice = Identity::from_verified_key(A).unwrap();
    let app = MessageBox::memory(Arc::new(FeeTen), Limits::default())
        .await
        .unwrap();
    assert_eq!(
        quote(&app, &alice, "inbox").await.1["quote"]["deliveryFee"],
        10
    );
    let app = app.with_sqlite_server_fees().await.unwrap();
    assert_eq!(
        quote(&app, &alice, "inbox").await.1["quote"]["deliveryFee"],
        0
    );
    assert_eq!(send(&app, &alice, "inbox", "allowed").await, 200);
    app.close().await;
    let blocked = MessageBox::memory(Arc::new(Block), Limits::default())
        .await
        .unwrap()
        .with_sqlite_server_fees()
        .await
        .unwrap();
    assert_eq!(send(&blocked, &alice, "inbox", "blocked").await, 403);
    blocked.close().await;
}

struct Required;
impl DeliveryPolicy for Required {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::PaymentRequired)
    }
}
#[tokio::test]
async fn table_fee_does_not_bypass_host_payment_requirement() {
    let app = MessageBox::memory(Arc::new(Required), Limits::default())
        .await
        .unwrap()
        .with_sqlite_server_fees()
        .await
        .unwrap();
    let alice = Identity::from_verified_key(A).unwrap();
    assert_eq!(send(&app, &alice, "inbox", "required").await, 501);
    app.close().await;
}
#[tokio::test]
async fn failed_initial_migration_rolls_back_and_can_be_retried() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let app = MessageBox::open(&path, Arc::new(Allow), Limits::default())
        .await
        .unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("CREATE TABLE server_fees (message_box TEXT PRIMARY KEY NOT NULL, delivery_fee INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)").execute(&pool).await.unwrap();
    sqlx::query("CREATE TRIGGER reject_inbox BEFORE INSERT ON server_fees WHEN NEW.message_box='inbox' BEGIN SELECT RAISE(FAIL,'synthetic migration error'); END").execute(&pool).await.unwrap();
    assert!(app.with_sqlite_server_fees().await.is_err());
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM server_fees")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    let marker:i64=sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rust_server_fee_migrations'").fetch_one(&pool).await.unwrap();
    assert_eq!(marker, 0);
    sqlx::query("DROP TRIGGER reject_inbox")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let app = MessageBox::open(&path, Arc::new(Allow), Limits::default())
        .await
        .unwrap()
        .with_sqlite_server_fees()
        .await
        .unwrap();
    let alice = Identity::from_verified_key(A).unwrap();
    assert_eq!(
        quote(&app, &alice, "notifications").await.1["quote"]["deliveryFee"],
        10
    );
    assert_eq!(
        quote(&app, &alice, "inbox").await.1["quote"]["deliveryFee"],
        0
    );
    app.close().await;
}

#[tokio::test]
async fn invalid_table_fee_precedes_recipient_block_like_fixed_ts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let app = MessageBox::open(&path, Arc::new(Allow), Limits::default())
        .await
        .unwrap()
        .with_sqlite_server_fees()
        .await
        .unwrap();
    let alice = Identity::from_verified_key(A).unwrap();
    let bob = Identity::from_verified_key(B).unwrap();
    assert_eq!(
        app.handle(
            "/permissions/set",
            Some(&bob),
            &json!({"messageBox":"inbox","recipientFee":-1})
        )
        .await
        .status,
        200
    );
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("UPDATE server_fees SET delivery_fee=-1 WHERE message_box='inbox'")
        .execute(&pool)
        .await
        .unwrap();
    let response=app.handle("/sendMessage",Some(&alice),&json!({"message":{"recipient":B,"messageBox":"inbox","messageId":"blocked","body":"fake"}})).await;
    assert_eq!(response.status, 500);
    assert_eq!(response.body["code"], "ERR_INTERNAL");
    sqlx::query("UPDATE server_fees SET delivery_fee=0 WHERE message_box='inbox'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(send(&app, &alice, "inbox", "blocked").await, 403);
    let listed = app
        .handle("/listMessages", Some(&bob), &json!({"messageBox":"inbox"}))
        .await;
    assert_eq!(listed.body["messages"], json!([]));
    pool.close().await;
    app.close().await;
}

struct BlockWithUnavailableFee;
impl DeliveryPolicy for BlockWithUnavailableFee {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Blocked)
    }
}
#[tokio::test]
async fn default_host_policy_keeps_block_before_unavailable_fee() {
    let app = MessageBox::memory(Arc::new(BlockWithUnavailableFee), Limits::default())
        .await
        .unwrap();
    let alice = Identity::from_verified_key(A).unwrap();
    assert_eq!(send(&app, &alice, "inbox", "blocked").await, 403);
    app.close().await;
}
