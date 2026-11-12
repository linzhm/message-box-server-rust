use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
    fcm_delivery::{FcmOptions, FcmProvider},
};
use serde_json::{Value, json};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
const ALICE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const BOB: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
struct Free;
impl DeliveryPolicy for Free {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
struct Fake {
    pool: sqlx::SqlitePool,
    messages: Mutex<Vec<Value>>,
    fail: bool,
}
impl FcmProvider for Fake {
    fn send<'a>(
        &'a self,
        message: Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let id = message["android"]["data"]["messageId"].as_str().unwrap();
            let exists: Option<i64> =
                sqlx::query_scalar("SELECT 1 FROM messages WHERE message_id=?")
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await
                    .unwrap();
            assert_eq!(exists, Some(1), "FCM must run after message commit");
            self.messages.lock().unwrap().push(message);
            if self.fail {
                Err("temporary".into())
            } else {
                Ok(())
            }
        })
    }
}
#[tokio::test]
async fn injected_fake_runs_after_commit_only_for_notification_box_and_never_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("message.sqlite");
    let app = MessageBox::open(&path, Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    let provider = Arc::new(Fake {
        pool: pool.clone(),
        messages: Mutex::new(Vec::new()),
        fail: true,
    });
    let app = app
        .with_fcm_provider(provider.clone(), FcmOptions::default(), 4)
        .unwrap();
    let alice = Identity::from_verified_key(ALICE).unwrap();
    let bob = Identity::from_verified_key(BOB).unwrap();
    assert_eq!(
        app.handle(
            "/registerDevice",
            Some(&bob),
            &json!({"fcmToken":"fake-token"})
        )
        .await
        .status,
        200
    );
    assert_eq!(
        app.handle(
            "/permissions/set",
            Some(&bob),
            &json!({"messageBox":"notifications","recipientFee":0,"sender":ALICE})
        )
        .await
        .status,
        200
    );
    let send = |message_id: &str, message_box: &str| json!({"message":{"recipient":BOB,"messageBox":message_box,"messageId":message_id,"body":"private body"}});
    assert_eq!(
        app.handle("/sendMessage", Some(&alice), &send("inbox-id", "inbox"))
            .await
            .status,
        200
    );
    assert!(provider.messages.lock().unwrap().is_empty());
    assert_eq!(
        app.handle(
            "/sendMessage",
            Some(&alice),
            &send("notification-id", "notifications")
        )
        .await
        .status,
        200
    );
    let messages = provider.messages.lock().unwrap().clone();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["token"], "fake-token");
    assert_eq!(messages[0]["notification"]["title"], "New Message");
    assert_eq!(
        messages[0]["notification"]["body"],
        "Open the app to view this message."
    );
    assert_eq!(
        messages[0]["android"]["data"]["messageId"],
        "notification-id"
    );
    assert!(!messages[0].to_string().contains("private body"));
    assert_eq!(
        app.handle(
            "/sendMessage",
            Some(&alice),
            &send("notification-id", "notifications")
        )
        .await
        .status,
        400
    );
    assert_eq!(provider.messages.lock().unwrap().len(), 1);
    let mut payment = send("payment-field", "notifications");
    payment["payment"] = Value::Null;
    assert_eq!(
        app.handle("/sendMessage", Some(&alice), &payment)
            .await
            .status,
        501
    );
    assert_eq!(provider.messages.lock().unwrap().len(), 1);
    let list = app
        .handle(
            "/listMessages",
            Some(&bob),
            &json!({"messageBox":"notifications"}),
        )
        .await;
    assert_eq!(list.status, 200);
    assert_eq!(list.body["messages"][0]["messageId"], "notification-id");
    pool.close().await;
    app.close().await;
}

#[tokio::test]
async fn batch_notifies_each_recipient_and_rejected_batches_never_notify() {
    const CAROL: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("message.sqlite");
    let app = MessageBox::open(&path, Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    let provider = Arc::new(Fake {
        pool: pool.clone(),
        messages: Mutex::new(Vec::new()),
        fail: false,
    });
    let app = app
        .with_fcm_provider(provider.clone(), FcmOptions::default(), 4)
        .unwrap();
    let alice = Identity::from_verified_key(ALICE).unwrap();
    let bob = Identity::from_verified_key(BOB).unwrap();
    let carol = Identity::from_verified_key(CAROL).unwrap();
    for (owner, token) in [(&bob, "fake-bob"), (&carol, "fake-carol")] {
        assert_eq!(
            app.handle("/registerDevice", Some(owner), &json!({"fcmToken":token}))
                .await
                .status,
            200
        );
        assert_eq!(
            app.handle(
                "/permissions/set",
                Some(owner),
                &json!({"messageBox":"notifications","recipientFee":0,"sender":ALICE})
            )
            .await
            .status,
            200
        );
    }
    let batch = |a: &str, b: &str| json!({"message":{"recipients":[BOB,CAROL],"messageBox":"notifications","messageId":[a,b],"body":"secret"}});
    assert_eq!(
        app.handle("/sendMessage", Some(&alice), &batch("batch-b", "batch-c"))
            .await
            .status,
        200
    );
    let messages = provider.messages.lock().unwrap().clone();
    assert_eq!(messages.len(), 2);
    for (token, id) in [("fake-bob", "batch-b"), ("fake-carol", "batch-c")] {
        let message = messages.iter().find(|m| m["token"] == token).unwrap();
        assert_eq!(message["android"]["data"]["messageId"], id);
        assert!(!message.to_string().contains("secret"));
    }
    assert_eq!(
        app.handle(
            "/permissions/set",
            Some(&bob),
            &json!({"messageBox":"notifications","recipientFee":-1,"sender":ALICE})
        )
        .await
        .status,
        200
    );
    assert_eq!(
        app.handle(
            "/sendMessage",
            Some(&alice),
            &batch("blocked-b", "blocked-c")
        )
        .await
        .status,
        403
    );
    assert_eq!(provider.messages.lock().unwrap().len(), 2);
    assert_eq!(
        app.handle(
            "/permissions/set",
            Some(&bob),
            &json!({"messageBox":"notifications","recipientFee":1,"sender":ALICE})
        )
        .await
        .status,
        200
    );
    assert_eq!(
        app.handle("/sendMessage", Some(&alice), &batch("paid-b", "paid-c"))
            .await
            .status,
        501
    );
    assert_eq!(provider.messages.lock().unwrap().len(), 2);
    let list = app
        .handle(
            "/listMessages",
            Some(&carol),
            &json!({"messageBox":"notifications"}),
        )
        .await;
    assert_eq!(list.body["messages"].as_array().unwrap().len(), 1);
    pool.close().await;
    app.close().await;
}

struct Noop;
impl FcmProvider for Noop {
    fn send<'a>(
        &'a self,
        _: Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
#[tokio::test]
async fn fcm_configuration_is_optional_and_validated() {
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let alice = Identity::from_verified_key(ALICE).unwrap();
    let bob = Identity::from_verified_key(BOB).unwrap();
    assert_eq!(
        app.handle(
            "/permissions/set",
            Some(&bob),
            &json!({"messageBox":"notifications","recipientFee":0,"sender":ALICE})
        )
        .await
        .status,
        200
    );
    assert_eq!(app.handle("/sendMessage",Some(&alice),&json!({"message":{"recipient":BOB,"messageBox":"notifications","messageId":"no-provider","body":"hello"}})).await.status,200);
    app.close().await;
    for (options, recipients) in [
        (
            FcmOptions {
                max_devices: -2,
                concurrency: 1,
            },
            1,
        ),
        (
            FcmOptions {
                max_devices: 100,
                concurrency: 0,
            },
            1,
        ),
        (
            FcmOptions {
                max_devices: 100,
                concurrency: -2,
            },
            1,
        ),
        (FcmOptions::default(), 0),
        (FcmOptions::default(), -2),
    ] {
        let app = MessageBox::memory(Arc::new(Free), Limits::default())
            .await
            .unwrap();
        assert!(
            app.with_fcm_provider(Arc::new(Noop), options, recipients)
                .is_err()
        );
    }
    let app = MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let app = app
        .with_fcm_provider(
            Arc::new(Noop),
            FcmOptions {
                max_devices: -1,
                concurrency: -1,
            },
            -1,
        )
        .unwrap();
    app.close().await;
}
