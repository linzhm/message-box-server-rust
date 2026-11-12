use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
    fcm_delivery::{FcmOptions, FcmPayload, FcmProvider},
};
use serde_json::{Value, json};
use sqlx::{
    Row,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
struct Free;
impl DeliveryPolicy for Free {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
struct FakeProvider {
    outcomes: HashMap<String, String>,
    attempts: Mutex<Vec<String>>,
    messages: Mutex<Vec<Value>>,
    wait_token: Option<String>,
    signal_token: Option<String>,
    delay_token: Option<String>,
    delay_ms: u64,
    signal: tokio::sync::Notify,
}
impl FcmProvider for FakeProvider {
    fn send<'a>(
        &'a self,
        message: Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let token = message["token"].as_str().unwrap().to_owned();
            self.messages.lock().unwrap().push(message);
            self.attempts.lock().unwrap().push(token.clone());
            if self.signal_token.as_deref() == Some(token.as_str()) {
                self.signal.notify_one();
            }
            if self.wait_token.as_deref() == Some(token.as_str()) {
                self.signal.notified().await;
            }
            if self.delay_token.as_deref() == Some(token.as_str()) {
                tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            }
            match self.outcomes.get(&token).map(String::as_str) {
                Some("ok") => Ok(()),
                Some(error) => Err(error.to_owned()),
                None => Err("temporary".to_owned()),
            }
        })
    }
}
#[tokio::test]
async fn fake_provider_and_sqlite_match_executed_fixed_typescript() {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/fcm_delivery_vectors.json")).unwrap();
    for case in cases["cases"].as_array().unwrap() {
        let input = &case["input"];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.sqlite");
        let app = MessageBox::open(&path, Arc::new(Free), Limits::default())
            .await
            .unwrap();
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
        for item in input["devices"].as_array().unwrap() {
            let stamp = format!(
                "2020-01-{:02}T00:00:00.000Z",
                item["updated"].as_u64().unwrap()
            );
            sqlx::query("INSERT INTO device_registrations(identity_key,fcm_token,active,created_at,updated_at,last_used) VALUES(?,?,?,?,?,?)").bind(item["owner"].as_str().unwrap()).bind(item["token"].as_str().unwrap()).bind(item["active"].as_bool().unwrap()).bind(&stamp).bind(&stamp).bind(&stamp).execute(&pool).await.unwrap();
        }
        if input["name"] == "success-write-failure" {
            sqlx::query("CREATE TRIGGER fail_timestamp BEFORE UPDATE ON device_registrations WHEN OLD.fcm_token='badupdate' BEGIN SELECT RAISE(FAIL, 'synthetic update failure'); END").execute(&pool).await.unwrap();
        }
        if input["name"] == "invalid-write-failure"
            || input["name"] == "stop-worker-after-inactive-update-failure"
            || input["name"] == "other-worker-continues"
        {
            sqlx::query("CREATE TRIGGER fail_inactive BEFORE UPDATE ON device_registrations WHEN OLD.fcm_token='bad' BEGIN SELECT RAISE(FAIL, 'synthetic update failure'); END").execute(&pool).await.unwrap();
        }
        if input["dbFailure"].as_bool() == Some(true) {
            sqlx::query("DROP TABLE device_registrations")
                .execute(&pool)
                .await
                .unwrap();
        }
        let provider = Arc::new(FakeProvider {
            outcomes: serde_json::from_value(input["outcomes"].clone()).unwrap(),
            attempts: Mutex::new(Vec::new()),
            messages: Mutex::new(Vec::new()),
            wait_token: input["waitToken"].as_str().map(str::to_owned),
            signal_token: input["signalToken"].as_str().map(str::to_owned),
            delay_token: input["delayToken"].as_str().map(str::to_owned),
            delay_ms: input["delayMillis"].as_u64().unwrap_or(0),
            signal: tokio::sync::Notify::new(),
        });
        let selected: Option<Arc<dyn FcmProvider>> = if input["enabled"].as_bool().unwrap() {
            Some(provider.clone())
        } else {
            None
        };
        let result = app
            .send_fcm_notification(
                "alice",
                &FcmPayload {
                    title: "New Message",
                    message_id: "id-1",
                    originator: None,
                },
                selected,
                FcmOptions {
                    max_devices: input["max"].as_i64().unwrap(),
                    concurrency: input["concurrency"].as_i64().unwrap_or(10),
                },
            )
            .await;
        if let Some(ms) = input["settleMs"].as_u64() {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        assert_eq!(result.to_json(), case["result"], "{}", input["name"]);
        let mut attempts = provider.attempts.lock().unwrap().clone();
        attempts.sort();
        assert_eq!(json!(attempts), case["attempts"], "{}", input["name"]);
        for message in provider.messages.lock().unwrap().iter() {
            assert_eq!(
                message["notification"]["body"],
                "Open the app to view this message."
            );
            assert_eq!(message["android"]["data"]["messageId"], "id-1");
            assert_eq!(message["android"]["data"]["originator"], "unknown");
        }
        if input["dbFailure"].as_bool() != Some(true) {
            for expected in case["devices"].as_array().unwrap() {
                let row=sqlx::query("SELECT active,last_used,updated_at FROM device_registrations WHERE fcm_token=?").bind(expected["token"].as_str().unwrap()).fetch_one(&pool).await.unwrap();
                let original = input["devices"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|d| d["token"] == expected["token"])
                    .unwrap();
                let initial = format!(
                    "2020-01-{:02}T00:00:00.000Z",
                    original["updated"].as_u64().unwrap()
                );
                assert_eq!(
                    row.get::<bool, _>("active"),
                    expected["active"].as_bool().unwrap()
                );
                assert_eq!(
                    row.get::<String, _>("last_used") != initial,
                    expected["lastUsedChanged"].as_bool().unwrap()
                );
                assert_eq!(
                    row.get::<String, _>("updated_at") != initial,
                    expected["updatedChanged"].as_bool().unwrap()
                );
            }
        }
        pool.close().await;
        app.close().await;
    }
}

struct ConcurrentProvider {
    active: std::sync::atomic::AtomicUsize,
    maximum: std::sync::atomic::AtomicUsize,
}
impl FcmProvider for ConcurrentProvider {
    fn send<'a>(
        &'a self,
        _: Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            use std::sync::atomic::Ordering;
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        })
    }
}
#[tokio::test]
async fn provider_concurrency_is_bounded_and_nonzero() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("messages.sqlite");
    let app = MessageBox::open(&path, Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let pool = SqlitePoolOptions::new()
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    for n in 0..8 {
        sqlx::query("INSERT INTO device_registrations(identity_key,fcm_token,active,created_at,updated_at,last_used) VALUES('alice',?,1,'2020','2020','2020')").bind(format!("fake-{n}")).execute(&pool).await.unwrap();
    }
    let provider = Arc::new(ConcurrentProvider {
        active: AtomicUsize::new(0),
        maximum: AtomicUsize::new(0),
    });
    let payload = FcmPayload {
        title: "New Message",
        message_id: "id",
        originator: None,
    };
    assert!(
        app.send_fcm_notification(
            "alice",
            &payload,
            Some(provider.clone()),
            FcmOptions {
                max_devices: 100,
                concurrency: 3
            }
        )
        .await
        .success
    );
    assert_eq!(provider.maximum.load(Ordering::SeqCst), 3);
    assert!(
        !app.send_fcm_notification(
            "alice",
            &payload,
            Some(provider.clone()),
            FcmOptions {
                max_devices: 100,
                concurrency: 0
            }
        )
        .await
        .success
    );
    pool.close().await;
    app.close().await;
}
