use k256::elliptic_curve::sec1::ToEncodedPoint;
use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, MessageBox, PolicyError,
    resource_config::{EnvironmentSnapshot, ResourceConfig},
    runtime_resources::RuntimeResources,
};
use serde_json::json;
use sqlx::{Connection, Row, SqliteConnection};
use std::sync::Arc;

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
fn resources(settings: &[(&str, &str)]) -> RuntimeResources {
    let env: EnvironmentSnapshot = settings
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    RuntimeResources::new(ResourceConfig::from_snapshot(&env).unwrap()).unwrap()
}
fn id(key: &str) -> Identity {
    Identity::from_verified_key(key).unwrap()
}
fn message(id: &str, body: &str) -> serde_json::Value {
    json!({"message":{"recipient":BOB,"messageBox":"inbox","messageId":id,"body":body}})
}

#[tokio::test]
async fn send_snapshot_array_bound_precedes_validation_and_configured_limit() {
    let app = MessageBox::memory_with_resources(
        Arc::new(Free),
        resources(&[("MESSAGE_BOX_RESOURCE_PROFILE", "high-throughput")]),
    )
    .await
    .unwrap();
    let recipients: Vec<String> = (1u16..=101)
        .map(|index| {
            let mut secret = [0u8; 32];
            secret[30..].copy_from_slice(&index.to_be_bytes());
            let key = k256::SecretKey::from_slice(&secret).unwrap();
            hex::encode(key.public_key().to_encoded_point(true).as_bytes())
        })
        .collect();
    let ids: Vec<String> = (1..=101).map(|i| format!("boundary-{i}")).collect();
    let valid = json!({"message":{"recipient":recipients,"messageBox":"inbox","messageId":ids,"body":"hello"}});
    let response = app.handle("/sendMessage", Some(&id(ALICE)), &valid).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body["results"].as_array().unwrap().len(), 101);

    for count in [102, 251] {
        for field in ["recipient", "recipients", "messageBox", "messageId", "body"] {
            let mut request = message("unused", "hello");
            request["message"][field] = json!(vec!["x"; count]);
            let response = app.handle("/sendMessage", Some(&id(ALICE)), &request).await;
            assert_eq!(response.status, 400, "{field}, {count}: {}", response.body);
            assert_eq!(
                response.body["code"], "ERR_INVALID_REQUEST_DATA",
                "{field}, {count}"
            );
        }
    }
    let shadowed = json!({"message":{"recipient":vec![BOB; 102],"recipients":[BOB],"messageBox":"","messageId":"shadowed","body":"hello"}});
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &shadowed)
            .await
            .body["code"],
        "ERR_INVALID_REQUEST_DATA"
    );
    let mut request = message("unused", "hello");
    request["message"]["recipient"] = json!(vec![BOB; 102]);
    assert_eq!(
        app.handle("/sendMessage", None, &request).await.body["code"],
        "ERR_AUTH_REQUIRED"
    );

    let small = MessageBox::memory_with_resources(
        Arc::new(Free),
        resources(&[("MESSAGE_BOX_RESOURCE_PROFILE", "small")]),
    )
    .await
    .unwrap();
    request["message"]["recipient"] = json!(vec![BOB; 101]);
    assert_eq!(
        small
            .handle("/sendMessage", Some(&id(ALICE)), &request)
            .await
            .body["code"],
        "ERR_TOO_MANY_RECIPIENTS"
    );
    request["message"]["recipient"] = json!(vec![BOB; 102]);
    assert_eq!(
        small
            .handle("/sendMessage", Some(&id(ALICE)), &request)
            .await
            .body["code"],
        "ERR_INVALID_REQUEST_DATA"
    );
}

#[tokio::test]
async fn configured_body_and_quota_limits_reach_core() {
    let app = MessageBox::memory_with_resources(
        Arc::new(Free),
        resources(&[
            ("MESSAGE_BOX_MAX_MESSAGE_BODY_BYTES", "3"),
            ("MESSAGE_BOX_MAX_SENDER_MESSAGES", "1"),
        ]),
    )
    .await
    .unwrap();
    assert_eq!(
        app.handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &message("too-big", "abcd")
        )
        .await
        .status,
        413
    );
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &message("one", "abc"))
            .await
            .status,
        200
    );
    assert_ne!(
        app.handle("/sendMessage", Some(&id(ALICE)), &message("two", "abc"))
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn old_database_migrates_and_unlimited_retention_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.sqlite");
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let mut db = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::query("CREATE TABLE messages (message_id TEXT PRIMARY KEY NOT NULL, recipient TEXT NOT NULL, sender TEXT NOT NULL, message_box TEXT NOT NULL, body TEXT NOT NULL, body_bytes INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at INTEGER NOT NULL)").execute(&mut db).await.unwrap();
    sqlx::query("INSERT INTO messages VALUES ('old', ?, ?, 'inbox', '{\"message\":\"old\"}', 17, '2026-01-01T00:00:00.000Z', 4102444800000)").bind(BOB).bind(ALICE).execute(&mut db).await.unwrap();
    db.close().await.unwrap();
    let r = resources(&[("MESSAGE_BOX_RETENTION_DAYS", "unlimited")]);
    let app = MessageBox::open_with_resources(&path, Arc::new(Free), r.clone())
        .await
        .unwrap();
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &message("new", "abc"))
            .await
            .status,
        200
    );
    assert_eq!(app.purge_expired().await.unwrap(), 0);
    app.close().await;
    let app = MessageBox::open_with_resources(&path, Arc::new(Free), r)
        .await
        .unwrap();
    let listed = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(listed.status, 200);
    assert_eq!(listed.body["messages"].as_array().unwrap().len(), 2);
    app.close().await;
    let mut db = SqliteConnection::connect_with(&options).await.unwrap();
    let rows = sqlx::query("SELECT message_id, expires_at FROM messages ORDER BY message_id")
        .fetch_all(&mut db)
        .await
        .unwrap();
    assert_eq!(rows[0].get::<String, _>(0), "new");
    assert_eq!(rows[0].get::<Option<i64>, _>(1), None);
    assert_eq!(rows[1].get::<Option<i64>, _>(1), Some(4102444800000));
    let index_count: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type='index' AND name IN ('inbox_order','sender_usage')").fetch_one(&mut db).await.unwrap();
    assert_eq!(index_count, 2);
}

#[tokio::test]
async fn unlimited_core_ceilings_do_not_reject_ordinary_sends() {
    let app = MessageBox::memory_with_resources(
        Arc::new(Free),
        resources(&[
            ("MESSAGE_BOX_MAX_MESSAGE_BODY_BYTES", "unlimited"),
            ("MESSAGE_BOX_MAX_RECIPIENTS", "-1"),
            ("MESSAGE_BOX_LIST_MAX_RESPONSE_BYTES", "-1"),
            ("MESSAGE_BOX_MAX_ACKNOWLEDGMENT_IDS", "-1"),
            ("MESSAGE_BOX_MAX_SENDER_MESSAGES", "-1"),
            ("MESSAGE_BOX_MAX_SENDER_BYTES", "-1"),
            ("MESSAGE_BOX_MAX_INBOX_MESSAGES", "-1"),
            ("MESSAGE_BOX_MAX_INBOX_BYTES", "-1"),
        ]),
    )
    .await
    .unwrap();
    for i in 0..2 {
        assert_eq!(
            app.handle(
                "/sendMessage",
                Some(&id(ALICE)),
                &message(&format!("unlimited-{i}"), "abc")
            )
            .await
            .status,
            200
        );
    }
    let listed = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(listed.body["messages"].as_array().unwrap().len(), 2);
    assert_eq!(
        app.handle(
            "/acknowledgeMessage",
            Some(&id(BOB)),
            &json!({"messageIds":["unlimited-0", "unlimited-1"]})
        )
        .await
        .status,
        200
    );
}

#[tokio::test]
async fn unlimited_list_bounds_reach_pagination() {
    let app = MessageBox::memory_with_resources(
        Arc::new(Free),
        resources(&[
            ("MESSAGE_BOX_LIST_DEFAULT_LIMIT", "-1"),
            ("MESSAGE_BOX_LIST_MAX_LIMIT", "-1"),
            ("MESSAGE_BOX_LIST_MAX_OFFSET", "-1"),
        ]),
    )
    .await
    .unwrap();
    let listed = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(listed.status, 200);
    assert_eq!(listed.body["limit"], json!(9_007_199_254_740_991u64));
    let listed = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox", "limit": 100001, "offset": 1000001}),
        )
        .await;
    assert_eq!(listed.status, 200);
}

#[tokio::test]
async fn unlimited_default_with_finite_max_rejects_default_but_accepts_explicit_limit() {
    let app = MessageBox::memory_with_resources(
        Arc::new(Free),
        resources(&[
            ("MESSAGE_BOX_LIST_DEFAULT_LIMIT", "-1"),
            ("MESSAGE_BOX_LIST_MAX_LIMIT", "2"),
        ]),
    )
    .await
    .unwrap();
    let default = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(default.status, 400);
    assert_eq!(default.body["code"], "ERR_INVALID_LIMIT");
    let explicit = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox", "limit": 2}),
        )
        .await;
    assert_eq!(explicit.status, 200);
}

#[tokio::test]
async fn configured_device_and_permission_pages_reach_consumers() {
    let app = MessageBox::memory_with_resources(
        Arc::new(Free),
        resources(&[
            ("MESSAGE_BOX_DEVICE_LIST_DEFAULT_LIMIT", "1"),
            ("MESSAGE_BOX_DEVICE_LIST_MAX_LIMIT", "2"),
            ("MESSAGE_BOX_DEVICE_LIST_MAX_OFFSET", "3"),
            ("MESSAGE_BOX_PERMISSION_LIST_DEFAULT_LIMIT", "1"),
            ("MESSAGE_BOX_PERMISSION_LIST_MAX_LIMIT", "2"),
            ("MESSAGE_BOX_PERMISSION_LIST_MAX_OFFSET", "3"),
        ]),
    )
    .await
    .unwrap();
    for box_name in ["one", "two"] {
        assert_eq!(
            app.handle(
                "/permissions/set",
                Some(&id(BOB)),
                &json!({"sender": null, "messageBox": box_name, "recipientFee": 0})
            )
            .await
            .status,
            200
        );
    }
    for path in ["/devices", "/permissions/list"] {
        let app_ref = &app;
        let get = |query: serde_json::Value| async move {
            app_ref
                .dispatch_http("GET", path, Some(&id(BOB)), &query, &json!({}))
                .await
                .unwrap()
        };
        let default = get(json!({})).await;
        assert_eq!(default.status, 200, "{path}: {}", default.body);
        if path == "/devices" {
            assert_eq!(default.body["limit"], 1);
        } else {
            assert_eq!(default.body["permissions"].as_array().unwrap().len(), 1);
            assert_eq!(default.body["totalCount"], 2);
        }
        assert_eq!(
            get(json!({"limit": 3})).await.body["code"],
            "ERR_INVALID_LIMIT"
        );
        assert_eq!(
            get(json!({"offset": 4})).await.body["code"],
            "ERR_INVALID_OFFSET"
        );
    }
}

#[tokio::test]
async fn legacy_limits_keep_existing_validation() {
    use message_box_server_rust::Limits;
    assert!(
        MessageBox::memory(
            Arc::new(Free),
            Limits {
                max_recipients: 1_001,
                ..Limits::default()
            }
        )
        .await
        .is_err()
    );
    assert!(
        MessageBox::memory(
            Arc::new(Free),
            Limits {
                max_inbox_messages: -1,
                ..Limits::default()
            }
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn finite_safe_max_error_is_not_reported_as_unlimited() {
    let app = MessageBox::memory_with_resources(
        Arc::new(Free),
        resources(&[
            ("MESSAGE_BOX_LIST_MAX_LIMIT", "9007199254740991"),
            ("MESSAGE_BOX_LIST_MAX_OFFSET", "9007199254740991"),
        ]),
    )
    .await
    .unwrap();
    for (field, value, expected) in [
        (
            "limit",
            json!(0),
            "limit must be an integer between 1 and 9007199254740991.",
        ),
        (
            "offset",
            json!(-1),
            "offset must be an integer between 0 and 9007199254740991.",
        ),
    ] {
        let mut query = json!({"messageBox":"inbox"});
        query[field] = value;
        let result = app.handle("/listMessages", Some(&id(BOB)), &query).await;
        assert_eq!(result.status, 400);
        assert_eq!(result.body["description"], expected);
    }
}

#[test]
fn safe_integer_retention_is_accepted_at_startup() {
    let env = EnvironmentSnapshot::from([(
        "MESSAGE_BOX_RETENTION_DAYS".into(),
        "9007199254740991".into(),
    )]);
    assert!(RuntimeResources::new(ResourceConfig::from_snapshot(&env).unwrap()).is_ok());
}

#[test]
fn expiry_matches_js_date_range_and_unlimited_is_distinct() {
    let now = 1_800_000_000_000;
    assert_eq!(
        resources(&[]).expires_at_ms(now).unwrap(),
        Some(now + 30 * 86_400_000)
    );
    assert_eq!(
        resources(&[("MESSAGE_BOX_RETENTION_DAYS", "-1")])
            .expires_at_ms(now)
            .unwrap(),
        None
    );
    assert_eq!(
        resources(&[("MESSAGE_BOX_RETENTION_DAYS", "100000000")])
            .expires_at_ms(0)
            .unwrap(),
        Some(8_640_000_000_000_000)
    );
    for days in ["100000001", "4294967296", "9007199254740991"] {
        assert!(
            resources(&[("MESSAGE_BOX_RETENTION_DAYS", days)])
                .expires_at_ms(now)
                .is_err()
        );
    }
}

#[test]
fn maintenance_defaults_overrides_and_node_timer_bounds() {
    use message_box_server_rust::resource_config::ResourceLimit;
    use message_box_server_rust::runtime_resources::MaintenanceConfig;
    let default = MaintenanceConfig::from_snapshot(&EnvironmentSnapshot::new()).unwrap();
    assert_eq!(default.batch_size, ResourceLimit::Finite(1000));
    assert_eq!(default.timer_duration().unwrap().as_millis(), 900000);
    let mut env = EnvironmentSnapshot::from([
        (
            "MESSAGE_BOX_RETENTION_CLEANUP_INTERVAL_MS".into(),
            "-1".into(),
        ),
        (
            "MESSAGE_BOX_RETENTION_CLEANUP_BATCH_SIZE".into(),
            " unlimited ".into(),
        ),
    ]);
    let c = MaintenanceConfig::from_snapshot(&env).unwrap();
    assert_eq!(c.timer_duration(), None);
    assert_eq!(c.batch_size, ResourceLimit::Unlimited);
    env.insert(
        "MESSAGE_BOX_RETENTION_CLEANUP_INTERVAL_MS".into(),
        "2147483648".into(),
    );
    assert_eq!(
        MaintenanceConfig::from_snapshot(&env)
            .unwrap()
            .timer_duration()
            .unwrap()
            .as_millis(),
        1
    );
    env.insert(
        "MESSAGE_BOX_RETENTION_CLEANUP_BATCH_SIZE".into(),
        "0".into(),
    );
    assert_eq!(
        MaintenanceConfig::from_snapshot(&env)
            .unwrap_err()
            .to_string(),
        "MESSAGE_BOX_RETENTION_CLEANUP_BATCH_SIZE must be -1, unlimited, or a positive integer"
    );
}

#[tokio::test]
async fn normal_reopen_preserves_permissions_devices_order_and_quota_then_ack_releases_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lifecycle.sqlite");
    let r = resources(&[
        ("MESSAGE_BOX_MAX_SENDER_MESSAGES", "2"),
        ("MESSAGE_BOX_RETENTION_DAYS", "-1"),
    ]);
    let app = MessageBox::open_with_resources(&path, Arc::new(Free), r.clone())
        .await
        .unwrap();
    for (sender, fee) in [(None, -1), (Some(ALICE), 0)] {
        assert_eq!(
            app.handle(
                "/permissions/set",
                Some(&id(BOB)),
                &json!({"messageBox":"inbox", "sender":sender,"recipientFee":fee})
            )
            .await
            .status,
            200
        );
    }
    let registered = app
        .handle(
            "/registerDevice",
            Some(&id(BOB)),
            &json!({"fcmToken":"test-only-device-token","platform":"web"}),
        )
        .await;
    assert_eq!(registered.status, 200);
    for name in ["b", "a"] {
        assert_eq!(
            app.handle("/sendMessage", Some(&id(ALICE)), &message(name, "abc"))
                .await
                .status,
            200
        );
    }
    app.close().await;
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(&path);
    let mut db = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::query("UPDATE messages SET created_at='2026-01-01T00:00:00.000Z'")
        .execute(&mut db)
        .await
        .unwrap();
    db.close().await.unwrap();
    let app = MessageBox::open_with_resources(&path, Arc::new(Free), r.clone())
        .await
        .unwrap();
    let listed = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(listed.body["messages"][0]["messageId"], "a");
    assert_eq!(listed.body["messages"][1]["messageId"], "b");
    let quota = app
        .handle("/sendMessage", Some(&id(ALICE)), &message("c", "abc"))
        .await;
    assert_eq!(quota.status, 429, "{}", quota.body);
    let permission = app
        .handle(
            "/permissions/get",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox", "sender":ALICE}),
        )
        .await;
    assert_eq!(permission.body["permission"]["recipientFee"], 0);
    let devices = app.handle("/devices", Some(&id(BOB)), &json!({})).await;
    assert_eq!(
        devices.body["devices"][0]["id"],
        registered.body["deviceId"]
    );
    assert_eq!(
        app.handle(
            "/registerDevice",
            Some(&id(ALICE)),
            &json!({"fcmToken":"test-only-device-token"})
        )
        .await
        .status,
        409
    );
    assert_eq!(
        app.handle(
            "/acknowledgeMessage",
            Some(&id(BOB)),
            &json!({"messageIds":["a"]})
        )
        .await
        .status,
        200
    );
    app.close().await;
    let app = MessageBox::open_with_resources(&path, Arc::new(Free), r)
        .await
        .unwrap();
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &message("c", "abc"))
            .await
            .status,
        200
    );
    app.close().await;
}

#[tokio::test]
async fn cleanup_is_bounded_and_does_not_delete_unlimited_or_future_messages() {
    use message_box_server_rust::resource_config::ResourceLimit;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cleanup.sqlite");
    let app = MessageBox::open_with_resources(
        &path,
        Arc::new(Free),
        resources(&[("MESSAGE_BOX_RETENTION_DAYS", "-1")]),
    )
    .await
    .unwrap();
    for name in ["expired-a", "expired-b", "live", "future"] {
        assert_eq!(
            app.handle("/sendMessage", Some(&id(ALICE)), &message(name, "abc"))
                .await
                .status,
            200
        );
    }
    let mut db =
        SqliteConnection::connect_with(&sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    sqlx::query("UPDATE messages SET expires_at=0 WHERE message_id LIKE 'expired-%'")
        .execute(&mut db)
        .await
        .unwrap();
    sqlx::query("UPDATE messages SET expires_at=8640000000000000 WHERE message_id='future'")
        .execute(&mut db)
        .await
        .unwrap();
    db.close().await.unwrap();
    assert_eq!(
        app.purge_expired_batch(ResourceLimit::Finite(1))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        app.purge_expired_batch(ResourceLimit::Unlimited)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        app.purge_expired_batch(ResourceLimit::Unlimited)
            .await
            .unwrap(),
        0
    );
    let list = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(list.body["messages"].as_array().unwrap().len(), 2);
    app.close().await;
}
