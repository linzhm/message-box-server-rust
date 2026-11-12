use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
};
use serde_json::{Value, json};
use std::sync::Arc;
const A: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const B: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
struct Free;
impl DeliveryPolicy for Free {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
fn id(key: &str) -> Identity {
    Identity::from_verified_key(key).unwrap()
}
async fn app() -> MessageBox {
    MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap()
}
async fn route(
    app: &MessageBox,
    method: &str,
    path: &str,
    who: Option<&Identity>,
    fields: Value,
) -> (u16, Value) {
    let (q, b) = if method == "GET" {
        (fields, json!({}))
    } else {
        (json!({}), fields)
    };
    let r = app.dispatch_http(method, path, who, &q, &b).await.unwrap();
    (r.status, r.body)
}
#[tokio::test]
async fn registrations_are_owner_scoped_and_tokens_are_redacted() {
    let app = app().await;
    let a = id(A);
    let b = id(B);
    let r = route(
        &app,
        "POST",
        "/registerDevice",
        Some(&a),
        json!({"fcmToken":"secret-device-token","deviceId":"browser","platform":"web"}),
    )
    .await;
    assert_eq!(r.0, 200);
    let device_id = r.1["deviceId"].clone();
    let other = route(
        &app,
        "POST",
        "/registerDevice",
        Some(&b),
        json!({"fcmToken":"secret-device-token"}),
    )
    .await;
    assert_eq!(other.0, 409);
    assert_eq!(other.1["code"], "ERR_DEVICE_TOKEN_ALREADY_REGISTERED");
    let refresh = route(
        &app,
        "POST",
        "/registerDevice",
        Some(&a),
        json!({"fcmToken":"secret-device-token","deviceId":"updated","platform":"ios"}),
    )
    .await;
    assert_eq!(refresh.1["deviceId"], device_id);
    let list = route(&app, "GET", "/devices", Some(&a), json!({})).await;
    assert_eq!(list.0, 200);
    assert_eq!(list.1["limit"], 100);
    assert_eq!(list.1["offset"], 0);
    assert_eq!(list.1["devices"][0]["deviceId"], "updated");
    assert_eq!(list.1["devices"][0]["platform"], "ios");
    assert_eq!(list.1["devices"][0]["fcmToken"], "...vice-token");
    assert_eq!(list.1["devices"][0]["active"], true);
    assert_eq!(
        route(&app, "GET", "/devices", Some(&b), json!({})).await.1["devices"],
        json!([])
    );
}
#[tokio::test]
async fn validation_and_page_boundaries_match_source_contract() {
    let app = app().await;
    let a = id(A);
    assert_eq!(
        route(&app, "POST", "/registerDevice", None, json!({}))
            .await
            .1["code"],
        "ERR_AUTHENTICATION_REQUIRED"
    );
    for (body, code) in [
        (json!({"fcmToken":" token"}), "ERR_INVALID_FCM_TOKEN"),
        (json!({"fcmToken":"x".repeat(501)}), "ERR_INVALID_FCM_TOKEN"),
        (
            json!({"fcmToken":"a","deviceId":" d"}),
            "ERR_INVALID_DEVICE_ID",
        ),
        (
            json!({"fcmToken":"a","platform":"desktop"}),
            "ERR_INVALID_PLATFORM",
        ),
    ] {
        let r = route(&app, "POST", "/registerDevice", Some(&a), body).await;
        assert_eq!(r.0, 400);
        assert_eq!(r.1["code"], code);
    }
    for (query, code) in [
        (json!({"limit":"101"}), "ERR_INVALID_LIMIT"),
        (json!({"limit":"1.5"}), "ERR_INVALID_LIMIT"),
        (json!({"offset":"100001"}), "ERR_INVALID_OFFSET"),
        (json!({"limit":"0","offset":"bad"}), "ERR_INVALID_LIMIT"),
    ] {
        let r = route(&app, "GET", "/devices", Some(&a), query).await;
        assert_eq!(r.0, 400);
        assert_eq!(r.1["code"], code);
    }
    let r = route(
        &app,
        "GET",
        "/devices",
        Some(&a),
        json!({"limit":"0x2","offset":""}),
    )
    .await;
    assert_eq!(r.1["limit"], 2);
    assert_eq!(r.1["offset"], 0);
}

#[tokio::test]
async fn device_registrations_persist_and_storage_errors_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.sqlite");
    let a = id(A);
    let app = MessageBox::open(&path, Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let r = route(
        &app,
        "POST",
        "/registerDevice",
        Some(&a),
        json!({"fcmToken":"short"}),
    )
    .await;
    assert_eq!(r.0, 200);
    app.close().await;
    let app = MessageBox::open(&path, Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let r = route(&app, "GET", "/devices", Some(&a), json!({})).await;
    assert_eq!(r.1["devices"][0]["fcmToken"], "...short");
    assert_eq!(r.1["devices"][0]["deviceId"], Value::Null);
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    // MySQL BOOLEAN/TINYINT values are returned unchanged by the pinned TS route.
    sqlx::query("UPDATE device_registrations SET active=0")
        .execute(&pool)
        .await
        .unwrap();
    let inactive = route(&app, "GET", "/devices", Some(&a), json!({})).await;
    assert_eq!(inactive.1["devices"][0]["active"], false);
    assert_eq!(inactive.1["devices"][0]["fcmToken"], "...short");
    let refreshed = route(
        &app,
        "POST",
        "/registerDevice",
        Some(&a),
        json!({"fcmToken":"short"}),
    )
    .await;
    assert_eq!(refreshed.0, 200);
    let active = route(&app, "GET", "/devices", Some(&a), json!({})).await;
    assert_eq!(active.1["devices"][0]["active"], true);
    sqlx::query("DROP TABLE device_registrations")
        .execute(&pool)
        .await
        .unwrap();
    for (method, path, fields) in [
        ("GET", "/devices", json!({})),
        ("POST", "/registerDevice", json!({"fcmToken":"another"})),
    ] {
        let r = route(&app, method, path, Some(&a), fields).await;
        assert_eq!(r.0, 500);
        assert_eq!(r.1["code"], "ERR_DATABASE_ERROR");
    }
}

#[tokio::test]
async fn device_pages_follow_updated_time_and_utf16_redaction_is_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pages.sqlite");
    let app = MessageBox::open(&path, Arc::new(Free), Limits::default())
        .await
        .unwrap();
    let a = id(A);
    for token in ["older-token", "newer-token", "😀123456789"] {
        assert_eq!(
            route(
                &app,
                "POST",
                "/registerDevice",
                Some(&a),
                json!({"fcmToken":token})
            )
            .await
            .0,
            200
        );
    }
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    for (token, time) in [
        ("older-token", "2026-01-01T00:00:00.000Z"),
        ("newer-token", "2026-01-02T00:00:00.000Z"),
        ("😀123456789", "2026-01-03T00:00:00.000Z"),
    ] {
        sqlx::query("UPDATE device_registrations SET updated_at=? WHERE fcm_token=?")
            .bind(time)
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
    }
    let page = route(
        &app,
        "GET",
        "/devices",
        Some(&a),
        json!({"limit":"1","offset":"1"}),
    )
    .await;
    assert_eq!(page.0, 200);
    assert_eq!(page.1["devices"].as_array().unwrap().len(), 1);
    assert_eq!(page.1["devices"][0]["fcmToken"], "...ewer-token");
    let first = route(&app, "GET", "/devices", Some(&a), json!({"limit":"1"})).await;
    assert_eq!(first.1["devices"][0]["fcmToken"], "...�123456789");
}
