use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
};
use serde_json::{Value, json};
use std::sync::Arc;

const ALICE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const BOB: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const CAROL: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
struct Policy(Decision);
impl DeliveryPolicy for Policy {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(self.0)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
fn id(key: &str) -> Identity {
    Identity::from_verified_key(key).unwrap()
}
async fn app() -> MessageBox {
    MessageBox::memory(Arc::new(Policy(Decision::Free)), Limits::default())
        .await
        .unwrap()
}
async fn set(
    app: &MessageBox,
    owner: &str,
    sender: Option<&str>,
    box_name: &str,
    fee: i64,
) -> Value {
    let result = app
        .handle(
            "/permissions/set",
            Some(&id(owner)),
            &json!({"sender":sender,"messageBox":box_name,"recipientFee":fee}),
        )
        .await;
    assert_eq!(result.status, 200, "{}", result.body);
    result.body
}
async fn get(app: &MessageBox, owner: &str, sender: Option<&str>, box_name: &str) -> Value {
    let result = app
        .handle(
            "/permissions/get",
            Some(&id(owner)),
            &json!({"sender":sender,"messageBox":box_name}),
        )
        .await;
    assert_eq!(result.status, 200, "{}", result.body);
    result.body
}
fn message(to: Value, ids: Value, box_name: &str) -> Value {
    json!({"message":{"recipient":to,"messageId":ids,"messageBox":box_name,"body":"hello"}})
}
async fn inbox(app: &MessageBox, owner: &str, box_name: &str) -> Value {
    app.handle(
        "/listMessages",
        Some(&id(owner)),
        &json!({"messageBox":box_name}),
    )
    .await
    .body["messages"]
        .clone()
}

#[tokio::test]
async fn permission_set_get_are_owner_scoped_and_get_does_not_resolve_defaults() {
    let app = app().await;
    assert_eq!(
        get(&app, BOB, None, "inbox").await,
        json!({"status":"success","description":"No box-wide permission setting found for inbox.","permission":null})
    );
    assert_eq!(
        set(&app, BOB, None, "inbox", -1).await,
        json!({"status":"success","description":"Box-wide default for all senders to inbox is now blocked."})
    );
    let stored = get(&app, BOB, None, "inbox").await;
    assert_eq!(stored["permission"]["sender"], Value::Null);
    assert_eq!(stored["permission"]["recipientFee"], -1);
    assert_eq!(stored["permission"]["status"], "blocked");
    assert!(
        chrono::DateTime::parse_from_rfc3339(stored["permission"]["createdAt"].as_str().unwrap())
            .is_ok()
    );
    assert_eq!(
        get(&app, BOB, Some(ALICE), "inbox").await["permission"],
        Value::Null
    );
    assert_eq!(
        get(&app, CAROL, None, "inbox").await["permission"],
        Value::Null
    );
    assert_eq!(
        get(&app, BOB, None, "other").await["permission"],
        Value::Null
    );
    set(&app, BOB, Some(&ALICE.to_uppercase()), "inbox", 0).await;
    let specific = get(&app, BOB, Some(ALICE), "inbox").await;
    assert_eq!(specific["permission"]["sender"], ALICE);
    assert_eq!(specific["permission"]["status"], "always_allow");
    // A caller-provided recipient cannot change whose permission is written.
    let own = app
        .handle(
            "/permissions/set",
            Some(&id(CAROL)),
            &json!({"recipient":BOB,"messageBox":"inbox","recipientFee":23}),
        )
        .await;
    assert_eq!(own.status, 200);
    assert_eq!(
        get(&app, BOB, None, "inbox").await["permission"]["recipientFee"],
        -1
    );
    assert_eq!(
        get(&app, CAROL, None, "inbox").await["permission"]["status"],
        "payment_required"
    );
}

#[tokio::test]
async fn permission_validation_and_auth_errors_leave_prior_state_intact() {
    let app = app().await;
    for route in ["/permissions/set", "/permissions/get"] {
        let error = app.handle(route, None, &json!({})).await;
        assert_eq!(error.status, 401);
        assert_eq!(error.body["code"], "ERR_AUTHENTICATION_REQUIRED");
    }
    set(&app, BOB, None, "inbox", 0).await;
    for (request, code) in [
        (json!({}), "ERR_INVALID_REQUEST"),
        (
            json!({"messageBox":"inbox","recipientFee":"0"}),
            "ERR_INVALID_REQUEST",
        ),
        (
            json!({"messageBox":"inbox","recipientFee":-2}),
            "ERR_INVALID_FEE_VALUE",
        ),
        (
            json!({"messageBox":"inbox","recipientFee":2147483648i64}),
            "ERR_INVALID_FEE_VALUE",
        ),
        (
            json!({"messageBox":"inbox","recipientFee":0.5}),
            "ERR_INVALID_FEE_VALUE",
        ),
        (
            json!({"messageBox":"inbox","recipientFee":0,"sender":"bad"}),
            "ERR_INVALID_PUBLIC_KEY",
        ),
        (
            json!({"messageBox":"inbox ","recipientFee":0}),
            "ERR_INVALID_MESSAGE_BOX",
        ),
        (
            json!({"messageBox":"信".repeat(43),"recipientFee":0}),
            "ERR_INVALID_MESSAGE_BOX",
        ),
        (
            json!({"messageBox":"in\u{0085}box","recipientFee":0}),
            "ERR_INVALID_MESSAGE_BOX",
        ),
        (
            json!({"messageBox":[],"recipientFee":0}),
            "ERR_INVALID_MESSAGE_BOX",
        ),
        (
            json!({"messageBox":"invalid ","recipientFee":-2,"sender":"bad"}),
            "ERR_INVALID_PUBLIC_KEY",
        ),
    ] {
        let error = app
            .handle("/permissions/set", Some(&id(BOB)), &request)
            .await;
        assert_eq!(error.status, 400, "{request}");
        assert_eq!(error.body["code"], code, "{request}");
        assert_eq!(
            get(&app, BOB, None, "inbox").await["permission"]["recipientFee"],
            0
        );
    }
    let error = app
        .handle(
            "/permissions/get",
            Some(&id(BOB)),
            &json!({"sender":"bad","messageBox":"invalid "}),
        )
        .await;
    assert_eq!(error.body["code"], "ERR_INVALID_MESSAGE_BOX");
    let result = app
        .handle(
            "/permissions/set",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox","recipientFee":2147483647.0}),
        )
        .await;
    assert_eq!(result.status, 200);
    assert_eq!(
        get(&app, BOB, None, "inbox").await["permission"]["recipientFee"],
        2147483647i64
    );
}

#[tokio::test]
async fn sender_override_box_default_and_notification_fee_control_delivery() {
    let app = app().await;
    let send = message(json!(BOB), json!("notice"), "notifications");
    let paid = app.handle("/sendMessage", Some(&id(ALICE)), &send).await;
    assert_eq!(paid.body["code"], "ERR_PAYMENT_NOT_IMPLEMENTED");
    assert_eq!(inbox(&app, BOB, "notifications").await, json!([]));
    // Reading default policy must not create a user preference.
    assert_eq!(
        get(&app, BOB, None, "notifications").await["permission"],
        Value::Null
    );
    set(&app, BOB, None, "notifications", 0).await;
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &send)
            .await
            .status,
        200
    );
    set(&app, BOB, None, "inbox", -1).await;
    let send = message(json!(BOB), json!("override"), "inbox");
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &send)
            .await
            .status,
        403
    );
    set(&app, BOB, Some(ALICE), "inbox", 0).await;
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &send)
            .await
            .status,
        200
    );
    let send = message(json!(BOB), json!("other-sender"), "inbox");
    assert_eq!(
        app.handle("/sendMessage", Some(&id(CAROL)), &send)
            .await
            .status,
        403
    );
}

#[tokio::test]
async fn blocked_fanout_beats_fee_and_never_partially_delivers() {
    let app = app().await;
    set(&app, BOB, None, "inbox", 10).await;
    set(&app, CAROL, None, "inbox", -1).await;
    let send = message(json!([BOB, CAROL]), json!(["paid", "blocked"]), "inbox");
    let result = app.handle("/sendMessage", Some(&id(ALICE)), &send).await;
    assert_eq!(result.status, 403);
    assert_eq!(result.body["blockedRecipients"], json!([CAROL]));
    for recipient in [BOB, CAROL] {
        assert_eq!(inbox(&app, recipient, "inbox").await, json!([]));
    }
}

#[tokio::test]
async fn stored_allow_cannot_override_additional_server_policy() {
    for (policy, expected) in [(Decision::Blocked, 403), (Decision::PaymentRequired, 501)] {
        let app = MessageBox::memory(Arc::new(Policy(policy)), Limits::default())
            .await
            .unwrap();
        set(&app, BOB, None, "inbox", 0).await;
        let send = message(json!(BOB), json!("server-policy"), "inbox");
        assert_eq!(
            app.handle("/sendMessage", Some(&id(ALICE)), &send)
                .await
                .status,
            expected
        );
        assert_eq!(inbox(&app, BOB, "inbox").await, json!([]));
    }
}

#[tokio::test]
async fn permission_upsert_preserves_creation_across_close_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("permissions.sqlite");
    let app = MessageBox::open(&path, Arc::new(Policy(Decision::Free)), Limits::default())
        .await
        .unwrap();
    set(&app, BOB, None, "inbox", -1).await;
    let created = get(&app, BOB, None, "inbox").await["permission"]["createdAt"].clone();
    app.close().await;
    let app = MessageBox::open(&path, Arc::new(Policy(Decision::Free)), Limits::default())
        .await
        .unwrap();
    set(&app, BOB, None, "inbox", 0).await;
    let permission = get(&app, BOB, None, "inbox").await;
    assert_eq!(permission["permission"]["createdAt"], created);
    assert_eq!(permission["permission"]["recipientFee"], 0);
    assert_eq!(
        app.handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &message(json!(BOB), json!("persisted"), "inbox")
        )
        .await
        .status,
        200
    );
}

#[tokio::test]
async fn permission_storage_failure_and_invalid_fee_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken-permissions.sqlite");
    let app = MessageBox::open(&path, Arc::new(Policy(Decision::Free)), Limits::default())
        .await
        .unwrap();
    set(&app, BOB, None, "inbox", 0).await;
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    for fee in [
        json!(2147483648i64),
        json!(-2),
        json!(0.5),
        json!("corrupt"),
    ] {
        let sql = format!(
            "UPDATE message_permissions SET recipient_fee={} WHERE recipient=?",
            if fee.is_string() {
                "'corrupt'".to_string()
            } else {
                fee.to_string()
            }
        );
        sqlx::query(&sql).bind(BOB).execute(&pool).await.unwrap();
        let denied = app
            .handle(
                "/sendMessage",
                Some(&id(ALICE)),
                &message(json!(BOB), json!("must-not-deliver"), "inbox"),
            )
            .await;
        assert_eq!(denied.status, 503, "stored fee: {fee}");
        assert_eq!(denied.body["code"], "ERR_POLICY_UNAVAILABLE");
        let get = app
            .handle(
                "/permissions/get",
                Some(&id(BOB)),
                &json!({"messageBox":"inbox"}),
            )
            .await;
        assert_eq!(get.status, 500);
        assert_eq!(get.body["code"], "ERR_INTERNAL");
        assert_eq!(inbox(&app, BOB, "inbox").await, json!([]));
    }
    sqlx::query("DROP TABLE message_permissions")
        .execute(&pool)
        .await
        .unwrap();
    let failed = app
        .handle(
            "/permissions/set",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox","recipientFee":0}),
        )
        .await;
    assert_eq!(failed.status, 500);
    assert_eq!(failed.body["code"], "ERR_DATABASE_ERROR");
    assert_eq!(
        app.handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &message(json!(BOB), json!("missing-table"), "inbox")
        )
        .await
        .status,
        503
    );
    assert_eq!(inbox(&app, BOB, "inbox").await, json!([]));
}

#[tokio::test]
async fn opening_old_core_schema_preserves_existing_messages() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("upgrade.sqlite");
    let app = MessageBox::open(&path, Arc::new(Policy(Decision::Free)), Limits::default())
        .await
        .unwrap();
    let send = message(json!(BOB), json!("existing"), "inbox");
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &send)
            .await
            .status,
        200
    );
    app.close().await;
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    // The previous core schema has messages but no permission table.
    sqlx::query("DROP TABLE message_permissions")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let app = MessageBox::open(&path, Arc::new(Policy(Decision::Free)), Limits::default())
        .await
        .unwrap();
    assert_eq!(inbox(&app, BOB, "inbox").await[0]["messageId"], "existing");
    set(&app, BOB, None, "inbox", -1).await;
    assert_eq!(inbox(&app, BOB, "inbox").await[0]["messageId"], "existing");
}

async fn permission_list(app: &MessageBox, owner: &str, query: Value) -> Value {
    let response = app
        .handle("/permissions/list", Some(&id(owner)), &query)
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    response.body
}

#[tokio::test]
async fn permission_list_is_owner_scoped_filtered_and_sorted_before_pagination() {
    let app = app().await;
    assert_eq!(
        permission_list(&app, BOB, json!({})).await,
        json!({"status":"success","permissions":[],"totalCount":0})
    );
    set(&app, BOB, Some(CAROL), "z-box", 2).await;
    set(&app, BOB, Some(CAROL), "a-box", 3).await;
    set(&app, BOB, None, "a-box", -1).await;
    set(&app, BOB, Some(ALICE), "a-box", 0).await;
    set(&app, CAROL, None, "a-box", 99).await;
    let listed = permission_list(&app, BOB, json!({})).await;
    assert_eq!(listed["totalCount"], 4);
    let rows = listed["permissions"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| (&r["messageBox"], &r["sender"]))
            .collect::<Vec<_>>(),
        vec![
            (&json!("a-box"), &Value::Null),
            (&json!("a-box"), &json!(ALICE)),
            (&json!("a-box"), &json!(CAROL)),
            (&json!("z-box"), &json!(CAROL))
        ]
    );
    let exact = get(&app, BOB, None, "a-box").await;
    assert_eq!(
        rows[0],
        json!({"sender":null,"messageBox":"a-box","recipientFee":-1,"createdAt":exact["permission"]["createdAt"],"updatedAt":exact["permission"]["updatedAt"]})
    );
    // createdAtOrder is only the third sort key, not a global time ordering.
    assert_eq!(
        permission_list(&app, BOB, json!({"createdAtOrder":"asc"})).await,
        listed
    );
    let page = permission_list(
        &app,
        BOB,
        json!({"messageBox":"a-box","limit":"1","offset":"1","recipient":CAROL}),
    )
    .await;
    assert_eq!(page["totalCount"], 3);
    assert_eq!(page["permissions"], json!([rows[1]]));
    assert_eq!(page.as_object().unwrap().len(), 3);
    assert_eq!(
        permission_list(&app, BOB, json!({"offset":"100000"})).await["permissions"],
        json!([])
    );
    assert_eq!(
        permission_list(&app, BOB, json!({"messageBox":"missing"})).await["totalCount"],
        0
    );
}

#[tokio::test]
async fn permission_list_query_coercion_validation_and_auth_match_scalar_contract() {
    let app = app().await;
    let unauthorized = app
        .handle("/permissions/list", None, &json!({"limit":"bad"}))
        .await;
    assert_eq!(unauthorized.status, 401);
    assert_eq!(
        unauthorized.body,
        json!({"status":"error","code":"ERR_UNAUTHORIZED","description":"Authentication required"})
    );
    for n in 0..3 {
        set(&app, BOB, None, &format!("box-{n}"), 0).await;
    }
    for limit in [
        json!(2),
        json!(2.0),
        json!("2e0"),
        json!("0x2"),
        json!("0o2"),
        json!("0b10"),
        json!("\u{feff}+2.0\u{00a0}"),
    ] {
        let result = permission_list(&app, BOB, json!({"limit":limit,"offset":""})).await;
        assert_eq!(result["permissions"].as_array().unwrap().len(), 2);
    }
    for (query, code) in [
        (json!({"limit":"0"}), "ERR_INVALID_LIMIT"),
        (json!({"limit":"101"}), "ERR_INVALID_LIMIT"),
        (json!({"limit":"1.5"}), "ERR_INVALID_LIMIT"),
        (json!({"limit":"Infinity"}), "ERR_INVALID_LIMIT"),
        (json!({"limit":"+0x2"}), "ERR_INVALID_LIMIT"),
        (json!({"limit":"0x+2"}), "ERR_INVALID_LIMIT"),
        (json!({"limit":"0o+2"}), "ERR_INVALID_LIMIT"),
        (json!({"limit":"0b+10"}), "ERR_INVALID_LIMIT"),
        (json!({"limit":[]}), "ERR_INVALID_LIMIT"),
        (json!({"offset":"100001"}), "ERR_INVALID_OFFSET"),
        (json!({"offset":"-1"}), "ERR_INVALID_OFFSET"),
        (json!({"offset":"1.5"}), "ERR_INVALID_OFFSET"),
        (json!({"createdAtOrder":"DESC"}), "ERR_INVALID_SORT_ORDER"),
        (json!({"createdAtOrder":false}), "ERR_INVALID_SORT_ORDER"),
        (json!({"messageBox":""}), "ERR_INVALID_MESSAGE_BOX"),
        (json!({"messageBox":"box-0 "}), "ERR_INVALID_MESSAGE_BOX"),
        (json!({"messageBox":[]}), "ERR_INVALID_MESSAGE_BOX"),
        (
            json!({"limit":"bad","offset":"bad","createdAtOrder":"bad","messageBox":""}),
            "ERR_INVALID_LIMIT",
        ),
        (
            json!({"offset":"bad","createdAtOrder":"bad","messageBox":""}),
            "ERR_INVALID_OFFSET",
        ),
        (
            json!({"createdAtOrder":"bad","messageBox":""}),
            "ERR_INVALID_SORT_ORDER",
        ),
    ] {
        let result = app
            .handle("/permissions/list", Some(&id(BOB)), &query)
            .await;
        assert_eq!(result.status, 400, "{query}");
        assert_eq!(result.body["code"], code, "{query}");
    }
    let defaults = permission_list(
        &app,
        BOB,
        json!({"messageBox":null,"limit":null,"offset":null,"createdAtOrder":null}),
    )
    .await;
    assert_eq!(defaults["totalCount"], 3);
    assert_eq!(defaults["permissions"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn permission_list_default_page_and_database_errors_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("list.sqlite");
    let app = MessageBox::open(&path, Arc::new(Policy(Decision::Free)), Limits::default())
        .await
        .unwrap();
    for n in 0..102 {
        set(&app, BOB, None, &format!("box-{n:03}"), 0).await;
    }
    let first = permission_list(&app, BOB, json!({})).await;
    assert_eq!(first["permissions"].as_array().unwrap().len(), 100);
    assert_eq!(first["totalCount"], 102);
    let second = permission_list(&app, BOB, json!({"offset":"100"})).await;
    assert_eq!(second["permissions"].as_array().unwrap().len(), 2);
    assert_eq!(second["totalCount"], 102);
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    sqlx::query(
        "UPDATE message_permissions SET recipient_fee=2147483648 WHERE message_box='box-000'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let failure = app
        .handle("/permissions/list", Some(&id(BOB)), &json!({}))
        .await;
    assert_eq!(failure.status, 500);
    assert_eq!(
        failure.body,
        json!({"status":"error","code":"ERR_LIST_PERMISSIONS_FAILED","description":"Failed to list permissions"})
    );
    sqlx::query("DROP TABLE message_permissions")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        app.handle("/permissions/list", Some(&id(BOB)), &json!({}))
            .await
            .body,
        failure.body
    );
}
