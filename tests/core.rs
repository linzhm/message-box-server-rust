use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
};
use serde_json::{Value, json};
use std::sync::Arc;

const ALICE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const BOB: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const CAROL: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
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
async fn service() -> MessageBox {
    MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap()
}
fn send(to: Value, ids: Value) -> Value {
    json!({"message":{"recipient":to,"messageBox":"inbox","messageId":ids,"body":"hello"}})
}

#[tokio::test]
async fn send_list_ack_is_recipient_scoped() {
    let app = service().await;
    let sent = app
        .handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!(BOB), json!("m1")),
        )
        .await;
    assert_eq!(sent.status, 200);
    assert_eq!(
        sent.body,
        json!({"status":"success","message":"Your message has been sent to 1 recipient(s).","results":[{"recipient":BOB,"messageId":"m1"}]})
    );
    let listed = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(listed.status, 200);
    assert_eq!(
        listed.body["messages"][0]["body"],
        "{\"message\":\"hello\"}"
    );
    assert_eq!(listed.body["messages"][0]["sender"], ALICE);
    let stolen = app
        .handle(
            "/acknowledgeMessage",
            Some(&id(CAROL)),
            &json!({"messageIds":["m1"]}),
        )
        .await;
    assert_eq!(stolen.body["code"], "ERR_INVALID_ACKNOWLEDGMENT");
    assert_eq!(
        app.handle(
            "/acknowledgeMessage",
            Some(&id(BOB)),
            &json!({"messageIds":["m1","m1","missing"]})
        )
        .await
        .status,
        200
    );
    let again = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(again.body["messages"], json!([]));
}

#[tokio::test]
async fn unauthenticated_calls_and_unimplemented_routes_fail_explicitly() {
    let app = service().await;
    for (path, code) in [
        ("/sendMessage", "ERR_AUTH_REQUIRED"),
        ("/listMessages", "ERR_AUTHENTICATION_REQUIRED"),
        ("/acknowledgeMessage", "ERR_AUTHENTICATION_REQUIRED"),
    ] {
        let response = app.handle(path, None, &json!({})).await;
        assert_eq!(response.status, 401);
        assert_eq!(response.body["code"], code);
    }
    assert_eq!(
        app.handle("/unknown", Some(&id(ALICE)), &json!({}))
            .await
            .status,
        501
    );
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &json!([]))
            .await
            .body["code"],
        "ERR_INVALID_REQUEST_DATA"
    );
}

#[tokio::test]
async fn multi_recipient_conflict_rolls_back_every_insert() {
    let app = service().await;
    assert_eq!(
        app.handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!(BOB), json!("exists"))
        )
        .await
        .status,
        200
    );
    let response = app
        .handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!([CAROL, BOB]), json!(["would-be-new", "exists"])),
        )
        .await;
    assert_eq!(response.body["code"], "ERR_DUPLICATE_MESSAGE");
    let listed = app
        .handle(
            "/listMessages",
            Some(&id(CAROL)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(listed.body["messages"], json!([]));
    // IDs are globally unique, not just scoped to a recipient or box.
    assert_eq!(
        app.handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!(CAROL), json!("exists"))
        )
        .await
        .body["code"],
        "ERR_DUPLICATE_MESSAGE"
    );
    assert_eq!(
        app.handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!([BOB, CAROL]), json!(["same", "same"]))
        )
        .await
        .body["code"],
        "ERR_DUPLICATE_MESSAGE"
    );
    assert_eq!(
        app.handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!(CAROL), json!("same"))
        )
        .await
        .status,
        200
    );
}

#[tokio::test]
async fn recipient_aliases_normalize_keys_and_reject_duplicates() {
    let app = service().await;
    let mut request = send(json!(BOB), json!("upper"));
    request["message"]["recipients"] = json!([format!(" {} ", CAROL.to_uppercase())]);
    let result = app.handle("/sendMessage", Some(&id(ALICE)), &request).await;
    assert_eq!(result.body["results"][0]["recipient"], CAROL);
    request["message"]["recipients"] = Value::Null;
    request["message"]["messageId"] = json!("fallback");
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &request)
            .await
            .body["results"][0]["recipient"],
        BOB
    );
    let request = send(json!([BOB, BOB.to_uppercase()]), json!(["a", "b"]));
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &request)
            .await
            .body["code"],
        "ERR_DUPLICATE_RECIPIENT"
    );
}

#[test]
fn identity_canonicalization_is_curve_checked_not_authentication() {
    assert_eq!(id(&ALICE.to_uppercase()).as_str(), ALICE);
    let uncompressed = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    assert_eq!(id(uncompressed).as_str(), ALICE);
    assert!(Identity::from_verified_key(&format!("02{}", "00".repeat(32))).is_err());
    assert!(Identity::from_verified_key("not a key").is_err());
}

#[tokio::test]
async fn message_validation_uses_byte_limits_and_exact_text() {
    let app = service().await;
    let cases = [
        ("messageBox", json!(" "), "ERR_INVALID_MESSAGEBOX"),
        ("messageBox", json!("inbox "), "ERR_INVALID_MESSAGEBOX"),
        ("messageBox", json!("x\u{0085}x"), "ERR_INVALID_MESSAGEBOX"),
        (
            "messageBox",
            json!("\u{feff}inbox"),
            "ERR_INVALID_MESSAGEBOX",
        ),
        (
            "messageBox",
            json!("信".repeat(43)),
            "ERR_MESSAGEBOX_TOO_LARGE",
        ),
        ("body", json!(" \u{feff}"), "ERR_INVALID_MESSAGE_BODY"),
        ("body", json!(42), "ERR_INVALID_MESSAGE_BODY"),
        (
            "body",
            json!("信".repeat(349_526)),
            "ERR_MESSAGE_BODY_TOO_LARGE",
        ),
        ("recipient", json!([]), "ERR_TOO_MANY_RECIPIENTS"),
        (
            "recipient",
            json!(vec![BOB; 101]),
            "ERR_TOO_MANY_RECIPIENTS",
        ),
        ("recipient", json!("bad"), "ERR_INVALID_RECIPIENT_KEY"),
        ("messageId", json!(" x"), "ERR_INVALID_MESSAGEID"),
        ("messageId", json!("x\u{007f}"), "ERR_INVALID_MESSAGEID"),
        ("messageId", json!("界".repeat(86)), "ERR_INVALID_MESSAGEID"),
        ("messageId", json!([]), "ERR_MESSAGEID_COUNT_MISMATCH"),
    ];
    for (field, value, code) in cases {
        let mut request = send(json!(BOB), json!("valid"));
        request["message"][field] = value;
        let response = app.handle("/sendMessage", Some(&id(ALICE)), &request).await;
        assert_eq!(response.body["code"], code, "field={field}");
    }
    let mut request = send(json!(BOB), json!("edge"));
    request["message"]["messageBox"] = json!("a".repeat(128));
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &request)
            .await
            .status,
        200
    );
    assert_eq!(
        app.handle("/sendMessage", Some(&id(ALICE)), &json!({}))
            .await
            .body["code"],
        "ERR_MESSAGE_REQUIRED"
    );
}

struct Policy {
    blocked: Option<&'static str>,
    decision: Decision,
    unavailable: bool,
}
impl DeliveryPolicy for Policy {
    fn evaluate(&self, _: &Identity, recipient: &str, _: &str) -> Result<Decision, PolicyError> {
        if self.unavailable {
            Err(PolicyError)
        } else if self.blocked == Some(recipient) {
            Ok(Decision::Blocked)
        } else {
            Ok(self.decision)
        }
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
#[tokio::test]
async fn policy_block_payment_and_failure_never_store_messages() {
    for (policy, code) in [
        (
            Policy {
                blocked: Some(CAROL),
                decision: Decision::Free,
                unavailable: false,
            },
            "ERR_DELIVERY_BLOCKED",
        ),
        (
            Policy {
                blocked: None,
                decision: Decision::PaymentRequired,
                unavailable: false,
            },
            "ERR_PAYMENT_NOT_IMPLEMENTED",
        ),
        (
            Policy {
                blocked: None,
                decision: Decision::Free,
                unavailable: true,
            },
            "ERR_POLICY_UNAVAILABLE",
        ),
    ] {
        let app = MessageBox::memory(Arc::new(policy), Limits::default())
            .await
            .unwrap();
        let result = app
            .handle(
                "/sendMessage",
                Some(&id(ALICE)),
                &send(json!([BOB, CAROL]), json!(["one", "two"])),
            )
            .await;
        assert_eq!(result.body["code"], code);
        assert_eq!(
            app.handle(
                "/listMessages",
                Some(&id(BOB)),
                &json!({"messageBox":"inbox"})
            )
            .await
            .body["messages"],
            json!([])
        );
    }
    let app = service().await;
    for payment in [Value::Null, json!({}), json!({"tx":[0],"outputs":[]})] {
        let mut request = send(json!(BOB), json!("payment"));
        request["payment"] = payment;
        assert_eq!(
            app.handle("/sendMessage", Some(&id(ALICE)), &request)
                .await
                .body["code"],
            "ERR_PAYMENT_NOT_IMPLEMENTED"
        );
    }
    assert_eq!(
        app.handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"})
        )
        .await
        .body["messages"],
        json!([])
    );
}

#[tokio::test]
async fn pagination_filters_and_validation_match_the_supported_contract() {
    let app = service().await;
    for number in 0..3 {
        assert_eq!(
            app.handle(
                "/sendMessage",
                Some(&id(ALICE)),
                &send(json!(BOB), json!(format!("m{number}")))
            )
            .await
            .status,
            200
        );
    }
    let first = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox","limit":1}),
        )
        .await;
    assert_eq!(first.body["messages"].as_array().unwrap().len(), 1);
    assert_eq!(first.body["hasMore"], true);
    assert_eq!(first.body["nextOffset"], 1);
    let second = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox","limit":2.0,"skip":1,"offset":1.0}),
        )
        .await;
    assert_eq!(second.body["messages"].as_array().unwrap().len(), 2);
    assert_eq!(second.body["hasMore"], false);
    assert_eq!(second.body["nextOffset"], 3);
    let filtered = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox","messageId":"m2"}),
        )
        .await;
    assert_eq!(filtered.body["messages"].as_array().unwrap().len(), 1);
    assert_eq!(filtered.body["messages"][0]["messageId"], "m2");
    let absent = app
        .handle(
            "/listMessages",
            Some(&id(CAROL)),
            &json!({"messageBox":"missing","offset":100}),
        )
        .await;
    assert_eq!(
        absent.body,
        json!({"status":"success","messages":[],"offset":100,"nextOffset":100,"limit":1000,"hasMore":false})
    );
    for (input, code) in [
        (json!({"messageBox":"inbox","limit":0}), "ERR_INVALID_LIMIT"),
        (
            json!({"messageBox":"inbox","limit":"1"}),
            "ERR_INVALID_LIMIT",
        ),
        (
            json!({"messageBox":"inbox","limit":1001}),
            "ERR_INVALID_LIMIT",
        ),
        (
            json!({"messageBox":"inbox","limit":1.5}),
            "ERR_INVALID_LIMIT",
        ),
        (
            json!({"messageBox":"inbox","offset":-1}),
            "ERR_INVALID_OFFSET",
        ),
        (
            json!({"messageBox":"inbox","offset":100001}),
            "ERR_INVALID_OFFSET",
        ),
        (
            json!({"messageBox":"inbox","offset":1,"skip":2}),
            "ERR_INVALID_OFFSET",
        ),
        (
            json!({"messageBox":"inbox","messageId":null}),
            "ERR_INVALID_MESSAGE_ID",
        ),
        (json!({"messageBox":"\u{feff}"}), "ERR_MESSAGEBOX_REQUIRED"),
        (json!({"messageBox":true}), "ERR_INVALID_MESSAGEBOX"),
        (json!({"messageBox":"x\n"}), "ERR_INVALID_MESSAGEBOX"),
    ] {
        assert_eq!(
            app.handle("/listMessages", Some(&id(BOB)), &input)
                .await
                .body["code"],
            code,
            "{input}"
        );
    }
}

#[tokio::test]
async fn acknowledgment_validates_the_entire_batch_before_deleting() {
    let app = service().await;
    app.handle(
        "/sendMessage",
        Some(&id(ALICE)),
        &send(json!(BOB), json!("retain")),
    )
    .await;
    for (ids, code) in [
        (Value::Null, "ERR_MESSAGE_ID_REQUIRED"),
        (json!([]), "ERR_MESSAGE_ID_REQUIRED"),
        (json!("retain"), "ERR_INVALID_MESSAGE_ID"),
        (json!(["retain", "bad\n"]), "ERR_INVALID_MESSAGE_ID"),
        (json!(["retain", 3]), "ERR_INVALID_MESSAGE_ID"),
        (json!(vec!["retain"; 1001]), "ERR_INVALID_MESSAGE_ID"),
    ] {
        assert_eq!(
            app.handle(
                "/acknowledgeMessage",
                Some(&id(BOB)),
                &json!({"messageIds":ids})
            )
            .await
            .body["code"],
            code
        );
    }
    assert_eq!(
        app.handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"})
        )
        .await
        .body["messages"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn sender_and_inbox_quotas_are_atomic() {
    let app = MessageBox::memory(
        Arc::new(Free),
        Limits {
            max_sender_messages: 1,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    let result = app
        .handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!([BOB, CAROL]), json!(["one", "two"])),
        )
        .await;
    assert_eq!(result.status, 429);
    assert_eq!(result.body["code"], "ERR_SENDER_QUOTA_EXCEEDED");
    assert_eq!(
        app.handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"})
        )
        .await
        .body["messages"],
        json!([])
    );
    let app = MessageBox::memory(
        Arc::new(Free),
        Limits {
            max_inbox_messages: 1,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    app.handle(
        "/sendMessage",
        Some(&id(ALICE)),
        &send(json!(CAROL), json!("full")),
    )
    .await;
    let result = app
        .handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!([BOB, CAROL]), json!(["first", "second"])),
        )
        .await;
    assert_eq!(result.body["code"], "ERR_INBOX_QUOTA_EXCEEDED");
    assert_eq!(
        app.handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"})
        )
        .await
        .body["messages"],
        json!([])
    );
    // Byte accounting is based on the stored envelope, not the plaintext alone.
    let app = MessageBox::memory(
        Arc::new(Free),
        Limits {
            max_inbox_bytes: 18,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    let result = app
        .handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!(BOB), json!("bytes")),
        )
        .await;
    assert_eq!(result.body["resource"], "bytes");
}

#[tokio::test]
async fn listing_respects_response_budget_and_never_skips_oversize_oldest() {
    let app = MessageBox::memory(
        Arc::new(Free),
        Limits {
            max_list_response_bytes: 256,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    app.handle(
        "/sendMessage",
        Some(&id(ALICE)),
        &send(json!(BOB), json!("oversize")),
    )
    .await;
    let result = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(result.status, 413);
    assert_eq!(result.body["code"], "ERR_MESSAGE_RESPONSE_TOO_LARGE");
    let app = MessageBox::memory(
        Arc::new(Free),
        Limits {
            max_list_response_bytes: 600,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    for id_ in ["one", "two"] {
        app.handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!(BOB), json!(id_)),
        )
        .await;
    }
    let first = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(first.body["messages"].as_array().unwrap().len(), 1);
    assert_eq!(first.body["hasMore"], true);
    assert_eq!(first.body["nextOffset"], 1);
}

#[tokio::test]
async fn sqlite_survives_close_and_reopen_and_expiry_releases_quota() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("messages.sqlite");
    let limits = Limits {
        max_inbox_messages: 1,
        ..Limits::default()
    };
    let app = MessageBox::open(&path, Arc::new(Free), limits.clone())
        .await
        .unwrap();
    app.handle(
        "/sendMessage",
        Some(&id(ALICE)),
        &send(json!(BOB), json!("durable")),
    )
    .await;
    app.close().await;
    let app = MessageBox::open(&path, Arc::new(Free), limits)
        .await
        .unwrap();
    assert_eq!(
        app.handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"})
        )
        .await
        .body["messages"][0]["messageId"],
        "durable"
    );
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("UPDATE messages SET expires_at=0 WHERE message_id='durable'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        app.handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"})
        )
        .await
        .body["messages"],
        json!([])
    );
    assert_eq!(
        app.handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!(BOB), json!("new"))
        )
        .await
        .status,
        200
    );
    assert_eq!(app.purge_expired().await.unwrap(), 1);
    assert_eq!(app.purge_expired().await.unwrap(), 0);
    assert_eq!(
        app.handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"})
        )
        .await
        .body["messages"][0]["messageId"],
        "new"
    );
    pool.close().await;
    app.close().await;
}

#[tokio::test]
async fn deterministic_tie_order_and_box_isolation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("messages.sqlite");
    let app = MessageBox::open(&path, Arc::new(Free), Limits::default())
        .await
        .unwrap();
    for id_ in ["z", "a"] {
        app.handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!(BOB), json!(id_)),
        )
        .await;
    }
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("UPDATE messages SET created_at='2026-11-10T00:00:00.000Z'")
        .execute(&pool)
        .await
        .unwrap();
    let result = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(result.body["messages"][0]["messageId"], "a");
    assert_eq!(
        app.handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"outbox"})
        )
        .await
        .body["messages"],
        json!([])
    );
    pool.close().await;
    app.close().await;
}

#[tokio::test]
async fn concurrent_duplicate_send_has_one_winner() {
    let app = service().await;
    let alice = id(ALICE);
    let request = send(json!(BOB), json!("once"));
    let (a, b) = tokio::join!(
        app.handle("/sendMessage", Some(&alice), &request),
        app.handle("/sendMessage", Some(&alice), &request)
    );
    let mut statuses = [a.status, b.status];
    statuses.sort();
    assert_eq!(statuses, [200, 400]);
    let result = app
        .handle(
            "/listMessages",
            Some(&id(BOB)),
            &json!({"messageBox":"inbox"}),
        )
        .await;
    assert_eq!(result.body["messages"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn invalid_configuration_is_rejected_before_open() {
    assert!(
        MessageBox::memory(
            Arc::new(Free),
            Limits {
                default_list_limit: 1001,
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
                retention_days: 0,
                ..Limits::default()
            }
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn validation_and_blocks_take_precedence_over_unsupported_payment() {
    let app = service().await;
    let invalid = app
        .handle("/sendMessage", Some(&id(ALICE)), &json!({"payment":null}))
        .await;
    assert_eq!(invalid.status, 400);
    assert_eq!(invalid.body["code"], "ERR_MESSAGE_REQUIRED");
    let app = MessageBox::memory(
        Arc::new(Policy {
            blocked: Some(CAROL),
            decision: Decision::PaymentRequired,
            unavailable: false,
        }),
        Limits::default(),
    )
    .await
    .unwrap();
    let mixed = app
        .handle(
            "/sendMessage",
            Some(&id(ALICE)),
            &send(json!([BOB, CAROL]), json!(["fee", "block"])),
        )
        .await;
    assert_eq!(mixed.status, 403);
    assert_eq!(mixed.body["code"], "ERR_DELIVERY_BLOCKED");
    assert_eq!(mixed.body["blockedRecipients"], json!([CAROL]));
    for key in [BOB, CAROL] {
        assert_eq!(
            app.handle(
                "/listMessages",
                Some(&id(key)),
                &json!({"messageBox":"inbox"})
            )
            .await
            .body["messages"],
            json!([])
        );
    }
}

#[tokio::test]
async fn list_array_body_matches_ts_missing_message_box_after_authentication() {
    let app = service().await;
    for body in [json!([]), json!([0, 1, 255]), json!(["x", 256, {}])] {
        let response = app.handle("/listMessages", Some(&id(ALICE)), &body).await;
        assert_eq!(response.status, 400);
        assert_eq!(
            response.body,
            json!({"status":"error","code":"ERR_MESSAGEBOX_REQUIRED","description":"Please provide the name of a valid MessageBox!"})
        );
        let unsigned = app.handle("/listMessages", None, &body).await;
        assert_eq!(unsigned.status, 401);
        assert_eq!(unsigned.body["code"], "ERR_AUTHENTICATION_REQUIRED");
    }
}
