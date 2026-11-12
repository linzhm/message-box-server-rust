use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
};
use serde_json::{Value, json};
use std::sync::Arc;
const A: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const B: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const C: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
struct Policy(Option<i64>);
impl DeliveryPolicy for Policy {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        self.0.ok_or(PolicyError)
    }
}
fn id(s: &str) -> Identity {
    Identity::from_verified_key(s).unwrap()
}
async fn app(fee: Option<i64>) -> MessageBox {
    MessageBox::memory(Arc::new(Policy(fee)), Limits::default())
        .await
        .unwrap()
}
async fn quote(app: &MessageBox, sender: Option<&Identity>, q: Value) -> (u16, Value) {
    let r = app
        .dispatch_http("GET", "/permissions/quote", sender, &q, &json!({}))
        .await
        .unwrap();
    (r.status, r.body)
}
#[tokio::test]
async fn quote_single_and_multiple_use_effective_recipient_fees_and_server_fee() {
    let app = app(Some(7)).await;
    for (owner, fee) in [(B, -1), (C, 23)] {
        assert_eq!(
            app.handle(
                "/permissions/set",
                Some(&id(owner)),
                &json!({"messageBox":"inbox","recipientFee":fee})
            )
            .await
            .status,
            200
        );
    }
    let alice = id(A);
    for recipient in [json!(B), json!([B])] {
        assert_eq!(
            quote(
                &app,
                Some(&alice),
                json!({"recipient":recipient,"messageBox":"inbox"})
            )
            .await,
            (
                200,
                json!({"status":"success","description":"Message delivery quote generated.","quote":{"deliveryFee":7,"recipientFee":-1}})
            )
        );
    }
    let (_, result) = quote(
        &app,
        Some(&alice),
        json!({"recipient":[B,C],"messageBox":"inbox"}),
    )
    .await;
    assert_eq!(
        result,
        json!({"status":"success","description":"Message delivery quotes generated for 2 recipients.","quotesByRecipient":[{"recipient":B,"messageBox":"inbox","deliveryFee":7,"recipientFee":-1,"status":"blocked"},{"recipient":C,"messageBox":"inbox","deliveryFee":7,"recipientFee":23,"status":"payment_required"}],"blockedRecipients":[B],"totals":{"deliveryFees":14,"recipientFees":23,"totalForPayableRecipients":37}})
    );
    assert_eq!(
        quote(
            &app,
            Some(&alice),
            json!({"recipient":B,"messageBox":"notifications"})
        )
        .await
        .1["quote"]["recipientFee"],
        10
    );
}
#[tokio::test]
async fn quote_validation_precedes_fee_lookup_and_reports_precise_errors() {
    let app = app(None).await;
    let alice = id(A);
    let cases = [
        (json!({}), "ERR_MISSING_PARAMETERS"),
        (
            json!({"recipient":B,"messageBox":" inbox"}),
            "ERR_INVALID_MESSAGE_BOX",
        ),
        (
            json!({"recipient":[],"messageBox":"inbox"}),
            "ERR_MISSING_PARAMETERS",
        ),
        (
            json!({"recipient":vec![B;101],"messageBox":"inbox"}),
            "ERR_TOO_MANY_RECIPIENTS",
        ),
        (
            json!({"recipient":["bad",B,"oops"],"messageBox":"inbox"}),
            "ERR_INVALID_PUBLIC_KEY",
        ),
        (
            json!({"recipient":[B,B.to_uppercase()],"messageBox":"inbox"}),
            "ERR_DUPLICATE_RECIPIENT",
        ),
    ];
    assert_eq!(
        quote(&app, None, json!({})).await.1["code"],
        "ERR_AUTHENTICATION_REQUIRED"
    );
    for (request, code) in cases {
        let r = quote(&app, Some(&alice), request).await;
        assert_eq!(r.0, 400);
        assert_eq!(r.1["code"], code);
    }
    let bad = quote(
        &app,
        Some(&alice),
        json!({"recipient":["bad",B,"oops"],"messageBox":"inbox"}),
    )
    .await;
    assert_eq!(
        bad.1["description"],
        "Invalid recipient public key at index(es): 0, 2."
    );
    assert_eq!(
        quote(
            &app,
            Some(&alice),
            json!({"recipient":B,"messageBox":"inbox"})
        )
        .await
        .1["code"],
        "ERR_INTERNAL"
    );
}

#[tokio::test]
async fn sender_override_and_fee_storage_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("quote.sqlite");
    let app = MessageBox::open(&path, Arc::new(Policy(Some(7))), Limits::default())
        .await
        .unwrap();
    for (sender, fee) in [(Value::Null, -1), (json!(A), 12)] {
        assert_eq!(
            app.handle(
                "/permissions/set",
                Some(&id(B)),
                &json!({"messageBox":"inbox", "sender":sender, "recipientFee":fee})
            )
            .await
            .status,
            200
        );
    }
    assert_eq!(
        quote(
            &app,
            Some(&id(A)),
            json!({"recipient":B, "messageBox":"inbox"})
        )
        .await
        .1["quote"]["recipientFee"],
        12
    );
    assert_eq!(
        quote(
            &app,
            Some(&id(C)),
            json!({"recipient":B, "messageBox":"inbox"})
        )
        .await
        .1["quote"]["recipientFee"],
        -1
    );
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    sqlx::query("UPDATE message_permissions SET recipient_fee = -2")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        quote(
            &app,
            Some(&id(A)),
            json!({"recipient":B, "messageBox":"inbox"})
        )
        .await
        .1["code"],
        "ERR_INTERNAL"
    );
    sqlx::query("DROP TABLE message_permissions")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        quote(
            &app,
            Some(&id(A)),
            json!({"recipient":B, "messageBox":"inbox"})
        )
        .await
        .1["code"],
        "ERR_INTERNAL"
    );
}

#[tokio::test]
async fn invalid_server_fees_fail_closed() {
    for fee in [-1, 2_147_483_648] {
        let app = app(Some(fee)).await;
        let result = quote(
            &app,
            Some(&id(A)),
            json!({"recipient":B, "messageBox":"inbox"}),
        )
        .await;
        assert_eq!(result.0, 500);
        assert_eq!(result.1["code"], "ERR_INTERNAL");
    }
}

#[tokio::test]
async fn quote_accepts_one_hundred_recipients_at_maximum_fees() {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let app = app(Some(2_147_483_647)).await;
    let mut recipients = Vec::new();
    for scalar in 1_u8..=100 {
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        let key = k256::SecretKey::from_slice(&bytes).unwrap().public_key();
        let key = hex::encode(key.to_encoded_point(true).as_bytes());
        let owner = id(&key);
        assert_eq!(
            app.handle(
                "/permissions/set",
                Some(&owner),
                &json!({"messageBox":"inbox","recipientFee":2_147_483_647_i64})
            )
            .await
            .status,
            200
        );
        recipients.push(key);
    }
    let result = quote(
        &app,
        Some(&id(A)),
        json!({"recipient":recipients,"messageBox":"inbox"}),
    )
    .await;
    assert_eq!(result.0, 200);
    assert_eq!(result.1["quotesByRecipient"].as_array().unwrap().len(), 100);
    assert_eq!(
        result.1["totals"],
        json!({"deliveryFees":214_748_364_700_i64,"recipientFees":214_748_364_700_i64,"totalForPayableRecipients":429_496_729_400_i64})
    );
}
