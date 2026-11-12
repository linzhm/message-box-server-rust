use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
};
use serde_json::json;
use std::sync::Arc;
const SENDER: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const RECIPIENT: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const OTHER: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
struct Fees(Option<i64>);
impl DeliveryPolicy for Fees {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        self.0.ok_or(PolicyError)
    }
}
struct Missing;
impl DeliveryPolicy for Missing {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
}
fn identity(key: &str) -> Identity {
    Identity::from_verified_key(key).unwrap()
}
async fn assert_no_delivery(app: &MessageBox) {
    for recipient in [RECIPIENT, OTHER] {
        let response = app
            .handle(
                "/listMessages",
                Some(&identity(recipient)),
                &json!({"messageBox":"inbox"}),
            )
            .await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["messages"], json!([]));
    }
}
async fn send(app: &MessageBox) -> (u16, serde_json::Value) {
    let response=app.handle("/sendMessage", Some(&identity(SENDER)), &json!({"message":{"recipient":[RECIPIENT,OTHER],"messageBox":"inbox","messageId":["fee-test-1","fee-test-2"],"body":"hi"}})).await;
    (response.status, response.body)
}
#[tokio::test]
async fn positive_and_unavailable_delivery_fees_fail_closed_before_fanout() {
    for (fee, status, code) in [
        (Some(7), 501, "ERR_PAYMENT_NOT_IMPLEMENTED"),
        (Some(-1), 503, "ERR_POLICY_UNAVAILABLE"),
        (Some(2_147_483_648), 503, "ERR_POLICY_UNAVAILABLE"),
        (None, 503, "ERR_POLICY_UNAVAILABLE"),
    ] {
        let app = MessageBox::memory(Arc::new(Fees(fee)), Limits::default())
            .await
            .unwrap();
        if fee == Some(7) {
            let quote = app
                .handle(
                    "/permissions/quote",
                    Some(&identity(SENDER)),
                    &json!({"recipient": RECIPIENT, "messageBox":"inbox"}),
                )
                .await;
            assert_eq!(quote.status, 200);
            assert_eq!(quote.body["quote"]["deliveryFee"], 7);
        }
        let (actual, body) = send(&app).await;
        assert_eq!(actual, status, "{fee:?}");
        assert_eq!(body["code"], code, "{fee:?}");
        assert_no_delivery(&app).await;
    }
    let app = MessageBox::memory(Arc::new(Missing), Limits::default())
        .await
        .unwrap();
    let (status, body) = send(&app).await;
    assert_eq!(status, 503);
    assert_eq!(body["code"], "ERR_POLICY_UNAVAILABLE");
    assert_no_delivery(&app).await;
}
#[tokio::test]
async fn zero_delivery_fee_allows_free_fanout() {
    let app = MessageBox::memory(Arc::new(Fees(Some(0))), Limits::default())
        .await
        .unwrap();
    assert_eq!(send(&app).await.0, 200);
    for recipient in [RECIPIENT, OTHER] {
        let response = app
            .handle(
                "/listMessages",
                Some(&identity(recipient)),
                &json!({"messageBox":"inbox"}),
            )
            .await;
        assert_eq!(response.body["messages"].as_array().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn blocked_recipient_takes_precedence_over_positive_server_fee() {
    let app = MessageBox::memory(Arc::new(Fees(Some(7))), Limits::default())
        .await
        .unwrap();
    let set = app
        .handle(
            "/permissions/set",
            Some(&identity(RECIPIENT)),
            &json!({"messageBox":"inbox","recipientFee":-1}),
        )
        .await;
    assert_eq!(set.status, 200);
    let (status, body) = send(&app).await;
    assert_eq!(status, 403);
    assert_eq!(body["code"], "ERR_DELIVERY_BLOCKED");
    assert_no_delivery(&app).await;
}
