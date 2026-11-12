use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
};
use serde_json::Value;
use std::sync::Arc;
const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
struct Policy;
impl DeliveryPolicy for Policy {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
async fn assert_rejected(path: &str, raw: &str, code: &str) {
    let app = MessageBox::memory(Arc::new(Policy), Limits::default())
        .await
        .unwrap();
    let caller = Identity::from_verified_key(KEY).unwrap();
    let request: Value = serde_json::from_str(raw).unwrap();
    let response = app.handle(path, Some(&caller), &request).await;
    assert_eq!(response.status, 400, "{path}: {}", response.body);
    assert_eq!(response.body["code"], code);
}
#[tokio::test]
async fn decimal_just_below_one_is_not_an_integer_fee() {
    assert_rejected(
        "/permissions/set",
        r#"{"messageBox":"inbox","recipientFee":0.9999999999999999}"#,
        "ERR_INVALID_FEE_VALUE",
    )
    .await;
}
#[tokio::test]
async fn decimal_just_below_one_is_not_an_integer_limit() {
    assert_rejected(
        "/listMessages",
        r#"{"messageBox":"inbox","limit":0.9999999999999999}"#,
        "ERR_INVALID_LIMIT",
    )
    .await;
}
#[test]
fn json_float_parsing_matches_js_binary64_observations() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/js/number_rounding_vectors.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let raw = case["input"].as_str().unwrap();
        let number: Value = serde_json::from_str(raw).unwrap();
        let bits = number.as_f64().unwrap().to_bits();
        assert_eq!(
            format!("{bits:016x}"),
            case["bits"].as_str().unwrap(),
            "{raw}"
        );
    }
}
