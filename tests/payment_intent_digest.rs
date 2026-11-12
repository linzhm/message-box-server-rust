use message_box_server_rust::payment_intent_digest::compute_digest;
use serde_json::{Value, json};
#[test]
fn matches_exact_fixed_typescript_digest_and_preimage() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/payment_intent_digest_vectors.json"
    ))
    .unwrap();
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let actual = compute_digest(&case["input"]).unwrap();
        assert_eq!(
            actual.preimage,
            case["preimage"].as_str().unwrap(),
            "case {index}"
        );
        assert_eq!(
            actual.sha256_hex,
            case["digest"].as_str().unwrap(),
            "case {index}"
        );
    }
}
#[test]
fn rejects_unrepresented_or_incompatible_fields_without_silent_dropping() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/payment_intent_digest_vectors.json"
    ))
    .unwrap();
    let base = &fixture["cases"][0]["input"];
    for (path, value) in [
        ("/payment/extra", json!(1)),
        ("/payment/outputs/0/customInstructions", json!({"a":1})),
        (
            "/payment/outputs/0/paymentRemittance/customInstructions",
            json!([1]),
        ),
        (
            "/payment/outputs/0/insertionRemittance",
            json!({"basket":"x"}),
        ),
        ("/payment/outputs/0/extra", json!(1)),
        ("/extra", json!(1)),
    ] {
        let mut candidate = base.clone();
        let (parent, key) = path.rsplit_once('/').unwrap();
        candidate
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(key.into(), value);
        assert!(compute_digest(&candidate).is_err(), "{path}");
    }
    for (key, value) in [
        ("labels", Value::Null),
        ("labels", json!([1])),
        ("seekPermission", json!(3)),
        ("seekPermission", json!("true")),
    ] {
        let mut candidate = base.clone();
        candidate["payment"]
            .as_object_mut()
            .unwrap()
            .insert(key.into(), value);
        assert!(compute_digest(&candidate).is_err(), "{key}");
    }
    for (path, value) in [
        ("/payment/outputs/0/outputIndex", json!(9007199254740992u64)),
        ("/payment/outputs/0/outputIndex", json!(-1)),
        ("/payment/outputs/0/protocol", json!("basket insertion")),
        ("/payment/tx", json!([256])),
        ("/payment/description", json!(12)),
        ("/message/body", json!({"x":1})),
        ("/message/recipients", json!([])),
    ] {
        let mut candidate = base.clone();
        *candidate.pointer_mut(path).unwrap() = value;
        assert!(compute_digest(&candidate).is_err(), "{path}");
    }
}
#[tokio::test]
async fn digest_binds_distinct_requests_in_offline_intent_store() {
    use message_box_server_rust::payment_intents::{
        Binding, IntentError, SqlitePaymentIntentStore,
    };
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/payment_intent_digest_vectors.json"
    ))
    .unwrap();
    let first = &fixture["cases"][0]["input"];
    let mut changed = first.clone();
    changed["message"]["messageIds"][0] = json!("changed");
    let digest = compute_digest(first).unwrap().sha256_hex;
    let changed_digest = compute_digest(&changed).unwrap().sha256_hex;
    assert_ne!(digest, changed_digest);
    let dir = tempfile::tempdir().unwrap();
    let store = SqlitePaymentIntentStore::open(dir.path().join("intents.sqlite"))
        .await
        .unwrap();
    let binding = Binding {
        transaction_id: "abc123".into(),
        request_digest: digest,
        attempt_token: "test-only-token".into(),
    };
    store.prepare(&binding).await.unwrap();
    let other = Binding {
        request_digest: changed_digest,
        attempt_token: "other-token".into(),
        ..binding
    };
    assert!(matches!(
        store.prepare(&other).await,
        Err(IntentError::DifferentRequest)
    ));
}

#[test]
fn absent_and_null_optional_values_are_distinct() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/payment_intent_digest_vectors.json"
    ))
    .unwrap();
    let base = &fixture["cases"][0]["input"];
    let mut absent = base.clone();
    absent["payment"]
        .as_object_mut()
        .unwrap()
        .remove("description");
    let mut explicit_null = absent.clone();
    explicit_null["payment"]["description"] = Value::Null;
    assert_ne!(
        compute_digest(&absent).unwrap().sha256_hex,
        compute_digest(&explicit_null).unwrap().sha256_hex
    );
}
