use message_box_server_rust::{Identity, delivery_remittance::has_canonical_delivery_remittance};
use serde_json::{Value, json};
#[test]
fn matches_fixed_source_and_sdk_vectors() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/delivery_remittance_vectors.json"
    ))
    .unwrap();
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let sender = Identity::from_verified_key(case["sender"].as_str().unwrap()).unwrap();
        let actual = has_canonical_delivery_remittance(&case["output"], &sender);
        if case["output"]["outputIndex"].as_f64().is_some()
            && case["output"]["outputIndex"].as_i64().is_none()
            && case["output"]["outputIndex"].as_u64().is_none()
        {
            assert_eq!(actual, None, "case {i}");
        } else {
            assert_eq!(
                actual,
                Some(case["expected"].as_bool().unwrap()),
                "case {i}"
            );
        }
    }
}
#[test]
fn rejects_missing_metadata_wrong_types_and_sender_mismatch() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/delivery_remittance_vectors.json"
    ))
    .unwrap();
    let base = &fixture["cases"][0]["output"];
    let sender =
        Identity::from_verified_key(fixture["cases"][0]["sender"].as_str().unwrap()).unwrap();
    for path in [
        "/paymentRemittance/derivationPrefix",
        "/paymentRemittance/derivationSuffix",
        "/paymentRemittance/senderIdentityKey",
        "/protocol",
        "/outputIndex",
    ] {
        let mut output = base.clone();
        let (parent, key) = path.rsplit_once('/').unwrap();
        output
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert_eq!(
            has_canonical_delivery_remittance(&output, &sender),
            Some(false),
            "{path}"
        );
    }
    for (path, value) in [
        ("/outputIndex", json!("0")),
        ("/paymentRemittance/derivationSuffix", json!(null)),
        ("/paymentRemittance/senderIdentityKey", json!(false)),
    ] {
        let mut output = base.clone();
        *output.pointer_mut(path).unwrap() = value;
        assert_eq!(
            has_canonical_delivery_remittance(&output, &sender),
            Some(false),
            "{path}"
        );
    }
}
#[test]
fn floating_point_representations_are_unsupported() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/delivery_remittance_vectors.json"
    ))
    .unwrap();
    let sender =
        Identity::from_verified_key(fixture["cases"][0]["sender"].as_str().unwrap()).unwrap();
    let mut output = fixture["cases"][0]["output"].clone();
    for index in [json!(1.0), json!(-0.0)] {
        output["outputIndex"] = index;
        assert_eq!(has_canonical_delivery_remittance(&output, &sender), None);
    }
}
