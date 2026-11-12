use message_box_server_rust::legacy_delivery_amount::inspect_legacy_delivery_output;
use serde_json::{Value, json};
#[test]
fn supported_legacy_observations_match_fixed_source_and_sdk() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/legacy_delivery_amount_vectors.json"
    ))
    .unwrap();
    let (mut supported, mut yes, mut no, mut unsupported) = (0, 0, 0, 0);
    for case in fixture["cases"].as_array().unwrap() {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let output = json!({"protocol":"wallet payment","outputIndex":case["index"]});
        match inspect_legacy_delivery_output(&bytes, &output, case["fee"].as_u64().unwrap()) {
            Some(actual) => {
                supported += 1;
                if actual {
                    yes += 1
                } else {
                    no += 1
                };
                assert_eq!(
                    actual,
                    case["expected"].as_bool().unwrap(),
                    "{}",
                    case["label"]
                );
            }
            None => unsupported += 1,
        }
    }
    eprintln!("supported={supported}, true={yes}, false={no}, unsupported={unsupported}");
    assert!(
        supported >= 20 && yes >= 5 && no >= 5 && unsupported >= 1,
        "{supported}/{yes}/{no}/{unsupported}"
    );
}
#[test]
fn unrelated_original_transaction_is_not_normalized_into_acceptance() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/legacy_delivery_amount_vectors.json"
    ))
    .unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["label"] == "payment_subject_vectors.json:unrelated"
                && c["fee"] == 1
                && c["index"] == 0
        })
        .unwrap();
    assert_eq!(case["expected"], false);
    let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
    assert!(
        inspect_legacy_delivery_output(
            &bytes,
            &json!({"protocol":"wallet payment","outputIndex":0}),
            1
        )
        .is_none()
    );
}
#[test]
fn checks_index_protocol_and_safe_fee_boundaries_after_supported_parse() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/legacy_delivery_amount_vectors.json"
    ))
    .unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["label"] == "payment_subject_vectors.json:amount-exact"
                && c["fee"] == 100
                && c["index"] == 0
        })
        .unwrap();
    let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        inspect_legacy_delivery_output(
            &bytes,
            &json!({"protocol":"wallet payment","outputIndex":0}),
            100
        ),
        Some(true)
    );
    for output in [
        json!({"protocol":"basket insertion","outputIndex":0}),
        json!({"protocol":"wallet payment","outputIndex":-1}),
        json!({"protocol":"wallet payment","outputIndex":1}),
        json!({"protocol":"wallet payment"}),
    ] {
        assert_eq!(
            inspect_legacy_delivery_output(&bytes, &output, 1),
            Some(false)
        );
    }
    assert_eq!(
        inspect_legacy_delivery_output(
            &bytes,
            &json!({"protocol":"wallet payment","outputIndex":0.5}),
            1
        ),
        None
    );
    let valid = json!({"protocol":"wallet payment","outputIndex":0});
    assert_eq!(
        inspect_legacy_delivery_output(&bytes, &valid, 0),
        Some(false)
    );
    assert_eq!(
        inspect_legacy_delivery_output(&bytes, &valid, 9_007_199_254_740_992),
        Some(false)
    );
    assert_eq!(
        inspect_legacy_delivery_output(&bytes, &valid, 101),
        Some(false)
    );
}
