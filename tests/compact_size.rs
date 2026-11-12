use message_box_server_rust::compact_size::decode_unsigned_compact_size;
use serde_json::{Value, json};
#[test]
fn matches_fixed_sdk_unsigned_reader() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/compact_size_vectors.json")).unwrap();
    for case in fixtures["cases"].as_array().unwrap() {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let actual = decode_unsigned_compact_size(&bytes)
            .map(|(value, consumed)| json!({"value":value,"consumed":consumed}))
            .unwrap_or(Value::Null);
        assert_eq!(actual, case["expected"], "{}", case["hex"]);
    }
}
