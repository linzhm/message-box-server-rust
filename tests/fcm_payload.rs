use message_box_server_rust::fcm_payload::build_fcm_message;
use serde_json::Value;
#[test]
fn payload_matches_executed_fixed_typescript_including_empty_originator() {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/fcm_payload_vectors.json")).unwrap();
    for case in cases["cases"].as_array().unwrap() {
        let input = &case["input"];
        let actual = build_fcm_message(
            input["token"].as_str().unwrap(),
            input["title"].as_str().unwrap(),
            input["messageId"].as_str().unwrap(),
            input.get("originator").and_then(Value::as_str),
        );
        assert_eq!(actual, case["output"], "{input}");
    }
}
