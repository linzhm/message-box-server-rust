use message_box_server_rust::websocket_policy::{
    authenticated_identity, is_identity_owned_room, message_box_from_recipient_room,
};
use serde_json::Value;

#[test]
fn matches_fixed_typescript_identity_and_room_observations() {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/websocket_policy_vectors.json")).unwrap();
    for case in cases["claims"].as_array().unwrap() {
        let input = &case["input"];
        let result = authenticated_identity(input.get("transport"), input.get("claim"));
        if let Some(expected) = case.get("error").and_then(Value::as_str) {
            assert_eq!(result.unwrap_err(), expected, "{input}");
        } else {
            assert_eq!(result.unwrap(), case["result"].as_str().unwrap(), "{input}");
        }
    }
    let identity = cases["identity"].as_str().unwrap();
    for case in cases["rooms"].as_array().unwrap() {
        assert_eq!(
            is_identity_owned_room(identity, Some(&case["room"])),
            case["owned"].as_bool().unwrap(),
            "{}",
            case["room"]
        );
        assert_eq!(
            message_box_from_recipient_room(identity, Some(&case["room"])).as_deref(),
            case["box"].as_str(),
            "{}",
            case["room"]
        );
    }
    for case in cases["recipients"].as_array().unwrap() {
        assert_eq!(
            message_box_from_recipient_room(
                case["recipient"].as_str().unwrap(),
                Some(&case["room"])
            )
            .as_deref(),
            case["box"].as_str(),
            "{}",
            case["recipient"]
        );
    }
}
