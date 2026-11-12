use message_box_server_rust::authsocket_payload::{
    PayloadError, encode_event_payload, parse_event_payload,
};
use serde_json::Value;
#[test]
fn restricted_encoding_matches_fixed_server_source() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/authsocket_payload_vectors.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let input = &case["input"];
        let label = input["label"].as_str().unwrap();
        let data = if input["hasData"].as_bool().unwrap() {
            Some(&input["data"])
        } else {
            None
        };
        let result = encode_event_payload(
            input["eventName"].as_str().unwrap(),
            data,
            input["max"].as_u64().unwrap_or(1_048_576) as usize,
        );
        if label.ends_with("source-valid") {
            assert_eq!(result.unwrap_err(), PayloadError::Unsupported, "{label}");
        } else if case["error"].as_bool().unwrap() {
            assert_eq!(result.unwrap_err(), PayloadError::Invalid, "{label}");
        } else {
            let bytes = result.unwrap();
            assert_eq!(
                hex::encode(&bytes),
                case["encoded"].as_str().unwrap(),
                "{label}"
            );
            let decoded = parse_event_payload(&bytes, 1_048_576).unwrap();
            assert_eq!(
                decoded.event_name,
                case["decoded"]["eventName"].as_str().unwrap()
            );
            assert_eq!(decoded.data, case["decoded"].get("data").cloned());
        }
    }
}
#[test]
fn parsing_matches_fixed_source_for_supported_raw_payloads() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/authsocket_payload_vectors.json"
    ))
    .unwrap();
    for case in fixture["rawCases"].as_array().unwrap() {
        let bytes = hex::decode(case["input"]["hex"].as_str().unwrap()).unwrap();
        let result = parse_event_payload(&bytes, 1_048_576);
        if case["error"].as_bool().unwrap() {
            assert_eq!(
                result.unwrap_err(),
                PayloadError::Invalid,
                "{}",
                case["input"]["label"]
            );
        } else {
            let event = result.unwrap();
            assert_eq!(
                event.event_name,
                case["decoded"]["eventName"].as_str().unwrap()
            );
            assert_eq!(event.data, case["decoded"].get("data").cloned());
        }
    }
}
#[test]
fn source_node_count_boundary_is_enforced_for_the_whole_envelope() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/authsocket_payload_vectors.json"
    ))
    .unwrap();
    for case in fixture["countCases"].as_array().unwrap() {
        let count = case["count"].as_u64().unwrap() as usize;
        let data = Value::Array(vec![Value::Null; count]);
        let actual = encode_event_payload("n", Some(&data), 1_048_576);
        assert_eq!(
            actual.is_err(),
            case["error"].as_bool().unwrap(),
            "count={count}"
        );
    }
}

#[test]
fn rejects_invalid_configured_limit() {
    assert_eq!(
        encode_event_payload("event", None, 0),
        Err(PayloadError::Invalid)
    );
    assert_eq!(parse_event_payload(b"{}", 0), Err(PayloadError::Invalid));
    if usize::BITS > 53 {
        assert_eq!(
            encode_event_payload("event", None, usize::MAX),
            Err(PayloadError::Invalid)
        );
    }
}
#[test]
fn rejects_deep_or_wide_borrowed_data_before_cloning() {
    let mut nested = Value::Null;
    for _ in 0..40_000 {
        nested = Value::Array(vec![nested]);
    }
    assert_eq!(
        encode_event_payload("event", Some(&nested), 1_048_576),
        Err(PayloadError::Invalid)
    );
    // Consume this synthetic deeply nested value iteratively; dropping it
    // recursively is unrelated to the codec and could exhaust the test stack.
    while let Value::Array(mut entries) = nested {
        nested = entries.pop().unwrap();
    }
    let wide = Value::Array(vec![Value::Null; 100_001]);
    assert_eq!(
        encode_event_payload("event", Some(&wide), 1_048_576),
        Err(PayloadError::Invalid)
    );
}
