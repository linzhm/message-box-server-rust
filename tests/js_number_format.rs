//! Representative Node parsing and ECMAScript formatting checks, no listener.
use serde_json::Value;

#[test]
fn locked_parser_and_js_formatter_match_node_samples() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/js-number-vectors.json")).unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 19);
    for vector in vectors {
        let raw = vector["raw"].as_str().unwrap();
        let number: Value = serde_json::from_str(raw).unwrap();
        let value = number.as_f64().unwrap();
        assert_eq!(
            format!("{:016x}", value.to_bits()),
            vector["bits"].as_str().unwrap(),
            "bits for {raw}"
        );
        assert_eq!(
            ryu_js::Buffer::new().format_finite(value),
            vector["json"].as_str().unwrap(),
            "format for {raw}"
        );
    }
}
