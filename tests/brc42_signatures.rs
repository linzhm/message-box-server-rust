use k256::SecretKey;
use message_box_server_rust::brc42::{sign_message, verify_message};
use serde_json::Value;
fn secret(s: &str) -> SecretKey {
    let s = format!("{s:0>64}");
    SecretKey::from_slice(&hex::decode(s).unwrap()).unwrap()
}
#[test]
fn signatures_match_fixed_sdk_and_reject_tampering() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/signature-sdk4.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let alice = secret(case["a"].as_str().unwrap());
        let bob = secret(case["b"].as_str().unwrap());
        let data: Vec<u8> = case["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        let invoice = case["invoice"].as_str().unwrap();
        let sdk = hex::decode(case["signature"].as_str().unwrap()).unwrap();
        let high = hex::decode(case["highSignature"].as_str().unwrap()).unwrap();
        let rust = sign_message(&alice, &bob.public_key(), invoice, &data).unwrap();
        assert_eq!(rust, sdk);
        assert!(verify_message(&bob, &alice.public_key(), invoice, &data, &sdk).unwrap());
        assert!(verify_message(&bob, &alice.public_key(), invoice, &data, &high).unwrap());
        assert!(!verify_message(&bob, &alice.public_key(), invoice, b"tampered", &sdk).unwrap());
        assert!(!verify_message(&secret("4"), &alice.public_key(), invoice, &data, &sdk).unwrap());
        assert!(!verify_message(&bob, &secret("5").public_key(), invoice, &data, &sdk).unwrap());
        assert!(!verify_message(&bob, &alice.public_key(), "wrong invoice", &data, &sdk).unwrap());
        assert!(!verify_message(&bob, &alice.public_key(), invoice, &data, b"not DER").unwrap());
    }
}
