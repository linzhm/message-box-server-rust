use message_box_server_rust::{Identity, brc29_recipient_script::derive_recipient_script};
use serde_json::Value;
#[test]
fn matches_fixed_sdk_anyone_wallet_and_p2pkh_vectors() {
    let f: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/brc29_recipient_script_vectors.json"
    ))
    .unwrap();
    assert_eq!(
        f["anyone"],
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    for c in f["cases"].as_array().unwrap() {
        let recipient = Identity::from_verified_key(c["recipient"].as_str().unwrap()).unwrap();
        let result = derive_recipient_script(
            &recipient,
            c["prefix"].as_str().unwrap(),
            c["suffix"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(result.public_key, c["publicKey"].as_str().unwrap());
        assert_eq!(
            hex::encode(result.locking_script),
            c["script"].as_str().unwrap()
        );
    }
}
#[test]
fn rejects_noncanonical_or_oversized_tokens() {
    let f: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/brc29_recipient_script_vectors.json"
    ))
    .unwrap();
    let recipient =
        Identity::from_verified_key(f["cases"][0]["recipient"].as_str().unwrap()).unwrap();
    for token in ["", "AA=", "AB==", "AA==\n", &"A".repeat(132)] {
        assert!(derive_recipient_script(&recipient, token, "AQ==").is_err());
        assert!(derive_recipient_script(&recipient, "AQ==", token).is_err());
    }
}
