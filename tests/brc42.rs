use k256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use message_box_server_rust::brc42::{derive_private_child, derive_public_child};
use serde_json::Value;
fn secret(n: u8) -> SecretKey {
    let mut bytes = [0_u8; 32];
    bytes[31] = n;
    SecretKey::from_slice(&bytes).unwrap()
}
#[test]
fn derived_keys_match_executed_fixed_sdk_source() {
    let data: Value = serde_json::from_str(include_str!("fixtures/brc42-sdk4.json")).unwrap();
    for c in data["cases"].as_array().unwrap() {
        let a = secret(c["a"].as_u64().unwrap() as u8);
        let b = secret(c["b"].as_u64().unwrap() as u8);
        let alice_public = PublicKey::from_secret_scalar(&a.to_nonzero_scalar());
        let bob_public = PublicKey::from_secret_scalar(&b.to_nonzero_scalar());
        assert_eq!(
            hex::encode(alice_public.to_encoded_point(true).as_bytes()),
            c["alicePublic"]
        );
        assert_eq!(
            hex::encode(bob_public.to_encoded_point(true).as_bytes()),
            c["bobPublic"]
        );
        let invoice = c["invoice"].as_str().unwrap();
        let child = derive_private_child(&a, &bob_public, invoice).unwrap();
        assert_eq!(hex::encode(child.to_bytes()), c["derivedPrivate"]);
        let receiver_child = derive_public_child(&b, &alice_public, invoice).unwrap();
        assert_eq!(
            hex::encode(receiver_child.to_encoded_point(true).as_bytes()),
            c["receiverDerivedPublic"]
        );
        assert_eq!(
            hex::encode(child.public_key().to_encoded_point(true).as_bytes()),
            c["derivedPublic"]
        );
    }
}
