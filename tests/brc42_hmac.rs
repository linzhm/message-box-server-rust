use k256::SecretKey;
use message_box_server_rust::{
    auth_nonce::{HmacCheckError, NonceHmacRequest, NonceWallet, verify_nonce},
    brc42::{InvalidDerivedKey, create_hmac, verify_hmac},
};
use serde_json::Value;
fn secret(s: &str) -> SecretKey {
    let s = format!("{s:0>64}");
    SecretKey::from_slice(&hex::decode(s).unwrap()).unwrap()
}
fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect()
}
#[test]
fn macs_match_fixed_sdk_real_protowallet() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/hmac-sdk4.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let alice = secret(case["a"].as_str().unwrap());
        let bob = secret(case["b"].as_str().unwrap());
        let data = bytes(&case["data"]);
        let invoice = case["invoice"].as_str().unwrap();
        let expected = hex::decode(case["hmac"].as_str().unwrap()).unwrap();
        let actual = create_hmac(&alice, &bob.public_key(), invoice, &data).unwrap();
        assert_eq!(actual.as_slice(), expected);
        assert!(verify_hmac(&bob, &alice.public_key(), invoice, &data, &actual).unwrap());
        assert!(!verify_hmac(&bob, &alice.public_key(), invoice, b"tampered", &actual).unwrap());
        assert!(!verify_hmac(&bob, &alice.public_key(), "wrong invoice", &data, &actual).unwrap());
    }
}
struct TestWallet(SecretKey);
impl NonceWallet for TestWallet {
    type Error = InvalidDerivedKey;
    async fn create_hmac(&self, request: &NonceHmacRequest) -> Result<[u8; 32], Self::Error> {
        create_hmac(
            &self.0,
            &self.0.public_key(),
            &format!("2-server hmac-{}", request.key_id),
            &request.data,
        )
    }
    async fn verify_hmac(
        &self,
        request: &NonceHmacRequest,
        mac: &[u8; 32],
    ) -> Result<bool, HmacCheckError<Self::Error>> {
        verify_hmac(
            &self.0,
            &self.0.public_key(),
            &format!("2-server hmac-{}", request.key_id),
            &request.data,
            mac,
        )
        .map_err(HmacCheckError::Other)
    }
}
#[tokio::test]
async fn real_sdk_protowallet_nonce_verifies_through_rust_wallet_adapter() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/hmac-sdk4.json")).unwrap();
    let case = &fixture["cases"][1];
    assert_eq!(case["nonceVerified"], true);
    let wallet = TestWallet(secret(case["a"].as_str().unwrap()));
    assert!(
        verify_nonce(&wallet, case["nonce"].as_str().unwrap(), "self", None)
            .await
            .unwrap()
    );
}
