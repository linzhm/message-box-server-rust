use k256::SecretKey;
use message_box_server_rust::{
    auth_nonce::{NonceHmacRequest, NonceWallet, create_nonce, verify_nonce},
    auth_responder::AuthWallet,
    local_auth_wallet::LocalAuthWallet,
};
fn secret(n: u8) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    SecretKey::from_slice(&bytes).unwrap()
}
#[tokio::test]
async fn configured_distinct_identities_sign_and_verify_without_shared_keys() {
    let alice = LocalAuthWallet::new(secret(2));
    let bob = LocalAuthWallet::new(secret(3));
    let other = LocalAuthWallet::new(secret(4));
    let alice_key = alice.identity_key().await.unwrap();
    let bob_key = bob.identity_key().await.unwrap();
    assert_ne!(alice_key, bob_key);
    let signature = alice
        .sign_auth(&bob_key, "test-key-id", b"payload")
        .await
        .unwrap();
    assert!(
        bob.verify_auth(&alice_key, "test-key-id", b"payload", &signature)
            .await
            .unwrap()
    );
    assert!(
        !bob.verify_auth(&alice_key, "test-key-id", b"different", &signature)
            .await
            .unwrap()
    );
    assert!(
        !other
            .verify_auth(&alice_key, "test-key-id", b"payload", &signature)
            .await
            .unwrap()
    );
    assert!(alice.sign_auth("not-a-key", "id", b"data").await.is_err());
}
#[tokio::test]
async fn nonce_is_bound_to_its_wallet_and_unexpected_parameters_fail_closed() {
    let alice = LocalAuthWallet::new(secret(2));
    let bob = LocalAuthWallet::new(secret(3));
    let nonce = create_nonce(&alice, "self", None).await.unwrap();
    assert!(verify_nonce(&alice, &nonce, "self", None).await.unwrap());
    assert!(!verify_nonce(&bob, &nonce, "self", None).await.unwrap());
    let request = NonceHmacRequest {
        protocol_id: (2, "server hmac"),
        key_id: "k".into(),
        data: [1; 16],
        counterparty: "anyone".into(),
        originator: None,
    };
    assert!(alice.create_hmac(&request).await.is_err());
    let request = NonceHmacRequest {
        counterparty: "self".into(),
        originator: Some("untrusted".into()),
        ..request
    };
    assert!(alice.create_hmac(&request).await.is_err());
    assert!(alice.verify_hmac(&request, &[0; 32]).await.is_err());
    let request = NonceHmacRequest {
        protocol_id: (1, "server hmac"),
        originator: None,
        ..request
    };
    assert!(alice.create_hmac(&request).await.is_err());
    assert!(alice.verify_hmac(&request, &[0; 32]).await.is_err());
}
#[tokio::test]
async fn matches_fixed_sdk_signature_vectors() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/signature-sdk4.json")).unwrap();
    for c in fixture["cases"].as_array().unwrap() {
        let key = |v: &serde_json::Value| {
            SecretKey::from_slice(&hex::decode(format!("{:0>64}", v.as_str().unwrap())).unwrap())
                .unwrap()
        };
        let alice = LocalAuthWallet::new(key(&c["a"]));
        let bob = LocalAuthWallet::new(key(&c["b"]));
        let data: Vec<u8> = c["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u8)
            .collect();
        let signature = alice
            .sign_auth(
                c["bobPublic"].as_str().unwrap(),
                c["keyID"].as_str().unwrap(),
                &data,
            )
            .await
            .unwrap();
        assert_eq!(hex::encode(&signature), c["signature"].as_str().unwrap());
        assert!(
            bob.verify_auth(
                c["alicePublic"].as_str().unwrap(),
                c["keyID"].as_str().unwrap(),
                &data,
                &signature
            )
            .await
            .unwrap()
        );
    }
}
