use message_box_server_rust::auth_nonce::{
    HmacCheckError, NonceHmacRequest, NonceIssueError, NonceWallet, create_nonce, verify_nonce,
};
use serde_json::Value;
use std::sync::Mutex;

#[derive(Debug, PartialEq)]
struct WalletError;
struct FixtureWallet {
    expected: Vec<(Vec<u8>, Vec<u8>)>,
    calls: Mutex<Vec<NonceHmacRequest>>,
    result: u8,
}
impl NonceWallet for FixtureWallet {
    type Error = WalletError;
    async fn create_hmac(&self, request: &NonceHmacRequest) -> Result<[u8; 32], Self::Error> {
        self.calls.lock().unwrap().push(request.clone());
        if self.result == 2 {
            return Err(WalletError);
        }
        Ok([0x44; 32])
    }
    async fn verify_hmac(
        &self,
        request: &NonceHmacRequest,
        hmac: &[u8; 32],
    ) -> Result<bool, HmacCheckError<Self::Error>> {
        self.calls.lock().unwrap().push(request.clone());
        match self.result {
            1 => return Err(HmacCheckError::Invalid),
            2 => return Err(HmacCheckError::Other(WalletError)),
            3 => return Ok(false),
            _ => {}
        }
        Ok(self
            .expected
            .iter()
            .any(|(d, m)| d == &request.data && m == hmac))
    }
}
fn wallet(expected: Vec<(Vec<u8>, Vec<u8>)>, result: u8) -> FixtureWallet {
    FixtureWallet {
        expected,
        calls: Mutex::new(vec![]),
        result,
    }
}
fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect()
}
#[tokio::test]
async fn fixed_sdk_source_vectors_match_nonce_fields_and_utf8_decoding() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/nonce-sdk4.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let w = wallet(vec![(bytes(&case["data"]), bytes(&case["mac"]))], 0);
        assert!(
            verify_nonce(
                &w,
                case["token"].as_str().unwrap(),
                "self",
                Some("app.example")
            )
            .await
            .unwrap()
        );
        let calls = w.calls.lock().unwrap();
        let req = &calls[0];
        assert_eq!(req.key_id, case["keyId"].as_str().unwrap());
        assert_eq!(req.protocol_id, (2, "server hmac"));
        assert_eq!(req.counterparty, "self");
        assert_eq!(req.originator.as_deref(), Some("app.example"));
    }
}
#[tokio::test]
async fn sdk_generated_nonce_is_accepted_with_its_wallet_observations() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/nonce-sdk4.json")).unwrap();
    let generated = &fixture["generated"];
    assert_eq!(generated["verified"], true);
    let w = wallet(
        vec![(bytes(&generated["data"]), bytes(&generated["mac"]))],
        0,
    );
    assert!(
        verify_nonce(
            &w,
            generated["token"].as_str().unwrap(),
            "self",
            Some("app.example")
        )
        .await
        .unwrap()
    );
    assert_eq!(
        w.calls.lock().unwrap()[0].key_id,
        generated["keyId"].as_str().unwrap()
    );
}

#[tokio::test]
async fn creation_uses_os_random_and_matching_wallet_arguments() {
    let w = wallet(vec![], 0);
    let token = create_nonce(&w, "self", None).await.unwrap();
    let req = w.calls.lock().unwrap()[0].clone();
    assert_eq!(req.data.len(), 16);
    assert_eq!(req.protocol_id, (2, "server hmac"));
    let expected = wallet(vec![(req.data.to_vec(), vec![0x44; 32])], 0);
    assert!(verify_nonce(&expected, &token, "self", None).await.unwrap());
}
#[tokio::test]
async fn malformed_tokens_skip_wallet_and_hmac_failures_are_distinguished() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/nonce-sdk4.json")).unwrap();
    let token = fixture["cases"][0]["token"].as_str().unwrap();
    let w = wallet(vec![], 0);
    for bad in ["", "abc", "!", "AAAAAAAA", &format!("{token}=")] {
        assert!(!verify_nonce(&w, bad, "self", None).await.unwrap());
    }
    for invalid in ['=', ' ', '-', '_', '!'] {
        let mut bad = token.to_owned();
        bad.replace_range(12..13, &invalid.to_string());
        assert_eq!(bad.len(), 64);
        assert!(!verify_nonce(&w, &bad, "self", None).await.unwrap());
    }
    assert!(w.calls.lock().unwrap().is_empty());
    assert!(
        !verify_nonce(&wallet(vec![], 1), token, "self", None)
            .await
            .unwrap()
    );
    assert!(
        !verify_nonce(&wallet(vec![], 3), token, "self", None)
            .await
            .unwrap()
    );
    assert_eq!(
        verify_nonce(&wallet(vec![], 2), token, "self", None).await,
        Err(WalletError)
    );
}

#[tokio::test]
async fn issuance_propagates_wallet_failure() {
    let result = create_nonce(&wallet(vec![], 2), "self", None).await;
    assert!(matches!(result, Err(NonceIssueError::Wallet(WalletError))));
}
