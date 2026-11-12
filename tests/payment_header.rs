use message_box_server_rust::payment_header::parse_payment_header;
use serde_json::{Value, json};

#[test]
fn matches_executed_pinned_middleware_header_parser() {
    let vectors: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/payment_header_vectors.json")).unwrap();
    assert_eq!(
        vectors["sourceBlob"],
        "c66270dafcc619b7d4f3de16d06e94ccbc143940"
    );
    for vector in vectors["vectors"].as_array().unwrap() {
        let raw = vector["raw"].as_str().unwrap();
        let actual = parse_payment_header(raw)
            .map(|header| {
                json!({
                    "derivationPrefix":header.derivation_prefix,
                    "derivationSuffix":header.derivation_suffix,
                    "transaction":header.transaction,
                })
            })
            .unwrap_or(Value::Null);
        assert_eq!(actual, vector["expected"], "{raw}");
    }
}

struct RealTestWallet(k256::SecretKey);
impl message_box_server_rust::auth_nonce::NonceWallet for RealTestWallet {
    type Error = message_box_server_rust::brc42::InvalidDerivedKey;
    async fn create_hmac(
        &self,
        _: &message_box_server_rust::auth_nonce::NonceHmacRequest,
    ) -> Result<[u8; 32], Self::Error> {
        unreachable!()
    }
    async fn verify_hmac(
        &self,
        request: &message_box_server_rust::auth_nonce::NonceHmacRequest,
        mac: &[u8; 32],
    ) -> Result<bool, message_box_server_rust::auth_nonce::HmacCheckError<Self::Error>> {
        assert_eq!(request.protocol_id, (2, "server hmac"));
        assert_eq!(request.counterparty, "self");
        assert_eq!(request.originator, None);
        message_box_server_rust::brc42::verify_hmac(
            &self.0,
            &self.0.public_key(),
            &format!("2-server hmac-{}", request.key_id),
            &request.data,
            mac,
        )
        .map_err(message_box_server_rust::auth_nonce::HmacCheckError::Other)
    }
}
struct BrokenWallet;
impl message_box_server_rust::auth_nonce::NonceWallet for BrokenWallet {
    type Error = ();
    async fn create_hmac(
        &self,
        _: &message_box_server_rust::auth_nonce::NonceHmacRequest,
    ) -> Result<[u8; 32], ()> {
        unreachable!()
    }
    async fn verify_hmac(
        &self,
        _: &message_box_server_rust::auth_nonce::NonceHmacRequest,
        _: &[u8; 32],
    ) -> Result<bool, message_box_server_rust::auth_nonce::HmacCheckError<()>> {
        Err(message_box_server_rust::auth_nonce::HmacCheckError::Other(
            (),
        ))
    }
}
#[tokio::test]
async fn payment_prefix_uses_real_sdk_nonce_and_fails_closed() {
    use message_box_server_rust::payment_header::verify_payment_prefix;
    let vectors: Value = serde_json::from_str(include_str!("fixtures/hmac-sdk4.json")).unwrap();
    let case = &vectors["cases"][1];
    let secret =
        |s: &str| k256::SecretKey::from_slice(&hex::decode(format!("{s:0>64}")).unwrap()).unwrap();
    let wallet = RealTestWallet(secret(case["a"].as_str().unwrap()));
    let other = RealTestWallet(secret("2"));
    let raw =
        json!({"derivationPrefix":case["nonce"],"derivationSuffix":"AQ==","transaction":"Ag=="})
            .to_string();
    let header = parse_payment_header(&raw).unwrap();
    assert!(verify_payment_prefix(&wallet, &header).await);
    assert!(!verify_payment_prefix(&other, &header).await);
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut tampered = header.clone();
    let mut bytes = STANDARD.decode(&tampered.derivation_prefix).unwrap();
    bytes[47] ^= 1;
    tampered.derivation_prefix = STANDARD.encode(bytes);
    assert!(!verify_payment_prefix(&wallet, &tampered).await);
    assert!(!verify_payment_prefix(&BrokenWallet, &header).await);
    let short = parse_payment_header(
        r#"{"derivationPrefix":"AA==","derivationSuffix":"AQ==","transaction":"Ag=="}"#,
    )
    .unwrap();
    assert!(!verify_payment_prefix(&wallet, &short).await);
}
