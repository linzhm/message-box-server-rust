use base64::{Engine, engine::general_purpose::STANDARD};
use message_box_server_rust::{
    payment_candidate::inspect_payment_candidate, payment_header::PaymentHeader,
};
use serde_json::{Value, json};
fn payment(hex: &str) -> PaymentHeader {
    PaymentHeader {
        derivation_prefix: "AA==".into(),
        derivation_suffix: "AQ==".into(),
        transaction: STANDARD.encode(hex::decode(hex).unwrap()),
    }
}
#[test]
fn compares_supported_candidate_bytes_and_first_amount_to_pinned_middleware() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/payment_subject_vectors.json")).unwrap();
    let cases = fixtures["vectors"].as_array().unwrap();
    for label in [
        "amount-under",
        "amount-exact",
        "amount-first-under",
        "no-outputs",
        "unrelated",
        "reordered-parent-child",
        "txid-only-parent",
        "long-chain",
        "branch-unsupported",
        "branch-v1-reversed",
        "diamond-shared",
    ] {
        let case = cases.iter().find(|v| v["label"] == label).unwrap();
        let result = inspect_payment_candidate(
            &payment(case["hex"].as_str().unwrap()),
            case["price"].as_u64().unwrap(),
        );
        let actual=result.map(|v|json!({"txid":v.transaction_id,"satoshis":v.first_output_satoshis,"normalizedHex":hex::encode(v.normalized_atomic_beef)})).unwrap_or(Value::Null);
        let expected = if case["expected"].is_null() {
            Value::Null
        } else {
            json!({"txid":case["expected"]["txid"],"satoshis":case["expected"]["satoshis"],"normalizedHex":case["normalizedHex"]})
        };
        assert_eq!(actual, expected, "{label}");
    }
}
#[test]
fn refuses_unsupported_graphs_and_invalid_prices() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/payment_subject_vectors.json")).unwrap();
    let cases = fixtures["vectors"].as_array().unwrap();
    for label in ["missing-parent", "duplicate-last-id", "duplicate-last-raw"] {
        let case = cases.iter().find(|v| v["label"] == label).unwrap();
        assert!(
            inspect_payment_candidate(&payment(case["hex"].as_str().unwrap()), 100).is_none(),
            "{label}"
        );
    }
    let case = cases.iter().find(|v| v["label"] == "amount-exact").unwrap();
    let p = payment(case["hex"].as_str().unwrap());
    assert!(inspect_payment_candidate(&p, 0).is_none());
    assert!(inspect_payment_candidate(&p, 9_007_199_254_740_992).is_none());
}

struct UnusedWallet;
impl message_box_server_rust::auth_nonce::NonceWallet for UnusedWallet {
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
        unreachable!()
    }
}
#[tokio::test]
async fn candidate_observation_does_not_verify_payment_prefix() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/payment_subject_vectors.json")).unwrap();
    let case = fixtures["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["label"] == "amount-exact")
        .unwrap();
    let p = payment(case["hex"].as_str().unwrap());
    assert!(inspect_payment_candidate(&p, 100).is_some());
    assert!(
        !message_box_server_rust::payment_header::verify_payment_prefix(&UnusedWallet, &p).await
    );
    let malformed = PaymentHeader {
        transaction: "AB==".into(),
        ..p
    };
    assert!(inspect_payment_candidate(&malformed, 100).is_none());
}

#[test]
fn inspects_supported_regular_bump_candidates_without_authorizing_payment() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/bump_payment_vectors.json")).unwrap();
    for label in [
        "v2-proof",
        "v1-proof",
        "v1-nonzero-marker",
        "unused-unsorted",
        "remap-unused",
        "unflagged-subject",
        "proof-stops-missing-parent",
        "parent-proof-child",
        "two-proof-remap",
        "known-and-proof",
        "shared-bump",
    ] {
        let case = fixtures["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["label"] == label)
            .unwrap();
        let candidate =
            inspect_payment_candidate(&payment(case["hex"].as_str().unwrap()), 1).expect(label);
        assert_eq!(
            candidate.transaction_id,
            case["expected"]["txid"].as_str().unwrap(),
            "{label}"
        );
        assert_eq!(
            candidate.first_output_satoshis,
            case["expected"]["satoshis"].as_u64().unwrap(),
            "{label}"
        );
        assert_eq!(
            hex::encode(candidate.normalized_atomic_beef),
            case["expected"]["normalizedHex"].as_str().unwrap(),
            "{label}"
        );
    }
}
#[test]
fn rejects_unhandled_regular_bump_candidates() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/bump_payment_vectors.json")).unwrap();
    for label in ["invalid-index", "unsorted-bump", "unmatched-leaf"] {
        let case = fixtures["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["label"] == label)
            .unwrap();
        assert!(case["expected"].is_object());
        assert!(
            inspect_payment_candidate(&payment(case["hex"].as_str().unwrap()), 1).is_none(),
            "{label}"
        );
    }
}
