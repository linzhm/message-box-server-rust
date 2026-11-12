use base64::{Engine, engine::general_purpose::STANDARD};
use message_box_server_rust::{
    Identity,
    auth_nonce::{HmacCheckError, NonceHmacRequest, NonceWallet},
    payment_stage::{
        InternalizeRequest, PaymentStageError, PaymentWallet, ReplayClaims,
        is_newly_accepted_result, process_supplied_payment,
    },
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
const SENDER: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
type Events = Arc<Mutex<Vec<&'static str>>>;
struct Wallet {
    events: Events,
    verify: bool,
    result: Option<Value>,
}
impl NonceWallet for Wallet {
    type Error = ();
    async fn create_hmac(&self, _: &NonceHmacRequest) -> Result<[u8; 32], ()> {
        unreachable!()
    }
    async fn verify_hmac(
        &self,
        request: &NonceHmacRequest,
        _: &[u8; 32],
    ) -> Result<bool, HmacCheckError<()>> {
        assert_eq!(request.protocol_id, (2, "server hmac"));
        assert_eq!(request.counterparty, "self");
        assert_eq!(request.originator, None);
        self.events.lock().unwrap().push("verify");
        Ok(self.verify)
    }
}
impl PaymentWallet for Wallet {
    async fn internalize(&self, request: &InternalizeRequest<'_>) -> Result<Value, ()> {
        assert_eq!(request.output_index, 0);
        assert_eq!(request.protocol, "wallet payment");
        assert_eq!(request.description, "Payment for request");
        assert_eq!(request.sender_identity, SENDER);
        assert_eq!(request.derivation_suffix, "AQ==");
        assert_eq!(request.derivation_prefix, STANDARD.encode([1u8; 48]));
        assert_eq!(
            request.transaction,
            hex::decode(fixture()["normalizedHex"].as_str().unwrap()).unwrap()
        );
        self.events.lock().unwrap().push("wallet");
        self.result.clone().ok_or(())
    }
}
struct Replay {
    events: Events,
    result: Option<bool>,
}
impl ReplayClaims for Replay {
    type Error = ();
    async fn claim(&self, txid: &str) -> Result<bool, ()> {
        assert_eq!(txid, fixture()["expected"]["txid"].as_str().unwrap());
        self.events.lock().unwrap().push("claim");
        self.result.ok_or(())
    }
}
fn fixture() -> Value {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/payment_subject_vectors.json")).unwrap();
    fixtures["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["label"] == "amount-exact")
        .unwrap()
        .clone()
}
fn raw_payment(prefix: &str) -> String {
    json!({"derivationPrefix":prefix,"derivationSuffix":"AQ==","transaction":STANDARD.encode(hex::decode(fixture()["hex"].as_str().unwrap()).unwrap())}).to_string()
}
fn sender() -> Identity {
    Identity::from_verified_key(SENDER).unwrap()
}
fn events() -> Events {
    Arc::new(Mutex::new(Vec::new()))
}
fn wallet(e: &Events, result: Option<Value>) -> Wallet {
    Wallet {
        events: Arc::clone(e),
        verify: true,
        result,
    }
}
fn replay(e: &Events, result: Option<bool>) -> Replay {
    Replay {
        events: Arc::clone(e),
        result,
    }
}
#[test]
fn result_shape_matches_pinned_source_vectors() {
    let f: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/internalization_result_vectors.json"
    ))
    .unwrap();
    for c in f["cases"].as_array().unwrap() {
        assert_eq!(
            is_newly_accepted_result(&c["value"]),
            c["expected"].as_bool().unwrap(),
            "{}",
            c["value"]
        );
    }
}
#[tokio::test]
async fn invalid_inputs_never_internalize_or_claim() {
    let e = events();
    let w = wallet(&e, Some(json!({"accepted":true})));
    let r = replay(&e, Some(true));
    assert_eq!(
        process_supplied_payment(&w, &r, &sender(), "{", 100)
            .await
            .unwrap_err(),
        PaymentStageError::Malformed
    );
    assert_eq!(
        process_supplied_payment(&w, &r, &sender(), &raw_payment("AA=="), 100)
            .await
            .unwrap_err(),
        PaymentStageError::InvalidPrefix
    );
    let prefix = STANDARD.encode([1u8; 48]);
    assert_eq!(
        process_supplied_payment(&w, &r, &sender(), &raw_payment(&prefix), 101)
            .await
            .unwrap_err(),
        PaymentStageError::InvalidPayment
    );
    assert_eq!(*e.lock().unwrap(), vec!["verify"]);
    let mut denied = wallet(&e, Some(json!({"accepted":true})));
    denied.verify = false;
    assert_eq!(
        process_supplied_payment(&denied, &r, &sender(), &raw_payment(&prefix), 100)
            .await
            .unwrap_err(),
        PaymentStageError::InvalidPrefix
    );
    assert_eq!(
        process_supplied_payment(&w, &r, &sender(), &raw_payment(&prefix), 0)
            .await
            .unwrap_err(),
        PaymentStageError::InvalidPrice
    );
    assert_eq!(*e.lock().unwrap(), vec!["verify", "verify"]);
}
#[tokio::test]
async fn accepts_only_new_wallet_receipt_then_claims() {
    let e = events();
    let prefix = STANDARD.encode([1u8; 48]);
    let raw = raw_payment(&prefix);
    let w = wallet(&e, Some(json!({"accepted":true,"isMerge":false})));
    let r = replay(&e, Some(true));
    let receipt = process_supplied_payment(&w, &r, &sender(), &raw, 100)
        .await
        .unwrap();
    assert_eq!(receipt.satoshis_paid, 100);
    assert_eq!(receipt.transaction_id.len(), 64);
    assert!(!receipt.normalized_atomic_beef.is_empty());
    assert_eq!(*e.lock().unwrap(), vec!["verify", "wallet", "claim"]);
}
#[tokio::test]
async fn wallet_and_replay_failures_stop_after_the_correct_step() {
    let prefix = STANDARD.encode([1u8; 48]);
    let raw = raw_payment(&prefix);
    for (result, claim, expected, trace) in [
        (
            Some(json!({"accepted":true,"isMerge":true})),
            Some(true),
            PaymentStageError::WalletNotNew,
            vec!["verify", "wallet"],
        ),
        (
            None,
            Some(true),
            PaymentStageError::WalletFailed,
            vec!["verify", "wallet"],
        ),
        (
            Some(json!({"accepted":true})),
            Some(false),
            PaymentStageError::AlreadyClaimed,
            vec!["verify", "wallet", "claim"],
        ),
        (
            Some(json!({"accepted":true})),
            None,
            PaymentStageError::ReplayUnavailable,
            vec!["verify", "wallet", "claim"],
        ),
    ] {
        let e = events();
        let w = wallet(&e, result);
        let r = replay(&e, claim);
        assert_eq!(
            process_supplied_payment(&w, &r, &sender(), &raw, 100)
                .await
                .unwrap_err(),
            expected
        );
        assert_eq!(*e.lock().unwrap(), trace);
    }
}

#[test]
fn failure_status_and_codes_match_fixed_middleware() {
    for (error, status, code) in [
        (PaymentStageError::InvalidPrice, 500, "ERR_PAYMENT_INTERNAL"),
        (PaymentStageError::Malformed, 400, "ERR_MALFORMED_PAYMENT"),
        (
            PaymentStageError::InvalidPrefix,
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
        ),
        (
            PaymentStageError::InvalidPayment,
            400,
            "ERR_INVALID_PAYMENT",
        ),
        (PaymentStageError::WalletNotNew, 409, "ERR_PAYMENT_REPLAYED"),
        (PaymentStageError::WalletFailed, 400, "ERR_PAYMENT_FAILED"),
        (
            PaymentStageError::AlreadyClaimed,
            409,
            "ERR_PAYMENT_REPLAYED",
        ),
        (
            PaymentStageError::ReplayUnavailable,
            503,
            "ERR_PAYMENT_UNAVAILABLE",
        ),
    ] {
        assert_eq!(error.status(), status);
        assert_eq!(error.code(), code);
    }
}
#[tokio::test]
async fn sqlite_replay_guard_stops_second_fake_wallet_receipt() {
    use message_box_server_rust::payment_replay::{ReplayRetention, SqlitePaymentReplayStore};
    let dir = tempfile::tempdir().unwrap();
    let store = SqlitePaymentReplayStore::open(
        dir.path().join("claims.sqlite"),
        ReplayRetention::Days(365),
    )
    .await
    .unwrap();
    let e = events();
    let w = wallet(&e, Some(json!({"accepted":true})));
    let raw = raw_payment(&STANDARD.encode([1u8; 48]));
    assert!(
        process_supplied_payment(&w, &store, &sender(), &raw, 100)
            .await
            .is_ok()
    );
    assert_eq!(
        process_supplied_payment(&w, &store, &sender(), &raw, 100)
            .await
            .unwrap_err(),
        PaymentStageError::AlreadyClaimed
    );
    assert_eq!(
        *e.lock().unwrap(),
        vec!["verify", "wallet", "verify", "wallet"]
    );
}
