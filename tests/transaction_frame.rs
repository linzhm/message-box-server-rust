use message_box_server_rust::transaction_frame::parse_transaction_frame;
use serde_json::{Value, json};
#[test]
fn matches_fixed_sdk_synthetic_transaction_frames() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/transaction_frames.json")).unwrap();
    for case in fixtures["vectors"].as_array().unwrap() {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let actual=parse_transaction_frame(&bytes).map(|tx|json!({
            "txid":tx.txid,
            "inputs":tx.input_txids,
            "outputs":tx.outputs.into_iter().map(|output|json!({"satoshis":output.satoshis,"script":hex::encode(output.script)})).collect::<Vec<_>>()
        })).unwrap_or(Value::Null);
        assert_eq!(actual, case["expected"], "{}", case["hex"]);
    }
}
