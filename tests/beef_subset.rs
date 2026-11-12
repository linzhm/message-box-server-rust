use message_box_server_rust::beef_subset::{BeefEntry, parse_atomic_beef_subset};
use serde_json::{Value, json};
#[test]
fn matches_pinned_sdk_for_the_explicit_subset() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/beef_subset_vectors.json")).unwrap();
    for case in fixtures["vectors"].as_array().unwrap() {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let actual=parse_atomic_beef_subset(&bytes).map(|beef|json!({
            "atomicTxid":beef.atomic_txid,
            "version":beef.version,
            "entries":beef.entries.into_iter().map(|entry|match entry {
                BeefEntry::TxidOnly(txid)=>json!({"kind":"txid-only","txid":txid}),
                BeefEntry::Raw(tx)=>json!({"kind":"raw","txid":tx.txid,"inputs":tx.input_txids,"outputs":tx.outputs.into_iter().map(|output|json!({"satoshis":output.satoshis,"script":hex::encode(output.script)})).collect::<Vec<_>>()})
            }).collect::<Vec<_>>()
        })).unwrap_or(Value::Null);
        assert_eq!(actual, case["expected"], "{}", case["hex"]);
    }
}

#[test]
fn subject_output_observations_match_fixed_middleware_in_the_subset() {
    use message_box_server_rust::beef_subset::inspect_subject_output;
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/payment_subject_vectors.json")).unwrap();
    assert_eq!(
        fixtures["sourceBlob"],
        "c66270dafcc619b7d4f3de16d06e94ccbc143940"
    );
    for case in fixtures["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["subsetSupported"] == true)
    {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let beef = parse_atomic_beef_subset(&bytes).unwrap();
        let price = case["price"].as_u64().unwrap();
        // Compare only the subject and first-output observation. This is not a
        // payment validation decision or normalized BEEF comparison.
        let actual = inspect_subject_output(&beef)
            .filter(|value| value.satoshis >= price)
            .map(|value| json!({"txid":value.txid,"satoshis":value.satoshis}))
            .unwrap_or(Value::Null);
        assert_eq!(actual, case["expected"], "{}", case["hex"]);
    }
}

#[test]
fn upstream_subject_observations_do_not_prove_dependencies() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/payment_subject_vectors.json")).unwrap();
    let cases = fixtures["vectors"].as_array().unwrap();
    let case = |label: &str| cases.iter().find(|value| value["label"] == label).unwrap();
    for label in ["missing-parent", "txid-only-parent"] {
        let value = case(label);
        assert_eq!(value["sdkVerifyValid"], false);
        assert_eq!(value["expected"]["satoshis"], 100);
    }
    let parent = "0c1ac3ff4105d9086443e01dad430f4435811485f255a64ae3399704bd25ac16";
    let child = "6bc0ea158260e472fda3b1f2aa6cc58544c88117c1598049d7cced9209171825";
    assert_eq!(case("unrelated")["normalizedTxids"], json!([parent, child]));
    assert_eq!(case("missing-parent")["normalizedTxids"], json!([child]));
    assert_eq!(
        case("txid-only-parent")["normalizedTxids"],
        json!([parent, child])
    );
    assert!(case("duplicate-last-id")["expected"].is_null());
    assert_eq!(case("duplicate-last-raw")["expected"]["satoshis"], 100);
}
