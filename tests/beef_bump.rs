use message_box_server_rust::beef_bump::{BumpBeefEntry, parse_atomic_beef_with_regular_bumps};
use serde_json::{Value, json};
#[test]
fn matches_fixed_sdk_for_documented_beef_bump_subset() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/beef_bump_vectors.json")).unwrap();
    for case in fixtures["vectors"].as_array().unwrap() {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let actual=parse_atomic_beef_with_regular_bumps(&bytes).map(|beef|json!({
            "atomicTxid":beef.atomic_txid,"version":beef.version,
            "bumps":beef.bumps.into_iter().map(|b|json!({"blockHeight":b.block_height,"leafTxid":b.leaf_txid,"root":b.root})).collect::<Vec<_>>(),
            "entries":beef.entries.into_iter().map(|entry|match entry {
                BumpBeefEntry::Raw {transaction,bump_index}=>json!({"kind":"raw","txid":transaction.txid,"bumpIndex":bump_index}),
                BumpBeefEntry::TxidOnly(id)=>json!({"kind":"txid-only","txid":id})
            }).collect::<Vec<_>>()
        })).unwrap_or(Value::Null);
        assert_eq!(actual, case["expected"], "{}", case["hex"]);
    }
}

#[test]
fn structural_parse_does_not_validate_the_bump_index() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/beef_bump_vectors.json")).unwrap();
    let case = &fixtures["vectors"][3];
    let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
    let beef = parse_atomic_beef_with_regular_bumps(&bytes).unwrap();
    assert_eq!(beef.bumps.len(), 1);
    assert!(matches!(
        &beef.entries[0],
        BumpBeefEntry::Raw {
            bump_index: Some(1),
            ..
        }
    ));
    // A readable out-of-range index is not an inclusion or payment proof.
}
