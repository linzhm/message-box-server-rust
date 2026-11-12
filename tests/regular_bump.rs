use message_box_server_rust::regular_bump::parse_regular_bump;
use serde_json::{Value, json};
#[test]
fn matches_pinned_sdk_for_documented_regular_paths() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/regular_bump_vectors.json")).unwrap();
    for case in fixtures["vectors"].as_array().unwrap() {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let actual=parse_regular_bump(&bytes).map(|bump|json!({"blockHeight":bump.block_height,"leafTxid":bump.leaf_txid,"root":bump.root})).unwrap_or(Value::Null);
        assert_eq!(actual, case["expected"], "{}", case["hex"]);
    }
}

#[test]
fn enforces_subset_bounds_and_does_not_authenticate_roots() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/regular_bump_vectors.json")).unwrap();
    let cases = fixtures["vectors"].as_array().unwrap();
    let single = hex::decode(cases[0]["hex"].as_str().unwrap()).unwrap();
    for height in [0, 55] {
        let mut bytes = single.clone();
        bytes[1] = height;
        assert!(parse_regular_bump(&bytes).is_none());
    }
    for flag in [0, 1, 3, 4, 6] {
        let mut bad_flag = single.clone();
        bad_flag[4] = flag;
        assert!(parse_regular_bump(&bad_flag).is_none());
    }
    let original =
        parse_regular_bump(&hex::decode(cases[3]["hex"].as_str().unwrap()).unwrap()).unwrap();
    let changed =
        parse_regular_bump(&hex::decode(cases[2]["hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_ne!(original.root, changed.root);
    // Both are structurally inspectable; neither root is checked against a chain.
}
