use message_box_server_rust::beef_subset::normalize_acyclic_atomic_beef;
use serde_json::Value;
#[test]
fn normalizes_supported_graphs_like_fixed_middleware() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/payment_subject_vectors.json")).unwrap();
    let cases = fixtures["vectors"].as_array().unwrap();
    for label in [
        "unrelated",
        "long-chain",
        "branch-unsupported",
        "branch-reversed",
        "branch-v1-reversed",
        "orphan-unrelated",
        "branch-known-parent",
        "fork-join-shuffled",
        "diamond-shared",
        "duplicate-parent-inputs",
    ] {
        let case = cases.iter().find(|case| case["label"] == label).unwrap();
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let expected = case["normalizedHex"]
            .as_str()
            .expect("SDK must normalize this fixture");
        assert_eq!(
            normalize_acyclic_atomic_beef(&bytes)
                .map(hex::encode)
                .as_deref(),
            Some(expected),
            "{label}"
        );
    }
}
#[test]
fn refuses_missing_or_duplicate_graphs_without_claiming_invalidity() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/payment_subject_vectors.json")).unwrap();
    let cases = fixtures["vectors"].as_array().unwrap();
    for label in ["missing-parent", "duplicate-last-id", "duplicate-last-raw"] {
        let case = cases.iter().find(|case| case["label"] == label).unwrap();
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        assert!(normalize_acyclic_atomic_beef(&bytes).is_none(), "{label}");
    }
}
