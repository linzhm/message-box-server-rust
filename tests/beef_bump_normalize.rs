use message_box_server_rust::beef_bump::normalize_regular_bump_atomic_beef;
use serde_json::Value;
#[test]
fn normalizes_supported_proof_graphs_like_fixed_middleware() {
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
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let expected = case["expected"]["normalizedHex"]
            .as_str()
            .expect("SDK must normalize this fixture");
        assert_eq!(
            normalize_regular_bump_atomic_beef(&bytes)
                .map(hex::encode)
                .as_deref(),
            Some(expected),
            "{label}"
        );
    }
}
#[test]
fn rejects_deliberately_unsupported_proof_shapes() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/bump_payment_vectors.json")).unwrap();
    for label in ["invalid-index", "unsorted-bump", "unmatched-leaf"] {
        let case = fixtures["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["label"] == label)
            .unwrap();
        assert!(
            case["expected"].is_object(),
            "SDK accepts this; Rust refusal is a subset restriction"
        );
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        assert!(
            normalize_regular_bump_atomic_beef(&bytes).is_none(),
            "{label}"
        );
    }
}
