use message_box_server_rust::beef_subset::normalize_linear_atomic_beef;
use serde_json::Value;
#[test]
fn normalizes_supported_linear_subset_like_fixed_middleware() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/payment_subject_vectors.json")).unwrap();
    let cases = fixtures["vectors"].as_array().unwrap();
    for case in [&cases[0], &cases[1]]
        .into_iter()
        .chain(cases.iter().filter(|case| {
            matches!(
                case["label"].as_str(),
                Some("unrelated" | "reordered-parent-child" | "txid-only-parent" | "long-chain")
            )
        }))
    {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let actual = normalize_linear_atomic_beef(&bytes).map(hex::encode);
        let expected = case["normalizedHex"]
            .as_str()
            .expect("SDK normalization must succeed for supported vectors");
        assert_eq!(actual.as_deref(), Some(expected), "{}", case["hex"]);
    }
}
#[test]
fn refuses_unsupported_graphs_without_implying_invalid_payment() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/payment_subject_vectors.json")).unwrap();
    for case in fixtures["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| {
            matches!(
                case["label"].as_str(),
                Some(
                    "missing-parent"
                        | "duplicate-last-id"
                        | "duplicate-last-raw"
                        | "branch-unsupported"
                )
            )
        })
    {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        assert!(
            normalize_linear_atomic_beef(&bytes).is_none(),
            "{}",
            case["label"]
        );
    }
}

#[test]
fn refuses_empty_missing_or_txid_only_subjects() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/beef_subset_vectors.json")).unwrap();
    let cases = fixtures["vectors"].as_array().unwrap();
    for index in [2, 3, 6] {
        let bytes = hex::decode(cases[index]["hex"].as_str().unwrap()).unwrap();
        assert!(
            normalize_linear_atomic_beef(&bytes).is_none(),
            "index {index}"
        );
    }
}
