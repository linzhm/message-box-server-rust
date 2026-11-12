use message_box_server_rust::{
    Identity,
    delivery_remittance::has_canonical_delivery_remittance,
    legacy_delivery_amount::inspect_legacy_delivery_output,
    recipient_allocation::{AllocationError, allocate_recipient_outputs},
    recipient_output_check::{RecipientGroup, RecipientOutputError, inspect_recipient_outputs},
    transaction_frame::TransactionOutputFrame,
};
use serde_json::{Value, json};
#[test]
fn differing_decimal_rounding_is_unsupported_at_every_offline_seam() {
    // Fixed repro: default serde_json and JS JSON.parse round this differently.
    let value: Value = serde_json::from_str("4634637815817395.509255768254").unwrap();
    assert!(value.as_f64().is_some() && value.as_u64().is_none());
    let outputs = vec![
        json!({"outputIndex":value,"customInstructions":"{\"recipientIdentityKey\":\"other\"}"}),
        json!({"outputIndex":4634637815817396u64}),
    ];
    assert_eq!(
        allocate_recipient_outputs(&outputs, &["a".into()]),
        Err(AllocationError::Unsupported)
    );
    let f: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/recipient_output_check_vectors.json"
    ))
    .unwrap();
    let input = &f["cases"][0]["input"];
    let identity = Identity::from_verified_key(input["recipient"].as_str().unwrap()).unwrap();
    let mut rem = input["outputs"][0].clone();
    rem["outputIndex"] = value;
    assert_eq!(has_canonical_delivery_remittance(&rem, &identity), None);
    let frames = vec![TransactionOutputFrame {
        satoshis: 10,
        script: hex::decode(input["transactionOutputs"][0]["script"].as_str().unwrap()).unwrap(),
    }];
    assert_eq!(
        inspect_recipient_outputs(
            &frames,
            &[RecipientGroup {
                recipient: &identity,
                fee: 10,
                outputs: std::slice::from_ref(&rem)
            }],
            None
        ),
        Err(RecipientOutputError::Unsupported)
    );
    let amount: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/legacy_delivery_amount_vectors.json"
    ))
    .unwrap();
    let case = amount["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["label"] == "payment_subject_vectors.json:amount-exact")
        .unwrap();
    let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
    assert_eq!(inspect_legacy_delivery_output(&bytes, &rem, 1), None);
}
