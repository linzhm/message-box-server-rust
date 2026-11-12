use message_box_server_rust::recipient_allocation::{AllocationError, allocate_recipient_outputs};
use serde_json::Value;
#[test]
fn matches_fixed_typescript_allocation_cases() {
    let f: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/recipient_allocation_vectors.json"
    ))
    .unwrap();
    for c in f["cases"].as_array().unwrap() {
        let input = &c["input"];
        let recipients: Vec<String> = input["feeRecipients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect();
        let result = allocate_recipient_outputs(input["outputs"].as_array().unwrap(), &recipients);
        if c["label"] == "malformed-is-untagged" {
            assert_eq!(result, Err(AllocationError::Unsupported));
            continue;
        }
        if let Some(code) = c["expected"]["error"].as_str() {
            assert_eq!(result.unwrap_err().code(), Some(code), "{}", c["label"]);
        } else {
            let expected: Vec<Vec<usize>> = c["expected"]["alloc"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| {
                    a.as_array()
                        .unwrap()
                        .iter()
                        .map(|n| n.as_u64().unwrap() as usize)
                        .collect()
                })
                .collect();
            assert_eq!(result.unwrap(), expected, "{}", c["label"]);
        }
    }
}
#[test]
fn unsupported_indices_and_duplicate_recipients_are_not_silently_normalized() {
    use serde_json::json;
    assert_eq!(
        allocate_recipient_outputs(&[json!({"outputIndex":-1})], &["a".into()]),
        Err(AllocationError::Unsupported)
    );
    assert_eq!(
        allocate_recipient_outputs(&[json!({"outputIndex":0})], &["a".into(), "a".into()]),
        Err(AllocationError::Unsupported)
    );
}
#[test]
fn allocated_positions_can_feed_offline_recipient_inspection() {
    use message_box_server_rust::{
        Identity,
        recipient_output_check::{RecipientGroup, inspect_recipient_outputs},
        transaction_frame::TransactionOutputFrame,
    };
    let f: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/recipient_output_check_vectors.json"
    ))
    .unwrap();
    let input = &f["cases"][0]["input"];
    let recipient = Identity::from_verified_key(input["recipient"].as_str().unwrap()).unwrap();
    let outputs = input["outputs"].as_array().unwrap();
    let allocation = allocate_recipient_outputs(outputs, &[recipient.as_str().to_owned()]).unwrap();
    let selected: Vec<Value> = allocation[0].iter().map(|&i| outputs[i].clone()).collect();
    let frames: Vec<_> = input["transactionOutputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| TransactionOutputFrame {
            satoshis: o["satoshis"].as_u64().unwrap(),
            script: hex::decode(o["script"].as_str().unwrap()).unwrap(),
        })
        .collect();
    assert_eq!(
        inspect_recipient_outputs(
            &frames,
            &[RecipientGroup {
                recipient: &recipient,
                fee: input["fee"].as_u64().unwrap(),
                outputs: &selected
            }],
            None
        ),
        Ok(())
    );
}
