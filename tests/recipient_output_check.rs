use message_box_server_rust::{
    Identity,
    recipient_output_check::{RecipientGroup, RecipientOutputError, inspect_recipient_outputs},
    transaction_frame::TransactionOutputFrame,
};
use serde_json::Value;
#[test]
fn synthetic_metadata_and_script_observations_match_fixed_typescript() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/recipient_output_check_vectors.json"
    ))
    .unwrap();
    for c in fixture["cases"].as_array().unwrap() {
        let input = &c["input"];
        let recipient = Identity::from_verified_key(input["recipient"].as_str().unwrap()).unwrap();
        let outputs = input["outputs"].as_array().unwrap();
        let tx_outputs: Vec<_> = input["transactionOutputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| TransactionOutputFrame {
                satoshis: o["satoshis"].as_u64().unwrap(),
                script: hex::decode(o["script"].as_str().unwrap()).unwrap(),
            })
            .collect();
        let group = RecipientGroup {
            recipient: &recipient,
            fee: input["fee"].as_u64().unwrap(),
            outputs,
        };
        let result =
            inspect_recipient_outputs(&tx_outputs, &[group], input["deliveryIndex"].as_u64());
        if let Some(expected) = c["expected"].as_str() {
            assert_eq!(result.unwrap_err().code(), Some(expected), "{}", c["label"]);
        } else {
            assert!(result.is_ok(), "{}: {result:?}", c["label"]);
        }
    }
}
#[test]
fn shares_index_reservations_across_groups_and_fails_on_overflow() {
    let f: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/recipient_output_check_vectors.json"
    ))
    .unwrap();
    let i = &f["cases"][0]["input"];
    let recipient = Identity::from_verified_key(i["recipient"].as_str().unwrap()).unwrap();
    let rem = i["outputs"].as_array().unwrap();
    let script = hex::decode(i["transactionOutputs"][0]["script"].as_str().unwrap()).unwrap();
    let frame = TransactionOutputFrame {
        satoshis: 10,
        script: script.clone(),
    };
    let first = RecipientGroup {
        recipient: &recipient,
        fee: 5,
        outputs: rem,
    };
    let second = RecipientGroup {
        recipient: &recipient,
        fee: 5,
        outputs: rem,
    };
    assert_eq!(
        inspect_recipient_outputs(std::slice::from_ref(&frame), &[first, second], None),
        Err(RecipientOutputError::Invalid)
    );
    let mut two = rem.clone();
    let mut next = two[0].clone();
    next["outputIndex"] = Value::from(1);
    two.push(next);
    let frames = [
        TransactionOutputFrame {
            satoshis: 9_007_199_254_740_991,
            script: script.clone(),
        },
        TransactionOutputFrame {
            satoshis: 1,
            script,
        },
    ];
    assert_eq!(
        inspect_recipient_outputs(
            &frames,
            &[RecipientGroup {
                recipient: &recipient,
                fee: 1,
                outputs: &two
            }],
            None
        ),
        Err(RecipientOutputError::Invalid)
    );
}
#[test]
fn zero_fee_groups_do_not_require_or_reserve_outputs() {
    let f: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/recipient_output_check_vectors.json"
    ))
    .unwrap();
    let i = &f["cases"][0]["input"];
    let recipient = Identity::from_verified_key(i["recipient"].as_str().unwrap()).unwrap();
    assert_eq!(
        inspect_recipient_outputs(
            &[],
            &[RecipientGroup {
                recipient: &recipient,
                fee: 0,
                outputs: &[]
            }],
            None
        ),
        Ok(())
    );
}
