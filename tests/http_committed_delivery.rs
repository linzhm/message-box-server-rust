use message_box_server_rust::{ApiResponse, Identity, http_auth::committed_deliveries};
use serde_json::json;
use std::sync::Arc;
const ALICE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
#[test]
fn batch_metadata_uses_verified_sender_results_and_one_shared_body() {
    let identity = Identity::from_verified_key(ALICE).unwrap();
    let body = "x".repeat(1_048_576);
    let fields = json!({"sender":"untrusted","message":{"messageBox":"inbox","body":body,"recipient":"ignored"}});
    let results = (0..100)
        .map(|i| json!({"recipient":format!("recipient-{i}"),"messageId":format!("id-{i}")}))
        .collect::<Vec<_>>();
    let response = ApiResponse {
        status: 200,
        body: json!({"status":"success","results":results}),
    };
    let deliveries = committed_deliveries(&identity, &fields, &response)
        .unwrap()
        .0;
    assert_eq!(deliveries.len(), 100);
    for (i, item) in deliveries.iter().enumerate() {
        assert_eq!(item.sender, ALICE);
        assert_eq!(item.recipient, format!("recipient-{i}"));
        assert_eq!(item.message_id, format!("id-{i}"));
        assert_eq!(item.message_box, "inbox");
        assert_eq!(item.body.len(), 1_048_576);
        assert!(Arc::ptr_eq(&deliveries[0].body, &item.body));
    }
}
#[test]
fn rejects_failure_and_malformed_result_metadata() {
    let identity = Identity::from_verified_key(ALICE).unwrap();
    let fields = json!({"message":{"messageBox":"inbox","body":"hello"}});
    for response in [
        ApiResponse {
            status: 403,
            body: json!({"status":"success","results":[]}),
        },
        ApiResponse {
            status: 200,
            body: json!({"status":"error","results":[]}),
        },
        ApiResponse {
            status: 200,
            body: json!({"status":"success","results":[{"recipient":"x"}]}),
        },
    ] {
        assert!(committed_deliveries(&identity, &fields, &response).is_none());
    }
}

#[test]
fn paid_messages_do_not_generate_push_metadata() {
    let identity = Identity::from_verified_key(ALICE).unwrap();
    let result = ApiResponse {
        status: 200,
        body: json!({"status":"success","results":[{"recipient":"recipient","messageId":"id"}]}),
    };
    let mut fields =
        json!({"message":{"messageBox":"inbox","body":"hello"},"payment":{"synthetic":true}});
    assert!(committed_deliveries(&identity, &fields, &result).is_none());
    fields["payment"] = serde_json::Value::Null;
    assert!(committed_deliveries(&identity, &fields, &result).is_some());
}
