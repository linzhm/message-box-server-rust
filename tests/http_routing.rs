use message_box_server_rust::{
    Decision, DeliveryPolicy, Identity, Limits, MessageBox, PolicyError,
};
use serde_json::json;
use std::sync::Arc;

const ALICE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

struct Free;
impl DeliveryPolicy for Free {
    fn evaluate(&self, _: &Identity, _: &str, _: &str) -> Result<Decision, PolicyError> {
        Ok(Decision::Free)
    }
    fn delivery_fee(&self, _: &str) -> Result<i64, PolicyError> {
        Ok(0)
    }
}
async fn service() -> MessageBox {
    MessageBox::memory(Arc::new(Free), Limits::default())
        .await
        .unwrap()
}

#[tokio::test]
async fn only_registered_method_and_path_pairs_reach_the_core() {
    let app = service().await;
    for (method, path) in [
        ("POST", "/sendMessage"),
        ("POST", "/listMessages"),
        ("POST", "/acknowledgeMessage"),
        ("POST", "/permissions/set"),
        ("GET", "/permissions/get"),
        ("GET", "/permissions/list"),
        ("GET", "/permissions/quote"),
        ("GET", "/devices"),
        ("POST", "/registerDevice"),
    ] {
        let response = app
            .dispatch_http(method, path, None, &json!({}), &json!({}))
            .await;
        assert_eq!(response.unwrap().status, 401, "{method} {path}");
        let wrong_method = if method == "GET" { "POST" } else { "GET" };
        assert!(
            app.dispatch_http(wrong_method, path, None, &json!({}), &json!({}))
                .await
                .is_none()
        );
    }
    for (method, path) in [
        ("GET", "/health"),
        ("PUT", "/sendMessage"),
        ("POST", "/unknown"),
    ] {
        assert!(
            app.dispatch_http(method, path, None, &json!({}), &json!({}))
                .await
                .is_none()
        );
    }
}

#[tokio::test]
async fn post_uses_body_and_get_uses_query_without_identity_from_input() {
    let app = service().await;
    let alice = Identity::from_verified_key(ALICE).unwrap();
    let query = json!({"messageBox":"query-box", "recipientFee": 9});
    let body = json!({"messageBox":"body-box", "recipientFee": 0, "identity": ALICE});
    assert_eq!(
        app.dispatch_http("POST", "/permissions/set", None, &query, &body)
            .await
            .unwrap()
            .status,
        401
    );
    assert_eq!(
        app.dispatch_http("POST", "/permissions/set", Some(&alice), &query, &body)
            .await
            .unwrap()
            .status,
        200
    );
    let get = app
        .dispatch_http("GET", "/permissions/get", Some(&alice), &query, &body)
        .await
        .unwrap();
    assert_eq!(get.status, 200);
    assert!(get.body["permission"].is_null());
    let get = app
        .dispatch_http(
            "GET",
            "/permissions/get",
            Some(&alice),
            &json!({"messageBox":"body-box"}),
            &query,
        )
        .await
        .unwrap();
    assert_eq!(get.body["permission"]["recipientFee"], 0);
}

#[tokio::test]
async fn authenticated_core_routes_are_reached_through_dispatch() {
    let app = service().await;
    let alice = Identity::from_verified_key(ALICE).unwrap();
    let empty = json!({});
    let send = json!({"message":{"recipient":ALICE,"messageId":"one","messageBox":"inbox","body":"hello"}});
    assert_eq!(
        app.dispatch_http("POST", "/sendMessage", Some(&alice), &empty, &send)
            .await
            .unwrap()
            .status,
        200
    );
    let listed = app
        .dispatch_http(
            "POST",
            "/listMessages",
            Some(&alice),
            &empty,
            &json!({"messageBox":"inbox"}),
        )
        .await
        .unwrap();
    assert_eq!(listed.body["messages"][0]["messageId"], "one");
    assert_eq!(
        app.dispatch_http(
            "POST",
            "/acknowledgeMessage",
            Some(&alice),
            &empty,
            &json!({"messageIds":["one"]})
        )
        .await
        .unwrap()
        .status,
        200
    );
    assert_eq!(
        app.dispatch_http(
            "GET",
            "/permissions/list",
            Some(&alice),
            &empty,
            &json!({"limit":0})
        )
        .await
        .unwrap()
        .status,
        200
    );
}
