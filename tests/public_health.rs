use http::{StatusCode, header::CACHE_CONTROL};
use message_box_server_rust::public_health::{health_response, readiness_response};
use serde_json::json;
#[test]
fn health_and_readiness_match_fixed_source_shapes_and_no_store() {
    let health = health_response("testnet");
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(health.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(health.body()).unwrap(),
        json!({"ok":true,"status":"ok","service":"messagebox-server","network":"testnet","websockets":false})
    );
    let ready = readiness_response(true);
    assert_eq!(ready.status(), StatusCode::OK);
    assert_eq!(ready.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(ready.body()).unwrap(),
        json!({"status":"ready"})
    );
    let failed = readiness_response(false);
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(failed.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(failed.body()).unwrap(),
        json!({"status":"error","code":"ERR_NOT_READY","description":"Message Box dependencies are not ready."})
    );
}
#[test]
fn matches_fixed_typescript_handler_observations() {
    let f: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sdk4/public_health_vectors.json")).unwrap();
    for (name, response) in [
        ("health", health_response("testnet")),
        ("healthz", health_response("testnet")),
        ("ready", readiness_response(true)),
        ("notReady", readiness_response(false)),
    ] {
        let expected = &f["cases"][name];
        assert_eq!(
            response.status().as_u16() as u64,
            expected["status"].as_u64().unwrap()
        );
        assert_eq!(
            response.headers()[CACHE_CONTROL],
            expected["headers"]["cache-control"].as_str().unwrap()
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
            expected["body"]
        );
    }
}

#[test]
fn reports_enabled_websocket_setting() {
    let response =
        message_box_server_rust::public_health::health_response_with_websockets("testnet", true);
    let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["websockets"], true);
}
