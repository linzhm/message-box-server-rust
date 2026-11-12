use message_box_server_rust::websocket_registry::WebSocketRegistry;
use serde_json::{Value, json};
#[test]
fn state_transitions_match_executed_fixed_typescript() {
    let vectors: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/websocket_registry_vectors.json"
    ))
    .unwrap();
    let mut registry = WebSocketRegistry::default();
    for case in vectors["results"].as_array().unwrap() {
        let a = case["operation"].as_array().unwrap();
        let string = |i: usize| a[i].as_str().unwrap();
        let limit = |i: usize| a[i].as_i64().unwrap();
        let actual = match string(0) {
            "register" => json!(registry.register(string(1), limit(2))),
            "authenticate" => json!(registry.authenticate(string(1), string(2), limit(3))),
            "join" => json!(registry.join(string(1), string(2), limit(3))),
            "leave" => {
                registry.leave(string(1), string(2));
                Value::Null
            }
            "disconnect" => {
                registry.remove(string(1));
                Value::Null
            }
            "select" => json!(registry.recipient_sockets(string(1), string(2), limit(3))),
            "state" => {
                json!({"authenticated":registry.is_authenticated(string(1)),"identity":registry.identity(string(1)),"rooms":registry.room_count(string(1)),"connections":registry.connection_count()})
            }
            "sockets" => json!(registry.sockets()),
            "clear" => {
                registry.clear();
                Value::Null
            }
            other => panic!("unknown operation {other}"),
        };
        assert_eq!(actual, case["result"], "operation {a:?}");
    }
}

#[test]
fn rate_limit_windows_match_fixed_typescript() {
    use message_box_server_rust::websocket_registry::MinuteRateLimiter;
    let vectors: Value = serde_json::from_str(include_str!(
        "fixtures/sdk4/websocket_registry_vectors.json"
    ))
    .unwrap();
    for case in vectors["rates"].as_array().unwrap() {
        let mut limiter = MinuteRateLimiter::new(
            case["limit"].as_i64().unwrap(),
            case["start"].as_i64().unwrap(),
        );
        let results: Vec<_> = case["times"]
            .as_array()
            .unwrap()
            .iter()
            .map(|time| limiter.consume(time.as_i64().unwrap()))
            .collect();
        assert_eq!(json!(results), case["results"]);
    }
}
