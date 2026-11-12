use message_box_server_rust::{
    resource_config::EnvironmentSnapshot,
    runtime_config::{CorsMode, RuntimeConfig},
};
use serde_json::json;

fn base() -> serde_json::Value {
    json!({"bind":"127.0.0.1:0","dataDir":"/tmp/messagebox-test","identityKeyFile":"/tmp/test-key","freeBoxes":["inbox"]})
}
fn env(pairs: &[(&str, &str)]) -> EnvironmentSnapshot {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

#[test]
fn environment_precedence_normalizes_mode_and_origins() {
    let settings = env(&[
        ("CORS_MODE", "disabled"),
        ("CORS_ALLOWED_ORIGINS", "https://fallback.invalid"),
        ("MESSAGE_BOX_CORS_MODE", " ALLOWLIST "),
        (
            "MESSAGE_BOX_CORS_ALLOWED_ORIGINS",
            "https://EXAMPLE.test:443, https://example.test, https://other.test",
        ),
    ]);
    let config = RuntimeConfig::parse_with_environment(&base(), &settings).unwrap();
    assert_eq!(
        config.cors.mode,
        CorsMode::Allowlist(vec![
            "https://example.test".into(),
            "https://example.test".into(),
            "https://other.test".into()
        ])
    );
    let fallback = env(&[
        ("MESSAGE_BOX_CORS_MODE", " "),
        ("CORS_MODE", " ALLOWLIST "),
        ("MESSAGE_BOX_CORS_ALLOWED_ORIGINS", " "),
        ("CORS_ALLOWED_ORIGINS", "https://fallback.invalid"),
    ]);
    assert_eq!(
        RuntimeConfig::parse_with_environment(&base(), &fallback)
            .unwrap()
            .cors
            .mode,
        CorsMode::Allowlist(vec!["https://fallback.invalid".into()])
    );
    let automatic = env(&[("MESSAGE_BOX_CORS_ALLOWED_ORIGINS", "https://example.test")]);
    assert_eq!(
        RuntimeConfig::parse_with_environment(&base(), &automatic)
            .unwrap()
            .cors
            .mode,
        CorsMode::Allowlist(vec!["https://example.test".into()])
    );
}

#[test]
fn invalid_origins_modes_and_wildcard_fail_before_startup() {
    for settings in [
        env(&[("MESSAGE_BOX_CORS_ALLOWED_ORIGINS", "*")]),
        env(&[("MESSAGE_BOX_CORS_ALLOWED_ORIGINS", "null")]),
        env(&[
            ("MESSAGE_BOX_CORS_MODE", "public"),
            ("CORS_ALLOWED_ORIGINS", "https://example.test"),
        ]),
        env(&[("MESSAGE_BOX_CORS_MODE", "allowlist")]),
        env(&[("MESSAGE_BOX_CORS_MODE", "unknown")]),
        env(&[("MESSAGE_BOX_CORS_ALLOWED_HEADERS", "*")]),
        env(&[("MESSAGE_BOX_CORS_EXPOSED_HEADERS", "ok\r\nbad")]),
    ] {
        assert!(
            RuntimeConfig::parse_with_environment(&base(), &settings).is_err(),
            "{settings:?}"
        );
    }
}

#[test]
fn explicit_json_policy_overrides_environment_and_header_lists_are_separate() {
    let mut value = base();
    value["corsAllowedOrigins"] = json!(["https://json.test"]);
    let settings = env(&[
        ("MESSAGE_BOX_CORS_MODE", "disabled"),
        ("MESSAGE_BOX_CORS_ALLOWED_HEADERS", "X-One, X-Two, X-One"),
        ("MESSAGE_BOX_CORS_EXPOSED_HEADERS", "X-Reply, X-Other"),
    ]);
    let cors = RuntimeConfig::parse_with_environment(&value, &settings)
        .unwrap()
        .cors;
    assert_eq!(
        cors.mode,
        CorsMode::Allowlist(vec!["https://json.test".into()])
    );
    assert_eq!(cors.allowed_headers.as_deref(), Some("X-One, X-Two"));
    assert_eq!(cors.exposed_headers.as_deref(), Some("X-Reply, X-Other"));
    let empty = RuntimeConfig::parse_with_environment(
        &base(),
        &env(&[("MESSAGE_BOX_CORS_ALLOWED_HEADERS", "  ")]),
    )
    .unwrap();
    assert!(empty.cors.allowed_headers.is_none());
}

#[test]
fn empty_query_and_fragment_delimiters_match_typescript_url_semantics() {
    use message_box_server_rust::runtime_config::normalize_cors_origin;

    for origin in [
        "https://EXAMPLE.test:443?",
        "https://EXAMPLE.test:443#",
        "https://EXAMPLE.test:443?#",
    ] {
        assert_eq!(
            normalize_cors_origin(origin).as_deref(),
            Some("https://example.test"),
            "{origin}"
        );
        let settings = env(&[("MESSAGE_BOX_CORS_ALLOWED_ORIGINS", origin)]);
        assert_eq!(
            RuntimeConfig::parse_with_environment(&base(), &settings)
                .unwrap()
                .cors
                .mode,
            CorsMode::Allowlist(vec!["https://example.test".into()]),
            "{origin}"
        );
        let mut config = base();
        config["corsAllowedOrigins"] = json!([origin]);
        assert_eq!(
            RuntimeConfig::parse(&config).unwrap().cors.mode,
            CorsMode::Allowlist(vec!["https://example.test".into()]),
            "{origin}"
        );
    }
    for origin in [
        "https://example.test?x",
        "https://example.test#x",
        "https://example.test?x#",
        "https://example.test?#x",
    ] {
        assert_eq!(normalize_cors_origin(origin), None, "{origin}");
        assert!(
            RuntimeConfig::parse_with_environment(
                &base(),
                &env(&[("MESSAGE_BOX_CORS_ALLOWED_ORIGINS", origin)])
            )
            .is_err(),
            "{origin}"
        );
    }
}
