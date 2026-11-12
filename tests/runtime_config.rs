use k256::elliptic_curve::sec1::ToEncodedPoint;
use message_box_server_rust::{
    DeliveryPolicy, Identity,
    runtime_config::{FreeBoxPolicy, RuntimeConfig},
};
use serde_json::json;
const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
#[test]
fn explicit_loopback_config_requires_identity_path_data_directory_and_free_scope() {
    let valid = json!({"bind":"127.0.0.1:0","dataDir":"/tmp/messagebox-test","identityKeyFile":"/tmp/test-only-key","freeBoxes":["inbox","test-box"]});
    let config = RuntimeConfig::parse(&valid).unwrap();
    assert!(config.bind.ip().is_loopback());
    for key in ["bind", "dataDir", "identityKeyFile", "freeBoxes"] {
        let mut invalid = valid.clone();
        invalid.as_object_mut().unwrap().remove(key);
        assert!(RuntimeConfig::parse(&invalid).is_err(), "{key}");
    }
    let mut invalid = valid.clone();
    invalid["bind"] = json!("0.0.0.0:8080");
    assert!(RuntimeConfig::parse(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid["dataDir"] = json!("relative");
    assert!(RuntimeConfig::parse(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid["freeBoxes"] = json!(["inbox", "inbox"]);
    assert!(RuntimeConfig::parse(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid["unexpected"] = json!(true);
    assert!(RuntimeConfig::parse(&invalid).is_err());
}
#[test]
fn free_box_policy_denies_unconfigured_boxes() {
    let policy = FreeBoxPolicy::new(["inbox".to_owned()]);
    let owner = Identity::from_verified_key(KEY).unwrap();
    assert!(policy.evaluate(&owner, KEY, "inbox").is_ok());
    assert_eq!(policy.delivery_fee("inbox").unwrap(), 0);
    assert!(policy.evaluate(&owner, KEY, "other").is_err());
    assert!(policy.delivery_fee("other").is_err());
}
#[test]
fn key_file_requires_exact_nonzero_32_byte_hex_without_logging_contents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    assert!(message_box_server_rust::runtime_config::load_identity_key(&path).is_err());
    std::fs::write(&path, "not-hex-secret").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(message_box_server_rust::runtime_config::load_identity_key(&path).is_err());
    std::fs::write(&path, "00".repeat(32)).unwrap();
    assert!(message_box_server_rust::runtime_config::load_identity_key(&path).is_err());
    std::fs::write(&path, format!("{}01\n", "00".repeat(31))).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(message_box_server_rust::runtime_config::load_identity_key(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let key = message_box_server_rust::runtime_config::load_identity_key(&path).unwrap();
    assert_eq!(
        hex::encode(key.public_key().to_encoded_point(true).as_bytes()),
        KEY
    );
}
#[cfg(unix)]
#[test]
fn private_storage_creation_and_existing_permissions_are_enforced() {
    use message_box_server_rust::runtime_config::{
        prepare_private_database, prepare_private_directory,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let parent = tempfile::tempdir().unwrap();
    let directory = parent.path().join("new-private");
    prepare_private_directory(&directory).unwrap();
    assert_eq!(std::fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
    let db = directory.join("messages.sqlite");
    prepare_private_database(&db).unwrap();
    assert_eq!(std::fs::metadata(&db).unwrap().mode() & 0o777, 0o600);
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(prepare_private_database(&db).is_err());
    assert_eq!(std::fs::metadata(&db).unwrap().mode() & 0o777, 0o644);
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(prepare_private_directory(&directory).is_err());
    assert_eq!(std::fs::metadata(&directory).unwrap().mode() & 0o777, 0o755);
}

#[test]
fn websocket_configuration_is_explicit_and_optional() {
    let mut config = json!({"bind":"127.0.0.1:0","dataDir":"/tmp/messagebox-test","identityKeyFile":"/tmp/test-only-key","freeBoxes":["inbox"]});
    assert!(!RuntimeConfig::parse(&config).unwrap().enable_websockets);
    config["enableWebSockets"] = json!(true);
    assert!(RuntimeConfig::parse(&config).unwrap().enable_websockets);
    config["enableWebSockets"] = json!("true");
    assert!(RuntimeConfig::parse(&config).is_err());
}

#[test]
fn optional_routing_prefix_is_a_canonical_restricted_path() {
    use message_box_server_rust::http_auth::RoutingPrefix;
    let mut config = json!({"bind":"127.0.0.1:0","dataDir":"/tmp/messagebox-test","identityKeyFile":"/tmp/test-only-key","freeBoxes":["inbox"]});
    assert_eq!(
        RuntimeConfig::parse(&config).unwrap().routing_prefix,
        RoutingPrefix::default()
    );
    for value in ["/mb", "/mb/v1", "/box-test_1/~x"] {
        config["routingPrefix"] = json!(value);
        assert_eq!(
            RuntimeConfig::parse(&config).unwrap().routing_prefix,
            RoutingPrefix::parse(value).unwrap()
        );
    }
    for value in [
        "/", "mb", "/mb/", "/mb//v1", "/./x", "/../x", "/mb?x=1", "/a%2Fb", "/猫",
    ] {
        config["routingPrefix"] = json!(value);
        assert!(RuntimeConfig::parse(&config).is_err(), "{value}");
    }
    config["routingPrefix"] = json!(true);
    assert!(RuntimeConfig::parse(&config).is_err());
}

#[test]
fn ts_fee_table_mode_is_explicit_and_does_not_override_free_allowlist() {
    use message_box_server_rust::runtime_config::PricingMode;
    let mut config = json!({"bind":"127.0.0.1:0","dataDir":"/tmp/messagebox-test","identityKeyFile":"/tmp/test-only-key","freeBoxes":["inbox"]});
    assert_eq!(
        RuntimeConfig::parse(&config).unwrap().pricing_mode,
        PricingMode::FreeBoxes
    );
    config["pricingMode"] = json!("ts-table");
    assert!(RuntimeConfig::parse(&config).is_err());
    config.as_object_mut().unwrap().remove("freeBoxes");
    assert_eq!(
        RuntimeConfig::parse(&config).unwrap().pricing_mode,
        PricingMode::TsTable
    );
    config["pricingMode"] = json!("unknown");
    assert!(RuntimeConfig::parse(&config).is_err());
}

#[test]
fn cors_mode_requires_consistent_explicit_configuration() {
    let base = json!({"bind":"127.0.0.1:0","dataDir":"/tmp/messagebox-test","identityKeyFile":"/tmp/test-only-key","freeBoxes":["inbox"]});
    for extra in [
        json!({"corsMode":"allowlist"}),
        json!({"corsMode":"public","corsAllowedOrigins":["https://example.test"]}),
        json!({"corsMode":"disabled","corsAllowedOrigins":["https://example.test"]}),
        json!({"corsMode":"allowlist","corsAllowedOrigins":["null"]}),
        json!({"corsMode":"allowlist","corsAllowedOrigins":["https://example.test/path"]}),
        json!({"corsMode":"allowlist","corsAllowedOrigins":["https://u:p@example.test"]}),
        json!({"corsMode":"bogus"}),
        json!({"corsMode":true}),
    ] {
        let mut input = base.clone();
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert!(RuntimeConfig::parse(&input).is_err(), "{input}");
    }
    let mut input = base;
    input["corsMode"] = json!("allowlist");
    input["corsAllowedOrigins"] = json!(["https://EXAMPLE.test:443"]);
    assert!(
        matches!(RuntimeConfig::parse(&input).unwrap().cors.mode, message_box_server_rust::runtime_config::CorsMode::Allowlist(origins) if origins == ["https://example.test"])
    );
}

#[test]
fn ts_port_defaults_precedence_and_boundaries() {
    use message_box_server_rust::{
        resource_config::EnvironmentSnapshot, runtime_config::resolve_http_port,
    };
    assert_eq!(
        resolve_http_port(&EnvironmentSnapshot::new()).unwrap(),
        8080
    );
    for (port, fallback, expected) in [
        ("", "1234", 1234),
        ("\u{feff}00080\u{feff}", "bad", 80),
        ("65535", "1", 65535),
    ] {
        let env = EnvironmentSnapshot::from([
            ("PORT".into(), port.into()),
            ("HTTP_PORT".into(), fallback.into()),
        ]);
        assert_eq!(resolve_http_port(&env).unwrap(), expected);
    }
    for value in ["0", "65536", "1.0", "1e2", "-1", "+80", "\u{0085}80"] {
        let env = EnvironmentSnapshot::from([
            ("PORT".into(), value.into()),
            ("HTTP_PORT".into(), "80".into()),
        ]);
        assert_eq!(
            resolve_http_port(&env).unwrap_err(),
            "PORT must be an integer between 1 and 65535."
        );
    }
}
