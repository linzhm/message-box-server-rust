use message_box_server_rust::firebase_init::{
    FirebaseBackend, FirebaseBackendError, FirebaseConfig, FirebaseInitError, FirebaseInitializer,
};
use serde_json::{Value, json};
use std::collections::HashMap;

struct FakeBackend {
    calls: Vec<String>,
    files: HashMap<String, String>,
    existing: bool,
    fail: String,
}
impl FirebaseBackend for FakeBackend {
    type App = String;
    type Credential = ();
    fn read_service_account(&mut self, path: &str) -> Result<String, FirebaseBackendError> {
        // The fake host resolves paths just as Node does for this fixture's /work cwd.
        let mut segments = Vec::new();
        let full = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/work/{path}")
        };
        for s in full.split('/') {
            match s {
                "" | "." => (),
                ".." => {
                    segments.pop();
                }
                _ => segments.push(s.to_owned()),
            }
        }
        let resolved = format!("/{}", segments.join("/"));
        self.calls.push(format!("read:{resolved}"));
        self.files
            .get(&resolved)
            .cloned()
            .ok_or(FirebaseBackendError)
    }
    fn certificate(
        &mut self,
        private_key: &str,
        client_email: &str,
        project: &str,
    ) -> Result<(), FirebaseBackendError> {
        assert_eq!(private_key, "fake-key");
        assert_eq!(client_email, "fake@example.test");
        self.calls.push(format!("cert:{project}"));
        if self.fail == "cert" {
            Err(FirebaseBackendError)
        } else {
            Ok(())
        }
    }
    fn default_credential(&mut self) -> Result<(), FirebaseBackendError> {
        self.calls.push("default".into());
        if self.fail == "default" {
            Err(FirebaseBackendError)
        } else {
            Ok(())
        }
    }
    fn has_apps(&mut self) -> Result<bool, FirebaseBackendError> {
        self.calls.push("getApps".into());
        if self.fail == "getApps" {
            Err(FirebaseBackendError)
        } else {
            Ok(self.existing)
        }
    }
    fn get_app(&mut self) -> Result<String, FirebaseBackendError> {
        self.calls.push("getApp".into());
        if self.fail == "getApp" {
            Err(FirebaseBackendError)
        } else {
            Ok("existing".into())
        }
    }
    fn initialize_app(&mut self, project: &str, _: ()) -> Result<String, FirebaseBackendError> {
        self.calls.push(format!("initialize:{project}"));
        if self.fail == "init" {
            Err(FirebaseBackendError)
        } else {
            self.existing = true;
            Ok("new".into())
        }
    }
}
fn error_name(error: FirebaseInitError) -> &'static str {
    match error {
        FirebaseInitError::MissingProject => "missing-project",
        FirebaseInitError::InvalidCredential => "invalid-credential",
        FirebaseInitError::FileRead => "read-failure",
        FirebaseInitError::Backend => "backend-failure",
    }
}
#[test]
fn fake_backend_matches_fixed_ts_initializer_scenarios() {
    let vectors: Value =
        serde_json::from_str(include_str!("fixtures/sdk4/firebase_init_vectors.json")).unwrap();
    assert_eq!(
        vectors["sourceBlob"],
        "e5871dab0061bd7970925249fd6839bf5de409fb"
    );
    for case in vectors["cases"].as_array().unwrap() {
        let input = &case["input"];
        let backend = FakeBackend {
            calls: vec![],
            files: input
                .get("files")
                .map(|v| serde_json::from_value(v.clone()).unwrap())
                .unwrap_or_default(),
            existing: input["existing"].as_bool().unwrap_or(false),
            fail: input["fail"].as_str().unwrap_or("").into(),
        };
        let mut initializer = FirebaseInitializer::new(backend);
        let mut results = vec![];
        for step in input["steps"].as_array().unwrap() {
            let config = FirebaseConfig {
                enabled: step["ENABLE_FIREBASE"].as_str(),
                project: step["FIREBASE_PROJECT_ID"].as_str(),
                service_account_json: step["FIREBASE_SERVICE_ACCOUNT_JSON"].as_str(),
                service_account_path: step["FIREBASE_SERVICE_ACCOUNT_PATH"].as_str(),
            };
            let result = match initializer.initialize(&config) {
                Ok(app) => json!({"app":app,"error":null}),
                Err(error) => json!({"app":null,"error":error_name(error)}),
            };
            results.push(result);
        }
        assert_eq!(json!(results), case["results"], "{}", input["name"]);
        assert_eq!(
            json!(initializer.backend().calls),
            case["calls"],
            "{}",
            input["name"]
        );
        assert_eq!(
            json!(initializer.app()),
            case["messaging"],
            "{}",
            input["name"]
        );
    }
}

#[test]
fn invalid_field_types_and_empty_values_do_not_fall_back() {
    for raw in [
        "null",
        "[]",
        "42",
        "{}",
        r#"{"private_key":4,"client_email":"x","project_id":"y"}"#,
        r#"{"private_key":"","client_email":"x","project_id":"y"}"#,
    ] {
        let backend = FakeBackend {
            calls: vec![],
            files: HashMap::new(),
            existing: false,
            fail: String::new(),
        };
        let mut initializer = FirebaseInitializer::new(backend);
        let result = initializer.initialize(&FirebaseConfig {
            enabled: Some("true"),
            project: Some("project"),
            service_account_json: Some(raw),
            service_account_path: Some("fake-path"),
        });
        assert_eq!(result, Err(FirebaseInitError::InvalidCredential));
        assert!(initializer.backend().calls.is_empty());
        assert!(initializer.app().is_none());
    }
}
