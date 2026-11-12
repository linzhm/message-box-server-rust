//! Actual executable startup with isolated process environments and synthetic
//! service accounts. No send is requested, so no OAuth/FCM network is used.
#![cfg(unix)]
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn account() -> String {
    json!({"type":"service_account", "project_id":"fake-credential-project", "client_email":"synthetic@example.test", "private_key": format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", STANDARD.encode(include_bytes!("fixtures/fcm-synthetic-rsa.pk8")))}).to_string()
}
fn command(root: &std::path::Path) -> Command {
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = root.join("identity.key");
    std::fs::write(&key, format!("{}03", "00".repeat(31))).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = root.join("config.json");
    std::fs::write(
        &config,
        json!({"bind":"127.0.0.1:0", "dataDir":root, "identityKeyFile":key, "freeBoxes":["inbox"]})
            .to_string(),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_message-box-server"));
    cmd.env_clear()
        .env("HOME", root)
        .current_dir(root)
        .arg(config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}
fn ready(mut cmd: Command) {
    let mut child = Guard(cmd.spawn().unwrap());
    let out = child.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(out).read_line(&mut line);
        let _ = tx.send((result, line));
    });
    let (read, line) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("startup must be bounded");
    read.unwrap();
    assert!(!line.is_empty(), "runtime did not become ready");
    let value: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(value["status"], "ready");
    assert!(!line.contains("PRIVATE KEY") && !line.contains("synthetic@example.test"));
}
#[test]
fn executable_enabled_accepts_explicit_json_file_and_adc_service_accounts() {
    for source in ["json", "file", "adc", "well-known"] {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = command(dir.path());
        cmd.env("ENABLE_FIREBASE", "true")
            .env("FIREBASE_PROJECT_ID", "fake-target-project");
        match source {
            "json" => {
                cmd.env("FIREBASE_SERVICE_ACCOUNT_JSON", account())
                    .env("GOOGLE_APPLICATION_CREDENTIALS", "missing.json");
            }
            "file" => {
                std::fs::write(dir.path().join("service.json"), account()).unwrap();
                cmd.env("FIREBASE_SERVICE_ACCOUNT_PATH", "service.json");
            }
            "adc" => {
                std::fs::write(dir.path().join("adc.json"), account()).unwrap();
                cmd.env("GOOGLE_APPLICATION_CREDENTIALS", "adc.json");
            }
            _ => {
                std::fs::create_dir_all(dir.path().join(".config/gcloud")).unwrap();
                std::fs::write(
                    dir.path()
                        .join(".config/gcloud/application_default_credentials.json"),
                    account(),
                )
                .unwrap();
            }
        }
        ready(cmd);
    }
}
#[test]
fn executable_disabled_skips_bad_credentials_and_adc() {
    for enabled in [None, Some("false"), Some("TRUE"), Some(" true ")] {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = command(dir.path());
        if let Some(value) = enabled {
            cmd.env("ENABLE_FIREBASE", value);
        }
        cmd.env("FIREBASE_SERVICE_ACCOUNT_JSON", "broken-fake-secret")
            .env("GOOGLE_APPLICATION_CREDENTIALS", "missing-adc.json");
        ready(cmd);
    }
}
#[test]
fn executable_enabled_bad_configuration_fails_before_ready_without_secret_output() {
    for (project, json, adc) in [
        (None, None, None),
        (Some("fake-project"), Some("broken-fake-secret"), None),
        (Some("fake-project"), None, Some("missing-adc.json")),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = command(dir.path());
        cmd.env("ENABLE_FIREBASE", "true");
        if let Some(v) = project {
            cmd.env("FIREBASE_PROJECT_ID", v);
        }
        if let Some(v) = json {
            cmd.env("FIREBASE_SERVICE_ACCOUNT_JSON", v);
        }
        if let Some(v) = adc {
            cmd.env("GOOGLE_APPLICATION_CREDENTIALS", v);
        }
        let mut child = Guard(cmd.spawn().unwrap());
        for _ in 0..200 {
            if child.0.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(child.0.try_wait().unwrap().is_some_and(|s| !s.success()));
        let mut out = String::new();
        child
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        let mut err = String::new();
        child
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        assert!(out.is_empty());
        assert!(!err.contains("fake-secret"));
        assert!(err.contains("MessageBox startup or runtime failed"));
    }
}
