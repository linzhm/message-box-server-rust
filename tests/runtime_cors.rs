use serde_json::json;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

struct Server {
    child: Child,
    address: String,
    _dir: tempfile::TempDir,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Server {
    fn start() -> Self {
        Self::configured(json!({}))
    }
    fn configured(extra: serde_json::Value) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = dir.path().join("test-key");
        std::fs::write(&key, format!("{}03\n", "00".repeat(31))).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = dir.path().join("config.json");
        let mut config_value = json!({"bind":"127.0.0.1:0", "dataDir":dir.path(), "identityKeyFile":key, "freeBoxes":["inbox"]});
        config_value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        std::fs::write(&config, config_value.to_string()).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_message-box-server"))
            .arg(config)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).unwrap();
            tx.send(line).unwrap();
        });
        let line = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        Self {
            child,
            address: ready["address"].as_str().unwrap().to_owned(),
            _dir: dir,
        }
    }
    fn request(&self, request: &str) -> String {
        let mut stream = TcpStream::connect(&self.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "{request}\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.address
        )
        .unwrap();
        let mut result = String::new();
        stream.read_to_string(&mut result).unwrap();
        result.to_ascii_lowercase()
    }
}
#[test]
fn public_preflight_precedes_auth_and_reflects_valid_header_names() {
    let server = Server::start();
    let r = server.request("OPTIONS /listMessages HTTP/1.1\r\nOrigin: https://example.test\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type, x-bsv-auth-signature, x-client-extra");
    assert!(r.starts_with("http/1.1 204"), "{r}");
    for expected in [
        "access-control-allow-origin: *",
        "access-control-allow-methods: get, post, options",
        "access-control-allow-headers:",
        "x-bsv-auth-signature",
        "x-client-extra",
        "access-control-expose-headers: etag, ratelimit, ratelimit-policy, retry-after, x-bsv-auth-identity-key, x-bsv-auth-message-type, x-bsv-auth-nonce, x-bsv-auth-request-id, x-bsv-auth-requested-certificates, x-bsv-auth-signature",
        "x-bsv-auth-identity-key",
        "access-control-max-age: 600",
    ] {
        assert!(r.contains(expected), "missing {expected}: {r}");
    }
    assert!(!r.contains("access-control-allow-credentials:"));
    let invalid = server.request("OPTIONS /devices HTTP/1.1\r\nOrigin: https://example.test\r\nAccess-Control-Request-Headers: x-okay, bad name");
    assert!(invalid.contains("x-okay"), "{invalid}");
    assert!(!invalid.contains("bad name"), "{invalid}");
}
#[test]
fn ordinary_auth_response_has_exposed_headers_only_when_origin_present() {
    let server = Server::start();
    let r = server.request("GET /devices HTTP/1.1\r\nOrigin: null");
    assert!(r.starts_with("http/1.1 401"), "{r}");
    assert!(r.contains("access-control-allow-origin: *"), "{r}");
    assert!(r.contains("x-bsv-auth-signature"), "{r}");
    let no_origin = server.request("GET /devices HTTP/1.1");
    assert!(no_origin.starts_with("http/1.1 401"), "{no_origin}");
    assert!(!no_origin.contains("access-control-"), "{no_origin}");
    let options = server.request("OPTIONS /devices HTTP/1.1");
    assert!(!options.starts_with("http/1.1 204"), "{options}");
    assert!(!options.contains("access-control-"), "{options}");
}

#[test]
fn explicit_allowlist_and_disabled_modes() {
    let server = Server::configured(
        json!({"corsMode":"allowlist", "corsAllowedOrigins":["https://EXAMPLE.test:443"]}),
    );
    let allowed = server.request("OPTIONS /devices HTTP/1.1\r\nOrigin: https://example.test");
    assert!(allowed.starts_with("http/1.1 204"), "{allowed}");
    assert!(
        allowed.contains("access-control-allow-origin: https://example.test"),
        "{allowed}"
    );
    assert!(allowed.contains("vary: origin"), "{allowed}");
    for origin in ["https://other.test", "null", "https://example.test/path"] {
        let denied = server.request(&format!("GET /devices HTTP/1.1\r\nOrigin: {origin}"));
        assert!(denied.starts_with("http/1.1 403"), "{denied}");
        assert!(denied.contains("err_origin_not_allowed"), "{denied}");
        assert!(!denied.contains("access-control-allow-origin:"), "{denied}");
    }
    let disabled = Server::configured(json!({"corsMode":"disabled"}));
    let denied = disabled.request("OPTIONS /devices HTTP/1.1\r\nOrigin: https://example.test");
    assert!(denied.starts_with("http/1.1 403"), "{denied}");
    let no_origin = disabled.request("GET /devices HTTP/1.1");
    assert!(no_origin.starts_with("http/1.1 401"), "{no_origin}");
}
