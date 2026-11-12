use serde_json::json;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
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
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_message-box-server")
}
#[test]
fn refuses_invalid_or_incomplete_config_before_reporting_ready() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.json");
    for body in [
        json!({}),
        json!({"bind":"0.0.0.0:8080","dataDir":dir.path(),"identityKeyFile":dir.path().join("missing"),"freeBoxes":["inbox"]}),
        json!({"bind":"127.0.0.1:0","dataDir":dir.path(),"identityKeyFile":dir.path().join("missing"),"freeBoxes":["inbox"]}),
    ] {
        std::fs::write(&config, body.to_string()).unwrap();
        let output = Command::new(binary()).arg(&config).output().unwrap();
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "unexpected startup output: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
#[test]
fn starts_on_loopback_with_explicit_public_test_key_and_rejects_plain_request() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key = dir.path().join("test-key");
    let config = dir.path().join("config.json");
    std::fs::write(&key, format!("{}03\n", "00".repeat(31))).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&config,json!({"bind":"127.0.0.1:0","dataDir":dir.path(),"identityKeyFile":key,"freeBoxes":["inbox"]}).to_string()).unwrap();
    let child = Command::new(binary())
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = Guard(child);
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send((result, line));
    });
    let (result, line) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("runtime did not become ready");
    result.unwrap();
    if line.is_empty() {
        let mut stderr = String::new();
        child
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        panic!("runtime failed: {stderr}");
    }
    let ready: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(ready["status"], "ready");
    assert_eq!(
        ready["identityKey"],
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    );
    let address = ready["address"].as_str().unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET /devices HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    // Total field count includes Host and Connection. Above the parser limit,
    // no authenticated application response may be fabricated.
    for count in [100, 101, 1000, 1001] {
        let mut request =
            format!("GET /devices HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
        for index in 0..count - 2 {
            request.push_str(&format!("x-test-{index}: a\r\n"));
        }
        request.push_str("\r\n");
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(!headers.to_ascii_lowercase().contains("x-bsv-auth-"));
        if count <= 1000 {
            assert!(
                headers.starts_with("HTTP/1.1 401"),
                "count={count}: {response}"
            );
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(body).unwrap(),
                json!({"status":"error","code":"UNAUTHORIZED","description":"Mutual-authentication failed!"})
            );
        } else {
            assert!(headers.starts_with("HTTP/1.1 431"), "{response}");
            assert!(body.is_empty());
        }
    }
    assert!(dir.path().join("messages.sqlite").exists());
    assert!(dir.path().join("auth.sqlite").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for name in ["messages.sqlite", "auth.sqlite"] {
            assert_eq!(
                std::fs::metadata(dir.path().join(name)).unwrap().mode() & 0o777,
                0o600
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn sigint_drains_an_inflight_body_before_exiting() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = dir.path().join("key");
    std::fs::write(&key, format!("{}03\n", "00".repeat(31))).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = dir.path().join("config.json");
    std::fs::write(&config,json!({"bind":"127.0.0.1:0","dataDir":dir.path(),"identityKeyFile":key,"freeBoxes":["inbox"]}).to_string()).unwrap();
    let mut child = Guard(
        Command::new(binary())
            .arg(&config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    let address = ready["address"].as_str().unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(stream,"POST /.well-known/auth HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: 1\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n").unwrap();
    stream.flush().unwrap();
    let mut interim = [0u8; 25];
    stream.read_exact(&mut interim).unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    assert!(
        Command::new("kill")
            .args(["-s", "INT", &child.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    std::thread::sleep(Duration::from_millis(100));
    stream.write_all(b"{").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(child.0.wait().unwrap().success());
}
#[cfg(unix)]
#[test]
fn refuses_insecure_existing_paths_without_changing_permissions() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let parent = tempfile::tempdir().unwrap();
    let key = parent.path().join("key");
    std::fs::write(&key, format!("{}03\n", "00".repeat(31))).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let data = parent.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = parent.path().join("config.json");
    std::fs::write(
        &config,
        json!({"bind":"127.0.0.1:0","dataDir":data,"identityKeyFile":key,"freeBoxes":["inbox"]})
            .to_string(),
    )
    .unwrap();
    let result = Command::new(binary()).arg(&config).output().unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(std::fs::metadata(&data).unwrap().mode() & 0o777, 0o755);
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = data.join("messages.sqlite");
    std::fs::write(&db, []).unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
    let result = Command::new(binary()).arg(&config).output().unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(std::fs::metadata(&db).unwrap().mode() & 0o777, 0o644);
}
