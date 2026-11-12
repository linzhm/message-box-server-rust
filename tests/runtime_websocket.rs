#![cfg(unix)]
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
struct Server {
    child: Child,
    _dir: tempfile::TempDir,
    address: String,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn start() -> Server {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = dir.path().join("key");
    std::fs::write(&key, format!("{}03\n", "00".repeat(31))).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = dir.path().join("config.json");
    std::fs::write(&config,json!({"bind":"127.0.0.1:0","dataDir":dir.path(),"identityKeyFile":key,"freeBoxes":["inbox"],"enableWebSockets":true}).to_string()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_message-box-server"))
        .arg(config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let ready: Value = serde_json::from_str(&line).unwrap();
    let address = ready["address"].as_str().unwrap().to_owned();
    Server {
        child,
        _dir: dir,
        address,
    }
}
fn request(address: &str, path: &str, version: &str, key: &str, extra: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(stream,"GET {path} HTTP/{version}\r\nHost: {address}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n{extra}\r\n").unwrap();
    let mut data = [0u8; 1024];
    let n = stream.read(&mut data).unwrap();
    String::from_utf8_lossy(&data[..n]).into_owned()
}
#[test]
fn rejects_invalid_websocket_upgrade_requests() {
    let server = start();
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let valid = "/socket.io/?EIO=4&transport=websocket";
    for (path, version, key, extra) in [
        (valid, "1.1", "bad", ""),
        (valid, "1.0", key, ""),
        (
            "/socket.io/?EIO=4&EIO=3&transport=websocket",
            "1.1",
            key,
            "",
        ),
        (
            "/socket.io/?EIO=4&transport=websocket&sid=old",
            "1.1",
            key,
            "",
        ),
    ] {
        let response = request(&server.address, path, version, key, extra);
        assert_ne!(
            response.split_whitespace().nth(1),
            Some("101"),
            "{response}"
        );
    }
}
#[tokio::test]
async fn supports_control_ping_before_and_after_namespace_and_closes_idle_namespace() {
    let server = start();
    let url = format!(
        "ws://{}/socket.io/?EIO=4&transport=websocket",
        server.address
    );
    let (mut ws, _) = connect_async(&url).await.unwrap();
    assert!(
        ws.next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .starts_with('0')
    );
    ws.send(Message::Ping(vec![1, 2])).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::Pong(vec![1, 2]));
    ws.send(Message::Text("40".into())).await.unwrap();
    assert!(
        ws.next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .starts_with("40")
    );
    ws.send(Message::Ping(vec![3])).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::Pong(vec![3]));
    let (mut idle, _) = connect_async(&url).await.unwrap();
    assert!(
        idle.next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .starts_with('0')
    );
    let closed = tokio::time::timeout(Duration::from_secs(23), idle.next())
        .await
        .expect("idle namespace was not closed");
    assert!(matches!(
        closed,
        None | Some(Ok(Message::Close(_))) | Some(Err(_))
    ));
    ws.close(None).await.unwrap();
}

#[tokio::test]
async fn rejects_oversized_single_and_fragmented_websocket_messages() {
    use tokio_tungstenite::tungstenite::protocol::frame::{
        Frame,
        coding::{Data, OpCode},
    };
    let server = start();
    let url = format!(
        "ws://{}/socket.io/?EIO=4&transport=websocket",
        server.address
    );
    for fragmented in [false, true] {
        let (mut ws, _) = connect_async(&url).await.unwrap();
        let _ = ws.next().await.unwrap().unwrap();
        ws.send(Message::Text("40".into())).await.unwrap();
        let _ = ws.next().await.unwrap().unwrap();
        if fragmented {
            ws.send(Message::Frame(Frame::message(
                vec![b'a'; 524_289],
                OpCode::Data(Data::Text),
                false,
            )))
            .await
            .unwrap();
            let _ = ws
                .send(Message::Frame(Frame::message(
                    vec![b'a'; 524_289],
                    OpCode::Data(Data::Continue),
                    true,
                )))
                .await;
        } else {
            let _ = ws.send(Message::Text("a".repeat(1_048_577))).await;
        }
        let result = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("oversized message left socket open");
        assert!(
            matches!(result, None | Some(Err(_)) | Some(Ok(Message::Close(_)))),
            "{result:?}"
        );
    }
}

#[tokio::test]
async fn shutdown_closes_upgraded_websocket_and_exits() {
    let mut server = start();
    let url = format!(
        "ws://{}/socket.io/?EIO=4&transport=websocket",
        server.address
    );
    let (mut ws, _) = connect_async(&url).await.unwrap();
    let _ = ws.next().await.unwrap().unwrap();
    ws.send(Message::Text("40".into())).await.unwrap();
    let _ = ws.next().await.unwrap().unwrap();
    assert!(
        Command::new("kill")
            .args(["-s", "INT", &server.child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let result = tokio::time::timeout(Duration::from_secs(6), ws.next())
        .await
        .expect("socket did not close on shutdown");
    assert!(matches!(
        result,
        None | Some(Ok(Message::Close(_))) | Some(Err(_))
    ));
    let status = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if let Some(status) = server.child.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("server did not exit");
    assert!(status.success());
}
