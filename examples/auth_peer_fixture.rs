//! Test-only stdio bridge for fixed SDK Peer interoperability. Never deploy.
#![allow(dead_code)]
mod fixture {
    #![allow(dead_code, unused_imports)]
    include!("../tests/auth_responder.rs");
    use std::io::{self, Write};

    pub async fn run() {
        let wallet = Wallet(secret(3));
        let path = std::env::var("AUTH_TEST_DB").expect("test database path is required");
        let store = message_box_server_rust::auth_store::SqliteAuthSessionStore::open(
            path,
            message_box_server_rust::auth_store::AuthStoreOptions::default(),
        )
        .await
        .expect("open test database");
        let responder = AuthResponder::new(&wallet, &store);
        loop {
            let mut line = String::new();
            if io::stdin().read_line(&mut line).unwrap() == 0 {
                break;
            }
            let message: Value = serde_json::from_str(&line).unwrap();
            let result = match message["messageType"].as_str() {
                Some("initialRequest") => match responder.accept_initial(&message).await {
                    Ok(response) => json!({"ok":true,"message":response.to_json()}),
                    Err(error) => json!({"ok":false,"error":format!("{error:?}")}),
                },
                Some("general") => {
                    // Test transport only: not HTTP frame binding. Never deploy.
                    let payload: Vec<u8> = message["payload"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap() as u8)
                        .collect();
                    match responder.accept_general(&message, &payload).await {
                        Ok(verified) => match responder
                            .sign_http_response(&verified, 200, &[("x-bsv-extra", "ok")], b"hello")
                            .await
                        {
                            Ok(response) => {
                                json!({"ok":true,"identity":verified.identity_key(),"payload":verified.payload(),"message":response.to_json()})
                            }
                            Err(error) => json!({"ok":false,"error":format!("{error:?}")}),
                        },
                        Err(error) => json!({"ok":false,"error":format!("{error:?}")}),
                    }
                }
                _ => json!({"ok":false,"error":"unsupported test message"}),
            };
            println!("{result}");
            io::stdout().flush().unwrap();
        }
    }
}
#[tokio::main]
async fn main() {
    fixture::run().await;
}
