use k256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use message_box_server_rust::{
    auth_nonce::{HmacCheckError, NonceHmacRequest, NonceWallet, create_nonce},
    auth_responder::{AuthResponder, AuthSession, AuthSessionStore, AuthWallet, ResponderError},
    brc42,
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};
fn secret(n: u8) -> SecretKey {
    let mut b = [0u8; 32];
    b[31] = n;
    SecretKey::from_slice(&b).unwrap()
}
fn key(s: &SecretKey) -> String {
    hex::encode(s.public_key().to_encoded_point(true).as_bytes())
}
struct Wallet(SecretKey);
#[derive(Debug, PartialEq)]
struct WalletError;
impl NonceWallet for Wallet {
    type Error = WalletError;
    async fn create_hmac(&self, r: &NonceHmacRequest) -> Result<[u8; 32], Self::Error> {
        brc42::create_hmac(
            &self.0,
            &self.0.public_key(),
            &format!("2-server hmac-{}", r.key_id),
            &r.data,
        )
        .map_err(|_| WalletError)
    }
    async fn verify_hmac(
        &self,
        r: &NonceHmacRequest,
        h: &[u8; 32],
    ) -> Result<bool, HmacCheckError<Self::Error>> {
        brc42::verify_hmac(
            &self.0,
            &self.0.public_key(),
            &format!("2-server hmac-{}", r.key_id),
            &r.data,
            h,
        )
        .map_err(|_| HmacCheckError::Other(WalletError))
    }
}
impl AuthWallet for Wallet {
    async fn identity_key(&self) -> Result<String, Self::Error> {
        Ok(key(&self.0))
    }
    async fn sign_auth(
        &self,
        peer: &str,
        key_id: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let p = PublicKey::from_sec1_bytes(&hex::decode(peer).map_err(|_| WalletError)?)
            .map_err(|_| WalletError)?;
        brc42::sign_message(
            &self.0,
            &p,
            &format!("2-auth message signature-{key_id}"),
            data,
        )
        .map_err(|_| WalletError)
    }
    async fn verify_auth(
        &self,
        peer: &str,
        key_id: &str,
        data: &[u8],
        sig: &[u8],
    ) -> Result<bool, Self::Error> {
        let p = PublicKey::from_sec1_bytes(&hex::decode(peer).map_err(|_| WalletError)?)
            .map_err(|_| WalletError)?;
        brc42::verify_message(
            &self.0,
            &p,
            &format!("2-auth message signature-{key_id}"),
            data,
            sig,
        )
        .map_err(|_| WalletError)
    }
}
#[derive(Default)]
struct MemoryStore {
    initial: Mutex<HashSet<(String, String)>>,
    sessions: Mutex<HashMap<String, AuthSession>>,
    claims: Mutex<HashSet<(String, String)>>,
}
#[derive(Debug, PartialEq)]
struct StoreError;
impl AuthSessionStore for MemoryStore {
    type Error = StoreError;
    async fn claim_initial(&self, identity: &str, nonce: &str) -> Result<bool, Self::Error> {
        Ok(self
            .initial
            .lock()
            .unwrap()
            .insert((identity.into(), nonce.into())))
    }
    async fn add_session(&self, session: AuthSession) -> Result<(), Self::Error> {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.entry(session.session_nonce.clone()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(session);
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => Err(StoreError),
        }
    }
    async fn get_session(&self, nonce: &str) -> Result<Option<AuthSession>, Self::Error> {
        Ok(self.sessions.lock().unwrap().get(nonce).cloned())
    }
    async fn claim_message(&self, session: &str, nonce: &str) -> Result<bool, Self::Error> {
        if !self.sessions.lock().unwrap().contains_key(session) {
            return Err(StoreError);
        }
        Ok(self
            .claims
            .lock()
            .unwrap()
            .insert((session.into(), nonce.into())))
    }
    async fn mark_authenticated(&self, nonce: &str) -> Result<(), Self::Error> {
        self.sessions
            .lock()
            .unwrap()
            .get_mut(nonce)
            .ok_or(StoreError)?
            .authenticated = true;
        Ok(())
    }
}
async fn pair() -> (Wallet, Wallet, MemoryStore, Value) {
    let client = Wallet(secret(2));
    let server = Wallet(secret(3));
    let store = MemoryStore::default();
    let nonce = create_nonce(&client, "self", None).await.unwrap();
    let initial = json!({"version":"0.1","messageType":"initialRequest","identityKey":key(&client.0),"initialNonce":nonce,"requestedCertificates":{"certifiers":[],"types":{}}});
    (client, server, store, initial)
}
fn decode64(s: &str) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.decode(s).unwrap()
}
#[tokio::test]
async fn initial_request_is_not_authentication_and_valid_general_is_verified_once() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (client, server, store, initial) = pair().await;
    let r = AuthResponder::new(&server, &store);
    let response = r.accept_initial(&initial).await.unwrap();
    let session = store
        .get_session(&response.initial_nonce)
        .await
        .unwrap()
        .unwrap();
    assert!(!session.authenticated);
    let client_nonce = initial["initialNonce"].as_str().unwrap();
    let mut signed = decode64(client_nonce);
    signed.extend(decode64(&response.initial_nonce));
    assert!(
        client
            .verify_auth(
                &key(&server.0),
                &format!("{client_nonce} {}", response.initial_nonce),
                &signed,
                &response.signature
            )
            .await
            .unwrap()
    );
    let nonce = STANDARD.encode([9u8; 32]);
    let frame = b"bound request frame";
    let signature = client
        .sign_auth(
            &key(&server.0),
            &format!("{nonce} {}", response.initial_nonce),
            frame,
        )
        .await
        .unwrap();
    let msg = json!({"version":"0.1","messageType":"general","identityKey":key(&client.0),"nonce":nonce,"yourNonce":response.initial_nonce,"payload":frame,"signature":signature});
    let verified = r.accept_general(&msg, frame).await.unwrap();
    assert_eq!(verified.identity_key(), key(&client.0));
    assert_eq!(verified.payload(), frame);
    assert!(
        store
            .get_session(&response.initial_nonce)
            .await
            .unwrap()
            .unwrap()
            .authenticated
    );
    assert!(matches!(
        r.accept_general(&msg, frame).await,
        Err(ResponderError::Replay)
    ));
}
#[tokio::test]
async fn rejects_untrusted_or_malformed_inputs_before_authentication() {
    let (_client, server, store, initial) = pair().await;
    let r = AuthResponder::new(&server, &store);
    let mut unsupported = initial.clone();
    unsupported["requestedCertificates"]["certifiers"] = json!([key(&secret(7))]);
    assert!(matches!(
        r.accept_initial(&unsupported).await,
        Err(ResponderError::UnsupportedCertificates)
    ));
    let mut oversized = initial.clone();
    oversized["initialNonce"] = json!("A".repeat(1_000_000));
    assert!(matches!(
        r.accept_initial(&oversized).await,
        Err(ResponderError::InvalidMessage)
    ));
    assert!(store.initial.lock().unwrap().is_empty());
    let mut invalid = initial.clone();
    invalid["identityKey"] = json!(key(&secret(2)).to_uppercase());
    assert!(matches!(
        r.accept_initial(&invalid).await,
        Err(ResponderError::InvalidMessage)
    ));
    let response = r.accept_initial(&initial).await.unwrap();
    assert!(matches!(
        r.accept_initial(&initial).await,
        Err(ResponderError::Replay)
    ));
    let mut msg = json!({"version":"0.1","messageType":"general","identityKey":key(&secret(2)),"nonce":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=","yourNonce":response.initial_nonce,"payload":[1],"signature":[1]});
    assert!(matches!(
        r.accept_general(&msg, &[2]).await,
        Err(ResponderError::FrameMismatch)
    ));
    assert!(matches!(
        r.accept_general(&msg, &[1]).await,
        Err(ResponderError::InvalidProof)
    ));
    msg["identityKey"] = json!(key(&secret(4)));
    assert!(matches!(
        r.accept_general(&msg, &[1]).await,
        Err(ResponderError::IdentityMismatch)
    ));
    assert!(
        !store
            .get_session(&response.initial_nonce)
            .await
            .unwrap()
            .unwrap()
            .authenticated
    );
}

struct FailingStore<'a> {
    inner: &'a MemoryStore,
    fail: &'static str,
}
impl AuthSessionStore for FailingStore<'_> {
    type Error = StoreError;
    async fn claim_initial(&self, identity: &str, nonce: &str) -> Result<bool, Self::Error> {
        if self.fail == "initial" {
            Err(StoreError)
        } else {
            self.inner.claim_initial(identity, nonce).await
        }
    }
    async fn add_session(&self, session: AuthSession) -> Result<(), Self::Error> {
        if self.fail == "add" {
            Err(StoreError)
        } else {
            self.inner.add_session(session).await
        }
    }
    async fn get_session(&self, nonce: &str) -> Result<Option<AuthSession>, Self::Error> {
        if self.fail == "get" {
            Err(StoreError)
        } else {
            self.inner.get_session(nonce).await
        }
    }
    async fn claim_message(&self, session: &str, nonce: &str) -> Result<bool, Self::Error> {
        if self.fail == "claim" {
            Err(StoreError)
        } else {
            self.inner.claim_message(session, nonce).await
        }
    }
    async fn mark_authenticated(&self, nonce: &str) -> Result<(), Self::Error> {
        if self.fail == "mark" {
            Err(StoreError)
        } else {
            self.inner.mark_authenticated(nonce).await
        }
    }
}
struct FailingVerifyWallet<'a>(&'a Wallet);
impl NonceWallet for FailingVerifyWallet<'_> {
    type Error = WalletError;
    async fn create_hmac(&self, r: &NonceHmacRequest) -> Result<[u8; 32], Self::Error> {
        self.0.create_hmac(r).await
    }
    async fn verify_hmac(
        &self,
        r: &NonceHmacRequest,
        h: &[u8; 32],
    ) -> Result<bool, HmacCheckError<Self::Error>> {
        self.0.verify_hmac(r, h).await
    }
}
impl AuthWallet for FailingVerifyWallet<'_> {
    async fn identity_key(&self) -> Result<String, Self::Error> {
        self.0.identity_key().await
    }
    async fn sign_auth(&self, p: &str, k: &str, d: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.0.sign_auth(p, k, d).await
    }
    async fn verify_auth(&self, _: &str, _: &str, _: &[u8], _: &[u8]) -> Result<bool, Self::Error> {
        Err(WalletError)
    }
}
#[tokio::test]
async fn wallet_and_store_errors_never_return_verified_identity() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    for failed in ["initial", "add"] {
        let (_, server, store, initial) = pair().await;
        let failing = FailingStore {
            inner: &store,
            fail: failed,
        };
        let r = AuthResponder::new(&server, &failing);
        assert!(matches!(
            r.accept_initial(&initial).await,
            Err(ResponderError::Store(StoreError))
        ));
    }
    for failed in ["get", "claim", "mark", "wallet"] {
        let (client, server, store, initial) = pair().await;
        let response = AuthResponder::new(&server, &store)
            .accept_initial(&initial)
            .await
            .unwrap();
        let nonce = STANDARD.encode([7u8; 32]);
        let frame = b"actual frame";
        let signature = client
            .sign_auth(
                &key(&server.0),
                &format!("{nonce} {}", response.initial_nonce),
                frame,
            )
            .await
            .unwrap();
        let msg = json!({"version":"0.1","messageType":"general","identityKey":key(&client.0),"nonce":nonce,"yourNonce":response.initial_nonce,"payload":frame,"signature":signature});
        if failed == "wallet" {
            let bad = FailingVerifyWallet(&server);
            let result = AuthResponder::new(&bad, &store)
                .accept_general(&msg, frame)
                .await;
            assert!(matches!(result, Err(ResponderError::Wallet(WalletError))));
        } else {
            let bad = FailingStore {
                inner: &store,
                fail: failed,
            };
            let result = AuthResponder::new(&server, &bad)
                .accept_general(&msg, frame)
                .await;
            assert!(matches!(result, Err(ResponderError::Store(StoreError))));
        }
        assert!(
            !store
                .get_session(&response.initial_nonce)
                .await
                .unwrap()
                .unwrap()
                .authenticated
        );
    }
}

#[tokio::test]
async fn signed_response_is_bound_to_verified_request_and_live_session() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use message_box_server_rust::auth_frame::{PreparedResponseFrame, encode_response_frame};
    let (client, server, store, initial) = pair().await;
    let responder = AuthResponder::new(&server, &store);
    let response = responder.accept_initial(&initial).await.unwrap();
    let nonce = STANDARD.encode([4_u8; 32]);
    let frame: Vec<u8> = (0..40).collect();
    let signature = client
        .sign_auth(
            &key(&server.0),
            &format!("{nonce} {}", response.initial_nonce),
            &frame,
        )
        .await
        .unwrap();
    let message = json!({"version":"0.1","messageType":"general","identityKey":key(&client.0),"nonce":nonce,"yourNonce":response.initial_nonce,"payload":frame,"signature":signature});
    let verified = responder.accept_general(&message, &frame).await.unwrap();
    let signed = responder
        .sign_http_response(&verified, 200, &[("x-bsv-extra", "ok")], b"hello")
        .await
        .unwrap();
    let expected = encode_response_frame(&PreparedResponseFrame {
        request_id: frame[..32].try_into().unwrap(),
        status: 200,
        headers: &[("x-bsv-extra", "ok")],
        body: b"hello",
    });
    assert_eq!(signed.payload, expected);
    assert_eq!(signed.your_nonce, initial["initialNonce"].as_str().unwrap());
    assert!(
        client
            .verify_auth(
                &key(&server.0),
                &format!("{} {}", signed.nonce, signed.your_nonce),
                &signed.payload,
                &signed.signature
            )
            .await
            .unwrap()
    );
    store
        .sessions
        .lock()
        .unwrap()
        .remove(&response.initial_nonce);
    assert!(matches!(
        responder.sign_http_response(&verified, 200, &[], b"").await,
        Err(ResponderError::SessionMissing)
    ));
}

#[tokio::test]
async fn signed_http_response_rejects_short_verified_frames() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (client, server, store, initial) = pair().await;
    let responder = AuthResponder::new(&server, &store);
    let response = responder.accept_initial(&initial).await.unwrap();
    let nonce = STANDARD.encode([5_u8; 32]);
    let frame = b"short";
    let signature = client
        .sign_auth(
            &key(&server.0),
            &format!("{nonce} {}", response.initial_nonce),
            frame,
        )
        .await
        .unwrap();
    let message = json!({"version":"0.1","messageType":"general","identityKey":key(&client.0),"nonce":nonce,"yourNonce":response.initial_nonce,"payload":frame,"signature":signature});
    let verified = responder.accept_general(&message, frame).await.unwrap();
    assert!(matches!(
        responder.sign_http_response(&verified, 200, &[], b"").await,
        Err(ResponderError::InvalidMessage)
    ));
}

struct FailingResponseWallet<'a> {
    inner: &'a Wallet,
    fail: &'static str,
}
impl NonceWallet for FailingResponseWallet<'_> {
    type Error = WalletError;
    async fn create_hmac(&self, request: &NonceHmacRequest) -> Result<[u8; 32], Self::Error> {
        self.inner.create_hmac(request).await
    }
    async fn verify_hmac(
        &self,
        request: &NonceHmacRequest,
        mac: &[u8; 32],
    ) -> Result<bool, HmacCheckError<Self::Error>> {
        self.inner.verify_hmac(request, mac).await
    }
}
impl AuthWallet for FailingResponseWallet<'_> {
    async fn identity_key(&self) -> Result<String, Self::Error> {
        if self.fail == "identity" {
            Err(WalletError)
        } else {
            self.inner.identity_key().await
        }
    }
    async fn sign_auth(
        &self,
        peer: &str,
        key_id: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        if self.fail == "sign" {
            Err(WalletError)
        } else {
            self.inner.sign_auth(peer, key_id, data).await
        }
    }
    async fn verify_auth(
        &self,
        peer: &str,
        key_id: &str,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        self.inner.verify_auth(peer, key_id, data, signature).await
    }
}
#[tokio::test]
async fn signed_response_fails_closed_on_wallet_or_final_store_error() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (client, server, store, initial) = pair().await;
    let responder = AuthResponder::new(&server, &store);
    let response = responder.accept_initial(&initial).await.unwrap();
    let nonce = STANDARD.encode([6_u8; 32]);
    let frame = vec![7_u8; 40];
    let signature = client
        .sign_auth(
            &key(&server.0),
            &format!("{nonce} {}", response.initial_nonce),
            &frame,
        )
        .await
        .unwrap();
    let message = json!({"version":"0.1","messageType":"general","identityKey":key(&client.0),"nonce":nonce,"yourNonce":response.initial_nonce,"payload":frame,"signature":signature});
    let verified = responder.accept_general(&message, &frame).await.unwrap();
    for fail in ["sign", "identity"] {
        let bad = FailingResponseWallet {
            inner: &server,
            fail,
        };
        assert!(matches!(
            AuthResponder::new(&bad, &store)
                .sign_http_response(&verified, 200, &[], b"")
                .await,
            Err(ResponderError::Wallet(WalletError))
        ));
    }
    let bad = FailingStore {
        inner: &store,
        fail: "mark",
    };
    assert!(matches!(
        AuthResponder::new(&server, &bad)
            .sign_http_response(&verified, 200, &[], b"")
            .await,
        Err(ResponderError::Store(StoreError))
    ));
}

#[tokio::test]
async fn signed_general_payload_uses_exact_bytes_and_live_authenticated_session() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (client, server, store, initial) = pair().await;
    let responder = AuthResponder::new(&server, &store);
    let response = responder.accept_initial(&initial).await.unwrap();
    let nonce = STANDARD.encode([12_u8; 32]);
    let request = b"short websocket event";
    let signature = client
        .sign_auth(
            &key(&server.0),
            &format!("{nonce} {}", response.initial_nonce),
            request,
        )
        .await
        .unwrap();
    let message = json!({"version":"0.1","messageType":"general","identityKey":key(&client.0),"nonce":nonce,"yourNonce":response.initial_nonce,"payload":request,"signature":signature});
    let verified = responder.accept_general(&message, request).await.unwrap();
    let payload = b"{\"event\":\"reply\",\"data\":null}";
    let signed = responder
        .sign_general_payload(&verified, payload)
        .await
        .unwrap();
    assert_eq!(signed.payload, payload);
    assert_eq!(signed.your_nonce, initial["initialNonce"].as_str().unwrap());
    assert!(
        client
            .verify_auth(
                &key(&server.0),
                &format!("{} {}", signed.nonce, signed.your_nonce),
                payload,
                &signed.signature
            )
            .await
            .unwrap()
    );
    assert!(
        !client
            .verify_auth(
                &key(&server.0),
                &format!("{} {}", signed.nonce, signed.your_nonce),
                b"different",
                &signed.signature
            )
            .await
            .unwrap()
    );
    store
        .sessions
        .lock()
        .unwrap()
        .remove(&response.initial_nonce);
    assert!(matches!(
        responder.sign_general_payload(&verified, payload).await,
        Err(ResponderError::SessionMissing)
    ));
}
