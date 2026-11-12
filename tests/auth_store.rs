use message_box_server_rust::{
    auth_responder::{AuthSession, AuthSessionStore},
    auth_store::{AuthStoreOptions, SqliteAuthSessionStore, StoreError},
};
fn session(nonce: &str) -> AuthSession {
    AuthSession {
        session_nonce: nonce.into(),
        peer_nonce: "peer".into(),
        peer_identity: "identity".into(),
        authenticated: false,
    }
}
#[tokio::test]
async fn replay_claims_and_sessions_survive_close_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let store = SqliteAuthSessionStore::open(&path, AuthStoreOptions::default())
        .await
        .unwrap();
    assert!(store.claim_initial("identity", "client").await.unwrap());
    assert!(!store.claim_initial("identity", "client").await.unwrap());
    store.add_session(session("session")).await.unwrap();
    assert!(store.add_session(session("session")).await.is_err());
    assert!(store.claim_message("session", "message").await.unwrap());
    assert!(!store.claim_message("session", "message").await.unwrap());
    store.mark_authenticated("session").await.unwrap();
    assert!(
        store
            .get_session("session")
            .await
            .unwrap()
            .unwrap()
            .authenticated
    );
    store.close().await;
    let reopened = SqliteAuthSessionStore::open(&path, AuthStoreOptions::default())
        .await
        .unwrap();
    assert!(!reopened.claim_initial("identity", "client").await.unwrap());
    assert!(!reopened.claim_message("session", "message").await.unwrap());
    assert!(
        reopened
            .get_session("session")
            .await
            .unwrap()
            .unwrap()
            .authenticated
    );
}
#[tokio::test]
async fn concurrent_independent_pools_claim_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let first = SqliteAuthSessionStore::open(&path, AuthStoreOptions::default())
        .await
        .unwrap();
    let second = SqliteAuthSessionStore::open(&path, AuthStoreOptions::default())
        .await
        .unwrap();
    first.add_session(session("s")).await.unwrap();
    let (a, b) = tokio::join!(
        first.claim_message("s", "n"),
        second.claim_message("s", "n")
    );
    assert_ne!(a.unwrap(), b.unwrap());
    let (a, b) = tokio::join!(
        first.claim_initial("id", "nonce"),
        second.claim_initial("id", "nonce")
    );
    assert_ne!(a.unwrap(), b.unwrap());
}
#[tokio::test]
async fn expiry_and_capacity_fail_closed_for_signed_claims() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let opts = AuthStoreOptions {
        max_message_nonces_per_session: 1,
        ..Default::default()
    };
    let store = SqliteAuthSessionStore::open(&path, opts).await.unwrap();
    store.add_session(session("s")).await.unwrap();
    assert!(store.claim_message("s", "one").await.unwrap());
    assert!(matches!(
        store.claim_message("s", "two").await,
        Err(StoreError::Capacity)
    ));
    assert!(!store.claim_message("s", "one").await.unwrap());
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    sqlx::query("UPDATE auth_sessions SET expires_at=0 WHERE session_nonce='s'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.get_session("s").await.unwrap().is_none());
    assert!(matches!(
        store.claim_message("s", "two").await,
        Err(StoreError::SessionMissing)
    ));
    assert!(matches!(
        store.mark_authenticated("s").await,
        Err(StoreError::SessionMissing)
    ));
    store.prune_expired().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_message_nonces")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
async fn unsigned_initial_claims_use_bounded_eviction_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let opts = AuthStoreOptions {
        max_initial_per_identity: 2,
        max_initial_total: 3,
        ..Default::default()
    };
    let store = SqliteAuthSessionStore::open(&path, opts).await.unwrap();
    assert!(store.claim_initial("a", "one").await.unwrap());
    assert!(store.claim_initial("a", "two").await.unwrap());
    assert!(store.claim_initial("a", "three").await.unwrap());
    assert!(!store.claim_initial("a", "two").await.unwrap());
    assert!(store.claim_initial("a", "one").await.unwrap());
}

#[tokio::test]
async fn session_touch_never_shortens_a_later_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let store = SqliteAuthSessionStore::open(&path, AuthStoreOptions::default())
        .await
        .unwrap();
    store.add_session(session("s")).await.unwrap();
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    sqlx::query("UPDATE auth_sessions SET expires_at=9000000000000 WHERE session_nonce='s'")
        .execute(&pool)
        .await
        .unwrap();
    store.mark_authenticated("s").await.unwrap();
    let expiry: i64 =
        sqlx::query_scalar("SELECT expires_at FROM auth_sessions WHERE session_nonce='s'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(expiry, 9_000_000_000_000);
}
#[tokio::test]
async fn invalid_store_options_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    for options in [
        AuthStoreOptions {
            ttl_ms: 0,
            ..Default::default()
        },
        AuthStoreOptions {
            max_message_nonces_per_session: 0,
            ..Default::default()
        },
        AuthStoreOptions {
            ttl_ms: i64::MAX,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            SqliteAuthSessionStore::open(dir.path().join("invalid"), options).await,
            Err(StoreError::InvalidConfig)
        ));
    }
}

#[tokio::test]
async fn global_initial_capacity_evicts_oldest_claim() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let options = AuthStoreOptions {
        max_initial_per_identity: 3,
        max_initial_total: 3,
        ..Default::default()
    };
    let store = SqliteAuthSessionStore::open(&path, options).await.unwrap();
    for identity in ["a", "b", "c"] {
        assert!(store.claim_initial(identity, "nonce").await.unwrap());
    }
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    sqlx::query("UPDATE auth_initial_claims SET expires_at=expires_at-1000 WHERE identity_key='a'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.claim_initial("d", "nonce").await.unwrap());
    let remaining: Vec<String> =
        sqlx::query_scalar("SELECT identity_key FROM auth_initial_claims ORDER BY identity_key")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, vec!["b", "c", "d"]);
}

#[tokio::test]
async fn expiration_is_checked_after_waiting_for_write_lock_on_mark() {
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let store = SqliteAuthSessionStore::open(
        &path,
        AuthStoreOptions {
            ttl_ms: 1_500,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    store.add_session(session("mark")).await.unwrap();
    let lock = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let (mark, ()) = tokio::join!(store.mark_authenticated("mark"), async {
        tokio::time::sleep(Duration::from_millis(2_000)).await;
        lock.commit().await.unwrap();
    });
    assert!(matches!(mark, Err(StoreError::SessionMissing)));
}
#[tokio::test]
async fn expiration_is_checked_after_waiting_for_write_lock_on_claim() {
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let store = SqliteAuthSessionStore::open(
        &path,
        AuthStoreOptions {
            ttl_ms: 1_500,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    store.add_session(session("claim")).await.unwrap();
    let lock = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let (claim, ()) = tokio::join!(store.claim_message("claim", "message"), async {
        tokio::time::sleep(Duration::from_millis(2_000)).await;
        lock.commit().await.unwrap();
    });
    assert!(matches!(claim, Err(StoreError::SessionMissing)));
}
#[tokio::test]
async fn expiration_is_checked_after_waiting_for_read_lock() {
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let store = SqliteAuthSessionStore::open(
        &path,
        AuthStoreOptions {
            ttl_ms: 1_500,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    store.add_session(session("get")).await.unwrap();
    let lock = pool.begin_with("BEGIN EXCLUSIVE").await.unwrap();
    let (get, ()) = tokio::join!(store.get_session("get"), async {
        tokio::time::sleep(Duration::from_millis(2_000)).await;
        lock.commit().await.unwrap();
    });
    assert!(get.unwrap().is_none());
}
#[tokio::test]
async fn initial_claim_ttl_starts_after_waiting_for_write_lock() {
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let store = SqliteAuthSessionStore::open(
        &path,
        AuthStoreOptions {
            ttl_ms: 1_500,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    let lock = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let (claim, ()) = tokio::join!(store.claim_initial("id", "nonce"), async {
        tokio::time::sleep(Duration::from_millis(2_000)).await;
        lock.commit().await.unwrap();
    });
    assert!(claim.unwrap());
    assert!(!store.claim_initial("id", "nonce").await.unwrap());
}

#[tokio::test]
async fn new_session_ttl_starts_after_waiting_for_write_lock() {
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let store = SqliteAuthSessionStore::open(
        &path,
        AuthStoreOptions {
            ttl_ms: 1_500,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    let lock = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let (added, ()) = tokio::join!(store.add_session(session("s")), async {
        tokio::time::sleep(Duration::from_millis(2_000)).await;
        lock.commit().await.unwrap();
    });
    added.unwrap();
    assert!(store.get_session("s").await.unwrap().is_some());
}

#[tokio::test]
async fn pruning_checks_time_after_waiting_for_write_lock() {
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.sqlite");
    let store = SqliteAuthSessionStore::open(
        &path,
        AuthStoreOptions {
            ttl_ms: 1_500,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    store.add_session(session("s")).await.unwrap();
    let lock = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let (removed, ()) = tokio::join!(store.prune_expired(), async {
        tokio::time::sleep(Duration::from_millis(2_000)).await;
        lock.commit().await.unwrap();
    });
    assert_eq!(removed.unwrap(), 1);
}

#[tokio::test]
async fn maintenance_batches_sessions_and_cascades_nonce_rows() {
    use message_box_server_rust::resource_config::ResourceLimit;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("batch.sqlite");
    let store = SqliteAuthSessionStore::open(&path, AuthStoreOptions::default())
        .await
        .unwrap();
    for nonce in ["one", "two", "live"] {
        store.add_session(session(nonce)).await.unwrap();
        assert!(store.claim_message(nonce, "nonce").await.unwrap());
    }
    let pool =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    sqlx::query("UPDATE auth_sessions SET expires_at=0 WHERE session_nonce!='live'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store
            .prune_expired_batch(ResourceLimit::Finite(1))
            .await
            .unwrap(),
        1
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_message_nonces")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 2);
    assert_eq!(
        store
            .prune_expired_batch(ResourceLimit::Unlimited)
            .await
            .unwrap(),
        1
    );
    assert!(store.get_session("live").await.unwrap().is_some());
    pool.close().await;
    store.close().await;
}
