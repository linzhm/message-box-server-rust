//! FCM provider seam and device-state handling. No Firebase credentials,
//! provider, network transport or send-after-message hook is supplied here.
use crate::{MessageBox, fcm_payload::build_fcm_message};
use chrono::{SecondsFormat, Utc};
use futures_util::{StreamExt, stream::FuturesUnordered};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Trusted host-injected provider. It receives full device tokens. Provider
/// errors are inspected for invalid-token markers but never returned verbatim.
pub trait FcmProvider: Send + Sync {
    fn send<'a>(
        &'a self,
        message: Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}
pub struct FcmPayload<'a> {
    pub title: &'a str,
    pub message_id: &'a str,
    pub originator: Option<&'a str>,
}
#[derive(Clone, Copy)]
pub struct FcmOptions {
    pub max_devices: i64,
    pub concurrency: i64,
}
pub(crate) struct FcmConfiguration {
    pub provider: Arc<dyn FcmProvider>,
    pub options: FcmOptions,
    pub recipient_concurrency: i64,
}
impl Default for FcmOptions {
    fn default() -> Self {
        Self {
            max_devices: 100,
            concurrency: 10,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct FcmResult {
    pub success: bool,
    pub error: Option<String>,
}
impl FcmResult {
    fn success() -> Self {
        Self {
            success: true,
            error: None,
        }
    }
    fn failure(reason: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(reason.into()),
        }
    }
    pub fn to_json(&self) -> Value {
        match &self.error {
            Some(error) => json!({"success":self.success,"error":error}),
            None => json!({"success":self.success}),
        }
    }
}
struct OwnedPayload {
    title: String,
    message_id: String,
    originator: Option<String>,
}
async fn send_one(
    pool: &SqlitePool,
    provider: &dyn FcmProvider,
    payload: &OwnedPayload,
    token: &str,
) -> Result<bool, ()> {
    let message = build_fcm_message(
        token,
        &payload.title,
        &payload.message_id,
        payload.originator.as_deref(),
    );
    let send_and_update = match provider.send(message).await {
        Ok(()) => {
            let last_used = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            let updated = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            sqlx::query(
                "UPDATE device_registrations SET last_used=?,updated_at=? WHERE fcm_token=?",
            )
            .bind(last_used)
            .bind(updated)
            .bind(token)
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
        }
        Err(error) => Err(error),
    };
    match send_and_update {
        Ok(()) => Ok(true),
        Err(error) => {
            if error.contains("registration-token-not-registered")
                || error.contains("invalid-registration-token")
            {
                let updated = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
                sqlx::query(
                    "UPDATE device_registrations SET active=0,updated_at=? WHERE fcm_token=?",
                )
                .bind(updated)
                .bind(token)
                .execute(pool)
                .await
                .map_err(|_| ())?;
            }
            Ok(false)
        }
    }
}
impl MessageBox {
    /// Configure a trusted provider for post-commit notification-box sends.
    /// No provider is configured by default. `-1` means unlimited recipients.
    pub fn with_fcm_provider(
        mut self,
        provider: Arc<dyn FcmProvider>,
        options: FcmOptions,
        recipient_concurrency: i64,
    ) -> Result<Self, &'static str> {
        if options.max_devices < -1
            || options.concurrency < -1
            || options.concurrency == 0
            || recipient_concurrency < -1
            || recipient_concurrency == 0
        {
            return Err("invalid FCM configuration");
        }
        let (options, recipient_concurrency) = if let Some(resources) = &self.resources {
            let signed = crate::runtime_resources::RuntimeResources::signed;
            (
                FcmOptions {
                    max_devices: signed(resources.config.max_notification_devices),
                    concurrency: signed(resources.config.fcm_send_concurrency),
                },
                signed(resources.config.notification_recipient_concurrency),
            )
        } else {
            (options, recipient_concurrency)
        };
        self.fcm = Some(FcmConfiguration {
            provider,
            options,
            recipient_concurrency,
        });
        Ok(self)
    }
    /// Trusted host-only operation. It does not authenticate the caller, check
    /// message commitment or box type, or initialize a network provider. A
    /// supplied provider receives the full device token. On worker failure,
    /// already-started workers may continue, as with upstream Promise.all.
    pub async fn send_fcm_notification(
        &self,
        recipient: &str,
        payload: &FcmPayload<'_>,
        provider: Option<Arc<dyn FcmProvider>>,
        options: FcmOptions,
    ) -> FcmResult {
        if options.max_devices < -1 || options.concurrency < -1 || options.concurrency == 0 {
            return FcmResult::failure("FCM notification failed");
        }
        let tokens=match sqlx::query_scalar::<_,String>("SELECT fcm_token FROM device_registrations WHERE identity_key=? AND active=1 ORDER BY updated_at DESC LIMIT ?").bind(recipient).bind(options.max_devices).fetch_all(&self.pool).await {Ok(tokens)=>tokens,Err(_)=>return FcmResult::failure("FCM notification failed")};
        if tokens.is_empty() {
            return FcmResult::failure("No registered devices found for recipient");
        }
        let count = tokens.len();
        let Some(provider) = provider else {
            return FcmResult::failure(format!("Failed to send to all {count} registered devices"));
        };
        let workers = if options.concurrency == -1 {
            count
        } else {
            usize::try_from(options.concurrency)
                .unwrap_or(usize::MAX)
                .min(count)
        };
        let tokens = Arc::new(tokens);
        let next = Arc::new(AtomicUsize::new(0));
        let successes = Arc::new(AtomicUsize::new(0));
        let payload = Arc::new(OwnedPayload {
            title: payload.title.to_owned(),
            message_id: payload.message_id.to_owned(),
            originator: payload.originator.map(str::to_owned),
        });
        let mut tasks = FuturesUnordered::new();
        for _ in 0..workers {
            let pool = self.pool.clone();
            let provider = Arc::clone(&provider);
            let tokens = Arc::clone(&tokens);
            let next = Arc::clone(&next);
            let successes = Arc::clone(&successes);
            let payload = Arc::clone(&payload);
            tasks.push(tokio::spawn(async move {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(token) = tokens.get(index) else {
                        return Ok::<(), ()>(());
                    };
                    if send_one(&pool, provider.as_ref(), &payload, token).await? {
                        successes.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        while let Some(result) = tasks.next().await {
            if !matches!(result, Ok(Ok(()))) {
                return FcmResult::failure("FCM notification failed");
            }
        }
        if successes.load(Ordering::Relaxed) > 0 {
            FcmResult::success()
        } else {
            FcmResult::failure(format!("Failed to send to all {count} registered devices"))
        }
    }
}
