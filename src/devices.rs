//! Device-registration persistence and list routes, without a push transport.
use super::{ApiResponse, ApiResult, Identity, MessageBox, exact_text, permissions::query_integer};
use chrono::{SecondsFormat, Utc};
use serde_json::{Value, json};
use sqlx::Row;

fn db_error(description: &str) -> ApiResponse {
    ApiResponse::error(500, "ERR_DATABASE_ERROR", description)
}
fn optional_text<'a>(
    request: &'a Value,
    field: &str,
    max: usize,
    code: &str,
    description: &str,
) -> ApiResult<Option<&'a str>> {
    match request.get(field).filter(|v| !v.is_null()) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|s| exact_text(s, max))
            .map(Some)
            .ok_or_else(|| ApiResponse::error(400, code, description)),
    }
}
impl MessageBox {
    pub(super) async fn register_device(
        &self,
        owner: &Identity,
        request: &Value,
    ) -> ApiResult<Value> {
        let token = request
            .get("fcmToken")
            .and_then(Value::as_str)
            .filter(|s| exact_text(s, 500))
            .ok_or_else(|| {
                ApiResponse::error(
                    400,
                    "ERR_INVALID_FCM_TOKEN",
                    "fcmToken must be an exact, control-free string of at most 500 bytes.",
                )
            })?;
        let device_id = optional_text(
            request,
            "deviceId",
            255,
            "ERR_INVALID_DEVICE_ID",
            "deviceId must be an exact, control-free string of at most 255 bytes.",
        )?;
        let platform = match request.get("platform").filter(|v| !v.is_null()) {
            None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .filter(|s| matches!(*s, "ios" | "android" | "web"))
                    .ok_or_else(|| {
                        ApiResponse::error(
                            400,
                            "ERR_INVALID_PLATFORM",
                            "platform must be one of: ios, android, web",
                        )
                    })?,
            ),
        };
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let id: Option<i64> = sqlx::query_scalar("INSERT INTO device_registrations(identity_key, fcm_token, device_id, platform, active, created_at, updated_at, last_used) VALUES(?,?,?,?,1,?,?,?) ON CONFLICT(fcm_token) DO UPDATE SET device_id=excluded.device_id, platform=excluded.platform, active=1, updated_at=excluded.updated_at, last_used=excluded.last_used WHERE device_registrations.identity_key=excluded.identity_key RETURNING id")
            .bind(owner.as_str()).bind(token).bind(device_id).bind(platform).bind(&now).bind(&now).bind(&now)
            .fetch_optional(&self.pool).await.map_err(|_| db_error("Failed to register device."))?;
        let Some(id) = id else {
            return Err(ApiResponse::error(
                409,
                "ERR_DEVICE_TOKEN_ALREADY_REGISTERED",
                "This device token is already registered to another identity.",
            ));
        };
        Ok(
            json!({"status":"success","message":"Device registered successfully for push notifications","deviceId":id}),
        )
    }
    pub(super) async fn list_devices(&self, owner: &Identity, request: &Value) -> ApiResult<Value> {
        let config = self.resources.as_ref().map(|r| &r.config);
        let signed = crate::runtime_resources::RuntimeResources::signed;
        let limit = query_integer(
            request,
            "limit",
            config.map_or(100, |c| match c.device_list_default_limit {
                crate::resource_config::ResourceLimit::Finite(n) => n as i64,
                crate::resource_config::ResourceLimit::Unlimited => 9_007_199_254_740_991,
            }),
            1,
            config.map_or(100, |c| signed(c.device_list_max_limit)),
            "ERR_INVALID_LIMIT",
        )?;
        let offset = query_integer(
            request,
            "offset",
            0,
            0,
            config.map_or(100_000, |c| signed(c.device_list_max_offset)),
            "ERR_INVALID_OFFSET",
        )?;
        let rows = sqlx::query("SELECT id, device_id, platform, fcm_token, active, created_at, updated_at, last_used FROM device_registrations WHERE identity_key=? ORDER BY updated_at DESC LIMIT ? OFFSET ?")
            .bind(owner.as_str()).bind(limit).bind(offset).fetch_all(&self.pool).await.map_err(|_| db_error("Failed to retrieve devices."))?;
        let mut devices = Vec::with_capacity(rows.len());
        for row in rows {
            let get_error = || db_error("Failed to retrieve devices.");
            let token: String = row.try_get("fcm_token").map_err(|_| get_error())?;
            let utf16: Vec<u16> = token.encode_utf16().collect();
            let tail = String::from_utf16_lossy(&utf16[utf16.len().saturating_sub(10)..]);
            // The pinned TS route exposes MySQL BOOLEAN/TINYINT as JSON 0/1.
            let active: bool = row.try_get("active").map_err(|_| get_error())?;
            devices.push(json!({"id":row.try_get::<i64,_>("id").map_err(|_| get_error())?,"deviceId":row.try_get::<Option<String>,_>("device_id").map_err(|_| get_error())?,"platform":row.try_get::<Option<String>,_>("platform").map_err(|_| get_error())?,"fcmToken":format!("...{tail}"),"active":active,"createdAt":row.try_get::<String,_>("created_at").map_err(|_| get_error())?,"updatedAt":row.try_get::<String,_>("updated_at").map_err(|_| get_error())?,"lastUsed":row.try_get::<String,_>("last_used").map_err(|_| get_error())?}));
        }
        Ok(json!({"status":"success","limit":limit,"offset":offset,"devices":devices}))
    }
}
