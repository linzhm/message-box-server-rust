//! Recipient-owned permission storage. Authentication remains the embedding
//! application's responsibility; request fields never select the owner.

use super::{
    ApiResponse, ApiResult, Decision, Identity, MessageBox, canonical_key, exact_text, js_trim,
};
use chrono::{SecondsFormat, Utc};
use serde_json::{Value, json};
use sqlx::Row;

const MAX_RECIPIENT_FEE: i64 = 2_147_483_647;

fn invalid_box() -> ApiResponse {
    ApiResponse::error(
        400,
        "ERR_INVALID_MESSAGE_BOX",
        "messageBox must be an exact, control-free string of at most 128 bytes.",
    )
}
fn message_box(request: &Value) -> ApiResult<&str> {
    request["messageBox"]
        .as_str()
        .filter(|name| exact_text(name, 128))
        .ok_or_else(invalid_box)
}
fn sender(request: &Value) -> ApiResult<Option<String>> {
    match request.get("sender").filter(|value| !value.is_null()) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .and_then(canonical_key)
            .map(Some)
            .ok_or_else(|| {
                ApiResponse::error(
                    400,
                    "ERR_INVALID_PUBLIC_KEY",
                    "Invalid sender public key format.",
                )
            }),
    }
}
fn internal() -> ApiResponse {
    ApiResponse::error(500, "ERR_INTERNAL", "An internal error has occurred.")
}
fn policy_unavailable() -> ApiResponse {
    ApiResponse::error(
        503,
        "ERR_POLICY_UNAVAILABLE",
        "Delivery policy is unavailable.",
    )
}
fn valid_stored_fee(fee: i64) -> bool {
    (-1..=MAX_RECIPIENT_FEE).contains(&fee)
}

// HTTP query strings use JavaScript Number conversion upstream. Support its
// scalar numeric forms, including radix strings, without coercing arrays or
// objects into pagination controls. The adapter owns HTTP query parsing.
fn query_number(value: &Value) -> Option<f64> {
    if let Some(number) = value.as_f64() {
        return Some(number);
    }
    let text = js_trim(value.as_str()?);
    if text.is_empty() {
        return Some(0.0);
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = text.strip_prefix(prefix) {
            if !digits.chars().all(|digit| digit.is_digit(radix)) {
                return None;
            }
            return u64::from_str_radix(digits, radix).ok().map(|n| n as f64);
        }
    }
    text.parse().ok()
}
pub(super) fn query_integer(
    request: &Value,
    field: &str,
    default: i64,
    minimum: i64,
    maximum: i64,
    code: &str,
) -> ApiResult<i64> {
    let value = request.get(field).filter(|v| !v.is_null());
    let parsed = value.map(query_number).unwrap_or(Some(default as f64));
    parsed
        .filter(|n| {
            n.fract() == 0.0
                && *n >= minimum as f64
                && (maximum == -1 || *n <= maximum as f64)
                && *n <= 9_007_199_254_740_991.0
        })
        .map(|n| n as i64)
        .ok_or_else(|| {
            let description = if maximum == -1 {
                if minimum == 1 {
                    format!("{field} must be a positive safe integer.")
                } else {
                    format!("{field} must be a non-negative safe integer.")
                }
            } else {
                format!("{field} must be an integer between {minimum} and {maximum}.")
            };
            ApiResponse::error(400, code, description)
        })
}
fn list_failure() -> ApiResponse {
    ApiResponse::error(
        500,
        "ERR_LIST_PERMISSIONS_FAILED",
        "Failed to list permissions",
    )
}

impl MessageBox {
    pub(super) async fn set_permission(
        &self,
        owner: &Identity,
        request: &Value,
    ) -> ApiResult<Value> {
        // Match the upstream field/error precedence before touching storage.
        if request["messageBox"].is_null() || !request["recipientFee"].is_number() {
            return Err(ApiResponse::error(
                400,
                "ERR_INVALID_REQUEST",
                "messageBox (string) and recipientFee (number) are required. sender (string) is optional for box-wide settings.",
            ));
        }
        let sender = sender(request)?;
        let fee = request["recipientFee"]
            .as_f64()
            .filter(|fee| fee.fract() == 0.0 && *fee >= -1.0 && *fee <= MAX_RECIPIENT_FEE as f64)
            .map(|fee| fee as i64)
            .ok_or_else(|| {
                ApiResponse::error(
                    400,
                    "ERR_INVALID_FEE_VALUE",
                    format!("recipientFee must be -1, 0, or a positive integer no greater than {MAX_RECIPIENT_FEE}."),
                )
            })?;
        let box_name = message_box(request)?;
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        sqlx::query("INSERT INTO message_permissions(recipient, message_box, sender_scope, recipient_fee, created_at, updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(recipient, message_box, sender_scope) DO UPDATE SET recipient_fee=excluded.recipient_fee, updated_at=excluded.updated_at")
            .bind(owner.as_str()).bind(box_name).bind(sender.as_deref().unwrap_or(""))
            .bind(fee).bind(&now).bind(&now).execute(&self.pool).await.map_err(|_| {
                ApiResponse::error(500, "ERR_DATABASE_ERROR", "Failed to update message permission.")
            })?;
        let action = if sender.is_some() {
            "Messages from"
        } else {
            "Box-wide default for"
        };
        let who = sender.as_deref().unwrap_or("all senders");
        let verb = if sender.is_some() { "are" } else { "is" };
        let description = match fee {
            -1 => format!("{action} {who} to {box_name} {verb} now blocked."),
            0 => format!("{action} {who} to {box_name} {verb} now always allowed."),
            _ => format!(
                "{action} {who} to {box_name} now require{} {fee} satoshis.",
                if sender.is_some() { "" } else { "s" }
            ),
        };
        Ok(json!({"status":"success", "description":description}))
    }

    pub(super) async fn get_permission(
        &self,
        owner: &Identity,
        request: &Value,
    ) -> ApiResult<Value> {
        let box_name = message_box(request)?;
        let sender = sender(request)?;
        let row = sqlx::query("SELECT recipient_fee, created_at, updated_at FROM message_permissions WHERE recipient=? AND message_box=? AND sender_scope=?")
            .bind(owner.as_str()).bind(box_name).bind(sender.as_deref().unwrap_or(""))
            .fetch_optional(&self.pool).await.map_err(|_| internal())?;
        let found = row.is_some();
        let permission = if let Some(row) = row {
            let fee: i64 = row.try_get("recipient_fee").map_err(|_| internal())?;
            if !valid_stored_fee(fee) {
                return Err(internal());
            }
            let status = match fee {
                -1 => "blocked",
                0 => "always_allow",
                _ => "payment_required",
            };
            let created_at: String = row.try_get("created_at").map_err(|_| internal())?;
            let updated_at: String = row.try_get("updated_at").map_err(|_| internal())?;
            json!({"sender":sender, "messageBox":box_name, "recipientFee":fee, "status":status, "createdAt":created_at, "updatedAt":updated_at})
        } else {
            Value::Null
        };
        let description = match (found, sender.as_deref()) {
            (true, Some(sender)) => {
                format!("Permission setting found for sender {sender} to {box_name}.")
            }
            (true, None) => format!("Box-wide permission setting found for {box_name}."),
            (false, Some(sender)) => {
                format!("No permission setting found for sender {sender} to {box_name}.")
            }
            (false, None) => format!("No box-wide permission setting found for {box_name}."),
        };
        Ok(json!({"status":"success", "description":description, "permission":permission}))
    }

    pub(super) async fn list_permissions(
        &self,
        owner: &Identity,
        request: &Value,
    ) -> ApiResult<Value> {
        let config = self.resources.as_ref().map(|r| &r.config);
        let signed = crate::runtime_resources::RuntimeResources::signed;
        let limit = query_integer(
            request,
            "limit",
            config.map_or(100, |c| match c.permission_list_default_limit {
                crate::resource_config::ResourceLimit::Finite(n) => n as i64,
                crate::resource_config::ResourceLimit::Unlimited => 9_007_199_254_740_991,
            }),
            1,
            config.map_or(100, |c| signed(c.permission_list_max_limit)),
            "ERR_INVALID_LIMIT",
        )?;
        let offset = query_integer(
            request,
            "offset",
            0,
            0,
            config.map_or(100_000, |c| signed(c.permission_list_max_offset)),
            "ERR_INVALID_OFFSET",
        )?;
        let sort_order = match request.get("createdAtOrder").filter(|v| !v.is_null()) {
            None => "desc",
            Some(value) => value
                .as_str()
                .filter(|v| matches!(*v, "asc" | "desc"))
                .ok_or_else(|| {
                    ApiResponse::error(
                        400,
                        "ERR_INVALID_SORT_ORDER",
                        "createdAtOrder must be asc or desc.",
                    )
                })?,
        };
        let box_name = request
            .get("messageBox")
            .filter(|v| !v.is_null())
            .map(|v| {
                v.as_str()
                    .filter(|name| exact_text(name, 128))
                    .ok_or_else(|| {
                        ApiResponse::error(
                            400,
                            "ERR_INVALID_MESSAGE_BOX",
                            "messageBox must be a non-empty string of at most 128 bytes.",
                        )
                    })
            })
            .transpose()?;
        // Match the upstream count-before-page contract, not a cross-request
        // snapshot or an invented hasMore/nextOffset response.
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM message_permissions WHERE recipient=? AND (? IS NULL OR message_box=?)")
            .bind(owner.as_str()).bind(box_name).bind(box_name).fetch_one(&self.pool).await.map_err(|_| list_failure())?;
        let query = format!(
            "SELECT sender_scope, message_box, recipient_fee, created_at, updated_at FROM message_permissions WHERE recipient=? AND (? IS NULL OR message_box=?) ORDER BY message_box ASC, sender_scope ASC, created_at {sort_order} LIMIT ? OFFSET ?"
        );
        let rows = sqlx::query(&query)
            .bind(owner.as_str())
            .bind(box_name)
            .bind(box_name)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| list_failure())?;
        let mut permissions = Vec::with_capacity(rows.len());
        for row in rows {
            let fee: i64 = row.try_get("recipient_fee").map_err(|_| list_failure())?;
            if !valid_stored_fee(fee) {
                return Err(list_failure());
            }
            let scope: String = row.try_get("sender_scope").map_err(|_| list_failure())?;
            let sender = if scope.is_empty() { None } else { Some(scope) };
            let box_name: String = row.try_get("message_box").map_err(|_| list_failure())?;
            let created_at: String = row.try_get("created_at").map_err(|_| list_failure())?;
            let updated_at: String = row.try_get("updated_at").map_err(|_| list_failure())?;
            permissions.push(json!({"sender":sender,"messageBox":box_name,"recipientFee":fee,"createdAt":created_at,"updatedAt":updated_at}));
        }
        Ok(json!({"status":"success","permissions":permissions,"totalCount":total}))
    }

    async fn recipient_fee(
        &self,
        sender: &Identity,
        recipient: &str,
        box_name: &str,
    ) -> Result<i64, ()> {
        let fee: Option<i64> = sqlx::query_scalar("SELECT recipient_fee FROM message_permissions WHERE recipient=? AND message_box=? AND sender_scope IN (?, '') ORDER BY CASE WHEN sender_scope=? THEN 0 ELSE 1 END LIMIT 1")
            .bind(recipient).bind(box_name).bind(sender.as_str()).bind(sender.as_str())
            .fetch_optional(&self.pool).await.map_err(|_| ())?;
        let fee = fee.unwrap_or(if box_name == "notifications" { 10 } else { 0 });
        if valid_stored_fee(fee) {
            Ok(fee)
        } else {
            Err(())
        }
    }

    pub(super) async fn recipient_decision(
        &self,
        sender: &Identity,
        recipient: &str,
        box_name: &str,
    ) -> ApiResult<Decision> {
        // Exact sender overrides box-wide scope. Defaults are computed, never
        // persisted as implicit user preferences on a read/send path.
        let fee = self
            .recipient_fee(sender, recipient, box_name)
            .await
            .map_err(|_| policy_unavailable())?;
        Ok(match fee {
            -1 => Decision::Blocked,
            0 => Decision::Free,
            _ => Decision::PaymentRequired,
        })
    }
}

impl MessageBox {
    pub(super) async fn quote_permission(
        &self,
        sender: &Identity,
        request: &Value,
    ) -> ApiResult<Value> {
        let recipient = request.get("recipient").filter(|v| !v.is_null());
        let box_value = request.get("messageBox").filter(|v| !v.is_null());
        if recipient.is_none() || box_value.is_none() {
            return Err(ApiResponse::error(
                400,
                "ERR_MISSING_PARAMETERS",
                "recipient and messageBox parameters are required.",
            ));
        }
        let box_name = message_box(request)?;
        let input = recipient.unwrap();
        let recipients: Vec<&Value> = match input.as_array() {
            Some(values) => values.iter().collect(),
            None => vec![input],
        };
        if recipients.is_empty() {
            return Err(ApiResponse::error(
                400,
                "ERR_MISSING_PARAMETERS",
                "At least one recipient is required.",
            ));
        }
        if recipients.len() > 100 {
            return Err(ApiResponse::error(
                400,
                "ERR_TOO_MANY_RECIPIENTS",
                "A quote may include at most 100 recipients.",
            ));
        }
        let mut normalized = Vec::with_capacity(recipients.len());
        let mut invalid = Vec::new();
        for (index, recipient) in recipients.iter().enumerate() {
            if let Some(key) = recipient.as_str().and_then(canonical_key) {
                normalized.push(key);
            } else {
                invalid.push(index.to_string());
            }
        }
        if !invalid.is_empty() {
            return Err(ApiResponse::error(
                400,
                "ERR_INVALID_PUBLIC_KEY",
                format!(
                    "Invalid recipient public key at index(es): {}.",
                    invalid.join(", ")
                ),
            ));
        }
        if normalized
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != normalized.len()
        {
            return Err(ApiResponse::error(
                400,
                "ERR_DUPLICATE_RECIPIENT",
                "Each recipient may appear only once in a quote.",
            ));
        }
        let delivery = self
            .server_delivery_fee(box_name)
            .await
            .map_err(|_| internal())?;
        let mut quotes = Vec::new();
        let mut blocked = Vec::new();
        let mut recipient_total = 0_i64;
        for recipient in &normalized {
            let fee = self
                .recipient_fee(sender, recipient, box_name)
                .await
                .map_err(|_| internal())?;
            if normalized.len() == 1 {
                return Ok(
                    json!({"status":"success","description":"Message delivery quote generated.","quote":{"deliveryFee":delivery,"recipientFee":fee}}),
                );
            }
            let status = match fee {
                -1 => {
                    blocked.push(recipient);
                    "blocked"
                }
                0 => "always_allow",
                _ => "payment_required",
            };
            if fee != -1 {
                recipient_total += fee;
            }
            quotes.push(json!({"recipient":recipient,"messageBox":box_name,"deliveryFee":delivery,"recipientFee":fee,"status":status}));
        }
        // Both fees are at most i32::MAX and there are at most 100 recipients.
        let delivery_total = delivery * normalized.len() as i64;
        let total = delivery_total + recipient_total;
        Ok(
            json!({"status":"success","description":format!("Message delivery quotes generated for {} recipients.", normalized.len()),"quotesByRecipient":quotes,"blockedRecipients":blocked,"totals":{"deliveryFees":delivery_total,"recipientFees":recipient_total,"totalForPayableRecipients":total}}),
        )
    }
}
