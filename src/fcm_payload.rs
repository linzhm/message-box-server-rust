//! Pure fixed-source FCM payload construction. This does not initialize
//! Firebase, select devices, send notifications or prove device delivery.
use serde_json::{Value, json};
/// Build the source's generic notification. An empty originator is treated as
/// unknown on Android but preserved on APNS, matching JS `||` versus `??`.
pub fn build_fcm_message(
    token: &str,
    title: &str,
    message_id: &str,
    originator: Option<&str>,
) -> Value {
    const BODY: &str = "Open the app to view this message.";
    let android = originator
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    let apns = originator.unwrap_or("unknown");
    json!({"token":token,"notification":{"title":title,"body":BODY},"android":{"priority":"high","data":{"messageId":message_id,"originator":android}},"apns":{"headers":{"apns-push-type":"alert","apns-priority":"10"},"payload":{"aps":{"mutable-content":1,"alert":{"title":title,"body":BODY}},"messageId":message_id,"originator":apns}}})
}
