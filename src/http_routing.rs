//! Route matching for already-parsed requests after external middleware.
//!
//! This is not an HTTP server or an authentication implementation.
use crate::{ApiResponse, Identity, MessageBox};
use serde_json::Value;

impl MessageBox {
    /// Dispatches the implemented method/path pairs using already-parsed fields.
    ///
    /// The caller must resolve or strip any routing prefix, parse the request, and verify
    /// authentication before invoking this post-middleware seam. Payment middleware
    /// is not implemented, and the core still refuses payment fields.
    /// `identity` must come from proof verified by that middleware, never from a
    /// request field or an unverified header. `None` means no route was matched;
    /// the outer framework determines its own response. HEAD and other framework
    /// semantics are not implemented here. This function opens no listener.
    pub async fn dispatch_http(
        &self,
        method: &str,
        path: &str,
        identity: Option<&Identity>,
        query: &Value,
        body: &Value,
    ) -> Option<ApiResponse> {
        let fields = match (method, path) {
            (
                "POST",
                "/sendMessage"
                | "/listMessages"
                | "/acknowledgeMessage"
                | "/permissions/set"
                | "/registerDevice",
            ) => body,
            (
                "GET",
                "/permissions/get" | "/permissions/list" | "/permissions/quote" | "/devices",
            ) => query,
            _ => return None,
        };
        Some(self.handle(path, identity, fields).await)
    }
}
