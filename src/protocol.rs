//! JSON-RPC 2.0 envelopes and the MCP protocol identity.
//!
//! Mirrors the fleet's shipped server (`/opt/swift/mcp`) exactly, so a client that works against
//! the hub works against every product door and vice versa.

use serde_json::{json, Value};

/// Newest first. A modern client names its version in `params._meta` on EVERY request; a legacy
/// client negotiates once via `initialize`. Answering both eras is what makes one endpoint usable
/// from Hermes, OpenClaw, Claude Code and a plain `curl` probe at the same time.
pub const SUPPORTED_VERSIONS: &[&str] = &[
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];

/// The version this server prefers when a client does not name one.
pub const NEWEST: &str = SUPPORTED_VERSIONS[0];

pub const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

// JSON-RPC 2.0 codes, plus the MCP-specific ones.
pub const ERR_PARSE: i64 = -32700;
pub const ERR_INVALID_REQUEST: i64 = -32600;
pub const ERR_METHOD_NOT_FOUND: i64 = -32601;
pub const ERR_INVALID_PARAMS: i64 = -32602;
pub const ERR_INTERNAL: i64 = -32603;
/// MCP: the caller's credential was missing, malformed, revoked or unknown.
pub const ERR_UNAUTHORIZED: i64 = -32001;
/// The credential is live but this door is operator-only and the caller is not an operator.
///
/// Distinct from [`ERR_UNAUTHORIZED`] on purpose: 401 means "I do not know you" and invites a
/// retry with another token; 403 means "I know you, and this door is not yours". An admin-only
/// door must never answer a customer key with a tool list, and must not pretend the key is unknown.
pub const ERR_FORBIDDEN: i64 = -32003;
/// MCP 2026-07-28: `UnsupportedProtocolVersionError`. The data carries the supported list so the
/// client can retry instead of guessing.
pub const ERR_UNSUPPORTED_VERSION: i64 = -32022;

/// Who this door says it is. Carried in every result's `_meta`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

impl ServerInfo {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({ "name": self.name, "version": self.version })
    }
}

/// A successful JSON-RPC response. `result` gains `_meta` with `serverInfo` (spec 2026-07-28:
/// servers SHOULD identify themselves in each result).
pub fn rpc_ok(id: &Value, mut result: Value, server: &ServerInfo) -> Value {
    if let Some(obj) = result.as_object_mut() {
        let info = json!({ "name": server.name, "version": server.version });
        match obj.get_mut("_meta") {
            Some(Value::Object(meta)) => {
                meta.insert(META_SERVER_INFO.to_string(), info);
            }
            _ => {
                obj.insert("_meta".to_string(), json!({ META_SERVER_INFO: info }));
            }
        }
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

pub fn rpc_error(id: &Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut err = json!({ "code": code, "message": message });
    if let Some(d) = data {
        err["data"] = d;
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": err })
}

/// `UnsupportedProtocolVersionError` with the list the client should retry from.
pub fn unsupported_version(id: &Value, requested: &str) -> Value {
    rpc_error(
        id,
        ERR_UNSUPPORTED_VERSION,
        "UnsupportedProtocolVersionError",
        Some(json!({ "requested": requested, "supported": SUPPORTED_VERSIONS })),
    )
}

/// The caller's stated protocol version, if any (modern clients state it on every request).
pub fn requested_version(body: &Value) -> Option<&str> {
    body.pointer("/params/_meta")
        .and_then(|m| m.get(META_VERSION))
        .and_then(|v| v.as_str())
}

/// The JSON-RPC id, preserved verbatim (string, number or null).
pub fn request_id(body: &Value) -> Value {
    body.get("id").cloned().unwrap_or(Value::Null)
}

/**
 * Cap a caller-supplied `limit`.
 *
 * Every list tool must clamp: a tool that honours `limit: 100000` can dump a table into a context
 * window. `None` takes the default; anything outside `1..=max` is clamped, never refused, because
 * a refused limit teaches an agent nothing.
 */
pub fn clamp_limit(requested: Option<i64>, default: i64, max: i64) -> i64 {
    requested.unwrap_or(default).clamp(1, max.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_carries_server_info() {
        let info = ServerInfo::new("door", "1.0.0");
        let v = rpc_ok(&json!(1), json!({ "tools": [] }), &info);
        assert_eq!(
            v["result"]["_meta"][META_SERVER_INFO]["name"], "door",
            "unexpected envelope: {v}"
        );
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn error_shape() {
        let v = rpc_error(&json!("a"), -32602, "bad", None);
        assert_eq!(v["error"]["code"], -32602);
        assert!(v["error"].get("data").is_none());
    }

    #[test]
    fn unsupported_version_lists_alternatives() {
        let v = unsupported_version(&Value::Null, "1999-01-01");
        assert_eq!(v["error"]["code"], ERR_UNSUPPORTED_VERSION);
        assert_eq!(v["error"]["data"]["requested"], "1999-01-01");
        assert_eq!(v["error"]["data"]["supported"][0], NEWEST);
    }

    #[test]
    fn limit_is_clamped_not_refused() {
        assert_eq!(clamp_limit(None, 25, 200), 25);
        assert_eq!(clamp_limit(Some(0), 25, 200), 1);
        assert_eq!(clamp_limit(Some(10_000), 25, 200), 200);
    }
}
