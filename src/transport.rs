//! The HTTP transport: one `POST` route, JSON-RPC 2.0, dual-era protocol negotiation, 401 and 404
//! semantics, and one audit line per call.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::audit::{AuditRecord, AuditSink, FileAudit, NullAudit};
use crate::credential::{AuthError, Caller, CredentialResolver, Role};
use crate::protocol::{
    self, requested_version, rpc_error, rpc_ok, unsupported_version, ServerInfo, ERR_FORBIDDEN,
    ERR_INVALID_PARAMS, ERR_INVALID_REQUEST, ERR_METHOD_NOT_FOUND, ERR_PARSE, ERR_UNAUTHORIZED,
    SUPPORTED_VERSIONS,
};
use crate::tool::{Ctx, Registry, ToolError};

/// Knobs that are the same for every product, with one name each.
#[derive(Debug, Clone)]
pub struct DoorConfig {
    pub server_name: String,
    pub server_version: String,
    /// Route path inside the app's router. `/mcp` is the fleet default; `/api/mcp` matches
    /// CoreSwift's existing door.
    pub path: String,
    /// `tools/list` page size.
    pub page_size: usize,
    pub max_body_bytes: usize,
    pub tool_timeout: Duration,
    /// Optional onboarding text returned by `initialize`/`server/discover`.
    pub instructions: Option<String>,
}

impl DoorConfig {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            server_name: name.into(),
            server_version: version.into(),
            path: "/mcp".to_string(),
            page_size: 50,
            max_body_bytes: 1024 * 1024,
            tool_timeout: Duration::from_secs(30),
            instructions: None,
        }
    }

    fn server_info(&self) -> ServerInfo {
        ServerInfo::new(&self.server_name, &self.server_version)
    }
}

/// Why a door refused to start. A door with a bad registry or config must not serve at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorError(pub Vec<String>);

impl std::fmt::Display for DoorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "door refused to start: {}", self.0.join("; "))
    }
}

impl std::error::Error for DoorError {}

/// Builder. `build()` validates the registry and the config, and fails closed.
pub struct DoorBuilder {
    config: DoorConfig,
    registry: Registry,
    resolver: Arc<dyn CredentialResolver>,
    audit: Arc<dyn AuditSink>,
}

impl DoorBuilder {
    pub fn path(mut self, path: &str) -> Self {
        self.config.path = path.to_string();
        self
    }

    pub fn page_size(mut self, page_size: usize) -> Self {
        self.config.page_size = page_size;
        self
    }

    pub fn max_body_bytes(mut self, bytes: usize) -> Self {
        self.config.max_body_bytes = bytes;
        self
    }

    pub fn tool_timeout(mut self, timeout: Duration) -> Self {
        self.config.tool_timeout = timeout;
        self
    }

    pub fn instructions(mut self, text: &str) -> Self {
        self.config.instructions = Some(text.to_string());
        self
    }

    /// Audit to an append-only JSON-lines file (`0600`).
    pub fn audit(mut self, path: impl Into<PathBuf>) -> Self {
        self.audit = Arc::new(FileAudit::new(path));
        self
    }

    /// Audit into the app's own store.
    pub fn audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = sink;
        self
    }

    pub fn build(self) -> Result<Door, DoorError> {
        let mut problems = self.registry.validate();
        if self.config.server_name.trim().is_empty() {
            problems.push("server_name must not be empty".into());
        }
        if !self.config.path.starts_with('/') {
            problems.push("path must start with '/'".into());
        }
        if self.config.page_size == 0 {
            problems.push("page_size must be > 0".into());
        }
        if self.config.max_body_bytes < 1024 {
            problems.push("max_body_bytes must be >= 1024".into());
        }
        if problems.is_empty() {
            Ok(Door {
                config: self.config,
                registry: Arc::new(self.registry),
                resolver: self.resolver,
                audit: self.audit,
            })
        } else {
            Err(DoorError(problems))
        }
    }
}

/// A product's MCP door. Cheap to clone behind an `Arc`; one per app.
pub struct Door {
    config: DoorConfig,
    registry: Arc<Registry>,
    resolver: Arc<dyn CredentialResolver>,
    audit: Arc<dyn AuditSink>,
}

impl Door {
    pub fn builder(
        name: impl Into<String>,
        version: impl Into<String>,
        registry: Registry,
        resolver: Arc<dyn CredentialResolver>,
    ) -> DoorBuilder {
        DoorBuilder {
            config: DoorConfig::new(name, version),
            registry,
            resolver,
            audit: Arc::new(NullAudit),
        }
    }

    pub fn config(&self) -> &DoorConfig {
        &self.config
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Mount this door inside the app's existing axum router: **the fleet recipe**.
    ///
    /// It serves only the MCP route (`config.path`, `POST`) plus the body limit — no `/healthz` —
    /// so it merges into an app that already answers `GET /healthz` and `GET <path>` without an
    /// overlapping-route panic. The app keeps its own health route and its own `GET` on the path
    /// (e.g. a human-readable `mcp/info` page); the door owns `POST <path>`.
    ///
    /// ```ignore
    /// let app = app
    ///     .route("/mcp", axum::routing::get(mcp_info)) // optional, the host's own GET
    ///     .merge(door.clone().mount());
    /// ```
    ///
    /// Every fleet app is on axum 0.8, so this router merges directly; a 0.7 app cannot consume
    /// this crate at all (an axum 0.7 `Router` cannot join an 0.8 one).
    pub fn mount(self: Arc<Self>) -> Router {
        let path = self.config.path.clone();
        self.mount_at(&path)
    }

    /// [`Door::mount`] at an explicit path, for a door whose `config.path` is not the final route.
    pub fn mount_at(self: Arc<Self>, path: &str) -> Router {
        let limit = self.config.max_body_bytes;
        Router::new()
            .route(path, post(handle))
            .layer(DefaultBodyLimit::max(limit))
            .with_state(self)
    }

    /// A **standalone** router for a door that is the whole service: the MCP route plus
    /// `GET /healthz`. Do not merge this into an app router that already answers `/healthz` —
    /// two `GET /healthz` routes panic at merge. Apps use [`Door::mount`].
    pub fn router(self: Arc<Self>) -> Router {
        let path = self.config.path.clone();
        self.router_at(&path)
    }

    /// [`Door::router`] at an explicit path (standalone use only, see the warning there).
    pub fn router_at(self: Arc<Self>, path: &str) -> Router {
        let limit = self.config.max_body_bytes;
        Router::new()
            .route(path, post(handle))
            .route("/healthz", get(healthz))
            .layer(DefaultBodyLimit::max(limit))
            .with_state(self)
    }

    /// The whole request path, callable directly from a test without a socket.
    pub async fn dispatch(self: &Arc<Self>, headers: &HeaderMap, body: &[u8]) -> Response {
        // 1. Credential. Resolved on EVERY request; never cached, so a revoked key dies on the
        //    next call rather than at the next restart.
        let token = match bearer_token(headers) {
            Some(t) => t.to_string(),
            None => {
                self.audit_auth(None, "unauthorized: missing").await;
                return self.unauthorized(ERR_UNAUTHORIZED, "unauthorized");
            }
        };
        let caller = match self.resolver.resolve(&token).await {
            Ok(c) => c,
            Err(AuthError::Forbidden) => {
                // Authenticated, not authorised: the credential is live but its role may not
                // reach this door at all (an admin-only door handed a customer key). Answer 403
                // and no tool list; a 401 would tell a live customer their key is unknown.
                self.audit_auth(
                    None,
                    "forbidden: live credential without the role this door requires",
                )
                .await;
                return self.forbidden(ERR_FORBIDDEN, "forbidden");
            }
            Err(e) => {
                self.audit_auth(None, &format!("unauthorized: {}", e.audit_reason()))
                    .await;
                return self.unauthorized(ERR_UNAUTHORIZED, "unauthorized");
            }
        };
        if let Err(e) = caller.validate() {
            let outcome = format!("unauthorized: malformed caller ({})", e.audit_reason());
            self.audit_auth(Some(&caller), &outcome).await;
            return self.unauthorized(ERR_UNAUTHORIZED, "unauthorized");
        }

        // 2. Envelope.
        let parsed: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                return self.rpc_response(
                    StatusCode::BAD_REQUEST,
                    rpc_error(&Value::Null, ERR_PARSE, "Parse error", None),
                )
            }
        };
        if parsed.is_array() {
            return self.rpc_response(
                StatusCode::BAD_REQUEST,
                rpc_error(
                    &Value::Null,
                    ERR_INVALID_REQUEST,
                    "JSON-RPC batching is not supported (removed in MCP 2025-06-18)",
                    None,
                ),
            );
        }
        let id = protocol::request_id(&parsed);
        let method = match parsed.get("method").and_then(|m| m.as_str()) {
            Some(m) if !m.is_empty() => m.to_string(),
            _ => {
                return self.rpc_response(
                    StatusCode::BAD_REQUEST,
                    rpc_error(&id, ERR_INVALID_REQUEST, "method is required", None),
                )
            }
        };

        // 3. Protocol version, stated by a modern client on every request.
        if let Some(v) = requested_version(&parsed) {
            if !SUPPORTED_VERSIONS.contains(&v) {
                return self.rpc_response(StatusCode::OK, unsupported_version(&id, v));
            }
        }

        // 4. Notifications have no id (and the initialized notification always is one).
        if method.starts_with("notifications/") || parsed.get("id").is_none() {
            return StatusCode::ACCEPTED.into_response();
        }

        let info = self.config.server_info();
        match method.as_str() {
            // Modern discovery: what this server speaks, before anything else.
            "server/discover" => {
                let mut result = json!({
                    "protocolVersions": SUPPORTED_VERSIONS,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": info.to_json(),
                });
                if let Some(text) = &self.config.instructions {
                    result["instructions"] = json!(text);
                }
                self.rpc_response(StatusCode::OK, rpc_ok(&id, result, &info))
            }
            // Legacy handshake: answered, and it echoes the caller's version instead of forcing a
            // downgrade on an older client.
            "initialize" => {
                let requested = parsed
                    .pointer("/params/protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or(protocol::NEWEST);
                let chosen = if SUPPORTED_VERSIONS.contains(&requested) {
                    requested
                } else {
                    protocol::NEWEST
                };
                let mut result = json!({
                    "protocolVersion": chosen,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": info.to_json(),
                });
                if let Some(text) = &self.config.instructions {
                    result["instructions"] = json!(text);
                }
                self.rpc_response(StatusCode::OK, rpc_ok(&id, result, &info))
            }
            "ping" => self.rpc_response(StatusCode::OK, rpc_ok(&id, json!({}), &info)),
            "tools/list" => {
                let cursor = parsed.pointer("/params/cursor").and_then(|c| c.as_str());
                match self.registry.page(cursor, self.config.page_size) {
                    Ok((tools, next)) => {
                        let mut result = json!({ "tools": tools });
                        if let Some(c) = next {
                            result["nextCursor"] = json!(c);
                        }
                        self.rpc_response(StatusCode::OK, rpc_ok(&id, result, &info))
                    }
                    Err(e) => self.rpc_response(
                        StatusCode::OK,
                        rpc_error(&id, ERR_INVALID_PARAMS, &e.public_message(), None),
                    ),
                }
            }
            "tools/call" => self.tools_call(&caller, &id, &parsed).await,
            other => self.rpc_response(
                StatusCode::OK,
                rpc_error(
                    &id,
                    ERR_METHOD_NOT_FOUND,
                    &format!("method not found: {other}"),
                    None,
                ),
            ),
        }
    }

    async fn tools_call(self: &Arc<Self>, caller: &Caller, id: &Value, body: &Value) -> Response {
        let info = self.config.server_info();
        let name = match body.pointer("/params/name").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => {
                return self.rpc_response(
                    StatusCode::OK,
                    rpc_error(id, ERR_INVALID_PARAMS, "params.name is required", None),
                )
            }
        };
        let args = body
            .pointer("/params/arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if !args.is_object() {
            return self.rpc_response(
                StatusCode::OK,
                rpc_error(
                    id,
                    ERR_INVALID_PARAMS,
                    "params.arguments must be an object",
                    None,
                ),
            );
        }
        let Some(handler) = self.registry.get(&name) else {
            self.audit_call(caller, &name, &args, "unknown_tool", 0, None)
                .await;
            return self.rpc_response(
                StatusCode::OK,
                rpc_error(
                    id,
                    ERR_INVALID_PARAMS,
                    &format!("unknown tool: {name}"),
                    None,
                ),
            );
        };
        let spec = handler.spec();

        // Role gate before the handler runs: a read-only credential cannot reach a write tool, and
        // a workspace credential cannot reach the operator's cross-workspace tools.
        if !caller.role.can(spec.min_role) {
            let e = ToolError::Forbidden(format!(
                "this tool requires role `{}`",
                spec.min_role.as_str()
            ));
            self.audit_call(caller, &name, &args, "denied", 0, None)
                .await;
            return self.rpc_response(StatusCode::OK, self.tool_result(id, &info, Err(e)));
        }

        let ctx = Ctx {
            caller: caller.clone(),
            scope: caller.scope(),
            tool: name.clone(),
        };
        let started = Instant::now();
        let outcome =
            tokio::time::timeout(self.config.tool_timeout, handler.call(&ctx, args.clone())).await;
        let elapsed = started.elapsed().as_millis() as u64;
        match outcome {
            Ok(Ok(value)) => {
                let rows = rows_from(&value);
                self.audit_call(caller, &name, &args, "ok", elapsed, rows)
                    .await;
                self.rpc_response(StatusCode::OK, self.tool_result(id, &info, Ok(value)))
            }
            Ok(Err(e)) => {
                self.audit_call(caller, &name, &args, &e.audit_outcome(), elapsed, None)
                    .await;
                self.rpc_response(StatusCode::OK, self.tool_result(id, &info, Err(e)))
            }
            Err(_) => {
                let e = ToolError::Unavailable(format!(
                    "tool timed out after {}s",
                    self.config.tool_timeout.as_secs()
                ));
                self.audit_call(caller, &name, &args, &e.audit_outcome(), elapsed, None)
                    .await;
                self.rpc_response(StatusCode::OK, self.tool_result(id, &info, Err(e)))
            }
        }
    }

    /// A tool result: the payload as text (what every client renders) plus `structuredContent`
    /// (what a newer client reads), and `isError` — a tool failure is a RESULT, not a protocol error.
    fn tool_result(&self, id: &Value, info: &ServerInfo, out: Result<Value, ToolError>) -> Value {
        match out {
            Ok(value) => {
                let text = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
                rpc_ok(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": text }],
                        "structuredContent": value,
                        "isError": false
                    }),
                    info,
                )
            }
            Err(e) => {
                let payload = e.to_payload();
                rpc_ok(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": payload.to_string() }],
                        "structuredContent": payload,
                        "isError": true
                    }),
                    info,
                )
            }
        }
    }

    fn rpc_response(&self, status: StatusCode, body: Value) -> Response {
        (status, Json(body)).into_response()
    }

    fn unauthorized(&self, code: i64, message: &str) -> Response {
        let body = rpc_error(&Value::Null, code, message, None);
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(body),
        )
            .into_response()
    }

    /// 403: the caller was recognised and refused. No `WWW-Authenticate` — nothing to retry.
    fn forbidden(&self, code: i64, message: &str) -> Response {
        let body = rpc_error(&Value::Null, code, message, None);
        (StatusCode::FORBIDDEN, Json(body)).into_response()
    }

    async fn audit_call(
        &self,
        caller: &Caller,
        tool: &str,
        args: &Value,
        outcome: &str,
        ms: u64,
        rows: Option<u64>,
    ) {
        let record = AuditRecord::new(
            &self.config.server_name,
            &caller.subject,
            caller.role.as_str(),
            tool,
            args,
            outcome,
            ms,
        )
        .with_rows(rows);
        self.audit.record(&record).await;
    }

    async fn audit_auth(&self, caller: Option<&Caller>, outcome: &str) {
        let record = AuditRecord::new(
            &self.config.server_name,
            caller.map(|c| c.subject.as_str()).unwrap_or("-"),
            caller.map(|c| c.role.as_str()).unwrap_or("-"),
            "(auth)",
            &json!({}),
            outcome,
            0,
        );
        self.audit.record(&record).await;
    }
}

async fn handle(State(door): State<Arc<Door>>, headers: HeaderMap, body: Bytes) -> Response {
    door.dispatch(&headers, &body).await
}

async fn healthz(State(door): State<Arc<Door>>) -> Response {
    Json(json!({
        "ok": true,
        "door": door.config.server_name,
        "version": door.config.server_version,
        "tools": door.registry.len(),
    }))
    .into_response()
}

/// `Authorization: Bearer <token>` (scheme compared case-insensitively, as the RFC requires).
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, rest) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// A row count for the audit line, when the result carries one under a conventional key.
fn rows_from(value: &Value) -> Option<u64> {
    for key in ["count", "rows", "total"] {
        if let Some(n) = value.get(key).and_then(|v| v.as_u64()) {
            return Some(n);
        }
    }
    value
        .get("items")
        .and_then(|v| v.as_array())
        .map(|a| a.len() as u64)
}

/// The role a `subject` claim would carry if it came from a token — exposed only so a port has one
/// obvious place to map its own roles. Not used by the transport.
pub fn role_from_claim(claim: &str) -> Option<Role> {
    match claim {
        "read_only" | "readonly" | "viewer" => Some(Role::ReadOnly),
        "workspace" | "tenant" | "member" | "owner" => Some(Role::Workspace),
        "admin" | "operator" | "super_admin" => Some(Role::Admin),
        _ => None,
    }
}

/// A resolver that answers nothing — for a door used only in tests. Fails closed.
#[derive(Debug, Default, Clone)]
pub struct NoCredentials;

#[async_trait::async_trait]
impl CredentialResolver for NoCredentials {
    async fn resolve(&self, _bearer: &str) -> Result<Caller, AuthError> {
        Err(AuthError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_parsing() {
        let mut h = HeaderMap::new();
        assert!(bearer_token(&h).is_none());
        h.insert(header::AUTHORIZATION, "bearer tok".parse().unwrap());
        assert_eq!(bearer_token(&h), Some("tok"));
        h.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(bearer_token(&h).is_none());
    }

    #[test]
    fn rows_are_found_under_conventional_keys() {
        assert_eq!(rows_from(&json!({ "count": 4 })), Some(4));
        assert_eq!(rows_from(&json!({ "items": [1, 2] })), Some(2));
        assert_eq!(rows_from(&json!({ "other": 1 })), None);
    }
}
