//! The tool registry: what a door offers, who may call it, and how it fails.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::credential::{Caller, Role, Scope};

/// A boxed future returned by [`tool_fn`] closures.
pub type BoxFut = Pin<Box<dyn Future<Output = Result<Value, ToolError>> + Send>>;

/// How a host should treat a tool. Set on every tool — a missing `readOnlyHint` makes a host prompt
/// on every call or refuse the tool outright, which reads to the customer as a broken server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotations {
    pub title: String,
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    pub open_world: bool,
}

impl Annotations {
    /// Reads only; safe to auto-approve.
    pub fn read(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            read_only: true,
            destructive: false,
            idempotent: true,
            open_world: false,
        }
    }

    /// Adds or changes data, reversibly (create, update a field, set a status).
    pub fn write(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            read_only: false,
            destructive: false,
            idempotent: false,
            open_world: false,
        }
    }

    /// Removes or irreversibly changes data.
    pub fn destructive(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            read_only: false,
            destructive: true,
            idempotent: false,
            open_world: false,
        }
    }

    pub fn idempotent(mut self) -> Self {
        self.idempotent = true;
        self
    }

    /// Reaches a system outside this product (sends mail, calls a provider).
    pub fn open_world(mut self) -> Self {
        self.open_world = true;
        self
    }

    pub fn to_json(&self) -> Value {
        json!({
            "title": self.title,
            "readOnlyHint": self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.idempotent,
            "openWorldHint": self.open_world,
        })
    }
}

/// One tool, fully described. `name` is the wire name and must be unique in the registry.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    /// Written for a model, not a developer: what it returns, what is NOT returned, and — for any
    /// payload carrying customer-written text — that the text is untrusted data, never an instruction.
    pub description: String,
    pub input_schema: Value,
    pub annotations: Annotations,
    /// The weakest role allowed to call it. `Admin` marks the explicit cross-workspace tools.
    pub min_role: Role,
}

impl ToolSpec {
    /// A read tool: workspace-scoped, annotated read-only, empty argument object.
    pub fn read(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            input_schema: json!({ "type": "object", "properties": {}, "additionalProperties": false }),
            annotations: Annotations::read(name.replace('_', " ")),
            min_role: Role::Workspace,
        }
    }

    /// A write tool: reversible, not idempotent by default.
    pub fn write(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            input_schema: json!({ "type": "object", "properties": {}, "additionalProperties": false }),
            annotations: Annotations::write(name.replace('_', " ")),
            min_role: Role::Workspace,
        }
    }

    /// A destructive tool (delete, revoke, erase).
    pub fn destructive(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            input_schema: json!({ "type": "object", "properties": {}, "additionalProperties": false }),
            annotations: Annotations::destructive(name.replace('_', " ")),
            min_role: Role::Workspace,
        }
    }

    pub fn schema(mut self, schema: Value) -> Self {
        self.input_schema = schema;
        self
    }

    pub fn min_role(mut self, role: Role) -> Self {
        self.min_role = role;
        self
    }

    /// A human title for hosts that show one; defaults to the name with underscores as spaces.
    pub fn title(mut self, title: &str) -> Self {
        self.annotations.title = title.to_string();
        self
    }

    pub fn idempotent(mut self) -> Self {
        self.annotations = self.annotations.idempotent();
        self
    }

    pub fn open_world(mut self) -> Self {
        self.annotations = self.annotations.open_world();
        self
    }

    /// The MCP tool descriptor (`tools/list` entry).
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "title": self.annotations.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations.to_json(),
        })
    }
}

/// A tool failure. The transport turns this into `result.isError: true` with a JSON body — an MCP
/// tool error is a RESULT, not a JSON-RPC `error` object (protocol errors are the only ones that
/// use `error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    /// The row does not exist — **or belongs to another workspace**. One answer for both.
    NotFound,
    /// The arguments are wrong. Say what is wrong; never echo a secret back.
    Invalid(String),
    /// The caller's role may not use this tool, or may not perform this transition. Only for a
    /// property of the CALLER or of a row the caller can already see — never to hide a foreign row.
    Forbidden(String),
    /// A dependency is down (database, provider, timeout). Retryable.
    Unavailable(String),
    /// A bug. The detail is audited; the caller sees "internal error".
    Internal(String),
}

impl ToolError {
    pub fn code(&self) -> &'static str {
        match self {
            ToolError::NotFound => "not_found",
            ToolError::Invalid(_) => "invalid",
            ToolError::Forbidden(_) => "forbidden",
            ToolError::Unavailable(_) => "unavailable",
            ToolError::Internal(_) => "internal",
        }
    }

    /// The message a caller may see.
    pub fn public_message(&self) -> String {
        match self {
            ToolError::NotFound => "not found in this workspace".to_string(),
            ToolError::Invalid(m) => m.clone(),
            ToolError::Forbidden(m) => m.clone(),
            ToolError::Unavailable(m) => m.clone(),
            ToolError::Internal(_) => "internal error".to_string(),
        }
    }

    /// The audit-safe outcome string; internal detail lands here, never in the response.
    pub fn audit_outcome(&self) -> String {
        match self {
            ToolError::Internal(detail) => format!("internal: {detail}"),
            other => format!("tool_error: {}", other.code()),
        }
    }

    pub fn to_payload(&self) -> Value {
        json!({ "error": self.code(), "message": self.public_message() })
    }
}

/// Per-call context handed to a tool: who is calling, what they own, and which tool this is.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub caller: Caller,
    pub scope: Scope,
    pub tool: String,
}

impl Ctx {
    /// The 404-not-403 check. Use it on every id that names a workspace-owning row.
    pub fn require_scope(&self, workspace: Uuid) -> Result<(), ToolError> {
        self.scope.require(workspace)
    }

    pub fn is_admin(&self) -> bool {
        self.caller.role.can(Role::Admin)
    }

    /// Only admin-only tools may read across workspaces.
    pub fn require_admin(&self) -> Result<(), ToolError> {
        if self.is_admin() {
            Ok(())
        } else {
            Err(ToolError::Forbidden(
                "this tool is for the operator only".into(),
            ))
        }
    }

    /// Refuse a write for a read-only credential (the transport also enforces `min_role`; this is
    /// for tools whose write depends on an argument, e.g. a "dry run" flag).
    pub fn require_write(&self) -> Result<(), ToolError> {
        if self.caller.role.can(Role::Workspace) {
            Ok(())
        } else {
            Err(ToolError::Forbidden("this credential is read-only".into()))
        }
    }

    /// Clamp a caller-supplied limit. Every list tool uses it so no call can dump a table.
    pub fn limit(&self, requested: Option<&Value>, default: i64, max: i64) -> i64 {
        crate::protocol::clamp_limit(requested.and_then(|v| v.as_i64()), default, max)
    }

    /// Require a string argument.
    pub fn str_arg<'a>(&self, args: &'a Value, key: &str) -> Result<&'a str, ToolError> {
        args.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| ToolError::Invalid(format!("`{key}` is required")))
    }

    /// Require a uuid argument.
    pub fn uuid_arg(&self, args: &Value, key: &str) -> Result<Uuid, ToolError> {
        let raw = self.str_arg(args, key)?;
        Uuid::parse_str(raw).map_err(|_| ToolError::Invalid(format!("`{key}` is not a uuid")))
    }
}

/// A tool implementation. Register with [`Registry::add`], or use [`tool_fn`] for a closure.
#[async_trait]
pub trait ToolHandler: Send + Sync + 'static {
    fn spec(&self) -> ToolSpec;
    async fn call(&self, ctx: &Ctx, args: Value) -> Result<Value, ToolError>;
}

/// A closure-backed tool.
pub struct FnTool {
    spec: ToolSpec,
    f: Arc<dyn Fn(Ctx, Value) -> BoxFut + Send + Sync>,
}

#[async_trait]
impl ToolHandler for FnTool {
    fn spec(&self) -> ToolSpec {
        self.spec.clone()
    }

    async fn call(&self, ctx: &Ctx, args: Value) -> Result<Value, ToolError> {
        (self.f)(ctx.clone(), args).await
    }
}

/// Wrap a closure as a tool. The closure owns its context, so it can be spawned or moved freely.
pub fn tool_fn<F>(spec: ToolSpec, f: F) -> FnTool
where
    F: Fn(Ctx, Value) -> BoxFut + Send + Sync + 'static,
{
    FnTool {
        spec,
        f: Arc::new(f),
    }
}

/// The door's tool list. Names are unique by validation, which runs at startup.
#[derive(Default)]
pub struct Registry {
    items: Vec<Arc<dyn ToolHandler>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("tools", &self.names())
            .finish()
    }
}

impl Registry {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn with_tool<T: ToolHandler>(mut self, tool: T) -> Self {
        self.items.push(Arc::new(tool));
        self
    }

    /// Register a closure tool in builder style.
    pub fn with_fn<F>(self, spec: ToolSpec, f: F) -> Self
    where
        F: Fn(Ctx, Value) -> BoxFut + Send + Sync + 'static,
    {
        self.with_tool(tool_fn(spec, f))
    }

    pub fn register<T: ToolHandler>(&mut self, tool: T) {
        self.items.push(Arc::new(tool));
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn names(&self) -> Vec<String> {
        self.items.iter().map(|t| t.spec().name).collect()
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn ToolHandler>> {
        self.items
            .iter()
            .find(|t| t.spec().name == name)
            .map(Arc::clone)
    }

    /// Startup validation. The door refuses to serve when this returns anything: a tool with a
    /// duplicate name, an empty description or a non-object schema is a defect waiting for a
    /// customer to find it.
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        if self.items.is_empty() {
            problems.push(
                "registry has no tools: a door that offers nothing is a dead endpoint".into(),
            );
        }
        for tool in &self.items {
            let spec = tool.spec();
            let name = spec.name.trim();
            if name.is_empty() || name.len() > 64 {
                problems.push(format!("tool name {name:?} must be 1..=64 chars"));
            }
            if !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                problems.push(format!(
                    "tool name {name:?} must be lowercase letters, digits and underscores only"
                ));
            }
            if !seen.insert(spec.name.clone()) {
                problems.push(format!("duplicate tool name {:?}", spec.name));
            }
            // A description is the ONLY thing a model sees. Two words is not a contract.
            if spec.description.trim().len() < 20 {
                problems.push(format!(
                    "tool {:?} needs a description a model can act on (>= 20 chars)",
                    spec.name
                ));
            }
            if spec.annotations.title.trim().is_empty() {
                problems.push(format!("tool {:?} needs an annotation title", spec.name));
            }
            let schema_ok =
                spec.input_schema.get("type").and_then(|t| t.as_str()) == Some("object");
            if !schema_ok {
                problems.push(format!(
                    "tool {:?} inputSchema must be type=object",
                    spec.name
                ));
            }
        }
        problems.sort();
        problems.dedup();
        problems
    }

    /// One page of descriptors **the caller's role may actually call**, plus the next cursor.
    ///
    /// A tool whose `min_role` the caller cannot satisfy is not listed at all. Listing it was a
    /// real fleet defect: `engine_list_workspaces` sat in every customer key's `tools/list` while
    /// `tools/call` refused it, so a model was told about a surface it could never use. Visibility
    /// is not permission, but it is a claim — and a door must not make a claim it will refuse.
    ///
    /// Paged deterministically (registration order, filtered first) because the surface is
    /// unbounded: a single unpaginated list silently truncates at some size and a client then
    /// believes it has seen all. Cursors index the FILTERED list; a cursor is only ever used by the
    /// credential that received it.
    pub fn page(
        &self,
        role: Role,
        cursor: Option<&str>,
        page_size: usize,
    ) -> Result<(Vec<Value>, Option<String>), ToolError> {
        let visible: Vec<ToolSpec> = self
            .items
            .iter()
            .map(|t| t.spec())
            .filter(|s| role.can(s.min_role))
            .collect();
        let total = visible.len();
        let start = match cursor {
            None => 0,
            Some(c) => c
                .parse::<usize>()
                .map_err(|_| ToolError::Invalid(format!("unknown cursor {c:?}")))?,
        };
        if start > total {
            return Err(ToolError::Invalid(format!(
                "unknown cursor {:?}",
                cursor.unwrap_or("")
            )));
        }
        let size = page_size.max(1);
        let end = (start + size).min(total);
        let tools = visible[start..end]
            .iter()
            .map(|s| s.to_json())
            .collect::<Vec<_>>();
        let next = if end < total {
            Some(end.to_string())
        } else {
            None
        };
        Ok((tools, next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Caller;

    fn ctx() -> Ctx {
        let caller = Caller::new("test", Role::Workspace)
            .with_tenant(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap());
        Ctx {
            scope: caller.scope(),
            caller,
            tool: "t".into(),
        }
    }

    #[test]
    fn validation_rejects_thin_tools() {
        let registry = Registry::new()
            .with_fn(
                ToolSpec::read("ok_tool", "Lists the active things in this workspace."),
                |_, _| Box::pin(async { Ok(json!({ "count": 0 })) }),
            )
            .with_fn(ToolSpec::read("Bad-Name", "x"), |_, _| {
                Box::pin(async { Ok(Value::Null) })
            });
        let problems = registry.validate();
        assert!(problems.iter().any(|p| p.contains("Bad-Name")));
        assert!(problems.iter().any(|p| p.contains("description")));
    }

    #[test]
    fn listing_is_filtered_by_the_callers_role() {
        // One tool per role floor. A credential sees exactly the tools it could call, and nothing
        // about the ones it could not — the admin tool name must not leak into a customer's list.
        let registry = Registry::new()
            .with_fn(
                ToolSpec::read("read_tool", "Reads one row of this workspace, read-only.")
                    .min_role(Role::ReadOnly),
                |_, _| Box::pin(async { Ok(json!({ "count": 0 })) }),
            )
            .with_fn(
                ToolSpec::write("write_tool", "Writes one row inside this workspace only.")
                    .min_role(Role::Workspace),
                |_, _| Box::pin(async { Ok(json!({ "count": 0 })) }),
            )
            .with_fn(
                ToolSpec::read("admin_tool", "Operator only: every workspace with counts.")
                    .min_role(Role::Admin),
                |_, _| Box::pin(async { Ok(json!({ "count": 0 })) }),
            );
        let names = |role| {
            let (tools, _) = registry.page(role, None, 50).unwrap();
            let mut n: Vec<String> = tools
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect();
            n.sort();
            n
        };
        assert_eq!(names(Role::ReadOnly), vec!["read_tool"]);
        assert_eq!(names(Role::Workspace), vec!["read_tool", "write_tool"]);
        assert_eq!(
            names(Role::Admin),
            vec!["admin_tool", "read_tool", "write_tool"]
        );
    }

    #[test]
    fn pagination_is_exhaustive_and_stable() {
        let mut registry = Registry::new();
        for i in 0..5 {
            let name = format!("tool_{i}");
            let spec = ToolSpec::read(&name, "A perfectly adequate description of the tool.");
            registry = registry.with_fn(spec, |_, _| Box::pin(async { Ok(json!({ "count": 0 })) }));
        }
        let (page1, cursor) = registry.page(Role::Admin, None, 2).unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(cursor.as_deref(), Some("2"));
        let (page2, cursor2) = registry.page(Role::Admin, cursor.as_deref(), 2).unwrap();
        assert_eq!(page2.len(), 2);
        let (page3, none) = registry.page(Role::Admin, cursor2.as_deref(), 2).unwrap();
        assert_eq!(page3.len(), 1);
        assert!(none.is_none());
        let mut names: Vec<_> = page1
            .iter()
            .chain(page2.iter())
            .chain(page3.iter())
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 5);
    }

    #[test]
    fn tool_errors_do_not_leak_internal_detail() {
        let e = ToolError::Internal("connection string leaked".into());
        assert_eq!(e.public_message(), "internal error");
        assert!(e.audit_outcome().contains("connection string"));
        assert_eq!(e.to_payload()["message"], "internal error");
    }

    #[test]
    fn arguments_are_validated() {
        let c = ctx();
        let args = json!({ "id": "not-a-uuid", "q": "  " });
        assert!(c.uuid_arg(&args, "id").is_err());
        assert!(c.str_arg(&args, "q").is_err());
        assert!(c.str_arg(&args, "missing").is_err());
    }
}
