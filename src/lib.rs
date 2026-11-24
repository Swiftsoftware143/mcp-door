//! # mcp-door — one MCP skeleton, many products
//!
//! Every SwiftSoftware product exposes its **own** MCP door: a route inside the app that owns the
//! rules (`/mcp` or `/api/mcp`), authenticated by **that app's** credential resolver, scoped by
//! **that app's** tenancy, serving **that app's** tools. This crate is the only implementation of
//! the parts that must never differ between products:
//!
//! * the JSON-RPC 2.0 transport and the current MCP protocol identity (dual-era: stateless
//!   `server/discover` with `_meta` versions, plus the legacy `initialize` handshake),
//! * the credential-resolution **contract** (a trait the app implements, called on every request),
//! * tenant scoping helpers, and the one place a foreign id becomes `not_found` instead of
//!   `forbidden` (a refusal must not confirm that the row exists),
//! * the audit line written for every call, with argument redaction and truncation,
//! * the tool registry (names, titles, descriptions, input schemas, annotations, minimum role,
//!   pagination), validated at startup so a half-annotated tool cannot ship.
//!
//! What this crate deliberately does **not** contain: SQL, database pools, a master key, or a
//! "run any query" tool. A door never reaches another product's data, and the app's own module
//! functions do the reading/writing so REST and MCP cannot drift apart.
//!
//! ## The non-negotiables encoded here
//!
//! 1. **A signature check is not a credential.** [`CredentialResolver`] must check the app's live
//!    credential row on every call: hash/prefix match, liveness predicate, the workspace row, and
//!    for session-backed doors the app's canonical session checks. Nothing is cached; a revoked
//!    key fails on the very next request.
//! 2. **No tool takes a tenant argument.** The token is the tenancy boundary. Cross-workspace
//!    reads are separate, admin-only tools that opt out explicitly via [`Scope::unscoped`].
//! 3. **Foreign ids answer `not_found`, never `forbidden`.** [`Scope::require`] is the single
//!    place that rule lives.
//! 4. **The filter belongs inside the statement.** [`Scope::sql_filter`] returns the `and …`
//!    clause to paste into a fixed query; a post-fetch check is not the same guarantee.
//! 5. **Every tool is annotated.** A host uses `readOnlyHint` to auto-approve; without annotations
//!    every call prompts, which reads as "the server is broken".
//!
//! ## Wiring a door (the port recipe)
//!
//! ```ignore
//! use std::sync::Arc;
//! use mcp_door::{tool_fn, Ctx, Door, Registry, ToolError, ToolSpec};
//!
//! let registry = Registry::new()
//!     .with_fn(ToolSpec::read("list_contacts", "Active contacts in this workspace, newest first."),
//!         |ctx: Ctx, args: serde_json::Value| Box::pin(async move {
//!             let limit = ctx.limit(args.get("limit"), 25, 200);
//!             // let rows = app::contacts::list(&ctx.scope, limit).await?;
//!             Ok(serde_json::json!({ "count": 0, "items": [] }))
//!         }));
//!
//! let door = Door::builder("coreswift", "1.0.0", registry, auth::Resolver::new(pool.clone()))
//!     .audit("/opt/swift/coreswift/data/mcp-audit.log")
//!     .build()?;
//! // mount at POST /mcp inside the app's existing axum router
//! let app = app.merge(Arc::new(door).router("/mcp"));
//! ```
//!
//! The resolver is the app's own authentication code. The skeleton ships
//! [`testkit`-free] contract tests in `tests/contract.rs` and a live probe in
//! `scripts/door-contract.py`; a port is not done until both pass against the real app.

pub mod audit;
pub mod credential;
pub mod protocol;
pub mod tool;
pub mod transport;

pub use audit::{AuditRecord, AuditSink, FileAudit, NullAudit};
pub use credential::{hash_token, AuthError, Caller, CredentialResolver, Role, Scope, ScopeIds};
pub use protocol::{ServerInfo, SUPPORTED_VERSIONS};
pub use tool::{tool_fn, Annotations, Ctx, FnTool, Registry, ToolError, ToolHandler, ToolSpec};
pub use transport::{Door, DoorBuilder, DoorConfig};
