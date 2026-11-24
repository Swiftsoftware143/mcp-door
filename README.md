# mcp-door

One MCP skeleton for every SwiftSoftware product. Each app exposes **its own** door — a route inside
the app that owns the rules — and this crate is the only implementation of the parts that must never
differ: the JSON-RPC transport, the MCP protocol identity, the credential-resolution contract, tenant
scoping, the 404-not-403 rule, the audit line, and the tool registry.

**This is not a hub.** It holds no database, no pool and no master key. It cannot read another
product's data, and no tool it ships is a "run any query" door.

## What it gives a product

| Piece | Guarantee |
|---|---|
| Transport | `POST <path>`, JSON-RPC 2.0, dual-era MCP: `server/discover` + `_meta` versions (2026-07-28) and the legacy `initialize` handshake; unknown version refused `-32022` with the supported list |
| Credential contract | `CredentialResolver` is called on **every** request and nothing is cached, so a revoked key dies on the next call |
| Tenancy | `Caller` carries the workspace ids; `Scope` turns them into a SQL predicate and a row check |
| 404, not 403 | `Scope::require` answers `not_found` for a foreign row — a refusal never confirms the row exists |
| Audit | one JSON line per call (subject, tool, redacted+truncated args, outcome, rows, ms), `0600`; a token can never be written |
| Registry | names, descriptions, input schemas, annotations, minimum role, paging; validated at startup so a half-annotated tool cannot serve |
| Errors | tool failures ride `result.isError` with `{error, message}`; protocol failures ride JSON-RPC `error`; an internal message is audited, never returned |

## Consume it

Build box (checked out beside the apps):

```toml
mcp-door = { path = "../mcp-door" }
```

CI / GitHub:

```toml
mcp-door = { git = "https://github.com/Swiftsoftware143/mcp-door", rev = "<commit>" }
```

Pin a `rev`, not a branch: a door that changes under a product between builds is not a contract.

## Wiring a door

1. **Implement `CredentialResolver` in the app.** It must do the live checks on every call:
   hash/prefix match, the app's liveness predicate, the workspace row. For a session-backed door,
   the app's canonical session checks (blacklist, `user_session_state`, password-change stamp).
   A signature check alone is a defect.
2. **Define the app's tools** from its own features, with `ToolSpec::read/write/destructive`,
   a schema, a description a model can act on, and a minimum role. Read tools filter with
   `ctx.scope.sql_filter("t.tenant_id", 2)` inside the statement.
3. **Build the door** — `Door::builder(name, version, registry, resolver).audit(path).build()?`.
   A bad registry fails at startup, not on a customer's first call.
4. **Mount it** inside the app's existing router: `router = router.merge(Arc::new(door).router())`.
5. **Prove it** — `cargo test` (the contract suite in `tests/contract.rs`) and
   `python3 scripts/door-contract.py https://<app-host>/mcp --workspace-token … --readonly-token …
   --admin-token … --revoked-token …`. Both must pass before the door is announced.

`examples/reference-door.rs` is the copy-paste template: four tools, three key kinds, one operator
key, one revoked key, audit to a file.

## Upgrading

The crate is versioned and shared. A product pins a revision and moves when it chooses; a change
that alters wire behaviour bumps the minor version and is recorded in the fleet docs. Protocol
constants mirror `/opt/swift/mcp` (the read hub) — the two must never disagree about what version
they speak.

## Verification (this revision)

- `cargo test` — 19 unit + 12 contract tests, including 401 with no detail, foreign id →
  `not_found` (and the owner still reads it), role gates, pagination to exhaustion, annotations on
  every tool, redaction, notification 202, batch refusal, parse error.
- `scripts/door-contract.py` against the live reference door — 14/14 checks.
- Live fixture proof: A cannot read B's item (same answer as a missing id), B can; a read-only key
  cannot write; a workspace key cannot call the admin tool; the audit file has zero token strings
  and is `0600`.

## Layout

```
src/protocol.rs    JSON-RPC envelopes, protocol versions, limit clamping
src/credential.rs  Caller, Role, Scope, the resolver trait, sha256 key hash
src/tool.rs        ToolSpec, annotations, ToolError, Registry (validation, paging)
src/audit.rs       AuditRecord, AuditSink, FileAudit (redaction, 0600), NullAudit
src/transport.rs   Door, DoorBuilder, the axum router, 401/4xx semantics, timeouts
tests/contract.rs  the behaviours every port must keep
examples/reference-door.rs  a runnable door to copy
scripts/door-contract.py    live protocol probe for a real endpoint
docs/tool-inventory.md      what each product exposes, per app
```
