//! A complete, runnable MCP door — the template an app lane copies.
//!
//! It is not a product: the store is in memory and the tokens are constants. What it demonstrates
//! is the shape every real port must keep:
//!
//! * the app owns the credential resolver (here: three workspace keys, one operator key, one
//!   revoked key) — a real port performs the live row checks documented on
//!   [`mcp_door::CredentialResolver`];
//! * no tool takes a workspace argument; every read is filtered by `ctx.scope` and a foreign id
//!   answers `not_found`;
//! * one admin-only tool opts out with `Scope::unscoped()` and says so in its description;
//! * every call lands in the audit file with the arguments redacted.
//!
//! Run it:  `cargo run --example reference-door`
//! Probe it: `python3 scripts/door-contract.py http://127.0.0.1:8111/mcp`

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mcp_door::{Caller, CredentialResolver, Door, Registry, Role, Scope, ToolError, ToolSpec};
use serde_json::{json, Value};
use uuid::Uuid;

fn tenant_a() -> Uuid {
    Uuid::parse_str("11111111-1111-1111-1111-111111111111").expect("uuid")
}
fn tenant_b() -> Uuid {
    Uuid::parse_str("22222222-2222-2222-2222-222222222222").expect("uuid")
}

#[derive(Clone, Debug)]
struct Item {
    id: Uuid,
    tenant: Uuid,
    name: String,
    qty: i64,
}

#[derive(Clone)]
struct Store {
    items: Arc<Mutex<Vec<Item>>>,
}

impl Store {
    fn seeded() -> Self {
        let items = vec![
            Item {
                id: Uuid::new_v4(),
                tenant: tenant_a(),
                name: "Acme starter".into(),
                qty: 2,
            },
            Item {
                id: Uuid::new_v4(),
                tenant: tenant_a(),
                name: "Acme refill".into(),
                qty: 5,
            },
            Item {
                id: Uuid::new_v4(),
                tenant: tenant_b(),
                name: "Beta starter".into(),
                qty: 1,
            },
        ];
        Self {
            items: Arc::new(Mutex::new(items)),
        }
    }

    fn list(&self, scope: &Scope, limit: i64) -> Vec<Item> {
        let guard = self.items.lock().expect("store poisoned");
        guard
            .iter()
            .filter(|i| scope.contains(i.tenant))
            .take(limit as usize)
            .cloned()
            .collect()
    }

    fn get(&self, id: Uuid) -> Option<Item> {
        self.items
            .lock()
            .expect("store poisoned")
            .iter()
            .find(|i| i.id == id)
            .cloned()
    }

    fn insert(&self, tenant: Uuid, name: String, qty: i64) -> Item {
        let item = Item {
            id: Uuid::new_v4(),
            tenant,
            name,
            qty,
        };
        self.items
            .lock()
            .expect("store poisoned")
            .push(item.clone());
        item
    }

    fn count_by_tenant(&self) -> HashMap<Uuid, usize> {
        let mut out = HashMap::new();
        for item in self.items.lock().expect("store poisoned").iter() {
            *out.entry(item.tenant).or_insert(0) += 1;
        }
        out
    }
}

fn item_json(item: &Item) -> Value {
    json!({ "id": item.id, "name": item.name, "qty": item.qty })
}

/// The app's own authentication. In a real door this is one live query per call:
///
/// ```ignore
/// let row = sqlx::query("select tenant_id, key_prefix from api_keys
///                        where key_hash = $1 and revoked_at is null")
///     .bind(mcp_door::hash_token(bearer)).fetch_optional(&pool).await?;
/// ```
struct AppAuth;

#[async_trait]
impl CredentialResolver for AppAuth {
    async fn resolve(&self, bearer: &str) -> Result<Caller, mcp_door::AuthError> {
        match bearer {
            // A customer's own key: read + write inside ONE workspace.
            "tok_acme_workspace" => {
                Ok(Caller::new("acme (workspace key)", Role::Workspace).with_tenant(tenant_a()))
            }
            "tok_beta_workspace" => {
                Ok(Caller::new("beta (workspace key)", Role::Workspace).with_tenant(tenant_b()))
            }
            // A key issued to an assistant that must not change anything.
            "tok_acme_readonly" => {
                Ok(Caller::new("acme-ro (workspace key)", Role::ReadOnly).with_tenant(tenant_a()))
            }
            // The operator: runs the software AND uses it, so it has a home workspace.
            "tok_ops_admin" => Ok(Caller::new("ops (admin key)", Role::Admin)
                .with_tenant(tenant_a())
                .with_home(tenant_a())),
            // A key whose row was revoked: rejected on the very next request, as it must be.
            "tok_revoked" => Err(mcp_door::AuthError::Revoked),
            _ => Err(mcp_door::AuthError::Invalid),
        }
    }
}

fn registry(store: Store) -> Registry {
    let list_store = store.clone();
    let get_store = store.clone();
    let create_store = store.clone();
    let tenants_store = store;
    let list = ToolSpec::read(
        "list_items",
        "List the items in this workspace, newest first. Returns { count, items: [{id, name, qty}] }. \
         Read-only and workspace-scoped: another workspace's items are never returned.",
    )
    .schema(json!({
        "type": "object",
        "properties": { "limit": { "type": "integer", "description": "1-200, default 25" } },
        "additionalProperties": false
    }));

    let get = ToolSpec::read(
        "get_item",
        "Fetch one item by id from this workspace. An id that belongs to another workspace answers \
         not_found, exactly like an id that does not exist. Read-only.",
    )
    .schema(json!({
        "type": "object",
        "properties": { "id": { "type": "string", "description": "Item uuid" } },
        "required": ["id"],
        "additionalProperties": false
    }));

    let create = ToolSpec::write(
        "create_item",
        "Create an item in the caller's own workspace. Returns the created row. A read-only \
         credential may not call this.",
    )
    .schema(json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "qty": { "type": "integer", "description": "Default 1" }
        },
        "required": ["name"],
        "additionalProperties": false
    }));

    let tenants = ToolSpec::read(
        "list_tenants",
        "Operator only: every workspace in this door with its item count. This is the one tool that \
         reads across workspaces; a workspace credential is refused.",
    )
    .min_role(Role::Admin);

    Registry::new()
        .with_fn(list, move |ctx, args| {
            let store = list_store.clone();
            Box::pin(async move {
                let limit = ctx.limit(args.get("limit"), 25, 200);
                let items = store.list(&ctx.scope, limit);
                Ok(json!({
                    "count": items.len(),
                    "items": items.iter().map(item_json).collect::<Vec<_>>()
                }))
            })
        })
        .with_fn(get, move |ctx, args| {
            let store = get_store.clone();
            Box::pin(async move {
                let id = ctx.uuid_arg(&args, "id")?;
                let item = store.get(id).ok_or(ToolError::NotFound)?;
                // The 404-not-403 rule: the row exists, but not for this caller.
                ctx.require_scope(item.tenant)?;
                Ok(json!({ "item": item_json(&item) }))
            })
        })
        .with_fn(create, move |ctx, args| {
            let store = create_store.clone();
            Box::pin(async move {
                ctx.require_write()?;
                let name = ctx.str_arg(&args, "name")?.trim().to_string();
                if name.is_empty() {
                    return Err(ToolError::Invalid("`name` must not be blank".into()));
                }
                let qty = args
                    .get("qty")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(1)
                    .clamp(0, 100_000);
                let tenant = *ctx.scope.ids().first().ok_or_else(|| {
                    ToolError::Forbidden("this credential owns no workspace".into())
                })?;
                let item = store.insert(tenant, name, qty);
                Ok(json!({ "item": item_json(&item) }))
            })
        })
        .with_fn(tenants, move |ctx, args| {
            let store = tenants_store.clone();
            Box::pin(async move {
                ctx.require_admin()?;
                let _ = args;
                let counts = store.count_by_tenant();
                let all = Scope::unscoped();
                let rows: Vec<Value> = counts
                    .iter()
                    .filter(|(t, _)| all.contains(**t))
                    .map(|(t, n)| json!({ "tenant": t, "items": n }))
                    .collect();
                Ok(json!({ "count": rows.len(), "tenants": rows }))
            })
        })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("DOOR_ADDR").unwrap_or_else(|_| "127.0.0.1:8111".to_string());
    let audit = std::env::var("DOOR_AUDIT").unwrap_or_else(|_| "./door-audit.log".to_string());

    let door = Arc::new(
        Door::builder(
            "reference-door",
            env!("CARGO_PKG_VERSION"),
            registry(Store::seeded()),
            Arc::new(AppAuth),
        )
        .audit(audit.clone())
        .instructions(
            "This is a reference door. Every tool is workspace-scoped by the bearer token; no tool \
             takes a workspace argument. Read-only examples: list_items, get_item.",
        )
        .build()?,
    );

    println!("mcp-door reference on http://{addr}/mcp  (audit: {audit})");
    println!("tools: {:?}", door.registry().names());

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, door.router()).await?;
    Ok(())
}
