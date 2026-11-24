//! Test fixture: a door with two workspaces, one operator, one read-only key and one revoked key.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mcp_door::{
    AuthError, Caller, CredentialResolver, Door, Registry, Role, Scope, ToolError, ToolSpec,
};
use serde_json::{json, Value};
use uuid::Uuid;

pub fn tenant_a() -> Uuid {
    Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
}
pub fn tenant_b() -> Uuid {
    Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
}

pub const TOK_A: &str = "tok_a_workspace";
pub const TOK_B: &str = "tok_b_workspace";
pub const TOK_READONLY: &str = "tok_a_readonly";
pub const TOK_ADMIN: &str = "tok_ops_admin";
pub const TOK_REVOKED: &str = "tok_revoked";

#[derive(Clone, Debug)]
struct Item {
    id: Uuid,
    tenant: Uuid,
    name: String,
}

#[derive(Clone)]
pub struct Store {
    items: Arc<Mutex<Vec<Item>>>,
    pub beta_id: Uuid,
}

impl Store {
    pub fn seeded() -> Self {
        let beta_id = Uuid::new_v4();
        let items = vec![
            Item {
                id: Uuid::new_v4(),
                tenant: tenant_a(),
                name: "a-1".into(),
            },
            Item {
                id: Uuid::new_v4(),
                tenant: tenant_a(),
                name: "a-2".into(),
            },
            Item {
                id: beta_id,
                tenant: tenant_b(),
                name: "b-1".into(),
            },
        ];
        Self {
            items: Arc::new(Mutex::new(items)),
            beta_id,
        }
    }

    fn list(&self, scope: &Scope, limit: i64) -> Vec<Item> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .filter(|i| scope.contains(i.tenant))
            .take(limit as usize)
            .cloned()
            .collect()
    }

    fn get(&self, id: Uuid) -> Option<Item> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .find(|i| i.id == id)
            .cloned()
    }

    fn insert(&self, tenant: Uuid, name: String) -> Item {
        let item = Item {
            id: Uuid::new_v4(),
            tenant,
            name,
        };
        self.items.lock().unwrap().push(item.clone());
        item
    }

    pub fn total(&self) -> usize {
        self.items.lock().unwrap().len()
    }
}

pub struct Auth;

#[async_trait]
impl CredentialResolver for Auth {
    async fn resolve(&self, bearer: &str) -> Result<Caller, AuthError> {
        match bearer {
            TOK_A => Ok(Caller::new("a-key", Role::Workspace).with_tenant(tenant_a())),
            TOK_B => Ok(Caller::new("b-key", Role::Workspace).with_tenant(tenant_b())),
            TOK_READONLY => Ok(Caller::new("a-ro", Role::ReadOnly).with_tenant(tenant_a())),
            TOK_ADMIN => Ok(Caller::new("ops", Role::Admin)
                .with_tenant(tenant_a())
                .with_home(tenant_a())),
            TOK_REVOKED => Err(AuthError::Revoked),
            _ => Err(AuthError::Invalid),
        }
    }
}

pub fn registry(store: Store) -> Registry {
    let list_store = store.clone();
    let get_store = store.clone();
    let create_store = store.clone();
    let tenants_store = store;

    Registry::new()
        .with_fn(
            ToolSpec::read(
                "list_items",
                "List the items in this workspace. Returns count and items. Read-only.",
            )
            .schema(json!({
                "type": "object",
                "properties": { "limit": { "type": "integer" } },
                "additionalProperties": false
            })),
            move |ctx, args| {
                let store = list_store.clone();
                Box::pin(async move {
                    let limit = ctx.limit(args.get("limit"), 25, 200);
                    let items = store.list(&ctx.scope, limit);
                    Ok(json!({ "count": items.len(), "items": items.iter().map(|i| json!({"id": i.id, "name": i.name})).collect::<Vec<_>>() }))
                })
            },
        )
        .with_fn(
            ToolSpec::read(
                "get_item",
                "Fetch one item by id from this workspace. A foreign id answers not_found.",
            )
            .schema(json!({
                "type": "object",
                "properties": { "id": { "type": "string" } },
                "required": ["id"],
                "additionalProperties": false
            })),
            move |ctx, args| {
                let store = get_store.clone();
                Box::pin(async move {
                    let id = ctx.uuid_arg(&args, "id")?;
                    let item = store.get(id).ok_or(ToolError::NotFound)?;
                    ctx.require_scope(item.tenant)?;
                    Ok(json!({ "item": { "id": item.id, "name": item.name } }))
                })
            },
        )
        .with_fn(
            ToolSpec::write(
                "create_item",
                "Create an item in the caller's own workspace. Read-only keys are refused.",
            )
            .schema(json!({
                "type": "object",
                "properties": { "name": { "type": "string" } },
                "required": ["name"],
                "additionalProperties": false
            })),
            move |ctx, args| {
                let store = create_store.clone();
                Box::pin(async move {
                    ctx.require_write()?;
                    let name = ctx.str_arg(&args, "name")?.to_string();
                    let tenant = *ctx.scope.ids().first().ok_or(ToolError::NotFound)?;
                    let item = store.insert(tenant, name);
                    Ok(json!({ "item": { "id": item.id } }))
                })
            },
        )
        .with_fn(
            ToolSpec::read(
                "list_tenants",
                "Operator only: every workspace with its item count. Reads across workspaces.",
            )
            .min_role(Role::Admin),
            move |ctx, _args| {
                let store = tenants_store.clone();
                Box::pin(async move {
                    ctx.require_admin()?;
                    let total = store.total();
                    Ok(json!({ "count": total }))
                })
            },
        )
}

pub struct Fixture {
    pub url: String,
    pub audit: PathBuf,
    pub store: Store,
}

/// Boot a door on an ephemeral port. The audit path is unique per fixture.
pub async fn start() -> Fixture {
    let store = Store::seeded();
    let audit = std::env::temp_dir().join(format!("mcp-door-test-{}.log", Uuid::new_v4()));
    let door = Arc::new(
        Door::builder(
            "test-door",
            "0.1.0",
            registry(store.clone()),
            Arc::new(Auth),
        )
        .page_size(2)
        .audit(audit.clone())
        .instructions("Fixture door: every tool is workspace-scoped by the bearer token.")
        .build()
        .expect("door builds"),
    );
    let router = door.clone().router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Fixture {
        url: format!("http://{addr}/mcp"),
        audit,
        store,
    }
}

/// One JSON-RPC round trip. Returns (HTTP status, parsed body or raw text as a JSON string).
pub async fn rpc(url: &str, token: Option<&str>, body: Value) -> (u16, Value) {
    let client = reqwest::Client::new();
    let mut req = client.post(url).json(&body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let res = req.send().await.expect("request");
    let status = res.status().as_u16();
    let text = res.text().await.expect("body");
    let parsed = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
    (status, parsed)
}

pub fn tools_call(name: &str, args: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": { "name": name, "arguments": args }
    })
}

/// The tool payload: `result.structuredContent`, falling back to the text block.
pub fn payload(response: &Value) -> Value {
    response
        .pointer("/result/structuredContent")
        .cloned()
        .unwrap_or_else(|| {
            let text = response
                .pointer("/result/content/0/text")
                .and_then(|v| v.as_str())
                .unwrap_or("{}");
            serde_json::from_str(text).unwrap_or_else(|_| json!({ "raw": text }))
        })
}

pub fn is_error(response: &Value) -> bool {
    response
        .pointer("/result/isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

pub fn audit_lines(path: &PathBuf) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or(Value::Null))
        .collect()
}
