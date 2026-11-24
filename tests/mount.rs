//! The fleet mounting recipe: `app.merge(door.mount())` inside a host that already answers
//! `GET /healthz` and `GET /mcp`. Every SwiftSoftware app runs axum 0.8 and always has a health
//! route, so the door must own `POST /mcp` only — a mount that also claimed `/healthz` would panic
//! at merge and a hand-written adapter in each app could silently drop the 401's
//! `WWW-Authenticate` header. This test is the one implementation every app consumes.

#[allow(dead_code)] // the shared fixture module serves two test binaries
mod support;

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use mcp_door::Door;
use serde_json::json;
use support::*;

#[tokio::test]
async fn mount_merges_into_a_host_router_that_owns_health_and_get() {
    let store = Store::seeded();
    let audit = std::env::temp_dir().join(format!("mcp-door-mount-{}.log", uuid::Uuid::new_v4()));
    let door = Arc::new(
        Door::builder(
            "test-door",
            "0.2.0",
            registry(store.clone()),
            Arc::new(Auth),
        )
        .page_size(2)
        .audit(audit.clone())
        .build()
        .expect("door builds"),
    );

    // The host shape shared by Engine and WorkflowSwift: its own health routes and a human-readable
    // GET on the MCP path. The door adds POST on that same path — different method, legal merge.
    let app = Router::new()
        .route("/healthz", get(|| async { "host-ok" }))
        .route("/readyz", get(|| async { "host-ok" }))
        .route("/mcp", get(|| async { "host-info" }))
        .merge(door.mount());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");

    let client = reqwest::Client::new();

    // 1. The host's own health route is untouched (mount() does not claim /healthz).
    let health = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(health.status(), 200);
    assert_eq!(health.text().await.unwrap(), "host-ok");

    // 2. The host's GET on the door's path is untouched.
    let info = client.get(format!("{base}/mcp")).send().await.unwrap();
    assert_eq!(info.status(), 200);
    assert_eq!(info.text().await.unwrap(), "host-info");

    // 3. POST /mcp is the door, and the 401 carries the header a client needs — the thing a
    //    hand-written adapter loses when it rebuilds a response by hand.
    let unauth = client
        .post(format!("{base}/mcp"))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);
    assert_eq!(
        unauth
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer"),
        "the mounted door must keep the WWW-Authenticate header"
    );

    // 4. A credentialled call is served by the same door through the same mount.
    let (status, body) = rpc(
        &format!("{base}/mcp"),
        Some(TOK_A),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await;
    assert_eq!(status, 200, "mounted door answers: {body}");
    let count = body["result"]["tools"]
        .as_array()
        .map(|t| t.len())
        .unwrap_or(0);
    assert!(count > 0, "mounted door lists tools: {body}");

    // 5. A real tool call goes through the same mount and is audited.
    let (status, body) = rpc(
        &format!("{base}/mcp"),
        Some(TOK_A),
        tools_call("list_items", json!({})),
    )
    .await;
    assert_eq!(status, 200, "mounted door answers a call: {body}");
    assert!(
        !support::is_error(&body),
        "list_items through the mount is a result: {body}"
    );

    // 6. One audit line per authenticated action, never a token.
    let lines = audit_lines(&audit);
    assert!(lines.len() >= 2, "audited: {lines:?}");
    let raw = std::fs::read_to_string(&audit).unwrap_or_default();
    assert!(!raw.contains(TOK_A), "audit must never contain a token");
}
