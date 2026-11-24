//! The door contract. Every product port must pass this file unchanged (fixture aside): these are
//! the behaviours that must never differ between apps.

mod support;

use serde_json::{json, Value};
use support::*;

#[tokio::test]
async fn unauthenticated_and_bad_tokens_are_401_with_no_detail() {
    let f = start().await;
    for token in [None, Some("tok_nope"), Some(TOK_REVOKED)] {
        let (status, body) = rpc(
            &f.url,
            token,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        .await;
        assert_eq!(
            status, 401,
            "token {token:?} must be rejected before parsing"
        );
        assert_eq!(body["error"]["code"], -32001);
        assert_eq!(body["error"]["message"], "unauthorized");
        assert!(body.to_string().to_lowercase().find("revoked").is_none());
    }
    // The rejection is audited, with the reason and without a usable token.
    let lines = audit_lines(&f.audit);
    assert!(
        lines.len() >= 3,
        "every rejected request leaves a line: {lines:?}"
    );
    assert!(lines
        .iter()
        .any(|l| l["outcome"].as_str().unwrap_or("").contains("revoked")));
}

#[tokio::test]
async fn a_live_customer_credential_on_an_operator_door_is_403_and_lists_no_tool() {
    // The admin-only access class (fleet MCP standard §4). A door that answered this with a tool
    // list, or with 401 (pretending a live key is unknown), is the defect this test exists for.
    let f = start().await;
    for method in ["tools/list", "tools/call"] {
        let (status, body) = rpc(
            &f.url,
            Some(TOK_CUSTOMER),
            json!({"jsonrpc": "2.0", "id": 1, "method": method,
                   "params": {"name": "list_items", "arguments": {}}}),
        )
        .await;
        assert_eq!(status, 403, "{method} must be refused before any tool runs");
        assert_eq!(body["error"]["code"], -32003, "{body}");
        assert_eq!(body["error"]["message"], "forbidden");
        assert!(
            body.get("result").is_none(),
            "{method} must return no result and no tool list: {body}"
        );
    }
    let lines = audit_lines(&f.audit);
    assert!(
        lines
            .iter()
            .any(|l| l["outcome"].as_str().unwrap_or("").contains("forbidden")),
        "the refusal is audited: {lines:?}"
    );
    // The audit names the reason, never the secret.
    let raw = std::fs::read_to_string(&f.audit).unwrap_or_default();
    assert!(!raw.contains(TOK_CUSTOMER));
}

#[tokio::test]
async fn legacy_initialize_and_modern_discover_both_answer() {
    let f = start().await;

    let (status, body) = rpc(
        &f.url,
        Some(TOK_A),
        json!({
            "jsonrpc": "2.0", "id": "init",
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "legacy"}}
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["id"], "init");
    assert_eq!(
        body["result"]["protocolVersion"], "2024-11-05",
        "echo, never force a downgrade"
    );
    assert_eq!(body["result"]["serverInfo"]["name"], "test-door");
    assert_eq!(
        body["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "test-door"
    );
    assert!(body["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("workspace-scoped"));

    let (status, body) = rpc(
        &f.url,
        Some(TOK_A),
        json!({"jsonrpc": "2.0", "id": 2, "method": "server/discover"}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["result"]["protocolVersions"][0], "2026-07-28");
    assert_eq!(
        body["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
}

#[tokio::test]
async fn unknown_protocol_version_is_refused_with_the_supported_list() {
    let f = start().await;
    let (status, body) = rpc(
        &f.url,
        Some(TOK_A),
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/list",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "1999-01-01"}}
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["error"]["code"], -32022);
    assert_eq!(body["error"]["data"]["requested"], "1999-01-01");
    assert!(body["error"]["data"]["supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "2026-07-28"));
}

#[tokio::test]
async fn tools_list_paginates_exhaustively_and_every_tool_is_annotated() {
    let f = start().await;
    let mut names = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let params = match &cursor {
            Some(c) => json!({"cursor": c}),
            None => json!({}),
        };
        let (status, body) = rpc(
            &f.url,
            Some(TOK_ADMIN),
            json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/list",
                "params": params
            }),
        )
        .await;
        assert_eq!(status, 200);
        let tools = body["result"]["tools"].as_array().unwrap();
        assert!(tools.len() <= 2, "fixture pages at 2");
        for t in tools {
            assert!(t["title"].as_str().is_some_and(|s| !s.is_empty()));
            assert!(t["description"].as_str().unwrap().len() >= 20);
            let a = &t["annotations"];
            assert!(a["readOnlyHint"].is_boolean(), "readOnlyHint is mandatory");
            assert!(a["destructiveHint"].is_boolean());
            assert!(a["idempotentHint"].is_boolean());
            assert!(a["openWorldHint"].is_boolean());
            assert_eq!(t["inputSchema"]["type"], "object");
        }
        names.extend(
            tools
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string()),
        );
        pages += 1;
        match body["result"]["nextCursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
        assert!(pages < 10, "pagination must terminate");
    }
    names.sort();
    names.dedup();
    assert_eq!(
        names,
        vec!["create_item", "get_item", "list_items", "list_tenants"]
    );
}

#[tokio::test]
async fn tools_list_shows_each_caller_only_what_it_can_call() {
    // The fleet defect this test exists for: an operator-only tool NAME in a customer credential's
    // `tools/list` is a surface the door will refuse. Visibility is not permission, but a door must
    // not advertise what it will not honour (kanban t_201dadc5). Admin is a superset of workspace,
    // workspace a superset of read-only — never the other way round.
    let f = start().await;
    let listed = |token: &'static str| {
        let url = f.url.clone();
        async move {
            let mut names: Vec<String> = Vec::new();
            let mut cursor: Option<String> = None;
            let mut pages = 0;
            loop {
                let params = match &cursor {
                    Some(c) => json!({ "cursor": c }),
                    None => json!({}),
                };
                let (status, body) = rpc(
                    &url,
                    Some(token),
                    json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": params }),
                )
                .await;
                assert_eq!(status, 200);
                names.extend(
                    body["result"]["tools"]
                        .as_array()
                        .expect("a tool list")
                        .iter()
                        .map(|t| t["name"].as_str().unwrap().to_string()),
                );
                pages += 1;
                assert!(pages < 10, "pagination must terminate");
                match body["result"]["nextCursor"].as_str() {
                    Some(c) => cursor = Some(c.to_string()),
                    None => break,
                }
            }
            names.sort();
            names
        }
    };
    assert_eq!(listed(TOK_READONLY).await, vec!["get_item", "list_items"]);
    assert_eq!(
        listed(TOK_A).await,
        vec!["create_item", "get_item", "list_items"]
    );
    assert_eq!(
        listed(TOK_ADMIN).await,
        vec!["create_item", "get_item", "list_items", "list_tenants"]
    );

    // The name itself must be absent from a customer's bytes, not merely un-callable.
    let (_, body) = rpc(
        &f.url,
        Some(TOK_A),
        json!({ "jsonrpc": "2.0", "id": 10, "method": "tools/list" }),
    )
    .await;
    assert!(
        !body.to_string().contains("list_tenants"),
        "a workspace credential must not see the operator tool's name: {body}"
    );
}

#[tokio::test]
async fn protocol_errors_are_errors_not_tool_results() {
    let f = start().await;
    let (status, body) = rpc(&f.url, Some(TOK_A), tools_call("does_not_exist", json!({}))).await;
    assert_eq!(status, 200);
    assert_eq!(body["error"]["code"], -32602);
    assert!(body.get("result").is_none());

    let (_, body) = rpc(
        &f.url,
        Some(TOK_A),
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {"cursor": "banana"}}),
    )
    .await;
    assert_eq!(body["error"]["code"], -32602);

    let (_, body) = rpc(
        &f.url,
        Some(TOK_A),
        json!({"jsonrpc": "2.0", "id": 6, "method": "nope"}),
    )
    .await;
    assert_eq!(body["error"]["code"], -32601);

    let (status, body) = rpc(
        &f.url,
        Some(TOK_A),
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"arguments": {}}}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["error"]["code"], -32602);
}

#[tokio::test]
async fn a_foreign_id_is_not_found_never_forbidden() {
    let f = start().await;

    // Workspace B's item, asked for with workspace A's key.
    let (status, body) = rpc(
        &f.url,
        Some(TOK_A),
        tools_call("get_item", json!({"id": f.store.beta_id})),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        is_error(&body),
        "a foreign id is a tool error, not a crash: {body}"
    );
    let p = payload(&body);
    assert_eq!(p["error"], "not_found");
    assert!(
        !p.to_string().contains("forbidden"),
        "a refusal must not confirm existence: {p}"
    );

    // An id that does not exist answers exactly the same thing.
    let (_, body2) = rpc(
        &f.url,
        Some(TOK_A),
        tools_call("get_item", json!({"id": uuid::Uuid::new_v4().to_string()})),
    )
    .await;
    assert_eq!(payload(&body2)["error"], p["error"]);

    // And the owner can still read it: the rule is scoping, not a blanket refusal.
    let (_, own) = rpc(
        &f.url,
        Some(TOK_B),
        tools_call("get_item", json!({"id": f.store.beta_id})),
    )
    .await;
    assert!(!is_error(&own));
    assert_eq!(payload(&own)["item"]["name"], "b-1");
}

#[tokio::test]
async fn role_gates_are_enforced_before_the_handler_runs() {
    let f = start().await;

    let (status, body) = rpc(
        &f.url,
        Some(TOK_READONLY),
        tools_call("create_item", json!({"name": "x"})),
    )
    .await;
    assert_eq!(status, 200);
    assert!(is_error(&body));
    assert_eq!(payload(&body)["error"], "forbidden");
    assert_eq!(f.store.total(), 3, "nothing was written");

    let (_, body) = rpc(&f.url, Some(TOK_A), tools_call("list_tenants", json!({}))).await;
    assert!(is_error(&body));
    assert_eq!(payload(&body)["error"], "forbidden");

    let (_, body) = rpc(
        &f.url,
        Some(TOK_ADMIN),
        tools_call("list_tenants", json!({})),
    )
    .await;
    assert!(!is_error(&body));
    assert_eq!(payload(&body)["count"], 3);
}

#[tokio::test]
async fn a_write_lands_in_the_callers_own_workspace_only() {
    let f = start().await;
    let (_, body) = rpc(
        &f.url,
        Some(TOK_A),
        tools_call("create_item", json!({"name": "a-3"})),
    )
    .await;
    assert!(!is_error(&body), "{body}");

    let (_, listed) = rpc(&f.url, Some(TOK_A), tools_call("list_items", json!({}))).await;
    assert_eq!(payload(&listed)["count"], 3);

    // B sees none of it — the same call under B's key is unchanged.
    let (_, other) = rpc(&f.url, Some(TOK_B), tools_call("list_items", json!({}))).await;
    assert_eq!(payload(&other)["count"], 1);
}

#[tokio::test]
async fn every_call_is_audited_and_no_token_reaches_the_log() {
    let f = start().await;
    let (_, _) = rpc(
        &f.url,
        Some(TOK_A),
        tools_call("list_items", json!({"limit": 5})),
    )
    .await;
    let (_, _) = rpc(
        &f.url,
        Some(TOK_A),
        tools_call(
            "create_item",
            json!({"name": "audited", "password": "hunter2"}),
        ),
    )
    .await;

    let raw = std::fs::read_to_string(&f.audit).expect("audit file");
    assert!(
        !raw.contains(TOK_A),
        "the audit must never store the bearer"
    );
    assert!(
        !raw.contains("hunter2"),
        "credential-shaped arguments are redacted, raw was: {raw}"
    );
    assert!(
        raw.contains("[redacted]"),
        "expected a redacted args line, raw was: {raw}"
    );

    let lines = audit_lines(&f.audit);
    let list = lines
        .iter()
        .find(|l| l["tool"] == "list_items")
        .expect("list_items audited");
    assert_eq!(list["subject"], "a-key");
    assert_eq!(list["role"], "workspace");
    assert_eq!(list["outcome"], "ok");
    assert_eq!(list["rows"], 2);
}

#[tokio::test]
async fn notifications_are_accepted_and_batches_are_refused() {
    let f = start().await;
    let (status, body) = rpc(
        &f.url,
        Some(TOK_A),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(status, 202, "a notification has no response body: {body}");

    let (status, body) = rpc(
        &f.url,
        Some(TOK_A),
        json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], -32600);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("batching"));
}

#[tokio::test]
async fn malformed_json_is_a_parse_error_not_a_500() {
    let f = start().await;
    let res = reqwest::Client::new()
        .post(&f.url)
        .bearer_auth(TOK_A)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"]["code"], -32700);
}

#[tokio::test]
async fn health_is_unauthenticated_and_names_the_door() {
    let f = start().await;
    let health = f.url.replace("/mcp", "/healthz");
    let res = reqwest::get(&health).await.unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["tools"], 4);
}
