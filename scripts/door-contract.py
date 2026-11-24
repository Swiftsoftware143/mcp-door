#!/usr/bin/env python3
"""Protocol conformance probe for one MCP door.

Any product port runs this against its own live endpoint before the door is announced. It proves the
TRANSPORT and PROTOCOL behaviours that must be identical in every app:

  1  unauthenticated request -> 401 with JSON-RPC -32001 (not 200, not 500)
  2  bogus bearer            -> 401
  3  revoked bearer          -> 401                       (when --revoked-token is given)
  4  server/discover         -> protocol versions, newest first
  5  legacy initialize       -> echoes the caller's version
  6  unknown version         -> -32022 with a supported list
  7  tools/list              -> pages to exhaustion, every tool annotated, object schema
  8  unknown tool            -> -32602 (a protocol error, not an isError result)
  9  unknown method          -> -32601
 10  notification            -> 202 with no body
 11  ping                    -> 200 result
 12  every result carries _meta.io.modelcontextprotocol/serverInfo
 13  tools/list is filtered to the caller's role: an --admin-only-tool name is absent for the
     workspace (and read-only) credential and present for --admin-token; admin is a superset.

App-specific acceptance (foreign id is not_found, role gates, audit lines) belongs to the port's own
card: this script cannot know your tool names and arguments. Pass --tool NAME=JSON to additionally
execute a call with the workspace token and print its payload.

Usage:
  python3 scripts/door-contract.py http://127.0.0.1:8111/mcp \\
      --workspace-token tok_acme_workspace \\
      --readonly-token tok_acme_readonly \\
      --admin-token tok_ops_admin \\
      --revoked-token tok_revoked \\
      --tool list_items='{}'

Exit code 0 = every check passed. 1 = at least one failure (printed).
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

UA = "mcp-door-contract/1.0"  # never a stock python UA: the fleet edge answers 403 to it
VERSION_NEWEST = "2026-07-28"
LEGACY_VERSION = "2024-11-05"

results: list[tuple[bool, str, str]] = []


def record(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}{('  — ' + detail) if detail and not ok else ''}")


def post(url: str, token: str | None, payload, timeout: float = 15.0):
    data = json.dumps(payload).encode()
    headers = {"content-type": "application/json", "user-agent": UA}
    if token:
        headers["authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # connection refused, DNS, TLS
        return 0, str(e).encode()


def body_json(raw: bytes):
    try:
        return json.loads(raw.decode() or "{}")
    except Exception:
        return {}


def rpc(url, token, method, params=None, ident: int | str = 1):
    payload = {"jsonrpc": "2.0", "id": ident, "method": method}
    if params is not None:
        payload["params"] = params
    status, raw = post(url, token, payload)
    return status, body_json(raw)


def has_server_info(body) -> bool:
    meta = (body.get("result") or {}).get("_meta") or {}
    return "io.modelcontextprotocol/serverInfo" in meta


def list_tool_names(url: str, token: str) -> list[str]:
    """Every tool name one credential is offered, paged to exhaustion."""
    names: list[str] = []
    cursor, pages = None, 0
    while True:
        params = {"_meta": {"io.modelcontextprotocol/protocolVersion": VERSION_NEWEST}}
        if cursor:
            params["cursor"] = cursor
        status, body = rpc(url, token, "tools/list", params, ident=200 + pages)
        if status != 200 or "result" not in body:
            return names
        names.extend(t.get("name", "") for t in (body["result"].get("tools") or []))
        pages += 1
        cursor = body["result"].get("nextCursor")
        if not cursor or pages > 100:
            return names


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--workspace-token", required=True)
    ap.add_argument("--readonly-token")
    ap.add_argument("--admin-token")
    ap.add_argument("--revoked-token")
    ap.add_argument("--bogus-token", default="mcp_door_contract_bogus_token")
    ap.add_argument("--tool", action="append", default=[], help="NAME=JSON to execute")
    ap.add_argument("--admin-only-tool", action="append", default=[],
                    help="a tool only an admin credential may call; must be absent below admin")
    args = ap.parse_args()
    url = args.url

    # 1-3 authentication
    status, body = rpc(url, None, "tools/list")
    record(status == 401 and (body.get("error") or {}).get("code") == -32001,
           "unauthenticated is 401 / -32001", f"status={status} body={body}")

    status, body = rpc(url, args.bogus_token, "tools/list")
    record(status == 401, "bogus bearer is 401", f"status={status}")

    if args.revoked_token:
        status, body = rpc(url, args.revoked_token, "tools/list")
        record(status == 401, "revoked bearer is 401", f"status={status}")

    # 4 discovery
    status, body = rpc(url, args.workspace_token, "server/discover", ident="discover")
    versions = ((body.get("result") or {}).get("protocolVersions")) or []
    record(status == 200 and versions[:1] == [VERSION_NEWEST],
           "server/discover lists versions newest first", f"status={status} versions={versions}")
    record(has_server_info(body), "result carries serverInfo in _meta")

    # 5 legacy initialize
    status, body = rpc(url, args.workspace_token, "initialize",
                       {"protocolVersion": LEGACY_VERSION, "capabilities": {},
                        "clientInfo": {"name": "door-contract", "version": "1.0"}}, ident=2)
    got = (body.get("result") or {}).get("protocolVersion")
    record(status == 200 and got == LEGACY_VERSION,
           "legacy initialize echoes the caller's version", f"status={status} got={got}")

    # 6 unknown version refused explicitly
    status, body = rpc(url, args.workspace_token, "tools/list",
                       {"_meta": {"io.modelcontextprotocol/protocolVersion": "1999-01-01"}}, ident=3)
    err = body.get("error") or {}
    supported = (err.get("data") or {}).get("supported") or []
    record(status == 200 and err.get("code") == -32022 and VERSION_NEWEST in supported,
           "unknown protocol version is -32022 with alternatives",
           f"status={status} err={err}")

    # 7 tool surface, paged to exhaustion
    tools, cursor, pages = [], None, 0
    ok = True
    while True:
        params = {"_meta": {"io.modelcontextprotocol/protocolVersion": VERSION_NEWEST}}
        if cursor:
            params["cursor"] = cursor
        status, body = rpc(url, args.workspace_token, "tools/list", params, ident=4 + pages)
        if status != 200 or "result" not in body:
            ok = False
            record(False, "tools/list page", f"status={status} body={body}")
            break
        page = body["result"].get("tools") or []
        tools.extend(page)
        pages += 1
        cursor = body["result"].get("nextCursor")
        if not cursor:
            break
        if pages > 100:
            ok = False
            record(False, "tools/list pagination terminates", f"{pages} pages")
            break
    record(ok and len(tools) > 0, "tools/list returns tools", f"count={len(tools)} pages={pages}")

    missing = []
    for t in tools:
        a = t.get("annotations") or {}
        problems = []
        if not t.get("title"):
            problems.append("title")
        if len((t.get("description") or "")) < 20:
            problems.append("description")
        if not isinstance(a.get("readOnlyHint"), bool):
            problems.append("readOnlyHint")
        if not isinstance(a.get("destructiveHint"), bool):
            problems.append("destructiveHint")
        if not isinstance(a.get("idempotentHint"), bool):
            problems.append("idempotentHint")
        if not isinstance(a.get("openWorldHint"), bool):
            problems.append("openWorldHint")
        if (t.get("inputSchema") or {}).get("type") != "object":
            problems.append("inputSchema")
        if problems:
            missing.append(f"{t.get('name')}:{'+'.join(problems)}")
    record(not missing, "every tool is annotated and has an object schema", "; ".join(missing[:8]))

    # 13 role-filtered listing: a door must not advertise a tool it will refuse. `tools` above is
    # the workspace credential's surface; compare it with the operator's and the named proof tools.
    workspace_names = {t.get("name") for t in tools}
    admin_names = set()
    if args.admin_token:
        admin_names = set(list_tool_names(url, args.admin_token))
        record(workspace_names <= admin_names,
               "admin sees every tool a workspace credential sees (filtering never hides a readable tool)",
               f"workspace={sorted(workspace_names - admin_names)}")
    readonly_names = set()
    if args.readonly_token:
        readonly_names = set(list_tool_names(url, args.readonly_token))
        record(readonly_names <= workspace_names,
               "read-only sees no tool above its own role",
               f"extra={sorted(readonly_names - workspace_names)}")
    for name in args.admin_only_tool:
        leaks = [label for label, visible in
                 (("workspace", workspace_names), ("read_only", readonly_names))
                 if name in visible]
        record(not leaks,
               f"{name} is not listed to a non-admin credential",
               f"visible to {leaks}")
        if args.admin_token:
            record(name in admin_names,
                   f"{name} is still listed to the admin credential",
                   f"admin tools={sorted(admin_names)}")

    # 8-9 protocol errors
    status, body = rpc(url, args.workspace_token, "tools/call",
                       {"name": "mcp_door_contract_unknown_tool", "arguments": {}}, ident=5)
    record((body.get("error") or {}).get("code") == -32602 and "result" not in body,
           "unknown tool is -32602", f"status={status} body={body}")

    status, body = rpc(url, args.workspace_token, "mcp/door/contract-unknown-method", ident=6)
    record((body.get("error") or {}).get("code") == -32601,
           "unknown method is -32601", f"body={body}")

    # 10 notification: no id, no body
    status, raw = post(url, args.workspace_token,
                       {"jsonrpc": "2.0", "method": "notifications/initialized"})
    record(status == 202 and raw.strip() == b"", "notification is 202 with no body",
           f"status={status} body={raw[:80]!r}")

    # 11 ping
    status, body = rpc(url, args.workspace_token, "ping", ident=7)
    record(status == 200 and "result" in body, "ping answers", f"status={status} body={body}")

    # 12 every result above carried serverInfo; check one more explicitly
    record(has_server_info(body), "ping result carries serverInfo in _meta")

    # optional app-specific calls
    for spec in args.tool:
        if "=" not in spec:
            record(False, f"--tool {spec!r} is NAME=JSON")
            continue
        name, raw_args = spec.split("=", 1)
        try:
            tool_args = json.loads(raw_args or "{}")
        except json.JSONDecodeError as e:
            record(False, f"--tool {name} JSON", str(e))
            continue
        status, body = rpc(url, args.workspace_token, "tools/call",
                           {"name": name, "arguments": tool_args}, ident=100)
        result = body.get("result") or {}
        text = (result.get("content") or [{}])[0].get("text")
        print(f"      call {name} -> status={status} isError={result.get('isError')} payload={text}")

    failed = [r for r in results if not r[0]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
