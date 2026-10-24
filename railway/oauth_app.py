#!/usr/bin/env python3
"""OAuth web endpoints for Feishu MCP Multi-Tenant.

Runs alongside the MCP server. Handles:
- GET /oauth/authorize -> redirect to Feishu
- GET /oauth/callback?code=xxx -> exchange, store user, show api_key
- GET /health -> health check
"""
import os
import inspect
import secrets
import time
import urllib.parse
import urllib.request
import json
import sqlite3
from flask import Flask, request, redirect

# Reuse MCP tool functions from the multi-tenant MCP server.
# Importing server_mt is safe: module-level code only builds the
# MCPServer object and defines functions; the `__main__` block is guarded.
from server_mt import (
    feishu_create_doc,
    feishu_read_doc,
    feishu_update_doc,
    feishu_search_docs,
    feishu_whoami,
    get_user_by_api_key,
)

app = Flask(__name__)

APP_ID = os.environ.get("FEISHU_APP_ID", "cli_aa4d74dcc0b8dcea")
APP_SECRET = os.environ.get("FEISHU_APP_SECRET", "")
REDIRECT_URI = os.environ.get(
    "FEISHU_REDIRECT_URI",
    "https://feishu-mcp-production.up.railway.app/oauth/callback"
)
DB_PATH = os.environ.get("FEISHU_MCP_DB", "/tmp/feishu_mcp_users.db")

SCOPES = [
    "contact:contact.base:readonly",
    "drive:drive:readonly",
    "docx:document",
    "sheets:spreadsheet",
    "wiki:wiki:readonly",
    "offline_access",
]


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/health")
def health():
    return {"ok": True, "service": "feishu-mcp-mt-oauth"}


@app.route("/oauth/authorize")
def oauth_authorize():
    params = {
        "client_id": APP_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": secrets.token_urlsafe(16),
    }
    url = "https://accounts.feishu.cn/open-apis/authen/v1/authorize?" + \
          urllib.parse.urlencode(params)
    return redirect(url)


@app.route("/oauth/callback")
def oauth_callback():
    code = request.args.get("code")
    if not code:
        return "Missing code", 400

    # Exchange code for tokens
    data = {
        "grant_type": "authorization_code",
        "client_id": APP_ID,
        "client_secret": APP_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    req = urllib.request.Request(
        "https://open.feishu.cn/open-apis/authen/v2/oauth/token",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            d = json.loads(resp.read())
    except Exception as e:
        return f"Token exchange failed: {e}", 500

    if d.get("code") != 0:
        return f"Feishu error: {d.get('msg')}", 500

    # Top-level fields (2026-10-19 lesson)
    at = d.get("access_token", "")
    rt = d.get("refresh_token", "")
    exp = int(d.get("expires_in", 0))
    user_info = d.get("user_info", {}) or {}
    feishu_uid = user_info.get("user_id", "") or d.get("open_id", "") or d.get("user_id", "")
    feishu_name = user_info.get("name", "Unknown")

    # If user_id not in token response, fetch via user_info API
    if at and not feishu_uid:
        try:
            u_req = urllib.request.Request(
                "https://open.feishu.cn/open-apis/authen/v1/user_info",
                headers={"Authorization": f"Bearer {at}"},
                method="GET",
            )
            with urllib.request.urlopen(u_req, timeout=15) as u_resp:
                u_d = json.loads(u_resp.read())
            u_data = u_d.get("data", {}) or {}
            feishu_uid = u_data.get("user_id", "") or u_data.get("open_id", "")
            feishu_name = u_data.get("name", feishu_name)
        except Exception:
            pass

    if not at or not feishu_uid:
        return "Incomplete token response", 500

    # Generate API key for this user
    api_key = "fmcp_" + secrets.token_urlsafe(32)
    now = int(time.time())

    conn = get_db()
    try:
        # Upsert by feishu_user_id
        existing = conn.execute(
            "SELECT id FROM users WHERE feishu_user_id = ?", (feishu_uid,)
        ).fetchone()
        if existing:
            conn.execute("""
                UPDATE users SET feishu_name=?, user_access_token=?,
                refresh_token=?, token_expiry=?, api_key=?, updated_at=?
                WHERE feishu_user_id=?
            """, (feishu_name, at, rt, now + exp, api_key, now, feishu_uid))
        else:
            conn.execute("""
                INSERT INTO users (feishu_user_id, feishu_name, user_access_token,
                refresh_token, token_expiry, api_key, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (feishu_uid, feishu_name, at, rt, now + exp, api_key, now, now))
        conn.commit()
    finally:
        conn.close()

    # Show the user their API key (one-time display)
    return f"""
    <html><head><meta charset="utf-8"><title>授权成功</title></head>
    <body style="font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
        <h2>✅ 飞书授权成功</h2>
        <p>你好，<strong>{feishu_name}</strong>！</p>
        <p>你的专属 API Key（请妥善保存，配置到 AI 客户端的 MCP 参数中）：</p>
        <p style="background: #f0f0f0; padding: 15px; word-break: break-all; font-family: monospace;">
            {api_key}
        </p>
        <p>MCP 地址：<code>https://feishu-mcp-production.up.railway.app/mcp</code></p>
        <p>每个工具调用时传入你的 <code>api_key</code> 参数，创建的文档归你所有。</p>
        <p style="color: #888; font-size: 12px;">Token 有效期 2 小时，服务端会自动刷新，无需重复授权。</p>
    </body></html>
    """


# --- MCP Streamable HTTP endpoint (JSON-RPC 2.0) ---
# Exposes the multi-tenant MCP tools over HTTP so AI clients
# (Doubao, ChatGPT, Claude, ...) can connect without stdio.
# The user's api_key comes from the HTTP Authorization header
# ("Bearer fmcp_...") and is injected into tool arguments.

_API_KEY_DESC = ("Your personal API key from OAuth authorization "
                 "(auto-filled from the HTTP Authorization header)")

MCP_TOOL_SCHEMAS = {
    "feishu_create_doc": {
        "description": "Create a new Feishu cloud document (owned by YOU).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": _API_KEY_DESC},
                "title": {"type": "string", "description": "Document title"},
                "folder_token": {"type": "string",
                                 "description": "Optional folder token (empty = root)"},
            },
            "required": ["title"],
        },
    },
    "feishu_read_doc": {
        "description": ("Read a Feishu document's content "
                        "(paginated - large docs won't truncate)."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": _API_KEY_DESC},
                "doc_id_or_url": {"type": "string",
                                  "description": "Document ID or full URL"},
                "page_token": {"type": "string",
                               "description": ("Pass the next_page_token from the "
                                               "previous call to get the next page; "
                                               "leave empty for the first page")},
                "page_size": {"type": "integer",
                              "description": "Blocks per page (1-100, default 50)"},
            },
            "required": ["doc_id_or_url"],
        },
    },
    "feishu_update_doc": {
        "description": "Update a Feishu document (you must have edit permission).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": _API_KEY_DESC},
                "doc_id_or_url": {"type": "string",
                                  "description": "Document ID or full URL"},
                "content": {"type": "string",
                            "description": "Markdown content to write"},
                "mode": {"type": "string",
                         "description": '"append" (add to end) or "overwrite" (replace all)'},
            },
            "required": ["doc_id_or_url", "content"],
        },
    },
    "feishu_search_docs": {
        "description": ("Search Feishu cloud documents by keyword "
                        "(searches YOUR accessible docs)."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": _API_KEY_DESC},
                "keyword": {"type": "string", "description": "Search keyword"},
                "page_size": {"type": "integer",
                              "description": "Max results (default 10)"},
            },
            "required": ["keyword"],
        },
    },
    "feishu_whoami": {
        "description": "Show who you are authenticated as (for verifying your identity).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": _API_KEY_DESC},
            },
            "required": [],
        },
    },
}

MCP_TOOL_FUNCS = {
    "feishu_create_doc": feishu_create_doc,
    "feishu_read_doc": feishu_read_doc,
    "feishu_update_doc": feishu_update_doc,
    "feishu_search_docs": feishu_search_docs,
    "feishu_whoami": feishu_whoami,
}


def _mcp_extract_api_key():
    """Extract api_key from HTTP Authorization header ('Bearer fmcp_...')
    or URL query parameter (?api_key=fmcp_...)."""
    # 1. Authorization header (Doubao, Claude, etc.)
    auth = request.headers.get("Authorization", "") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    # 2. URL query parameter (ChatGPT, which can't set custom headers)
    qkey = request.args.get("api_key", "") or ""
    if qkey:
        return qkey.strip()
    return ""


def _mcp_check_api_key(api_key):
    """Return (ok, message) for the given api_key."""
    if not api_key:
        return False, ("Missing api_key: add HTTP header "
                       "'Authorization: Bearer fmcp_...' or URL param "
                       "'?api_key=fmcp_...'")
    try:
        user = get_user_by_api_key(api_key)
    except Exception as e:
        # DB missing/corrupt: never leak a 500, answer in JSON-RPC
        return False, f"Auth backend unavailable: {e}"
    if not user:
        return False, ("Invalid api_key. "
                       "Re-authorize at /oauth/authorize to get a new one.")
    return True, ""


def _jsonrpc_error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


def _mcp_response(obj, status=200):
    # Streamable HTTP: a client that asks for SSE gets an SSE frame,
    # everyone else gets plain JSON. Both are spec-valid; choosing by
    # Accept keeps JSON clients and stricter SSE-only clients (Doubao,
    # Grok) working on the same endpoint.
    from flask import Response
    accept = request.headers.get("Accept", "") or ""
    if "text/event-stream" in accept:
        body = "event: message\ndata: " + json.dumps(
            obj, ensure_ascii=False) + "\n\n"
        return Response(body, status=status,
                        mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})
    return obj, status


@app.route("/mcp", methods=["GET"])
def mcp_get_not_supported():
    # No server-initiated SSE stream on this stateless service. Answer
    # 405 as JSON (not Flask's default HTML) so MCP clients fall back
    # to POST instead of failing on an HTML page.
    return _jsonrpc_error(None, -32601,
                          "GET not supported on /mcp, use POST"), 405


@app.route("/mcp", methods=["POST"])
def mcp_streamable_http():
    try:
        body = request.get_json(force=True)
    except Exception:
        return _mcp_response(
            _jsonrpc_error(None, -32700, "Parse error: invalid JSON"), 200)
    if not isinstance(body, dict):
        return _mcp_response(
            _jsonrpc_error(None, -32600, "Invalid Request"), 200)

    req_id = body.get("id")
    method = body.get("method", "") or ""

    # Notification: no response body expected
    if method == "notifications/initialized":
        return "", 202

    if method == "initialize":
        # Echo the client's requested protocol version when it sends one:
        # older clients reject a fixed newer version outright.
        params0 = body.get("params") or {}
        pv = (params0.get("protocolVersion")
              if isinstance(params0, dict) else None) or "2024-11-05"
        return _mcp_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": pv,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "feishu-docs-mt", "version": "1.0.0"},
            },
        }, 200)

    if method == "tools/list":
        # tools/list is public (no auth) - clients call this during discovery
        tools = [{"name": name, **MCP_TOOL_SCHEMAS[name]}
                 for name in MCP_TOOL_FUNCS]
        return _mcp_response({"jsonrpc": "2.0", "id": req_id,
                              "result": {"tools": tools}}, 200)

    # tools/call requires a valid api_key from the Authorization header
    api_key = _mcp_extract_api_key()
    ok, msg = _mcp_check_api_key(api_key)
    if not ok:
        return _mcp_response(_jsonrpc_error(req_id, -32000, msg), 200)

    if method == "tools/call":
        params = body.get("params") or {}
        if not isinstance(params, dict):
            return _mcp_response(_jsonrpc_error(
                req_id, -32602,
                "Invalid params: params must be an object"), 200)
        name = params.get("name", "") or ""
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return _mcp_response(_jsonrpc_error(
                req_id, -32602,
                "Invalid params: arguments must be an object"), 200)
        func = MCP_TOOL_FUNCS.get(name)
        if func is None:
            return _mcp_response(_jsonrpc_error(
                req_id, -32601, f"Method not found: {name}"), 200)
        # Inject api_key from the header if the caller didn't provide one
        arguments = dict(arguments)
        arguments.setdefault("api_key", api_key)
        # Drop unknown kwargs so extra client fields can't cause TypeError
        try:
            sig_params = inspect.signature(func).parameters
            arguments = {k: v for k, v in arguments.items()
                         if k in sig_params}
        except Exception:
            pass
        try:
            result_text = func(**arguments)
        except TypeError as e:
            return _mcp_response(_jsonrpc_error(
                req_id, -32602, f"Invalid params: {e}"), 200)
        except Exception as e:
            return _mcp_response(_jsonrpc_error(
                req_id, -32603, f"Internal error: {e}"), 200)
        if not isinstance(result_text, str):
            result_text = json.dumps(result_text, ensure_ascii=False)
        return _mcp_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": result_text}]},
        }, 200)

    return _mcp_response(_jsonrpc_error(
        req_id, -32601, f"Method not found: {method}"), 200)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8902))
    app.run(host="0.0.0.0", port=port)
