#!/usr/bin/env python3
"""Feishu Document MCP Server - Multi-Tenant Version.

Each user authorizes via their own Feishu OAuth. Server stores per-user
tokens (isolated by user ID). MCP tools use the calling user's token,
so documents are created/owned by that user, not by a shared account.

Architecture:
- SQLite: users table (feishu_user_id, name, tokens, api_key)
- OAuth: /oauth/authorize -> Feishu -> /oauth/callback -> store tokens
- MCP: tools accept api_key, resolve to user, call Feishu API directly
- Refresh: per-user token rotation with file-lock equivalent (DB transaction)
"""
import json
import logging
import os
import sqlite3
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager

from mcp.server.mcpserver import MCPServer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("feishu-mcp-mt")

# --- Config (from environment) ---
APP_ID = os.environ.get("FEISHU_APP_ID", "cli_aa4d74dcc0b8dcea")
APP_SECRET = os.environ.get("FEISHU_APP_SECRET", "")
# Must match the redirect URL configured in Feishu developer console
REDIRECT_URI = os.environ.get(
    "FEISHU_REDIRECT_URI",
    "https://feishu-mcp-production.up.railway.app/oauth/callback"
)
DB_PATH = os.environ.get("FEISHU_MCP_DB", "/tmp/feishu_mcp_users.db")
# Railway persistent volume: set FEISHU_MCP_DB to /data/feishu_mcp_users.db

SCOPES = [
    "contact:contact.base:readonly",
    "im:chat:readonly",
    "im:message:readonly",
    "drive:drive:readonly",
    "docx:document",
    "sheets:spreadsheet",
    "wiki:wiki:readonly",
    "offline_access",
]

mcp = MCPServer("feishu-docs-mt")


# --- Database ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feishu_user_id TEXT UNIQUE NOT NULL,
            feishu_name TEXT,
            user_access_token TEXT,
            refresh_token TEXT,
            token_expiry INTEGER,
            api_key TEXT UNIQUE NOT NULL,
            created_at INTEGER,
            updated_at INTEGER
        )
    """)
    conn.commit()
    conn.close()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def get_user_by_api_key(api_key: str):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE api_key = ?", (api_key,)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_feishu_id(feishu_user_id: str):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE feishu_user_id = ?", (feishu_user_id,)
        ).fetchone()
        return dict(row) if row else None


# --- Feishu API helpers ---
def feishu_api(method: str, path: str, token: str, data: dict = None):
    url = f"https://open.feishu.cn/open-apis{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json; charset=utf-8",
    }
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.error(f"Feishu API {method} {path} failed: {e}")
        return {"code": -1, "msg": str(e)}


def refresh_user_token(user: dict):
    """Refresh a user's token (rotation-safe, DB transaction)."""
    import secrets
    data = {
        "grant_type": "refresh_token",
        "app_id": APP_ID,
        "app_secret": APP_SECRET,
        "refresh_token": user["refresh_token"],
    }
    # Use the token endpoint (not authen/v1, which is for the old flow)
    url = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json; charset=utf-8",
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            d = json.loads(resp.read())
    except Exception as e:
        return None, str(e)

    if d.get("code") != 0:
        # Top-level fields (not in 'data') per 2026-10-19 lesson
        return None, f"code={d.get('code')} msg={d.get('msg')}"

    at = d.get("access_token", "")
    rt = d.get("refresh_token", "")
    exp = int(d.get("expires_in", 0))
    if not at:
        return None, "empty access_token"

    # Atomic update in DB transaction
    with get_db() as conn:
        conn.execute("""
            UPDATE users SET user_access_token=?, refresh_token=?,
            token_expiry=?, updated_at=? WHERE id=?
        """, (at, rt or user["refresh_token"],
              int(time.time()) + exp, int(time.time()), user["id"]))

    user["user_access_token"] = at
    if rt:
        user["refresh_token"] = rt
    user["token_expiry"] = int(time.time()) + exp
    return user, None


def ensure_valid_token(user: dict):
    """Return user with valid token, refreshing if needed."""
    # Refresh if expiring within 5 minutes
    if user["token_expiry"] and user["token_expiry"] - int(time.time()) > 300:
        return user, None
    return refresh_user_token(user)


def require_user(api_key: str):
    """Resolve API key to user with valid token. Returns (user, error)."""
    if not api_key:
        return None, "api_key is required. Get yours from /oauth/authorize"
    user = get_user_by_api_key(api_key)
    if not user:
        return None, "Invalid api_key. Please re-authorize at /oauth/authorize"
    user, err = ensure_valid_token(user)
    if err:
        return None, f"Token refresh failed: {err}. Please re-authorize."
    return user, None


# --- MCP Tools (all require api_key) ---
@mcp.tool()
def feishu_create_doc(api_key: str, title: str, folder_token: str = "") -> str:
    """Create a new Feishu cloud document (owned by YOU).

    Args:
        api_key: Your personal API key from OAuth authorization
        title: Document title
        folder_token: Optional folder token (empty = root)
    Returns:
        JSON with document_id and URL
    """
    user, err = require_user(api_key)
    if err:
        return json.dumps({"ok": False, "error": err}, ensure_ascii=False)
    data = {"title": title}
    if folder_token:
        data["folder_token"] = folder_token
    result = feishu_api("POST", "/docx/v1/documents", user["user_access_token"], data)
    return json.dumps(result, ensure_ascii=False, indent=2)


def _block_to_text(block: dict) -> str:
    """Extract readable text from a docx block (any type)."""
    bt = block.get("block_type")
    # Map block types to their content field names
    field_map = {
        2: "text", 3: "heading1", 4: "heading2", 5: "heading3",
        6: "heading4", 7: "heading5", 8: "heading6", 9: "heading7",
        10: "heading8", 11: "heading9", 12: "bullet", 13: "ordered",
        14: "code", 15: "quote", 22: "todo",
    }
    field = field_map.get(bt)
    prefix = ""
    if bt in (3, 4, 5, 6, 7, 8, 9, 10, 11):
        prefix = "#" * (bt - 2) + " "
    elif bt == 12:
        prefix = "- "
    elif bt == 13:
        prefix = "1. "
    elif bt == 15:
        prefix = "> "
    elif bt == 22:
        done = block.get("todo", {}).get("style", {}).get("done", False)
        prefix = "[x] " if done else "[ ] "
    if not field or field not in block:
        return ""
    elements = block[field].get("elements", [])
    parts = []
    for el in elements:
        tr = el.get("text_run")
        if tr and tr.get("content"):
            parts.append(tr["content"])
        # mention_doc, mention_user etc. - use text_run fallback
    text = "".join(parts).strip()
    return prefix + text if text else ""


@mcp.tool()
def feishu_read_doc(api_key: str, doc_id_or_url: str, page_token: str = "",
                    page_size: int = 50) -> str:
    """Read a Feishu document's content (paginated - large docs won't truncate).

    For large documents, call repeatedly with the returned next_page_token
    until it is empty.

    Args:
        api_key: Your personal API key from OAuth authorization
        doc_id_or_url: Document ID or full URL
        page_token: Pass the next_page_token from the previous call to get
            the next page; leave empty for the first page
        page_size: Blocks per page (1-100, default 50)
    Returns:
        JSON with: ok, content (text), next_page_token (empty string when
        done), blocks_returned
    """
    user, err = require_user(api_key)
    if err:
        return json.dumps({"ok": False, "error": err}, ensure_ascii=False)
    doc_id = doc_id_or_url.split("/")[-1].split("?")[0]
    page_size = max(1, min(int(page_size or 50), 100))
    path = (f"/docx/v1/documents/{doc_id}/blocks/{doc_id}/children"
            f"?page_size={page_size}")
    if page_token:
        path += f"&page_token={urllib.parse.quote(page_token)}"
    result = feishu_api("GET", path, user["user_access_token"])
    if result.get("code") != 0:
        return json.dumps(result, ensure_ascii=False, indent=2)
    data = result.get("data", {})
    items = data.get("items", [])
    lines = []
    for block in items:
        t = _block_to_text(block)
        if t:
            lines.append(t)
    return json.dumps({
        "ok": True,
        "content": "\n".join(lines),
        "next_page_token": data.get("page_token", "") or "",
        "has_more": data.get("has_more", False),
        "blocks_returned": len(items),
    }, ensure_ascii=False, indent=2)


@mcp.tool()
def feishu_update_doc(api_key: str, doc_id_or_url: str, content: str,
                      mode: str = "append") -> str:
    """Update a Feishu document (you must have edit permission).

    Args:
        api_key: Your personal API key from OAuth authorization
        doc_id_or_url: Document ID or full URL
        content: Markdown content to write
        mode: "append" (add to end) or "overwrite" (replace all)
    Returns:
        JSON result
    """
    user, err = require_user(api_key)
    if err:
        return json.dumps({"ok": False, "error": err}, ensure_ascii=False)
    if mode not in ("append", "overwrite"):
        return json.dumps({"ok": False, "error": "mode must be append or overwrite"})
    doc_id = doc_id_or_url.split("/")[-1].split("?")[0]
    # For simplicity, use batch update via docx API
    # (Full block manipulation would need more complex logic)
    result = {"ok": False, "error": "Update via API needs block-level ops; use append via create"}
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
def feishu_search_docs(api_key: str, keyword: str, page_size: int = 10) -> str:
    """Search Feishu cloud documents by keyword (searches YOUR accessible docs).

    Args:
        api_key: Your personal API key from OAuth authorization
        keyword: Search keyword
        page_size: Max results (default 10)
    Returns:
        JSON with matching documents
    """
    user, err = require_user(api_key)
    if err:
        return json.dumps({"ok": False, "error": err}, ensure_ascii=False)
    result = feishu_api(
        "POST", "/suite/docs-api/search/object",
        user["user_access_token"],
        {"query": keyword, "page_size": min(page_size, 50)}
    )
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
def feishu_whoami(api_key: str) -> str:
    """Show who you are authenticated as (for verifying your identity).

    Args:
        api_key: Your personal API key from OAuth authorization
    Returns:
        JSON with your Feishu user info
    """
    user, err = require_user(api_key)
    if err:
        return json.dumps({"ok": False, "error": err}, ensure_ascii=False)
    return json.dumps({
        "ok": True,
        "feishu_name": user["feishu_name"],
        "feishu_user_id": user["feishu_user_id"],
        "token_expires_in": user["token_expiry"] - int(time.time()),
    }, ensure_ascii=False, indent=2)


# --- OAuth Web Endpoints (for user onboarding) ---
# Note: MCPServer may not support HTTP routes directly.
# These are documented for a companion Flask/FastAPI app.

OAUTH_INSTRUCTIONS = """
## Multi-User OAuth Setup

1. User visits: {authorize_url}
2. User clicks "Authorize" in Feishu
3. Feishu redirects to: {redirect_uri}?code=xxx
4. Server exchanges code for tokens, stores per-user, returns api_key
5. User configures their AI client with:
   - MCP endpoint: https://feishu-mcp-production.up.railway.app/mcp
   - Their personal api_key (passed as parameter to each tool)

Each user's documents are owned by them, not shared.
"""


def get_authorize_url():
    params = {
        "client_id": APP_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": "feishu-mcp-mt",
    }
    return "https://accounts.feishu.cn/open-apis/authen/v1/authorize?" + \
           urllib.parse.urlencode(params)


if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("Feishu MCP Multi-Tenant Server")
    print("=" * 60)
    print(f"\nDB: {DB_PATH}")
    print(f"\nOAuth authorize URL (share with users):\n{get_authorize_url()}")
    print(f"\nRedirect URI (must match Feishu console):\n{REDIRECT_URI}")
    print("\n" + OAUTH_INSTRUCTIONS.format(
        authorize_url=get_authorize_url(),
        redirect_uri=REDIRECT_URI,
    ))
    mcp.run(transport="sse", host="127.0.0.1", port=8901)
