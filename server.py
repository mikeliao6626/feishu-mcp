#!/usr/bin/env python3
"""Feishu Document MCP Server for ChatGPT/Codex — Railway edition.

Direct Feishu OpenAPI calls (no lark-cli). Exposes 4 tools over
Streamable HTTP with Bearer-token auth and a /health endpoint.

Env vars:
    FEISHU_APP_ID       Feishu app id (default: cli_aa4d74dcc0b8dcea)
    FEISHU_APP_SECRET   Feishu app secret (required)
    MCP_AUTH_TOKEN      Bearer token MCP clients must present (required)
    PORT                Port to listen on (Railway injects this; default 8000)
"""
import json
import logging
import os
import re
import threading
import time
import urllib.request
import urllib.parse
import urllib.error

from mcp.server.mcpserver import MCPServer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("feishu-mcp-railway")

APP_ID = os.environ.get("FEISHU_APP_ID", "cli_aa4d74dcc0b8dcea")
APP_SECRET = os.environ.get("FEISHU_APP_SECRET", "")
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")
PORT = int(os.environ.get("PORT", "8000"))

BASE = "https://open.feishu.cn/open-apis"

mcp = MCPServer("feishu-docs")


# ---------------------------------------------------------------- Feishu client
class FeishuClient:
    """Thin Feishu OpenAPI client using tenant_access_token with in-memory cache."""

    def __init__(self, app_id: str, app_secret: str):
        self.app_id = app_id
        self.app_secret = app_secret
        self._token = ""
        self._expires_at = 0.0
        self._lock = threading.Lock()

    def _http(self, method: str, url: str, headers: dict, body: bytes | None) -> dict:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode())
            except Exception:
                return {"code": e.code, "msg": f"HTTP {e.code}"}
        except Exception as e:
            return {"code": -1, "msg": f"request failed: {str(e)[:200]}"}

    def _fetch_token(self) -> tuple[str, int]:
        data = self._http(
            "POST",
            f"{BASE}/auth/v3/tenant_access_token/internal",
            {"Content-Type": "application/json"},
            json.dumps({"app_id": self.app_id, "app_secret": self.app_secret}).encode(),
        )
        if data.get("code") != 0:
            raise RuntimeError(f"tenant token failed: {data}")
        return data["tenant_access_token"], int(data.get("expire", 7200))

    def token(self) -> str:
        with self._lock:
            if not self._token or time.time() > self._expires_at - 300:
                token, expire = self._fetch_token()
                self._token = token
                self._expires_at = time.time() + expire
                logger.info("Refreshed tenant_access_token")
            return self._token

    def request(self, method: str, path: str, params: dict | None = None,
                json_body: dict | None = None) -> dict:
        url = f"{BASE}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        body = json.dumps(json_body).encode() if json_body is not None else None
        headers = {
            "Authorization": f"Bearer {self.token()}",
            "Content-Type": "application/json",
        }
        return self._http(method, url, headers, body)


feishu = FeishuClient(APP_ID, APP_SECRET)


def _doc_id(doc_id_or_url: str) -> str:
    """Extract document id from a full URL or return as-is."""
    m = re.search(r"/(?:docx|doc)/([A-Za-z0-9]+)", doc_id_or_url)
    return m.group(1) if m else doc_id_or_url.strip()


def _text_blocks(content: str) -> list:
    """Split content into Feishu text blocks (one per non-empty line)."""
    blocks = []
    for line in content.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        blocks.append(
            {
                "block_type": 2,  # text
                "text": {
                    "elements": [{"text_run": {"content": line}}],
                    "style": {},
                },
            }
        )
    if not blocks:
        blocks.append(
            {
                "block_type": 2,
                "text": {"elements": [{"text_run": {"content": " "}}], "style": {}},
            }
        )
    return blocks


def _ok(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def _err(message: str) -> str:
    return json.dumps({"ok": False, "error": message}, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- MCP tools
@mcp.tool()
def feishu_create_doc(title: str, folder_token: str = "") -> str:
    """Create a new Feishu cloud document.

    Args:
        title: Document title
        folder_token: Optional folder token to create in (empty = root)
    Returns:
        JSON with document_id and URL
    """
    body: dict = {"title": title}
    if folder_token:
        body["folder_token"] = folder_token
    data = feishu.request("POST", "/docx/v1/documents", json_body=body)
    if data.get("code") != 0:
        return _err(f"create failed: {data.get('msg')} ({data.get('code')})")
    doc = data.get("data", {}).get("document", {})
    doc_id = doc.get("document_id", "")
    return _ok(
        {
            "ok": True,
            "document_id": doc_id,
            "title": doc.get("title", title),
            "url": f"https://feishu.cn/docx/{doc_id}" if doc_id else "",
        }
    )


@mcp.tool()
def feishu_read_doc(doc_id_or_url: str) -> str:
    """Read a Feishu document's content as plain text.

    Args:
        doc_id_or_url: Document ID or full URL
    Returns:
        JSON with document title and text content
    """
    doc_id = _doc_id(doc_id_or_url)
    data = feishu.request("GET", f"/docx/v1/documents/{doc_id}/raw_content")
    if data.get("code") != 0:
        return _err(f"read failed: {data.get('msg')} ({data.get('code')})")
    content = data.get("data", {}).get("content", "")
    return _ok({"ok": True, "document_id": doc_id, "content": content})


@mcp.tool()
def feishu_update_doc(doc_id_or_url: str, content: str, mode: str = "append") -> str:
    """Update a Feishu document.

    Args:
        doc_id_or_url: Document ID or full URL
        content: Plain-text content to write (one block per line)
        mode: "append" (add to end) or "overwrite" (best-effort: tries to
            clear existing blocks first, then appends; note the docx API
            does not support block deletion, so old content may remain —
            prefer creating a new document for a clean rewrite)
    Returns:
        JSON result
    """
    if mode not in ("append", "overwrite"):
        return _err("mode must be append or overwrite")
    doc_id = _doc_id(doc_id_or_url)

    if mode == "overwrite":
        # Delete existing top-level blocks (keep the root page block itself),
        # then fall through to append.
        blocks_data = feishu.request(
            "GET", f"/docx/v1/documents/{doc_id}/blocks", params={"page_size": 100}
        )
        if blocks_data.get("code") != 0:
            return _err(f"overwrite: list blocks failed: {blocks_data.get('msg')}")
        for b in blocks_data.get("data", {}).get("items", []):
            bid = b.get("block_id")
            if bid and bid != doc_id:  # never delete the root page block
                del_data = feishu.request(
                    "DELETE", f"/docx/v1/documents/{doc_id}/blocks/{bid}"
                )
                if del_data.get("code") != 0:
                    logger.warning("delete block %s failed: %s", bid, del_data.get("msg"))

    # Append: document_id doubles as the root block id; index -1 = end.
    children = _text_blocks(content)
    data = feishu.request(
        "POST",
        f"/docx/v1/documents/{doc_id}/blocks/{doc_id}/children",
        json_body={"index": -1, "children": children},
    )
    if data.get("code") != 0:
        return _err(f"update failed: {data.get('msg')} ({data.get('code')})")
    added = len(data.get("data", {}).get("children", []))
    return _ok({"ok": True, "document_id": doc_id, "mode": mode, "blocks_added": added})


@mcp.tool()
def feishu_search_docs(keyword: str, page_size: int = 10) -> str:
    """Search Feishu cloud documents by keyword.

    Args:
        keyword: Search keyword
        page_size: Max results (default 10, max 50)
    Returns:
        JSON with matching documents
    """
    page_size = max(1, min(int(page_size), 50))
    data = feishu.request(
        "POST",
        "/drive/v1/files/search",
        json_body={"query": keyword, "page_size": page_size},
    )
    if data.get("code") != 0:
        return _err(
            f"search failed: {data.get('msg')} ({data.get('code')}). "
            "Note: drive search requires the app to have drive permissions."
        )
    files = data.get("data", {}).get("files", [])
    return _ok(
        {
            "ok": True,
            "count": len(files),
            "files": [
                {
                    "name": f.get("name"),
                    "token": f.get("token"),
                    "type": f.get("type"),
                    "url": f.get("url"),
                }
                for f in files
            ],
        }
    )


# ---------------------------------------------------------------- Health check
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> Response:
    return JSONResponse({"status": "ok", "service": "feishu-mcp"})

def build_app():
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    app = mcp.streamable_http_app()
    # Allow all hosts (Railway proxy uses dynamic hostnames)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
    app.add_middleware(BearerAuthMiddleware)
    return app
# ---------------------------------------------------------------- Auth + serve
class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Require Authorization: Bearer <MCP_AUTH_TOKEN> on all routes except /health."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        if not MCP_AUTH_TOKEN:
            return JSONResponse(
                {"error": "server misconfigured: MCP_AUTH_TOKEN not set"}, status_code=500
            )
        auth = request.headers.get("authorization", "")
        if auth != f"Bearer {MCP_AUTH_TOKEN}":
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


def build_app():
    app = mcp.streamable_http_app()
    app.add_middleware(BearerAuthMiddleware)
    return app


if __name__ == "__main__":
    if not APP_SECRET:
        raise SystemExit("FEISHU_APP_SECRET env var is required")
    if not MCP_AUTH_TOKEN:
        raise SystemExit("MCP_AUTH_TOKEN env var is required")
    import uvicorn

    logger.info("Starting feishu-mcp on 0.0.0.0:%d (streamable HTTP)", PORT)
    uvicorn.run(build_app(), host="0.0.0.0", port=PORT)
