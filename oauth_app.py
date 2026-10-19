#!/usr/bin/env python3
"""OAuth web endpoints for Feishu MCP Multi-Tenant.

Runs alongside the MCP server. Handles:
- GET /oauth/authorize -> redirect to Feishu
- GET /oauth/callback?code=xxx -> exchange, store user, show api_key
- GET /health -> health check
"""
import os
import secrets
import time
import urllib.parse
import urllib.request
import json
import sqlite3
from flask import Flask, request, redirect

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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8902))
    app.run(host="0.0.0.0", port=port)
