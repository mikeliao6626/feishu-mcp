# feishu-mcp (Railway edition)

Feishu document MCP server for ChatGPT/Codex, deployable on Railway.

## Files

- `server.py` — MCP server (Streamable HTTP, Bearer auth, direct Feishu OpenAPI)
- `requirements.txt` — Python dependencies
- `railway.json` — Railway build/deploy config

## Environment variables (set in Railway dashboard)

| Var | Required | Description |
|-----|----------|-------------|
| `FEISHU_APP_ID` | No | Feishu app id (default: `cli_aa4d74dcc0b8dcea`) |
| `FEISHU_APP_SECRET` | Yes | Feishu app secret |
| `MCP_AUTH_TOKEN` | Yes | Bearer token MCP clients must present |
| `PORT` | No | Injected by Railway (default 8000) |

## Endpoints

- `POST /mcp` — Streamable HTTP MCP endpoint (requires `Authorization: Bearer <MCP_AUTH_TOKEN>`)
- `GET /health` — Health check (no auth, used by Railway)

## MCP tools

- `feishu_create_doc(title, folder_token="")` — create document
- `feishu_read_doc(doc_id_or_url)` — read document text
- `feishu_update_doc(doc_id_or_url, content, mode="append"|"overwrite")` — append (or best-effort overwrite) content
- `feishu_search_docs(keyword, page_size=10)` — search (requires drive permissions on the app)

## Deploy

1. Push this directory to a GitHub repo (or use Railway CLI)
2. Create a Railway project from the repo
3. Set `FEISHU_APP_SECRET` and `MCP_AUTH_TOKEN` in Variables
4. Railway builds via `railway.json` and health-checks `/health`

## ChatGPT setup

Add MCP server with URL `https://<your-app>.up.railway.app/mcp` and the bearer token.
