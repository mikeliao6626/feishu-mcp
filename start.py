#!/usr/bin/env python3
"""Start both OAuth web app (main, with /health) and MCP server (background)."""
import subprocess
import os
import sys
import time

# Start MCP server in background
mcp_proc = subprocess.Popen([sys.executable, "server_mt.py"])
print(f"MCP server started (pid {mcp_proc.pid})", flush=True)

# Give MCP a moment to initialize
time.sleep(2)

# Start OAuth Flask app in foreground (Railway monitors this, has /health)
# Flask reads PORT env var itself
os.execv(sys.executable, [sys.executable, "oauth_app.py"])
