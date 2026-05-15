# mcp-instantly

Pathfinder fork of [bcharleson/instantly-mcp](https://github.com/bcharleson/instantly-mcp). Deployed on the shared DO droplet at `instantly.mcp.pathfindermarketing.com.au`.

## Architecture

- **Runtime:** Python 3.11 / FastMCP + uvicorn (ASGI)
- **Port:** 8000 (internal Docker network)
- **Entry point:** `src/instantly_mcp/server.py` → HTTP mode via `src/instantly_mcp/http_app.py`
- **Tools:** 38 tools across 6 categories — accounts, campaigns, leads, emails, analytics, background_jobs

## Auth

OAuth 2.0 PKCE middleware is in `src/instantly_mcp/http_app.py`. Three env vars required:

| Var | Value |
|---|---|
| `MCP_AUTH_TOKEN` | Bearer token validated on every `/mcp/*` request |
| `OAUTH_CLIENT_ID` | `claude-pathfinder` (constant across all Pathfinder MCPs) |
| `OAUTH_CLIENT_SECRET` | Used for `client_credentials` grant |

The `INSTANTLY_API_KEY` env var is injected server-side. It is never exposed in URLs or logs.

**1Password:** `Claude_Remote_MCP - Instantly` (vault: `Claude Code`)

## Env template

`pmin-mcpinfrastructure/env-templates/instantly.env.example`

## Fork sync

This repo is a fork — `upstream` remote points to `bcharleson/instantly-mcp`. The weekly `sync.sh` cron on the droplet will cherry-pick missing upstream commits automatically. Use `.fork-sync-ignore` to reject unwanted upstream SHAs if a conflict arises.

## Deploying changes

```bash
# After pushing to origin/main:
ssh mcp-server "cd /opt/pmin-mcpinfrastructure/repos/mcp-instantly && git pull --ff-only && \
  cd /opt/pmin-mcpinfrastructure && bash scripts/check-repos-sync.sh instantly && \
  docker compose up -d instantly"
```
