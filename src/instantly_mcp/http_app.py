"""
Instantly MCP Server - OAuth 2.0 PKCE HTTP Application

Implements OAuth 2.0 PKCE authentication for claude.ai custom MCP integration.
Bearer token validation sits in front of the FastMCP ASGI app.

Authentication flow:
1. claude.ai discovers /.well-known/oauth-authorization-server
2. Redirects to /authorize with PKCE code_challenge
3. Server issues auth code, redirects back
4. Claude exchanges code for Bearer token via /oauth/token
5. All /mcp/* requests validated against MCP_AUTH_TOKEN

The INSTANTLY_API_KEY is injected server-side from env — never exposed in URLs.
"""

import hashlib
import json
import os
import secrets
import time
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlencode

# OAuth configuration from environment
AUTH_TOKEN = (os.environ.get("MCP_AUTH_TOKEN") or "").strip()
OAUTH_CLIENT_ID = (os.environ.get("OAUTH_CLIENT_ID") or "claude-pathfinder").strip()
OAUTH_CLIENT_SECRET = (os.environ.get("OAUTH_CLIENT_SECRET") or "").strip()

# Token lifetime: 90 days — avoids claude.ai "disconnected" after expiry
TOKEN_EXPIRES_IN = 7776000

# In-memory auth code store: code -> {code_challenge, code_challenge_method, redirect_uri, expires_at}
_auth_codes: dict[str, dict[str, Any]] = {}

# Token issuance tracking — persisted so the expiry-warning cron can read it.
_TOKEN_META_PATH = "/tmp/mcp-token-meta.json"
_token_issued_at: Optional[int] = None
try:
    with open(_TOKEN_META_PATH) as _f:
        _meta = json.load(_f)
        if _meta.get("issued_at"):
            _token_issued_at = int(_meta["issued_at"])
except Exception:
    pass


def _record_token_issuance() -> None:
    global _token_issued_at
    _token_issued_at = int(time.time())
    try:
        with open(_TOKEN_META_PATH, "w") as f:
            json.dump({"issued_at": _token_issued_at, "expires_in": TOKEN_EXPIRES_IN}, f)
    except Exception as e:
        import sys
        print(f"Failed to write token meta: {e}", file=sys.stderr)


def _get_base_url(scope: dict) -> str:
    host_header = dict(scope.get("headers", [])).get(b"host", b"localhost").decode()
    scheme = "https"
    return f"{scheme}://{host_header}"


def _qs(scope: dict) -> dict[str, list[str]]:
    qs = scope.get("query_string", b"").decode()
    return parse_qs(qs)


def _qs_get(scope: dict, key: str) -> Optional[str]:
    vals = _qs(scope).get(key)
    return vals[0] if vals else None


async def _read_body(receive: Callable) -> bytes:
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break
    return body


def _parse_form(raw: bytes) -> dict[str, str]:
    parsed = parse_qs(raw.decode(), keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items()}


async def _send_json(send: Callable, status: int, body: dict, extra_headers: list = None):
    body_bytes = json.dumps(body).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body_bytes)).encode()),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body_bytes})


async def _send_redirect(send: Callable, location: str):
    await send({
        "type": "http.response.start",
        "status": 302,
        "headers": [(b"location", location.encode())],
    })
    await send({"type": "http.response.body", "body": b""})


async def _handle_oauth_protected_resource(scope: dict, receive: Callable, send: Callable):
    base = _get_base_url(scope)
    await _send_json(send, 200, {
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
    })


async def _handle_oauth_authorization_server(scope: dict, receive: Callable, send: Callable):
    base = _get_base_url(scope)
    await _send_json(send, 200, {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "code_challenge_methods_supported": ["S256"],
        "response_types_supported": ["code"],
    })


async def _handle_authorize(scope: dict, receive: Callable, send: Callable):
    response_type = _qs_get(scope, "response_type")
    client_id = _qs_get(scope, "client_id")
    redirect_uri = _qs_get(scope, "redirect_uri")
    code_challenge = _qs_get(scope, "code_challenge")
    code_challenge_method = _qs_get(scope, "code_challenge_method") or "S256"
    state = _qs_get(scope, "state")

    if client_id != OAUTH_CLIENT_ID:
        await _send_json(send, 401, {"error": "invalid_client"})
        return
    if response_type != "code":
        await _send_json(send, 400, {"error": "unsupported_response_type"})
        return
    if not code_challenge:
        await _send_json(send, 400, {"error": "code_challenge required"})
        return

    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "redirect_uri": redirect_uri,
        "expires_at": time.time() + 300,  # 5 min
    }

    # Build redirect URL
    params = f"code={code}"
    if state:
        params += f"&state={state}"
    separator = "&" if "?" in (redirect_uri or "") else "?"
    await _send_redirect(send, f"{redirect_uri}{separator}{params}")


async def _handle_token(scope: dict, receive: Callable, send: Callable):
    if not OAUTH_CLIENT_ID or not AUTH_TOKEN:
        await _send_json(send, 500, {"error": "server_misconfigured"})
        return

    raw_body = await _read_body(receive)
    body = _parse_form(raw_body)
    grant_type = body.get("grant_type", "")

    if grant_type == "authorization_code":
        code = body.get("code", "")
        code_verifier = body.get("code_verifier", "")
        redirect_uri = body.get("redirect_uri", "")

        stored = _auth_codes.get(code)
        if not stored or stored["expires_at"] < time.time():
            await _send_json(send, 400, {"error": "invalid_grant"})
            return

        # Verify PKCE: SHA256(code_verifier) base64url == code_challenge
        digest = hashlib.sha256(code_verifier.encode()).digest()
        import base64
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if expected != stored["code_challenge"]:
            await _send_json(send, 400, {"error": "invalid_grant"})
            return

        if redirect_uri and redirect_uri != stored.get("redirect_uri"):
            await _send_json(send, 400, {"error": "invalid_grant"})
            return

        del _auth_codes[code]
        _record_token_issuance()
        await _send_json(send, 200, {
            "access_token": AUTH_TOKEN,
            "token_type": "Bearer",
            "expires_in": TOKEN_EXPIRES_IN,
        })
        return

    # client_credentials grant
    if not OAUTH_CLIENT_SECRET:
        await _send_json(send, 500, {"error": "server_misconfigured"})
        return

    # Support Basic auth header or body params
    headers_dict = dict(scope.get("headers", []))
    basic = headers_dict.get(b"authorization", b"").decode()
    client_id, client_secret = None, None
    if basic.lower().startswith("basic "):
        import base64
        decoded = base64.b64decode(basic[6:]).decode()
        colon = decoded.index(":")
        client_id, client_secret = decoded[:colon], decoded[colon + 1:]
    else:
        client_id = body.get("client_id")
        client_secret = body.get("client_secret")

    if client_id != OAUTH_CLIENT_ID or client_secret != OAUTH_CLIENT_SECRET:
        await _send_json(send, 401, {"error": "invalid_client"})
        return

    _record_token_issuance()
    await _send_json(send, 200, {
        "access_token": AUTH_TOKEN,
        "token_type": "Bearer",
        "expires_in": TOKEN_EXPIRES_IN,
    })


async def _handle_health(scope: dict, receive: Callable, send: Callable):
    await _send_json(send, 200, {"status": "healthy", "server": "instantly-mcp"})


async def _handle_token_expiry(scope: dict, receive: Callable, send: Callable):
    if _token_issued_at is None:
        await _send_json(send, 404, {"error": "no_token_issued"})
        return
    await _send_json(send, 200, {
        "issued_at": _token_issued_at,
        "expires_in": TOKEN_EXPIRES_IN,
        "expires_at": _token_issued_at + TOKEN_EXPIRES_IN,
    })


def create_http_app(mcp_app) -> Callable:
    """
    Create an ASGI app that wraps FastMCP with OAuth 2.0 PKCE auth.

    Routes:
    - GET /.well-known/oauth-protected-resource  — RFC 9728 resource metadata
    - GET /.well-known/oauth-authorization-server — RFC 8414 server metadata
    - GET /authorize                              — OAuth authorization endpoint
    - POST /oauth/token                           — OAuth token endpoint
    - GET /health                                 — Health check
    - /mcp/*                                      — FastMCP (Bearer required)
    """
    fastmcp_asgi = mcp_app.http_app()

    async def app(scope: dict, receive: Callable, send: Callable):
        if scope["type"] not in ("http", "websocket"):
            await fastmcp_asgi(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        # OAuth discovery — no auth required
        if path == "/.well-known/oauth-protected-resource":
            await _handle_oauth_protected_resource(scope, receive, send)
            return

        if path == "/.well-known/oauth-authorization-server":
            await _handle_oauth_authorization_server(scope, receive, send)
            return

        if path == "/.well-known/token-expiry":
            await _handle_token_expiry(scope, receive, send)
            return

        if path == "/authorize":
            await _handle_authorize(scope, receive, send)
            return

        if path == "/oauth/token" and method == "POST":
            await _handle_token(scope, receive, send)
            return

        # Health check — no auth required
        if path in ("/", "/health"):
            await _handle_health(scope, receive, send)
            return

        # All /mcp paths require Bearer token
        if path.startswith("/mcp"):
            if AUTH_TOKEN:
                headers_dict = dict(scope.get("headers", []))
                auth_header = headers_dict.get(b"authorization", b"").decode()

                if not auth_header.startswith("Bearer "):
                    base = _get_base_url(scope)
                    await _send_json(
                        send,
                        401,
                        {"error": "Unauthorized"},
                        extra_headers=[
                            (b"www-authenticate",
                             f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"'.encode()),
                        ],
                    )
                    return

                token = auth_header[7:]
                if token != AUTH_TOKEN:
                    await _send_json(
                        send,
                        401,
                        {"error": "Unauthorized"},
                        extra_headers=[(b"www-authenticate", b'Bearer error="invalid_token"')],
                    )
                    return

            await fastmcp_asgi(scope, receive, send)
            return

        # 404 for unknown paths
        await _send_json(send, 404, {"error": "Not found", "hint": "MCP endpoint is at /mcp"})

    return app


def run_http_server(mcp_app, host: str = "0.0.0.0", port: int = 8000):
    """Run the HTTP server with OAuth 2.0 PKCE auth."""
    import uvicorn

    app = create_http_app(mcp_app)
    uvicorn.run(app, host=host, port=port)
