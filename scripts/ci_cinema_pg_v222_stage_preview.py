"""Read-only-by-environment, Basic-authenticated PUBLIC-URL preview wrapper.

For synthetic JARVIS-WORKS V22.2 UX tests ONLY. This never authorizes real
customer DB access, deployment as production, or use of persistent storage.
The original FastAPI app and all its authentication and security remain intact.
"""
from __future__ import annotations

import base64
import hmac
import os
from pathlib import Path
from typing import Mapping

from app.deployment_safety_v78 import require_safe_runtime

DENIED_DB_VARS = (
    "DATABASE_URL", "JW_PG_STAGE_DSN", "JW_PG_CI_ROOT_DSN",
    "JW_PG_CI_RESTORE_DSN", "SUPABASE_DSN", "SUPABASE_DB_URL",
    "SUPABASE_SERVICE_ROLE_KEY", "PGHOST", "PGUSER",
    "BOOTSTRAP_EMAIL", "BOOTSTRAP_PASSWORD",
)
ACCESS_USER = "review"
DENIED_TEXT = b"Review access requires authentication."


def validate_sandbox(env: Mapping[str, str]) -> str:
    if env.get("JW_ENV", "").strip().lower() != "review":
        raise RuntimeError("PREVIEW_BLOCKED_NOT_REVIEW")
    if env.get("JW_ROOT_UI", "").strip().lower() != "v222":
        raise RuntimeError("PREVIEW_BLOCKED_NOT_V222")
    if env.get("DEMO_SEED") != "1":
        raise RuntimeError("PREVIEW_BLOCKED_NOT_SYNTHETIC")
    nonempty = sorted(k for k in DENIED_DB_VARS if env.get(k))
    if nonempty:
        raise RuntimeError("PREVIEW_BLOCKED_EXTERNAL_DB_VARIABLES:" + ",".join(nonempty))
    path = Path(env.get("JARVIS_DB_PATH", "")).resolve()
    if not path.is_relative_to(Path("/tmp")) or path.suffix != ".sqlite":
        raise RuntimeError("PREVIEW_BLOCKED_NON_EPHEMERAL_SQLITE_PATH")
    secret = env.get("JW_PREVIEW_SECRET", "")
    if len(secret) < 32 or secret.isspace() or secret.strip() != secret:
        raise RuntimeError("PREVIEW_BLOCKED_WEAK_ACCESS_SECRET")
    return secret


class PreviewAccess:
    def __init__(self, inner, secret: str):
        self.inner = inner
        self.expected = b"Basic " + base64.b64encode(
            (ACCESS_USER + ":" + secret).encode("utf-8"))
        self.robots = (b"x-robots-tag", b"noindex, nofollow, noarchive")

    async def __call__(self, scope, receive, send):
        typ = scope["type"]
        if typ == "lifespan":
            return await self.inner(scope, receive, send)
        if typ not in ("http", "websocket"):
            raise RuntimeError("PREVIEW_UNSUPPORTED_ASGI_SCOPE")
        headers = scope.get("headers", ())
        authorization = next((v for k, v in headers if k.lower() == b"authorization"), b"")
        valid = hmac.compare_digest(authorization, self.expected)
        if not valid:
            if typ == "websocket":
                return await send({"type": "websocket.close", "code": 1008})
            await send({"type": "http.response.start", "status": 401,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"cache-control", b"no-store"),
                    (b"www-authenticate", b'Basic realm="JARVIS-WORKS V22.2 Preview"'),
                    self.robots,
                ]})
            return await send({"type": "http.response.body", "body": DENIED_TEXT})
        async def safe_send(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + [self.robots]
            await send(message)
        return await self.inner(scope, receive, safe_send)


# Validate the public preview before importing/mounting the business app.
_SECRET = validate_sandbox(os.environ)
require_safe_runtime()
from app.main import app as _original_app  # noqa: E402
app = PreviewAccess(_original_app, _SECRET)
