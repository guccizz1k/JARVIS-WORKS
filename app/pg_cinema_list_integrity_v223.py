"""Opt-in, review-only ASGI guard for merged SQLite/PostgreSQL trade lists.

Does not modify the protected CutoverFront or either business engine. Safely
buffers bounded merged GET responses and refuses duplicate document IDs before
sending any upstream bytes to the browser. NOT a production deployment entry.
"""
from __future__ import annotations

import json
import os
from typing import Any

from starlette.responses import JSONResponse

LIST_PATHS = frozenset(("/api/customers", "/api/quotes", "/api/orders", "/api/invoices"))
MAX_LIST_BYTES = 4 * 1024 * 1024
MAX_LIST_RECORDS = 10000
REVIEW_OPT_IN = "ISOLATED_REVIEW_ONLY"


class ListIntegrityRefused(Exception):
    """Internal safe reason; never include upstream payload in a response."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def validate_merged_list(payload: bytes) -> None:
    """Validate shape and ID uniqueness, without changing rows or their order."""
    try:
        data: Any = json.loads(payload)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ListIntegrityRefused("invalid_merged_list_json") from exc
    if not isinstance(data, list) or len(data) > MAX_LIST_RECORDS:
        raise ListIntegrityRefused("invalid_merged_list_shape")
    seen: set[str] = set()
    for row in data:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
            raise ListIntegrityRefused("invalid_merged_list_shape")
        if row["id"] in seen:
            raise ListIntegrityRefused("duplicate_merged_list_id")
        seen.add(row["id"])


class MergedListIntegrityGuard:
    """Review-only ASGI composition around the existing V22.3 cutover front."""

    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (scope.get("type") != "http"
                or scope.get("method", "").upper() != "GET"
                or scope.get("path", "") not in LIST_PATHS):
            return await self.app(scope, receive, send)

        start = None
        body = bytearray()
        completed = False

        async def buffer_until_verified(message):
            nonlocal start, completed
            kind = message.get("type")
            if kind == "http.response.start":
                if start is not None or completed:
                    raise ListIntegrityRefused("invalid_merged_list_response")
                start = message
                return
            if kind != "http.response.body" or start is None or completed:
                raise ListIntegrityRefused("invalid_merged_list_response")
            chunk = message.get("body", b"")
            if not isinstance(chunk, bytes) or len(body) + len(chunk) > MAX_LIST_BYTES:
                raise ListIntegrityRefused("merged_list_response_too_large")
            body.extend(chunk)
            if message.get("more_body", False):
                return
            if start.get("status") == 200:
                headers = start.get("headers", ())
                content_types = [v for k, v in headers if k.lower() == b"content-type"]
                if (len(content_types) != 1 or
                        content_types[0].split(b";", 1)[0].strip().lower() != b"application/json"):
                    raise ListIntegrityRefused("invalid_merged_list_content_type")
                validate_merged_list(bytes(body))
            # Preserve existing auth, RLS, cookies, CSP and all response headers.
            completed = True
            await send(start)
            await send({"type": "http.response.body", "body": bytes(body), "more_body": False})

        try:
            await self.app(scope, receive, buffer_until_verified)
            if not completed:
                raise ListIntegrityRefused("incomplete_merged_list_response")
        except ListIntegrityRefused as exc:
            if completed:
                raise  # Never attempt a second ASGI response after emission.
            await JSONResponse(
                {"code": exc.code}, status_code=503,
                headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
            )(scope, receive, send)


def create_guarded_app():
    """Explicit isolated pilot factory; never mutates the main app selector."""
    if (os.environ.get("JW_MERGED_LIST_INTEGRITY_V223") != REVIEW_OPT_IN
            or os.environ.get("JW_ENV", "").lower() not in ("review", "test", "dev", "development")
            or os.environ.get("JW_INSECURE_LOCAL_DEV") == "1"):
        raise RuntimeError("BLOCKED: merged-list pilot requires isolated review opt-in")
    from .pg_cinema_cutover_front_v223 import create_app
    return MergedListIntegrityGuard(create_app())
