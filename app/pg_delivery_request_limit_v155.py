"""Bound POST review request bodies before FastAPI/Pydantic JSON parsing.

Isolated V15.4 API only. Does not affect other routes, production app.main,
or any external issuer service. Untrusted Content-Length is not sufficient:
the actual ASGI byte stream is counted and rejected too.
"""
from __future__ import annotations

import json

_REVIEW_PREFIX = "/api/pg-stage/v154/orders/"
_MAX_RAW_BYTES = 16_384


class _RequestTooLarge(Exception):
    pass


class ReviewBodyLimitV155:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (scope.get("type") != "http" or scope.get("method") != "POST"
            or not scope.get("path", "").startswith(_REVIEW_PREFIX)
            or not scope.get("path", "").endswith("/delivery-review")):
            return await self.app(scope, receive, send)

        headers = [(k.lower(), v) for k, v in scope.get("headers", [])]
        lengths = [v for k, v in headers if k == b"content-length"]
        if (len(lengths) > 1 or
            any(not v.isascii() or not v.isdigit() for v in lengths)):
            return await self._reject(send, 400, "Invalid Content-Length")
        # Never convert attacker-supplied megabyte-long decimal headers to int.
        if lengths and (len(lengths[0]) > 5 or int(lengths[0]) > _MAX_RAW_BYTES):
            return await self._reject(send, 413, "Review envelope too large")

        total = 0

        async def limited_receive():
            nonlocal total
            event = await receive()
            if event.get("type") == "http.request":
                total += len(event.get("body", b""))
                if total > _MAX_RAW_BYTES:
                    raise _RequestTooLarge()
            return event

        try:
            return await self.app(scope, limited_receive, send)
        except _RequestTooLarge:
            return await self._reject(send, 413, "Review envelope too large")

    @staticmethod
    async def _reject(send, code: int, detail: str):
        payload = json.dumps({"detail": detail}, separators=(",", ":")).encode()
        await send({"type": "http.response.start", "status": code,
                    "headers": [(b"content-type", b"application/json"),
                                (b"cache-control", b"no-store"),
                                (b"content-length", str(len(payload)).encode())]})
        await send({"type": "http.response.body", "body": payload})
