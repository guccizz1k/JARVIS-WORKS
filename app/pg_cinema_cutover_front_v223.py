"""Isolated, disabled-by-default V22.3 dual-session SQLite/PG ASGI front pilot.

Legacy and PostgreSQL both issue __Host-jw_session, but with independent
stores. This proxy virtualizes their cookies, authenticates both identities,
and routes by immutable document home. Never deploy without independent QA.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Callable

import httpx
from fastapi import HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

LEGACY_COOKIE = "__Host-jw_legacy_v223"
PG_COOKIE = "__Host-jw_pg_v223"
UPSTREAM_COOKIE = "__Host-jw_session"
OPT_IN = "ISOLATED_DEV_DUAL_SESSION_PILOT"
FRONT_FLAG = "JW_PG_CINEMA_CUTOVER_FRONT_V223"
_PG_ID = re.compile(r"pg_[0-9a-f]{32}\Z")
_ID_PART = re.compile(r"(?:^|/)pg_[^/]*")
_LISTS = frozenset({"/api/customers", "/api/quotes", "/api/orders", "/api/invoices"})
_COLLECTION = {"/api/quotes", "/api/customers"}
_TRADE = frozenset({"customers", "quotes", "orders", "invoices"})


class CutoverRefused(Exception):
    def __init__(self, code: str, status: int = 409):
        self.code = code
        self.status = status


def parse_home(identifier: str) -> str:
    if identifier.startswith("pg_"):
        if not _PG_ID.fullmatch(identifier):
            raise CutoverRefused("malformed_pg_id", 422)
        return "pg"
    return "legacy"


def is_trade(path: str) -> bool:
    segments = path.strip("/").split("/")
    return len(segments) >= 2 and segments[0] == "api" and segments[1] in _TRADE


def route_home(path: str, method: str, body: Any = None) -> str:
    """Select source by immutable record home; never silently mix ledger IDs."""
    if not is_trade(path):
        return "legacy"
    if method == "GET" and path in _LISTS:
        return "merge"
    if method == "POST" and path in _COLLECTION:
        return "pg"
    if path in ("/api/orders/from-quote", "/api/invoices/from-order"):
        if not isinstance(body, dict):
            raise CutoverRefused("invalid_document_reference", 422)
        key = "quote_id" if "from-quote" in path else "order_id"
        value = body.get(key)
        if not isinstance(value, str):
            raise CutoverRefused("invalid_document_reference", 422)
        return parse_home(value)
    segments = path.strip("/").split("/")
    if len(segments) >= 3 and segments[2] not in ("from-order", "from-quote"):
        first = parse_home(segments[2])
        if len(segments) >= 5 and segments[3] == "payments":
            second = parse_home(segments[4])
            if second != first:
                raise CutoverRefused("cross_store_reference")
        return first
    return "legacy"


def _cookies_to_scope(scope: dict, upstream_token: str) -> dict:
    new = dict(scope)
    headers = [(k, v) for k, v in scope.get("headers", ()) if k.lower() != b"cookie"]
    if upstream_token:
        headers.append((b"cookie", f"{UPSTREAM_COOKIE}={upstream_token}".encode("ascii")))
    new["headers"] = headers
    return new


def _safe_cookie(scope: dict, cookie_name: str) -> str:
    value = Request(scope).cookies.get(cookie_name, "")
    if value and (len(value) > 512 or not value.isascii()):
        raise CutoverRefused("invalid_session_cookie", 401)
    return value


def _source_tagged(body: Any, source: str) -> list[dict]:
    if not isinstance(body, list) or len(body) > 10000:
        raise CutoverRefused("unexpected_list_shape", 503)
    output = []
    for row in body:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise CutoverRefused("unexpected_list_shape", 503)
        if source == "pg" and parse_home(row["id"]) != "pg":
            raise CutoverRefused("invalid_pg_record_home", 503)
        if source == "legacy" and parse_home(row["id"]) != "legacy":
            raise CutoverRefused("invalid_legacy_record_home", 503)
        output.append({**row, "source": source})
    return output


@dataclass(frozen=True)
class Identity:
    org_id: str
    actor_id: str
    role: str


class CutoverFront:
    """ASGI routing front: default legacy, dual-authenticated PG for opted-in orgs."""

    def __init__(self, legacy_app: Any, pg_app: Any,
                 legacy_identity: Callable[[Request], Identity],
                 pg_identity: Callable[[Request], Identity],
                 enabled_orgs: Callable[[], frozenset[str]]):
        self.legacy_app = legacy_app
        self.pg_app = pg_app
        self.legacy_identity = legacy_identity
        self.pg_identity = pg_identity
        self.enabled_orgs = enabled_orgs

    async def _forward(self, app, scope, receive, send, cookie_name):
        token = _safe_cookie(scope, cookie_name)
        new_scope = _cookies_to_scope(scope, token)

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                headers = []
                for key, value in message.get("headers", []):
                    if key.lower() == b"set-cookie" and value.startswith((UPSTREAM_COOKIE + "=").encode()):
                        attrs = {part.strip().lower() for part in value.split(b";")[1:]}
                        if (b"path=/" not in attrs
                                or any(part.startswith(b"domain=") for part in attrs)):
                            raise CutoverRefused("insecure_upstream_session", 503)
                        if b"secure" not in attrs:
                            # SQLite's historical logout deletes the cookie without Secure.
                            # Permit ONLY the explicit empty, Max-Age=0 deletion and
                            # upgrade it to a valid __Host- Secure deletion. Never
                            # accept an insecure cookie that can create a session.
                            raw_value = value.split(b";", 1)[0].split(b"=", 1)[1]
                            if raw_value not in (b"", b'""') or b"max-age=0" not in attrs:
                                raise CutoverRefused("insecure_upstream_session", 503)
                            value += b"; Secure; HttpOnly"
                        value = (cookie_name + "=").encode() + value[len(UPSTREAM_COOKIE)+1:]
                    headers.append((key, value))
                message = {**message, "headers": headers}
            await send(message)

        return await app(new_scope, receive, wrapped_send)

    async def _dual_logout(self, scope, receive, send):
        """Revoke both *independent* sessions; a partial failure is never success.

        The browser must supply the SQLite CSRF in X-CSRF-Token and the separately
        issued PG CSRF in X-JW-PG-CSRF. Neither password nor session is reused
        across stores. PG revocation precedes SQLite; if SQLite fails, only
        the PG cookie is cleared and a retry can still revoke SQLite.
        """
        request = Request(scope, receive=receive)
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            raise CutoverRefused("cross_site_logout_denied", 403)
        origin = request.headers.get("Origin", "")
        if origin and origin.rstrip("/") != str(request.base_url).rstrip("/"):
            raise CutoverRefused("cross_site_logout_denied", 403)
        pg_csrf = request.headers.get("X-JW-PG-CSRF", "")
        legacy_csrf = request.headers.get("X-CSRF-Token", "")
        if not pg_csrf:
            raise CutoverRefused("pg_logout_required_first")
        if not legacy_csrf:
            raise CutoverRefused("dual_logout_csrf_required", 403)
        pg_token = _safe_cookie(scope, PG_COOKIE)
        legacy_token = _safe_cookie(scope, LEGACY_COOKIE)
        if len(pg_token) < 30 or len(legacy_token) < 30:
            raise CutoverRefused("reauthentication_required", 401)

        async def revoke(app, path, token, csrf):
            # Internal ASGI call uses the ORIGINAL upstream cookie name.
            # Do not forward other cookies, credentials, Origin, or client
            # authorization headers to the wrong credential store.
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="https://testserver", timeout=15
            ) as client:
                return await client.post(path, headers={
                    "Cookie": f"{UPSTREAM_COOKIE}={token}", "X-CSRF-Token": csrf,
                })

        try:
            pg = await revoke(self.pg_app, "/api/pg-stage/v85/logout", pg_token, pg_csrf)
        except Exception as exc:
            raise CutoverRefused("pg_logout_unavailable", 503) from exc
        if pg.status_code != 200:
            raise CutoverRefused("pg_logout_denied", 403 if pg.status_code in (401, 403) else 503)
        try:
            pg_result = pg.json()
        except ValueError:
            pg_result = {}
        if pg_result.get("ok") is not True:
            raise CutoverRefused("pg_logout_unverified", 503)
        try:
            legacy = await revoke(self.legacy_app, "/api/logout", legacy_token, legacy_csrf)
            legacy_ok = legacy.status_code == 200 and legacy.json().get("ok") is True
        except Exception:
            legacy_ok = False

        response = JSONResponse(
            {"ok": True} if legacy_ok else {"code": "partial_logout_legacy_pending"},
            status_code=200 if legacy_ok else 409,
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )
        response.delete_cookie(PG_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        if legacy_ok:
            response.delete_cookie(LEGACY_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        await response(scope, receive, send)

    async def _identity(self, scope, cookie_name, resolver):
        token = _safe_cookie(scope, cookie_name)
        if len(token) < 30:
            raise CutoverRefused("reauthentication_required", 401)
        sanitized = _cookies_to_scope({**scope, "method": "GET"}, token)
        try:
            ident = await run_in_threadpool(resolver, Request(sanitized))
        except HTTPException as exc:
            raise CutoverRefused(
                "reauthentication_required",
                exc.status_code if exc.status_code in (401, 403) else 503
            ) from exc
        if not isinstance(ident, Identity) or not ident.actor_id or not ident.org_id:
            raise CutoverRefused("invalid_identity", 503)
        return ident

    async def _merged(self, scope, send):
        headers = {k.decode("latin1"): v.decode("latin1") for k, v in scope.get("headers", [])
                   if k.lower() not in (b"cookie", b"host")}
        path = scope["path"]
        qs = scope.get("query_string", b"").decode("ascii", "strict")
        results = []
        for app, cookie in ((self.legacy_app, LEGACY_COOKIE), (self.pg_app, PG_COOKIE)):
            cookie_val = _safe_cookie(scope, cookie)
            h = {**headers, "cookie": f"{UPSTREAM_COOKIE}={cookie_val}"}
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="https://testserver", timeout=15
            ) as client:
                response = await client.get(path+("?" + qs if qs else ""), headers=h)
            if response.status_code != 200:
                raise CutoverRefused("dual_home_listing_failed", 503)
            try:
                data = response.json()
            except ValueError as exc:
                raise CutoverRefused("unexpected_list_shape", 503) from exc
            results.append(data)
        merged = _source_tagged(results[0], "legacy") + _source_tagged(results[1], "pg")
        result = JSONResponse(merged, headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        })
        await result(scope, lambda: {"type": "http.request", "body": b""}, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            # PG review currently has no lifespan startup. Preserve legacy's.
            return await self.legacy_app(scope, receive, send)
        if scope["type"] != "http":
            # WebSocket dual-cookie binding needs separate QA. Deny in pilot.
            await send({"type": "websocket.close", "code": 4403})
            return
        try:
            if scope.get("scheme") != "https":
                raise CutoverRefused("https_required", 403)
            req = Request(scope, receive=receive)
            if UPSTREAM_COOKIE in req.cookies:
                raise CutoverRefused("old_session_relogin_required", 401)
            path = scope.get("path", "")
            method = scope.get("method", "GET").upper()
            if path == "/api/pg-stage/cutover/status":
                if method != "GET":
                    raise CutoverRefused("method_not_allowed", 405)
                legacy_ident = await self._identity(scope, LEGACY_COOKIE, self.legacy_identity)
                active = legacy_ident.org_id in self.enabled_orgs()
                response = JSONResponse({
                    "cutover_available": True, "pg_required": active,
                    "aggregate_status": "blocked_until_verified" if active else "legacy_only",
                }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
                return await response(scope, receive, send)
            if path == "/api/pg-stage/cutover/verify":
                if method != "GET":
                    raise CutoverRefused("method_not_allowed", 405)
                legacy_ident = await self._identity(scope, LEGACY_COOKIE, self.legacy_identity)
                if legacy_ident.org_id not in self.enabled_orgs():
                    raise CutoverRefused("pg_store_disabled_for_org")
                pg_ident = await self._identity(scope, PG_COOKIE, self.pg_identity)
                if (pg_ident.org_id != legacy_ident.org_id
                        or pg_ident.actor_id != legacy_ident.actor_id
                        or pg_ident.role != legacy_ident.role):
                    raise CutoverRefused("identity_mismatch", 403)
                response = JSONResponse({"identity_verified": True}, headers={
                    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                })
                return await response(scope, receive, send)
            if path.startswith("/api/pg-stage/"):
                return await self._forward(self.pg_app, scope, receive, send, PG_COOKIE)
            if not is_trade(path):
                if path == "/api/logout" and _safe_cookie(scope, PG_COOKIE):
                    if method != "POST":
                        raise CutoverRefused("logout_method_not_allowed", 405)
                    return await self._dual_logout(scope, receive, send)
                if _ID_PART.search(path):
                    raise CutoverRefused("pg_document_feature_unsupported")
                if path in ("/api/dashboard", "/api/order-analytics"):
                    legacy_ident = await self._identity(scope, LEGACY_COOKIE, self.legacy_identity)
                    if legacy_ident.org_id in self.enabled_orgs():
                        raise CutoverRefused("cross_store_aggregate_not_available")
                return await self._forward(self.legacy_app, scope, receive, send, LEGACY_COOKIE)
            path_bits = path.strip("/").split("/")
            if len(path_bits) >= 3 and path_bits[2] not in ("from-order", "from-quote"):
                home_in_path = parse_home(path_bits[2])
                if home_in_path == "pg" and not self.enabled_orgs():
                    raise CutoverRefused("pg_store_disabled_for_org")
            legacy_ident = await self._identity(scope, LEGACY_COOKIE, self.legacy_identity)
            active = legacy_ident.org_id in self.enabled_orgs()
            if not active:
                if len(path_bits) >= 3 and path_bits[2] not in ("from-order", "from-quote"):
                    if parse_home(path_bits[2]) == "pg":
                        raise CutoverRefused("pg_store_disabled_for_org")
                return await self._forward(self.legacy_app, scope, receive, send, LEGACY_COOKIE)
            body = None
            if path in ("/api/orders/from-quote", "/api/invoices/from-order"):
                req_body = await req.body()
                if len(req_body) > 65536:
                    raise CutoverRefused("body_too_large", 413)
                try:
                    body = json.loads(req_body)
                except (ValueError, UnicodeDecodeError):
                    raise CutoverRefused("invalid_document_reference", 422)
                received = False

                async def replay():
                    nonlocal received
                    if received:
                        return {"type": "http.request", "body": b"", "more_body": False}
                    received = True
                    return {"type": "http.request", "body": req_body, "more_body": False}

                receive = replay
            home = route_home(path, method, body)
            if home == "legacy":
                return await self._forward(self.legacy_app, scope, receive, send, LEGACY_COOKIE)
            pg_ident = await self._identity(scope, PG_COOKIE, self.pg_identity)
            if (pg_ident.org_id != legacy_ident.org_id
                    or pg_ident.actor_id != legacy_ident.actor_id
                    or pg_ident.role != legacy_ident.role):
                raise CutoverRefused("identity_mismatch", 403)
            if home == "merge":
                return await self._merged(scope, send)
            return await self._forward(self.pg_app, scope, receive, send, PG_COOKIE)
        except CutoverRefused as exc:
            return await JSONResponse(
                {"code": exc.code}, status_code=exc.status,
                headers={"Cache-Control": "no-store"}
            )(scope, receive, send)


def create_app():
    """Explicit isolated preview entrypoint, never wired into app.main."""
    # Fail closed before importing either application or opening any source.
    if (os.environ.get(FRONT_FLAG) != OPT_IN
            or os.environ.get("JW_ENV", "").lower() not in ("dev", "development", "test")
            or os.environ.get("JW_INSECURE_LOCAL_DEV") == "1"):
        raise RuntimeError("BLOCKED: cutover pilot must be explicit and non-production")
    from . import main as legacy
    from . import pg_review_integrated_v202 as pg_stage
    from . import pg_cinema_legacy_api_v1 as trade
    from . import pg_v90_integrated_entry as v90
    if not trade.legacy_api_gate_on():
        raise RuntimeError("BLOCKED: PG trade feature is disabled")
    pg = pg_stage.create_app()

    def sqlite_user(request):
        row = legacy.current_user(request)
        return Identity(row["org_id"], row["id"], row["role"])

    def pg_user(request):
        session = v90._session_hash(request)
        with v90._pg_validated_cursor(session) as (_, ident):
            return Identity(ident[2], ident[1], ident[3])

    return CutoverFront(legacy.app, pg, sqlite_user, pg_user, trade.enabled_orgs)
