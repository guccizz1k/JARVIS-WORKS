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
# Legacy and PG session issuers both use secrets.token_urlsafe (RFC 4648 URL-safe alphabet).
# Reject cookie delimiters/control/ambiguous values before forwarding to either backend.
_SESSION_TOKEN = re.compile(r"[A-Za-z0-9_-]{30,512}\Z")
_UNTRUSTED_UPSTREAM_HEADERS = frozenset({
    b"authorization", b"proxy-authorization", b"x-api-key",
    b"x-jw-stage-key", b"x-tenant-id", b"x-org-id",
    b"x-acting-user", b"x-user-id", b"x-real-ip",
    b"forwarded", b"x-original-url", b"x-rewrite-url",
    b"x-http-method-override", b"x-method-override",
})


def _forwardable_header(key: bytes) -> bool:
    """Never route client-controlled identity, proxy or gateway headers to a store."""
    name = key.lower()
    return (name != b"cookie" and name not in _UNTRUSTED_UPSTREAM_HEADERS
            and not name.startswith(b"x-forwarded-"))


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
    # Applies to both direct ASGI routing and identity resolution. Session
    # tokens are recreated per-store below; client identity/proxy overrides
    # must not become backend-trusted assertions.
    headers = [(k, v) for k, v in scope.get("headers", ())
               if _forwardable_header(k)]
    if upstream_token:
        headers.append((b"cookie", f"{UPSTREAM_COOKIE}={upstream_token}".encode("ascii")))
    new["headers"] = headers
    return new


def _safe_cookie(scope: dict, cookie_name: str) -> str:
    # Starlette's cookie parser retains one value if the same cookie appears
    # twice. Reject ambiguity instead of authenticating whichever value wins.
    expected = cookie_name.encode("ascii")
    occurrences = sum(
        1 for key, raw in scope.get("headers", ())
        if key.lower() == b"cookie"
        for part in raw.split(b";")
        if part.partition(b"=")[0].strip() == expected
    )
    if occurrences > 1:
        raise CutoverRefused("duplicate_session_cookie", 401)
    value = Request(scope).cookies.get(cookie_name, "")
    if value and not _SESSION_TOKEN.fullmatch(value):
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
        # Preserve each store's independent CSRF. The additional front-end
        # token is NEVER forwarded to the SQLite backend.
        headers = [(k, v) for k, v in new_scope.get("headers", ())
                   if k.lower() != b"x-jw-pg-csrf"]
        pg_csrf = [v for k, v in new_scope.get("headers", ())
                   if k.lower() == b"x-jw-pg-csrf"]
        if cookie_name == PG_COOKIE and pg_csrf:
            if len(pg_csrf) != 1 or not (16 <= len(pg_csrf[0]) <= 512):
                raise CutoverRefused("invalid_pg_csrf", 403)
            headers = [(k, v) for k, v in headers if k.lower() != b"x-csrf-token"]
            headers.append((b"x-csrf-token", pg_csrf[0]))
        new_scope["headers"] = headers

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                headers = []
                session_count = 0
                upstream_name = (UPSTREAM_COOKIE + "=").encode("ascii")
                virtual_names = ((LEGACY_COOKIE + "=").encode("ascii"),
                                 (PG_COOKIE + "=").encode("ascii"))
                for key, value in message.get("headers", []):
                    if key.lower() == b"set-cookie":
                        # Only the proxy may mint virtualized store-cookie names.
                        if value.startswith(virtual_names):
                            raise CutoverRefused("upstream_cookie_namespace_collision", 503)
                        if value.startswith(upstream_name):
                            session_count += 1
                            if session_count > 1:
                                raise CutoverRefused("duplicate_upstream_session", 503)
                            attrs = {part.strip().lower() for part in value.split(b";")[1:]}
                            raw_value = value.split(b";", 1)[0].split(b"=", 1)[1]
                            is_delete = raw_value in (b"", b'""') and b"max-age=0" in attrs
                            if (b"path=/" not in attrs
                                    or any(part.startswith(b"domain=") for part in attrs)):
                                raise CutoverRefused("insecure_upstream_session", 503)
                            if is_delete:
                                # Keep the historical SQLite logout compatible,
                                # but never emit an unsafe __Host- deletion.
                                if b"secure" not in attrs:
                                    value += b"; Secure"
                                if b"httponly" not in attrs:
                                    value += b"; HttpOnly"
                            elif (b"secure" not in attrs or b"httponly" not in attrs
                                  or not ({b"samesite=lax", b"samesite=strict"} & attrs)
                                  or not _SESSION_TOKEN.fullmatch(raw_value.decode("latin1"))):
                                raise CutoverRefused("insecure_upstream_session", 503)
                            value = (cookie_name + "=").encode() + value[len(upstream_name):]
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
        # A merged GET reaches TWO independently authorized services. Forward
        # neither client-supplied credentials nor tenant/CSRF/proxy headers to
        # the other service; each receives only its own validated session cookie.
        headers = {"accept": "application/json"}
        path = scope["path"]
        try:
            qs = scope.get("query_string", b"").decode("ascii", "strict")
        except UnicodeError as exc:
            raise CutoverRefused("invalid_list_query_encoding", 400) from exc
        results = []
        for app, cookie in ((self.legacy_app, LEGACY_COOKIE), (self.pg_app, PG_COOKIE)):
            cookie_val = _safe_cookie(scope, cookie)
            h = {**headers, "cookie": f"{UPSTREAM_COOKIE}={cookie_val}"}
            try:
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="https://testserver", timeout=15
                ) as client:
                    response = await client.get(path+("?" + qs if qs else ""), headers=h)
            except httpx.RequestError as exc:
                # Never return only the successful store's records when the
                # other store cannot be reached; merged views are atomic.
                raise CutoverRefused("dual_home_listing_unavailable", 503) from exc
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
            if path.startswith("/api/pg-stage/cutover/legacy/"):
                if method != "GET":
                    raise CutoverRefused("method_not_allowed", 405)
                legacy_ident = await self._identity(scope, LEGACY_COOKIE, self.legacy_identity)
                if legacy_ident.org_id not in self.enabled_orgs():
                    raise CutoverRefused("pg_store_disabled_for_org")
                legacy_target = "/api/" + path[len("/api/pg-stage/cutover/legacy/"):]
                if legacy_target not in frozenset({
                    "/api/customers", "/api/quotes", "/api/orders",
                    "/api/invoices", "/api/audit", "/api/evidence/queue",
                    "/api/dashboard",
                }):
                    raise CutoverRefused("unsupported_legacy_read", 404)
                mapped_scope = {**scope, "path": legacy_target, "raw_path": legacy_target.encode("ascii")}
                return await self._forward(self.legacy_app, mapped_scope, receive, send,
                                           LEGACY_COOKIE)
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
