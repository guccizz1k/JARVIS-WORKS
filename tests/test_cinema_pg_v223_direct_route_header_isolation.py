"""Direct-route ASGI security: client authority must not cross backend trust boundaries.

Test the real CutoverFront with two independent FastAPI apps and separate
cookie issuers. No real accounts, network secrets, or customer data.
"""
import httpx
import pytest
from fastapi import FastAPI, Request

from app import pg_cinema_cutover_front_v223 as cut


L = "L" * 40
P = "P" * 40
G = "pg_" + "a" * 32

INJECTED = {
    "Authorization": "Bearer attacker",
    "Proxy-Authorization": "Basic attacker",
    "X-Api-Key": "attacker-key",
    "X-JW-Stage-Key": "fake-external-gateway-key",
    "X-Tenant-ID": "tenant-B",
    "X-Org-ID": "tenant-B",
    "X-Acting-User": "attacker",
    "X-User-ID": "attacker",
    "X-Real-IP": "127.0.0.1",
    "Forwarded": "for=127.0.0.1;host=attacker.invalid",
    "X-Forwarded-For": "127.0.0.1",
    "X-Forwarded-Host": "attacker.invalid",
    "X-Forwarded-Proto": "http",
    "X-Original-URL": "/api/admin",
    "X-Rewrite-URL": "/api/admin",
    "X-HTTP-Method-Override": "DELETE",
    "X-Method-Override": "DELETE",
}
DISALLOWED = {h.lower() for h in INJECTED}


def _harness():
    legacy, pg = FastAPI(), FastAPI()
    identities = []

    def l_identity(request: Request):
        identities.append(dict(request.headers))
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == L
        return cut.Identity("org-A", "actor-A", "admin")

    def p_identity(request: Request):
        identities.append(dict(request.headers))
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == P
        return cut.Identity("org-A", "actor-A", "admin")

    def reply(store, request):
        return {"store": store, "headers": dict(request.headers),
                "cookie": request.cookies.get(cut.UPSTREAM_COOKIE)}

    @legacy.get("/api/diagnostics")
    async def l_diagnostics(request: Request):
        return reply("legacy", request)

    @legacy.get("/api/quotes/{record_id}")
    async def l_get(record_id: str, request: Request):
        return reply("legacy", request)

    @pg.get("/api/pg-stage/v90/me")
    async def p_me(request: Request):
        return reply("pg", request)

    @pg.get("/api/quotes/{record_id}")
    async def p_get(record_id: str, request: Request):
        return reply("pg", request)

    @pg.post("/api/quotes")
    async def p_write(request: Request):
        return reply("pg", request)

    @legacy.post("/api/quotes/{record_id}/status")
    async def l_write(record_id: str, request: Request):
        return reply("legacy", request)

    front = cut.CutoverFront(legacy, pg, l_identity, p_identity,
                             lambda: frozenset({"org-A"}))
    return front, identities


def _assert_isolated(headers):
    assert not (DISALLOWED & set(headers)), DISALLOWED & set(headers)
    assert cut.LEGACY_COOKIE not in headers.get("cookie", "")
    assert cut.PG_COOKIE not in headers.get("cookie", "")


@pytest.mark.asyncio
@pytest.mark.parametrize("path,store", [
    ("/api/diagnostics", "legacy"),
    ("/api/quotes/legacy-document", "legacy"),
    ("/api/pg-stage/v90/me", "pg"),
    ("/api/quotes/" + G, "pg"),
])
async def test_direct_reads_remove_forged_authority_headers_before_backend(path, store):
    front, identities = _harness()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=front),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(cut.LEGACY_COOKIE, L)
        client.cookies.set(cut.PG_COOKIE, P)
        response = await client.get(path, headers=INJECTED)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["store"] == store
    assert payload["cookie"] == (L if store == "legacy" else P)
    _assert_isolated(payload["headers"])
    for seen in identities:
        _assert_isolated(seen)


@pytest.mark.asyncio
async def test_pg_write_keeps_only_pg_csrf_and_idempotency_key():
    front, identities = _harness()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=front),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(cut.LEGACY_COOKIE, L)
        client.cookies.set(cut.PG_COOKIE, P)
        response = await client.post("/api/quotes", json={"title": "Synthetic"},
                                     headers={
                                         **INJECTED,
                                         "X-CSRF-Token": "legacy-csrf",
                                         "X-JW-PG-CSRF": "pg-csrf-value-20261109",
                                         "Idempotency-Key": "repeat-key-1",
                                     })
    assert response.status_code == 200, response.text
    h = response.json()["headers"]
    assert h["x-csrf-token"] == "pg-csrf-value-20261109"
    assert h["idempotency-key"] == "repeat-key-1"
    assert h["content-type"] == "application/json"
    assert "x-jw-pg-csrf" not in h
    _assert_isolated(h)
    for seen in identities:
        _assert_isolated(seen)


@pytest.mark.asyncio
async def test_legacy_write_preserves_legacy_csrf_but_never_pg_csrf():
    front, identities = _harness()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=front),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(cut.LEGACY_COOKIE, L)
        client.cookies.set(cut.PG_COOKIE, P)
        response = await client.post("/api/quotes/legacy-document/status",
                                     json={"status": "draft"},
                                     headers={
                                         **INJECTED,
                                         "X-CSRF-Token": "legacy-csrf",
                                         "X-JW-PG-CSRF": "pg-csrf-value-20261109",
                                     })
    assert response.status_code == 200, response.text
    h = response.json()["headers"]
    assert h["x-csrf-token"] == "legacy-csrf"
    assert "x-jw-pg-csrf" not in h
    _assert_isolated(h)
    for seen in identities:
        _assert_isolated(seen)
