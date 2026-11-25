"""Review-only tests for dual-store list proxy credential/header isolation.

The front must not forward client-supplied authorization, tenant or CSRF headers
to both distinct backends. Both stores must still receive their own cookie,
query string and correct merged document attribution.
"""
from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI, Request

from app import pg_cinema_cutover_front_v223 as cut

LEGACY_TOKEN = "L" * 40
PG_TOKEN = "P" * 40
PG_RECORD = "pg_" + "a" * 32

SENSITIVE_HEADERS = {
    "Authorization": "Bearer synthetic-not-a-real-credential",
    "Proxy-Authorization": "Basic synthetic",
    "X-Api-Key": "synthetic-api-key",
    "X-CSRF-Token": "synthetic-legacy-csrf",
    "X-JW-PG-CSRF": "synthetic-pg-csrf",
    "X-Tenant-ID": "other-org",
    "X-Org-ID": "other-org",
    "X-Forwarded-Host": "untrusted.invalid",
    "X-Forwarded-Proto": "http",
}


@pytest.mark.asyncio
async def test_merge_passes_only_own_cookie_and_safe_accept_header():
    captured = []
    legacy, pg = FastAPI(), FastAPI()

    @legacy.get("/api/quotes")
    async def legacy_quotes(request: Request):
        captured.append(("legacy", dict(request.headers), request.url.query))
        return [{"id": "legacy-1", "source": "untrusted-data"}]

    @pg.get("/api/quotes")
    async def pg_quotes(request: Request):
        captured.append(("pg", dict(request.headers), request.url.query))
        return [{"id": PG_RECORD, "source": "untrusted-data"}]

    def legacy_user(request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == LEGACY_TOKEN
        return cut.Identity("org-A", "user-A", "admin")

    def pg_user(request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == PG_TOKEN
        return cut.Identity("org-A", "user-A", "admin")

    app = cut.CutoverFront(legacy, pg, legacy_user, pg_user,
                           lambda: frozenset({"org-A"}))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(cut.LEGACY_COOKIE, LEGACY_TOKEN)
        client.cookies.set(cut.PG_COOKIE, PG_TOKEN)
        response = await client.get("/api/quotes?limit=7&sort=created",
                                    headers=SENSITIVE_HEADERS)

    assert response.status_code == 200, response.text
    assert response.json() == [
        {"id": "legacy-1", "source": "legacy"},
        {"id": PG_RECORD, "source": "pg"},
    ]
    assert len(captured) == 2
    for store, headers, query in captured:
        assert query == "limit=7&sort=created"
        assert headers.get("accept") == "application/json"
        token = LEGACY_TOKEN if store == "legacy" else PG_TOKEN
        assert headers.get("cookie") == f"{cut.UPSTREAM_COOKIE}={token}"
        for name in SENSITIVE_HEADERS:
            assert name.lower() not in headers, (store, name)
        assert cut.LEGACY_COOKIE not in headers.get("cookie", "")
        assert cut.PG_COOKIE not in headers.get("cookie", "")
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_merge_rejects_unexpected_source_ids_before_responding():
    legacy, pg = FastAPI(), FastAPI()

    @legacy.get("/api/quotes")
    async def legacy_quotes():
        return [{"id": "legacy-1"}]

    @pg.get("/api/quotes")
    async def pg_quotes():
        return [{"id": "non_pg_record"}]

    def legacy_user(request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == LEGACY_TOKEN
        return cut.Identity("org-A", "user-A", "admin")

    def pg_user(request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == PG_TOKEN
        return cut.Identity("org-A", "user-A", "admin")

    app = cut.CutoverFront(legacy, pg, legacy_user, pg_user,
                           lambda: frozenset({"org-A"}))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(cut.LEGACY_COOKIE, LEGACY_TOKEN)
        client.cookies.set(cut.PG_COOKIE, PG_TOKEN)
        response = await client.get("/api/quotes")
    assert response.status_code == 503
    assert response.json()["code"] == "invalid_pg_record_home"
