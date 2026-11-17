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


@pytest.mark.parametrize("source,identifier", [
    ("legacy", "legacy-1"),
    ("pg", PG_RECORD),
])
def test_repeated_upstream_id_is_never_silently_doubled(source, identifier):
    rows = [{"id": identifier, "amount": 100}, {"id": identifier, "amount": 100}]
    with pytest.raises(cut.CutoverRefused) as failure:
        cut._source_tagged(rows, source)
    assert failure.value.code == "duplicate_list_record_id"
    assert failure.value.status == 503


def test_distinct_upstream_rows_preserve_order_and_authoritative_source():
    rows = [{"id": PG_RECORD, "source": "untrusted", "amount": 100},
            {"id": "pg_" + "b" * 32, "amount": 200}]
    assert cut._source_tagged(rows, "pg") == [
        {"id": PG_RECORD, "source": "pg", "amount": 100},
        {"id": "pg_" + "b" * 32, "source": "pg", "amount": 200},
    ]


@pytest.mark.asyncio
async def test_duplicate_pg_list_is_atomic_503_without_legacy_leak():
    legacy, pg = FastAPI(), FastAPI()
    calls = {"legacy": 0, "pg": 0}

    @legacy.get("/api/quotes")
    async def legacy_quotes():
        calls["legacy"] += 1
        return [{"id": "legacy-1", "amount": 500}]

    @pg.get("/api/quotes")
    async def pg_quotes():
        calls["pg"] += 1
        return [{"id": PG_RECORD, "amount": 100},
                {"id": PG_RECORD, "amount": 100}]

    def legacy_identity(request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == LEGACY_TOKEN
        return cut.Identity("org-A", "user-A", "admin")

    def pg_identity(request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == PG_TOKEN
        return cut.Identity("org-A", "user-A", "admin")

    app = cut.CutoverFront(legacy, pg, legacy_identity, pg_identity,
                           lambda: frozenset({"org-A"}))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(cut.LEGACY_COOKIE, LEGACY_TOKEN)
        client.cookies.set(cut.PG_COOKIE, PG_TOKEN)
        response = await client.get("/api/quotes")
    assert calls == {"legacy": 1, "pg": 1}
    assert response.status_code == 503
    assert response.json() == {"code": "duplicate_list_record_id"}
    assert response.headers["cache-control"] == "no-store"
    assert "legacy-1" not in response.text
