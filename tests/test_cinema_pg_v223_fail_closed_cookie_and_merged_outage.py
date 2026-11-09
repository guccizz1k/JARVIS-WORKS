"""A-only fail-closed tests for ambiguous cookies and merged-list outages.

Run against the real CutoverFront with two isolated FastAPI ASGI stores.
No secrets, external network access, or production database.
"""
import httpx
import pytest
from fastapi import FastAPI, Request

from app import pg_cinema_cutover_front_v223 as cut

LEGACY = "L" * 40
POSTGRES = "P" * 40
PG_ID = "pg_" + "c" * 32


def make_front(*, pg_outage=False):
    legacy = FastAPI()
    postgres = FastAPI()
    state = {"legacy_calls": 0, "pg_calls": 0}

    @legacy.get("/api/diagnostics")
    async def legacy_diag(request: Request):
        state["legacy_calls"] += 1
        return {"ok": True, "cookie": request.cookies.get(cut.UPSTREAM_COOKIE)}

    @postgres.get("/api/pg-stage/v90/me")
    async def postgres_me(request: Request):
        state["pg_calls"] += 1
        return {"ok": True, "cookie": request.cookies.get(cut.UPSTREAM_COOKIE)}

    @legacy.get("/api/quotes")
    async def legacy_quotes(request: Request):
        state["legacy_calls"] += 1
        return [{"id": "legacy-quote"}]

    @postgres.get("/api/quotes")
    async def postgres_quotes(request: Request):
        state["pg_calls"] += 1
        if pg_outage:
            raise httpx.ReadTimeout("synthetic disconnected PG service")
        return [{"id": PG_ID}]

    def legacy_identity(request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == LEGACY
        return cut.Identity("org-A", "actor-A", "admin")

    def postgres_identity(request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == POSTGRES
        return cut.Identity("org-A", "actor-A", "admin")

    return cut.CutoverFront(
        legacy, postgres, legacy_identity, postgres_identity,
        lambda: frozenset({"org-A"})
    ), state


@pytest.mark.asyncio
@pytest.mark.parametrize("cookie_name,path,expected", [
    (cut.LEGACY_COOKIE, "/api/diagnostics", "legacy_calls"),
    (cut.PG_COOKIE, "/api/pg-stage/v90/me", "pg_calls"),
])
@pytest.mark.parametrize("separate_headers", [False, True])
async def test_duplicate_session_cookie_refused_before_backend(
    cookie_name, path, expected, separate_headers
):
    front, state = make_front()
    first = (cookie_name + "=" + "a" * 40).encode("ascii")
    second = (cookie_name + "=" + "b" * 40).encode("ascii")
    raw_cookie_headers = (
        [(b"cookie", first), (b"cookie", second)]
        if separate_headers
        else [(b"cookie", first + b"; " + second)]
    )
    # Direct ASGI to preserve duplicate Cookie headers exactly, bypassing
    # any client library normalization or cookie jar collision behavior.
    scope = {
        "type": "http", "http_version": "1.1", "method": "GET",
        "scheme": "https", "path": path,
        "query_string": b"", "headers": raw_cookie_headers,
        "server": ("testserver", 443), "client": ("127.0.0.1", 12345),
        "root_path": "",
    }
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await front(scope, receive, send)
    status = next(m for m in messages if m["type"] == "http.response.start")
    assert status["status"] == 401
    body = b"".join(m["body"] for m in messages if m["type"] == "http.response.body")
    assert b"duplicate_session_cookie" in body
    assert state[expected] == 0


@pytest.mark.asyncio
async def test_merged_list_timeout_fails_atomically_without_partial_legacy_response():
    front, state = make_front(pg_outage=True)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=front),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(cut.LEGACY_COOKIE, LEGACY)
        client.cookies.set(cut.PG_COOKIE, POSTGRES)
        response = await client.get("/api/quotes")
    assert state["legacy_calls"] == 1
    assert state["pg_calls"] == 1
    assert response.status_code == 503
    assert response.json() == {"code": "dual_home_listing_unavailable"}
    assert response.headers["cache-control"] == "no-store"
    assert "legacy-quote" not in response.text


@pytest.mark.asyncio
async def test_merged_list_rejects_non_ascii_raw_query_before_either_backend():
    front, state = make_front()
    scope = {
        "type": "http", "http_version": "1.1", "method": "GET",
        "scheme": "https", "path": "/api/quotes", "query_string": b"q=\xff",
        "headers": [
            (b"cookie", (
                cut.LEGACY_COOKIE + "=" + LEGACY + "; "
                + cut.PG_COOKIE + "=" + POSTGRES
            ).encode("ascii"))
        ],
        "server": ("testserver", 443), "client": ("127.0.0.1", 12345),
        "root_path": "",
    }
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await front(scope, receive, send)
    status = next(m for m in messages if m["type"] == "http.response.start")
    assert status["status"] == 400
    body = b"".join(m["body"] for m in messages if m["type"] == "http.response.body")
    assert b"invalid_list_query_encoding" in body
    assert state["legacy_calls"] == 0
    assert state["pg_calls"] == 0


@pytest.mark.asyncio
async def test_valid_dual_cookie_lists_still_merge_both_sources():
    front, state = make_front()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=front),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(cut.LEGACY_COOKIE, LEGACY)
        client.cookies.set(cut.PG_COOKIE, POSTGRES)
        response = await client.get("/api/quotes")
    assert response.status_code == 200
    assert response.json() == [
        {"id": "legacy-quote", "source": "legacy"},
        {"id": PG_ID, "source": "pg"},
    ]
    assert state == {"legacy_calls": 1, "pg_calls": 1}
