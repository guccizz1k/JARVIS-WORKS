"""Fail-closed response-cookie boundary for the dual-store V22.3 preview.

All requests use two isolated FastAPI ASGI apps; no external secrets or real DB.
"""
import httpx
import pytest
from fastapi import FastAPI
from starlette.responses import Response

from app import pg_cinema_cutover_front_v223 as cut

TOKEN = "S" * 48
NAME = cut.UPSTREAM_COOKIE


def make_front(set_cookie_values):
    legacy, pg = FastAPI(), FastAPI()

    def result():
        response = Response(status_code=200)
        for value in set_cookie_values:
            response.raw_headers.append((b"set-cookie", value.encode("ascii")))
        return response

    @legacy.post("/api/login")
    async def legacy_login():
        return result()

    @pg.post("/api/pg-stage/v85/login")
    async def pg_login():
        return result()

    return cut.CutoverFront(
        legacy, pg,
        lambda request: cut.Identity("org-A", "actor-A", "admin"),
        lambda request: cut.Identity("org-A", "actor-A", "admin"),
        lambda: frozenset({"org-A"}),
    )


def session(value=TOKEN, attrs="Path=/; Secure; HttpOnly; SameSite=Strict"):
    return f"{NAME}={value}; {attrs}"


async def request(front, store):
    path = "/api/login" if store == "legacy" else "/api/pg-stage/v85/login"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=front),
        base_url="https://testserver",
    ) as client:
        response = await client.post(path)
        saved = list(client.cookies.items())
        return response, saved


@pytest.mark.asyncio
@pytest.mark.parametrize("store", ["legacy", "pg"])
@pytest.mark.parametrize("bad", [
    session(attrs="Path=/; Secure; SameSite=Strict"),  # script-accessible token
    session(attrs="Path=/; Secure; HttpOnly"),  # no same-site policy
    session(attrs="Path=/; Secure; HttpOnly; SameSite=None"),
    session(attrs="Path=/; HttpOnly; SameSite=Strict"),  # insecure mint
    session(attrs="Path=/login; Secure; HttpOnly; SameSite=Strict"),
    session(attrs="Path=/; Domain=evil.invalid; Secure; HttpOnly; SameSite=Strict"),
    session(value="too-short"),
])
async def test_insecure_new_session_refused_before_emitting_cookie(store, bad):
    response, saved = await request(make_front([bad]), store)
    assert response.status_code == 503
    assert response.json() == {"code": "insecure_upstream_session"}
    assert not saved
    assert "set-cookie" not in response.headers


@pytest.mark.asyncio
@pytest.mark.parametrize("store", ["legacy", "pg"])
async def test_duplicate_session_issue_refused_before_emitting_cookie(store):
    response, saved = await request(make_front([
        session(value="A" * 48), session(value="B" * 48)
    ]), store)
    assert response.status_code == 503
    assert response.json() == {"code": "duplicate_upstream_session"}
    assert not saved


@pytest.mark.asyncio
@pytest.mark.parametrize("store", ["legacy", "pg"])
@pytest.mark.parametrize("forged_name", [cut.LEGACY_COOKIE, cut.PG_COOKIE])
async def test_backend_cannot_issue_proxy_owned_cookie_names(store, forged_name):
    injected = f"{forged_name}={'E' * 48}; Path=/; Secure; HttpOnly; SameSite=Strict"
    response, saved = await request(make_front([session(), injected]), store)
    assert response.status_code == 503
    assert response.json() == {"code": "upstream_cookie_namespace_collision"}
    assert not saved


@pytest.mark.asyncio
@pytest.mark.parametrize("store", ["legacy", "pg"])
@pytest.mark.parametrize("same_site", ["Lax", "Strict"])
async def test_valid_http_only_cookie_rewritten_to_only_its_store(store, same_site):
    response, saved = await request(
        make_front([session(attrs=f"Path=/; Secure; HttpOnly; SameSite={same_site}")]), store
    )
    expected = cut.LEGACY_COOKIE if store == "legacy" else cut.PG_COOKIE
    assert response.status_code == 200
    assert saved == [(expected, TOKEN)]
    raw = response.headers.get_list("set-cookie")
    assert len(raw) == 1
    assert raw[0].startswith(expected + "=")
    assert cut.UPSTREAM_COOKIE not in raw[0]
    assert all(word in raw[0].lower() for word in ("secure", "httponly", "samesite="))


@pytest.mark.asyncio
@pytest.mark.parametrize("store", ["legacy", "pg"])
async def test_historical_insecure_legacy_deletion_is_normalized(store):
    response, saved = await request(make_front([
        f"{NAME}=; Max-Age=0; Path=/; SameSite=Lax"
    ]), store)
    assert response.status_code == 200
    assert saved == []
    raw = response.headers.get("set-cookie", "").lower()
    assert "secure" in raw and "httponly" in raw
    expected = cut.LEGACY_COOKIE if store == "legacy" else cut.PG_COOKIE
    assert raw.startswith(expected.lower() + "=")
