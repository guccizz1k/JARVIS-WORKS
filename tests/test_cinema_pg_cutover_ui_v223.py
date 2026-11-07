"""Cutover UI bridge and authenticated dual-store routing regressions.

Synthetic FastAPI apps only. No user data, real passwords or production DSN.
"""
from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request, Response

from app import pg_cinema_cutover_front_v223 as front
from app import pg_cinema_cutover_ui_v223 as ui
from app import cinema_entry_v1 as entry

L = "l"*40
P = "p"*40
G = "pg_"+"a"*32
STATE = {"enabled": False, "pg_org": "A"}


@pytest.fixture(autouse=True)
def clean():
    STATE.update(enabled=False, pg_org="A")


def make_app():
    legacy = FastAPI()
    pg = FastAPI()

    @legacy.post("/api/login")
    def l_login(response: Response):
        response.set_cookie(front.UPSTREAM_COOKIE, L, secure=True, httponly=True, path="/")
        return {"csrf_token": "legacy-csrf"}

    @pg.post("/api/pg-stage/v85/login")
    def p_login(response: Response):
        response.set_cookie(front.UPSTREAM_COOKIE, P, secure=True, httponly=True, path="/")
        return {"csrf_token": "pg-csrf-token-long"}

    @legacy.get("/api/quotes")
    def l_list(request: Request):
        assert request.cookies.get(front.UPSTREAM_COOKIE) == L
        return [{"id": "legacy-id", "title": "Legacy"}]

    @legacy.get("/api/dashboard")
    def l_dashboard():
        return {"source": "legacy-only", "count": 1}

    @pg.get("/api/quotes")
    def p_list():
        return [{"id": G, "title": "PG"}]

    @pg.post("/api/quotes")
    def p_write(request: Request):
        if request.headers.get("X-CSRF-Token") != "pg-csrf-token-long":
            raise HTTPException(403, "PG CSRF wrong")
        if request.headers.get("X-JW-PG-CSRF"):
            raise HTTPException(500, "PG CSRF leaked")
        return {"source": "pg"}

    @legacy.get("/api/audit")
    def audit():
        return []

    @legacy.post("/api/quotes/legacy-id")
    def l_write(request: Request):
        if request.headers.get("X-CSRF-Token") != "legacy-csrf":
            raise HTTPException(403, "legacy CSRF wrong")
        if request.headers.get("X-JW-PG-CSRF"):
            raise HTTPException(500, "PG CSRF leaked to legacy")
        return {"source": "legacy"}

    def l_identity(request):
        if request.cookies.get(front.UPSTREAM_COOKIE) != L:
            raise HTTPException(401, "legacy login needed")
        return front.Identity("A", "alice", "admin")

    def p_identity(request):
        if request.cookies.get(front.UPSTREAM_COOKIE) != P:
            raise HTTPException(401, "pg login needed")
        return front.Identity(STATE["pg_org"], "alice", "admin")

    return front.CutoverFront(legacy, pg, l_identity, p_identity,
                             lambda: frozenset({"A"} if STATE["enabled"] else set()))


async def sign_in(c):
    assert (await c.post("/api/login")).status_code == 200
    assert (await c.post("/api/pg-stage/v85/login")).status_code == 200


@pytest.mark.asyncio
async def test_status_requires_signed_in_legacy_and_never_leaks_org_id():
    STATE["enabled"] = True
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app()),
                                 base_url="https://testserver") as c:
        r = await c.get("/api/pg-stage/cutover/status")
        assert r.status_code == 401
        await sign_in(c)
        r = await c.get("/api/pg-stage/cutover/status")
        assert r.status_code == 200
        assert r.json() == {
            "cutover_available": True, "pg_required": True,
            "aggregate_status": "blocked_until_verified",
        }
        assert r.headers["cache-control"] == "no-store"
        assert (await c.post("/api/pg-stage/cutover/status")).status_code == 405


@pytest.mark.asyncio
async def test_status_off_never_demands_second_login():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app()),
                                 base_url="https://testserver") as c:
        await c.post("/api/login")
        r = await c.get("/api/pg-stage/cutover/status")
        assert r.status_code == 200
        assert r.json()["pg_required"] is False
        assert r.json()["aggregate_status"] == "legacy_only"


@pytest.mark.asyncio
async def test_cutover_verify_both_actors_orgs_roles_and_default_off():
    STATE["enabled"] = True
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app()),
                                 base_url="https://testserver") as c:
        await c.post("/api/login")
        assert (await c.get("/api/pg-stage/cutover/verify")).status_code == 401
        await c.post("/api/pg-stage/v85/login")
        assert (await c.get("/api/pg-stage/cutover/verify")).json() == {
            "identity_verified": True
        }
        STATE["pg_org"] = "B"
        r = await c.get("/api/pg-stage/cutover/verify")
        assert r.status_code == 403 and r.json()["code"] == "identity_mismatch"
        STATE["pg_org"] = "A"
        STATE["enabled"] = False
        assert (await c.get("/api/pg-stage/cutover/verify")).status_code == 409


@pytest.mark.asyncio
async def test_legacy_read_path_is_explicit_and_never_merge_or_edit():
    STATE["enabled"] = True
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app()),
                                 base_url="https://testserver") as c:
        await sign_in(c)
        path="/api/pg-stage/cutover/legacy/quotes"
        r = await c.get(path)
        assert r.status_code == 200
        assert r.json() == [{"id": "legacy-id", "title": "Legacy"}]
        assert (await c.get("/api/pg-stage/cutover/legacy/dashboard")).json()["source"] == "legacy-only"
        assert (await c.post(path)).status_code == 405
        assert (await c.get("/api/pg-stage/cutover/legacy/secret")).status_code == 404


@pytest.mark.asyncio
async def test_front_translates_only_pg_csrf_for_pg_trade():
    STATE["enabled"] = True
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app()),
                                 base_url="https://testserver") as c:
        await sign_in(c)
        r = await c.post("/api/quotes",json={"title":"PG"},headers={
            "X-CSRF-Token": "legacy-csrf",
            "X-JW-PG-CSRF": "pg-csrf-token-long",
        })
        assert r.status_code == 200 and r.json()["source"] == "pg"
        r = await c.post("/api/quotes/legacy-id", headers={
            "X-CSRF-Token": "legacy-csrf",
            "X-JW-PG-CSRF": "pg-csrf-token-long",
        })
        assert r.status_code == 200 and r.json()["source"] == "legacy"


@pytest.mark.asyncio
async def test_malformed_pg_csrf_is_denied_and_never_reaches_pg():
    STATE["enabled"] = True
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app()),
                                 base_url="https://testserver") as c:
        await sign_in(c)
        r = await c.post("/api/quotes",json={},headers={
            "X-CSRF-Token": "legacy-csrf", "X-JW-PG-CSRF": "short"
        })
        assert r.status_code == 403
        assert r.json()["code"] == "invalid_pg_csrf"


def test_ui_injection_is_default_off_and_guarded(monkeypatch):
    monkeypatch.delenv("JW_PG_CINEMA_CUTOVER_FRONT_V223",raising=False)
    monkeypatch.setenv("JW_ENV","test")
    assert ui.optional_bridge() == ""
    monkeypatch.setenv("JW_PG_CINEMA_CUTOVER_FRONT_V223",
                       "ISOLATED_DEV_DUAL_SESSION_PILOT")
    assert "cutover/status" in ui.optional_bridge()
    assert "통합 통계 검증 전" in ui.optional_bridge()
    monkeypatch.setenv("JW_ENV","production")
    assert ui.optional_bridge()==""
    monkeypatch.setenv("JW_ENV","test")
    monkeypatch.setenv("JW_INSECURE_LOCAL_DEV","1")
    assert ui.optional_bridge()==""


def test_cinema_original_html_is_not_modified_by_optional_bridge(monkeypatch):
    monkeypatch.setenv("JW_ENV","test")
    monkeypatch.delenv("JW_INSECURE_LOCAL_DEV",raising=False)
    monkeypatch.delenv("JW_PG_CINEMA_CUTOVER_FRONT_V223",raising=False)
    baseline = entry.cinema_main_response().body
    assert b"cutover/status" not in baseline
    monkeypatch.setenv("JW_PG_CINEMA_CUTOVER_FRONT_V223",
                       "ISOLATED_DEV_DUAL_SESSION_PILOT")
    opted = entry.cinema_main_response().body
    assert b"cutover/status" in opted
    assert b"Content-Security-Policy" not in opted
    assert len(opted)>len(baseline)
