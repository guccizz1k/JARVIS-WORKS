"""Standalone, synthetic ASGI security checks for the V22.3 cutover front.

Intentionally does not access actual SQLite user data or Supabase credentials.
"""
import httpx
import pytest
from fastapi import FastAPI, Request, Response
from app import pg_cinema_cutover_front_v223 as cut

L = "L" * 40
P = "P" * 40
G = "pg_" + "a" * 32
GG = "pg_" + "b" * 32
SWITCH = {"on": set()}
SESS = {"pg_actor": "alice", "pg_org": "org-A", "pg_role": "admin"}


def make_apps():
    legacy = FastAPI()
    pg = FastAPI()

    @legacy.post("/api/login")
    def login(response: Response):
        response.set_cookie(cut.UPSTREAM_COOKIE, L, secure=True, httponly=True, path="/")
        return {"backend": "legacy"}

    @pg.post("/api/pg-stage/v85/login")
    def pglogin(response: Response):
        response.set_cookie(cut.UPSTREAM_COOKIE, P, secure=True, httponly=True, path="/")
        return {"backend": "pg"}

    @legacy.get("/api/quotes")
    def legacy_list(request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == L
        return [{"id": "legacy-1", "title": "Legacy"}]

    @pg.get("/api/quotes")
    def pg_list(request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == P
        return [{"id": G, "title": "PG"}]

    @legacy.post("/api/quotes")
    def legacy_write(request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == L
        return {"backend": "legacy"}

    @pg.post("/api/quotes")
    def pg_write(request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == P
        return {"backend": "pg"}

    @legacy.get("/api/quotes/{the_id}")
    def legacy_get(the_id: str, request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == L
        return {"id": the_id, "backend": "legacy"}

    @pg.get("/api/quotes/{the_id}")
    def pg_get(the_id: str, request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == P
        return {"id": the_id, "backend": "pg"}

    @legacy.post("/api/orders/from-quote")
    async def legacy_order(request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == L
        return {"backend": "legacy", "json": await request.json()}

    @pg.post("/api/orders/from-quote")
    async def pg_order(request: Request):
        assert request.cookies.get(cut.UPSTREAM_COOKIE) == P
        return {"backend": "pg", "json": await request.json()}

    @pg.get("/api/pg-stage/v90/me")
    def pgme(request: Request):
        return {"cookie": request.cookies.get(cut.UPSTREAM_COOKIE)}

    def legacy_id(req):
        if req.cookies.get(cut.UPSTREAM_COOKIE) != L:
            raise cut.CutoverRefused("missing_legacy", 401)
        return cut.Identity("org-A", "alice", "admin")

    def pg_id(req):
        if req.cookies.get(cut.UPSTREAM_COOKIE) != P:
            raise cut.CutoverRefused("missing_pg", 401)
        return cut.Identity(SESS["pg_org"], SESS["pg_actor"], SESS["pg_role"])

    return cut.CutoverFront(legacy, pg, legacy_id, pg_id,
                            lambda: frozenset(SWITCH["on"]))


@pytest.fixture(autouse=True)
def reset_state():
    SWITCH["on"] = set()
    SESS.update(pg_actor="alice", pg_org="org-A", pg_role="admin")


async def ready(client):
    assert (await client.post("/api/login")).status_code == 200
    assert cut.LEGACY_COOKIE in client.cookies
    assert (await client.post("/api/pg-stage/v85/login")).status_code == 200
    assert cut.PG_COOKIE in client.cookies
    assert cut.UPSTREAM_COOKIE not in client.cookies


@pytest.mark.asyncio
async def test_default_off_keeps_legacy_and_rejects_raw_cookie():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=make_apps()), base_url="https://testserver"
    ) as c:
        await ready(c)
        r = await c.post("/api/quotes")
        assert r.status_code == 200 and r.json()["backend"] == "legacy"
        assert (await c.get("/api/quotes")).json() == [
            {"id": "legacy-1", "title": "Legacy"}
        ]
        r = await c.get("/api/quotes", headers={"cookie": cut.UPSTREAM_COOKIE + "=stolen"})
        assert r.status_code == 401 and r.json()["code"] == "old_session_relogin_required"


@pytest.mark.asyncio
async def test_verified_pg_route_and_both_home_lists():
    SWITCH["on"] = {"org-A"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=make_apps()), base_url="https://testserver"
    ) as c:
        await ready(c)
        r = await c.post("/api/quotes")
        assert r.status_code == 200 and r.json()["backend"] == "pg"
        r = await c.get("/api/quotes/" + G)
        assert r.status_code == 200 and r.json()["backend"] == "pg"
        r = await c.get("/api/quotes/legacy-1")
        assert r.status_code == 200 and r.json()["backend"] == "legacy"
        r = await c.get("/api/quotes")
        assert r.status_code == 200
        assert r.json() == [
            {"id": "legacy-1", "title": "Legacy", "source": "legacy"},
            {"id": G, "title": "PG", "source": "pg"},
        ]
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["x-frame-options"] == "DENY"
        r = await c.post("/api/orders/from-quote",
                         json={"quote_id": G, "due_date": "2026-12-12"})
        assert r.status_code == 200 and r.json()["backend"] == "pg"
        r = await c.post("/api/orders/from-quote", json={"quote_id": "legacy-1"})
        assert r.status_code == 200 and r.json()["backend"] == "legacy"
        assert (await c.get("/api/pg-stage/v90/me")).json()["cookie"] == P


@pytest.mark.asyncio
async def test_wrong_org_actor_and_role_never_reach_pg():
    SWITCH["on"] = {"org-A"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=make_apps()), base_url="https://testserver"
    ) as c:
        await ready(c)
        SESS["pg_org"] = "org-B"
        r = await c.post("/api/quotes")
        assert r.status_code == 403 and r.json()["code"] == "identity_mismatch"
        SESS["pg_org"] = "org-A"
        SESS["pg_actor"] = "mallory"
        assert (await c.get("/api/quotes")).status_code == 403
        SESS["pg_actor"] = "alice"
        SESS["pg_role"] = "member"
        assert (await c.get("/api/quotes/" + G)).status_code == 403


@pytest.mark.asyncio
async def test_malformed_pg_ids_and_body_fail_closed():
    SWITCH["on"] = {"org-A"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=make_apps()), base_url="https://testserver"
    ) as c:
        await ready(c)
        r = await c.get("/api/quotes/pg_bad")
        assert r.status_code == 422 and r.json()["code"] == "malformed_pg_id"
        r = await c.post("/api/orders/from-quote", content=b"{xxx",
                         headers={"content-type": "application/json"})
        assert r.status_code == 422
        r = await c.post("/api/orders/from-quote", json={"quote_id": 42})
        assert r.status_code == 422
        assert (await c.get("/api/automation/statements/pg_" + "1"*32)).status_code == 409


@pytest.mark.asyncio
async def test_pg_requires_second_login_and_http_denied():
    SWITCH["on"] = {"org-A"}
    app = make_apps()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://testserver"
    ) as c:
        await c.post("/api/login")
        r = await c.post("/api/quotes")
        assert r.status_code == 401 and r.json()["code"] == "reauthentication_required"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        r = await c.get("/api/quotes")
        assert r.status_code == 403 and r.json()["code"] == "https_required"


@pytest.mark.parametrize("first,second", [
    (G, "legacy-1"), ("legacy-1", GG)
])
def test_mixed_payment_ids_rejected(first, second):
    with pytest.raises(cut.CutoverRefused) as exc:
        cut.route_home(f"/api/invoices/{first}/payments/{second}/reverse", "POST")
    assert exc.value.code == "cross_store_reference"


def test_factory_gate_defaults_off():
    assert cut.FRONT_FLAG == "JW_PG_CINEMA_CUTOVER_FRONT_V223"
    assert cut.parse_home(G) == "pg"
    assert cut.parse_home("legacy-1") == "legacy"


@pytest.mark.asyncio
async def test_logout_requires_pg_revoke_first():
    SWITCH["on"] = {"org-A"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=make_apps()), base_url="https://testserver"
    ) as c:
        await ready(c)
        r = await c.post("/api/logout")
        assert r.status_code == 409 and r.json()["code"] == "pg_logout_required_first"


@pytest.mark.asyncio
async def test_mixed_aggregate_denied_when_pg_org_enabled():
    SWITCH["on"] = {"org-A"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=make_apps()), base_url="https://testserver"
    ) as c:
        await ready(c)
        for path in ("/api/dashboard", "/api/order-analytics"):
            r = await c.get(path)
            assert r.status_code == 409
            assert r.json()["code"] == "cross_store_aggregate_not_available"


@pytest.mark.asyncio
async def test_disabled_pg_document_refuses_instead_of_legacy_lookup():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=make_apps()), base_url="https://testserver"
    ) as c:
        await c.post("/api/login")
        r = await c.get("/api/quotes/" + G)
        assert r.status_code == 409 and r.json()["code"] == "pg_store_disabled_for_org"
        assert (await c.get("/api/quotes/pg_invalid")).status_code == 422


@pytest.mark.asyncio
async def test_cookie_isolation_on_pg_login_and_native_pg_route():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=make_apps()), base_url="https://testserver"
    ) as c:
        assert (await c.post("/api/pg-stage/v85/login")).status_code == 200
        assert cut.PG_COOKIE in c.cookies and cut.UPSTREAM_COOKIE not in c.cookies
        assert cut.LEGACY_COOKIE not in c.cookies
        assert (await c.get("/api/pg-stage/v90/me")).json()["cookie"] == P


def test_factory_blocks_without_importing_backends(monkeypatch):
    monkeypatch.delenv(cut.FRONT_FLAG, raising=False)
    monkeypatch.setenv("JW_ENV", "test")
    with pytest.raises(RuntimeError, match="BLOCKED: cutover pilot"):
        cut.create_app()
