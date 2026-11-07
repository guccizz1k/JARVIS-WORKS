"""V22.3: dual cookie logout across isolated PG and SQLite sessions.

All endpoints are synthetic; assertions check actual ASGI response cookies,
CSRF failures, partial revocation and inability to silently leave a session.
"""
import httpx
import pytest
from fastapi import FastAPI, Request, Response, HTTPException
from app import pg_cinema_cutover_front_v223 as cut

LEGACY_TOKEN = "l" * 40
PG_TOKEN = "p" * 40
LEGACY_CSRF = "csrf-legacy-v223"
PG_CSRF = "csrf-pg-v223"


def harness(pg_ok=True, legacy_ok=True, insecure_issuance=False, pg_reply_ok=True):
    state = {"legacy_valid": True, "pg_valid": True,
             "pg_revocations": 0, "legacy_revocations": 0}
    legacy = FastAPI()
    pg = FastAPI()

    @legacy.post("/api/login")
    def sqlite_login(response: Response):
        response.set_cookie(cut.UPSTREAM_COOKIE, LEGACY_TOKEN,
                            secure=not insecure_issuance, httponly=True,
                            path="/", samesite="strict")
        return {"ok": True}

    @pg.post("/api/pg-stage/v85/login")
    def pg_login(response: Response):
        response.set_cookie(cut.UPSTREAM_COOKIE, PG_TOKEN,
                            secure=True, httponly=True, path="/", samesite="strict")
        return {"ok": True}

    @legacy.post("/api/logout")
    def sqlite_logout(request: Request, response: Response):
        if (not legacy_ok or request.cookies.get(cut.UPSTREAM_COOKIE) != LEGACY_TOKEN
                or request.headers.get("X-CSRF-Token") != LEGACY_CSRF
                or not state["legacy_valid"]):
            raise HTTPException(403, "SQLite CSRF or session denied")
        state["legacy_valid"] = False
        state["legacy_revocations"] += 1
        # Exactly like the protected app/main.py legacy logout: no Secure.
        response.delete_cookie(cut.UPSTREAM_COOKIE, path="/")
        return {"ok": True}

    @pg.post("/api/pg-stage/v85/logout")
    def pg_logout(request: Request, response: Response):
        if (not pg_ok or request.cookies.get(cut.UPSTREAM_COOKIE) != PG_TOKEN
                or request.headers.get("X-CSRF-Token") != PG_CSRF
                or not state["pg_valid"]):
            raise HTTPException(403, "PG CSRF or session denied")
        if not pg_reply_ok:
            return {"ok": False}
        state["pg_valid"] = False
        state["pg_revocations"] += 1
        response.delete_cookie(cut.UPSTREAM_COOKIE, path="/",
                               secure=True, httponly=True, samesite="strict")
        return {"ok": True}

    def sqlite_identity(_):
        return cut.Identity("tenant-A", "actor-A", "admin")

    def pg_identity(_):
        return cut.Identity("tenant-A", "actor-A", "admin")

    app = cut.CutoverFront(legacy, pg, sqlite_identity, pg_identity,
                           lambda: frozenset({"tenant-A"}))
    return app, state


async def login_both(client):
    assert (await client.post("/api/login")).status_code == 200
    assert (await client.post("/api/pg-stage/v85/login")).status_code == 200
    assert cut.LEGACY_COOKIE in client.cookies
    assert cut.PG_COOKIE in client.cookies
    assert cut.UPSTREAM_COOKIE not in client.cookies


def cookies(client):
    return (cut.LEGACY_COOKIE in client.cookies, cut.PG_COOKIE in client.cookies)


@pytest.mark.asyncio
async def test_dual_logout_revokes_both_and_clears_both_secure_cookies():
    app, st = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="https://testserver") as c:
        await login_both(c)
        r = await c.post("/api/logout",
                         headers={"X-CSRF-Token": LEGACY_CSRF, "X-JW-PG-CSRF": PG_CSRF})
        assert r.status_code == 200 and r.json() == {"ok": True}
        assert cookies(c) == (False, False)
        assert st["pg_revocations"] == st["legacy_revocations"] == 1
        assert all(b"secure" in v.lower() for k, v in r.headers.raw if k.lower() == b"set-cookie")
        assert len(r.headers.get_list("set-cookie")) == 2
        assert r.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_pg_cookie_needs_independent_pg_csrf_not_legacy_token():
    app, st = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="https://testserver") as c:
        await login_both(c)
        r = await c.post("/api/logout", headers={"X-CSRF-Token": LEGACY_CSRF})
        assert r.status_code == 409 and r.json()["code"] == "pg_logout_required_first"
        assert cookies(c) == (True, True)
        assert st["pg_revocations"] == st["legacy_revocations"] == 0


@pytest.mark.asyncio
async def test_pg_logout_invalid_csrf_never_revokes_sqlite():
    app, st = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="https://testserver") as c:
        await login_both(c)
        r = await c.post("/api/logout",
                         headers={"X-CSRF-Token": LEGACY_CSRF, "X-JW-PG-CSRF": "wrong"})
        assert r.status_code == 403 and r.json()["code"] == "pg_logout_denied"
        assert cookies(c) == (True, True)
        assert st["pg_revocations"] == st["legacy_revocations"] == 0


@pytest.mark.asyncio
async def test_partial_failure_clears_pg_only_then_sqlite_retry():
    app, st = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="https://testserver") as c:
        await login_both(c)
        r = await c.post("/api/logout",
                         headers={"X-CSRF-Token": "bad", "X-JW-PG-CSRF": PG_CSRF})
        assert r.status_code == 409 and r.json()["code"] == "partial_logout_legacy_pending"
        assert cookies(c) == (True, False)
        assert st["pg_revocations"] == 1 and st["legacy_revocations"] == 0
        r2 = await c.post("/api/logout", headers={"X-CSRF-Token": LEGACY_CSRF})
        assert r2.status_code == 200 and r2.json() == {"ok": True}
        assert cookies(c) == (False, False)
        assert st["pg_revocations"] == 1 and st["legacy_revocations"] == 1
        assert any(b"secure" in v.lower() for k, v in r2.headers.raw
                   if k.lower() == b"set-cookie")


@pytest.mark.asyncio
async def test_only_sqlite_cookie_logout_normalizes_nonsecure_deletion():
    app, st = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="https://testserver") as c:
        assert (await c.post("/api/login")).status_code == 200
        r = await c.post("/api/logout", headers={"X-CSRF-Token": LEGACY_CSRF})
        assert r.status_code == 200
        assert cut.LEGACY_COOKIE not in c.cookies
        assert st["legacy_revocations"] == 1
        assert b"secure" in r.headers.get("set-cookie").lower().encode()


@pytest.mark.asyncio
async def test_spoofed_origin_rejected_before_either_logout():
    app, st = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="https://testserver") as c:
        await login_both(c)
        r = await c.post("/api/logout",
                         headers={"X-CSRF-Token": LEGACY_CSRF, "X-JW-PG-CSRF": PG_CSRF,
                                  "Origin": "https://evil.example"})
        assert r.status_code == 403 and r.json()["code"] == "cross_site_logout_denied"
        assert cookies(c) == (True, True)
        assert st["pg_revocations"] == st["legacy_revocations"] == 0


@pytest.mark.asyncio
async def test_pg_claims_success_false_blocks_legacy_logout():
    app, st = harness(pg_reply_ok=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="https://testserver") as c:
        await login_both(c)
        r = await c.post("/api/logout",
                         headers={"X-CSRF-Token": LEGACY_CSRF, "X-JW-PG-CSRF": PG_CSRF})
        assert r.status_code == 503 and r.json()["code"] == "pg_logout_unverified"
        assert cookies(c) == (True, True)
        assert st["pg_revocations"] == st["legacy_revocations"] == 0


@pytest.mark.asyncio
async def test_insecure_upstream_session_issuance_still_denied():
    app, st = harness(insecure_issuance=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="https://testserver") as c:
        r = await c.post("/api/login")
        assert r.status_code == 503 and r.json()["code"] == "insecure_upstream_session"
        assert cookies(c) == (False, False)
        assert st["pg_revocations"] == st["legacy_revocations"] == 0


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.asyncio
async def test_safe_http_methods_never_revoke_both_sessions(method):
    app, st = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="https://testserver") as c:
        await login_both(c)
        r = await c.request(method, "/api/logout", headers={
            "X-CSRF-Token": LEGACY_CSRF, "X-JW-PG-CSRF": PG_CSRF
        })
        assert r.status_code == 405
        assert cookies(c) == (True, True)
        assert st["pg_revocations"] == st["legacy_revocations"] == 0
