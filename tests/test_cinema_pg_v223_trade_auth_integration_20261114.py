"""Synthetic integrated ASGI security: V22.3 front -> real CINEMA trade router.

The production trade router must deny CSRF-less or cross-store requests BEFORE
reaching the SQL gateway. A dummy gateway records invocations; no DB/network.
"""
from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request

from app import pg_cinema_cutover_front_v223 as cut
from app.pg_cinema_trade_v1 import VerifiedSession, create_router


PG_TOKEN = "P" * 40
LEGACY_TOKEN = "L" * 40
PG_CSRF = "pg-csrf-isolated-token-20261114"
LEGACY_CSRF = "sqlite-csrf-isolated-token"
PARTNER_BODY = {"request_id": "req-20261114-0001", "name": "Synthetic Company"}


class IsolatedGateway:
    def __init__(self):
        self.calls = []

    def query(self, session_hash, sql, params):
        self.calls.append((session_hash, sql, params))
        return [{"result": {"ok": True, "source": "pg-only"}}]


def harness():
    legacy, pg = FastAPI(), FastAPI()
    gateway = IsolatedGateway()
    observed = []

    def authorize(request: Request) -> VerifiedSession:
        observed.append({
            "cookie": request.cookies.get(cut.UPSTREAM_COOKIE),
            "csrf": request.headers.get("x-csrf-token"),
            "legacy_cookie": request.cookies.get(cut.LEGACY_COOKIE),
            "pg_cookie": request.cookies.get(cut.PG_COOKIE),
            "pg_front_header": request.headers.get("x-jw-pg-csrf"),
            "attacker_authority": request.headers.get("authorization"),
        })
        if request.cookies.get(cut.UPSTREAM_COOKIE) != PG_TOKEN:
            raise HTTPException(401, "PG session required")
        return VerifiedSession("synthetic-session-hash-000001",
                               request.headers.get("x-csrf-token") == PG_CSRF)

    pg.include_router(create_router(gateway, authorize))
    front = cut.CutoverFront(
        legacy, pg,
        lambda req: cut.Identity("org-a", "actor-a", "admin"),
        lambda req: cut.Identity("org-a", "actor-a", "admin"),
        lambda: frozenset({"org-a"}),
    )
    return front, gateway, observed


@pytest.mark.asyncio
async def test_sqlite_only_csrf_cannot_commit_pg_write():
    front, db, observed = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=front),
                                 base_url="https://testserver") as client:
        client.cookies.set(cut.LEGACY_COOKIE, LEGACY_TOKEN)
        client.cookies.set(cut.PG_COOKIE, PG_TOKEN)
        r = await client.post("/api/pg-stage/cinema-trade/partners",
                              json=PARTNER_BODY,
                              headers={"X-CSRF-Token": LEGACY_CSRF})
    assert r.status_code == 403 and not db.calls
    assert observed[0]["csrf"] is None


@pytest.mark.asyncio
async def test_pg_specific_csrf_only_reaches_pg_trade_gateway():
    front, db, observed = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=front),
                                 base_url="https://testserver") as client:
        client.cookies.set(cut.LEGACY_COOKIE, LEGACY_TOKEN)
        client.cookies.set(cut.PG_COOKIE, PG_TOKEN)
        r = await client.post("/api/pg-stage/cinema-trade/partners",
                              json=PARTNER_BODY,
                              headers={"X-CSRF-Token": LEGACY_CSRF,
                                       "X-JW-PG-CSRF": PG_CSRF,
                                       "Authorization": "Bearer forged"})
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "source": "pg-only"}
    assert len(db.calls) == 1
    assert observed == [{
        "cookie": PG_TOKEN, "csrf": PG_CSRF,
        "legacy_cookie": None, "pg_cookie": None,
        "pg_front_header": None, "attacker_authority": None,
    }]


@pytest.mark.asyncio
async def test_wrong_pg_csrf_denied_before_sql_gateway():
    front, db, _ = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=front),
                                 base_url="https://testserver") as client:
        client.cookies.set(cut.PG_COOKIE, PG_TOKEN)
        r = await client.post("/api/pg-stage/cinema-trade/partners",
                              json=PARTNER_BODY,
                              headers={"X-JW-PG-CSRF": "wrong-pg-csrf-token-value"})
    assert r.status_code == 403 and not db.calls


@pytest.mark.asyncio
async def test_duplicate_pg_csrf_headers_denied_before_sql_gateway():
    front, db, _ = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=front),
                                 base_url="https://testserver") as client:
        client.cookies.set(cut.PG_COOKIE, PG_TOKEN)
        r = await client.post("/api/pg-stage/cinema-trade/partners",
                              json=PARTNER_BODY,
                              headers=[("X-JW-PG-CSRF", PG_CSRF),
                                       ("X-JW-PG-CSRF", PG_CSRF)])
    assert r.status_code == 403 and r.json()["code"] == "invalid_pg_csrf"
    assert not db.calls


@pytest.mark.asyncio
async def test_missing_pg_session_denied_even_with_pg_csrf():
    front, db, _ = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=front),
                                 base_url="https://testserver") as client:
        client.cookies.set(cut.LEGACY_COOKIE, LEGACY_TOKEN)
        r = await client.post("/api/pg-stage/cinema-trade/partners",
                              json=PARTNER_BODY, headers={"X-JW-PG-CSRF": PG_CSRF})
    assert r.status_code == 401 and not db.calls


@pytest.mark.asyncio
async def test_illegal_pg_csrf_bytes_denied_before_sql_gateway():
    front, db, _ = harness()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=front),
                                 base_url="https://testserver") as client:
        client.cookies.set(cut.PG_COOKIE, PG_TOKEN)
        r = await client.post("/api/pg-stage/cinema-trade/partners",
                              json=PARTNER_BODY, headers={"X-JW-PG-CSRF": "short"})
    assert r.status_code == 403 and r.json()["code"] == "invalid_pg_csrf"
    assert not db.calls
