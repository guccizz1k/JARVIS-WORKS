"""Actual ASGI front boundary; no external database or original UI changes."""
import os
from unittest.mock import patch
import httpx
import pytest
from fastapi import FastAPI,Request
from app import naruv_v223_read_bridge as bridge
from app import pg_cinema_cutover_front_v223 as cut
from tests.test_naruv_integrated_review import FLAGS

A=cut.Identity("org-A","actor-A","admin")
L="L"*40;P="P"*40;CSRF="C"*40
PATH=bridge.PREFIX+"/valuation/overview"
ENV={**FLAGS,bridge.FLAG:bridge.ACK,"NARUV_DRAFT_REVIEW":"ISOLATED_SYNTHETIC_ONLY","NARUV_HR_REVIEW":"ISOLATED_SYNTHETIC_ONLY"}

def front(pg=A,legacy=A,orgs=frozenset(("org-A",))):
    legacy_app=FastAPI();pg_app=FastAPI();erp=FastAPI()
    calls=[]
    @legacy_app.get("/")
    def home():return {"legacy":True}
    @erp.post(PATH)
    def overview(request:Request):
        calls.append(dict(request.headers))
        if request.cookies.get(cut.UPSTREAM_COOKIE)!=P or request.headers.get("x-csrf-token")!=CSRF:
            from fastapi import HTTPException
            raise HTTPException(403)
        return {"review":True}
    wrapped=cut.CutoverFront(legacy_app,pg_app,lambda req:legacy,lambda req:pg,lambda:orgs)
    return bridge.ReadBridge(wrapped,erp),calls

async def request(app,path=PATH,method="POST",headers=None,scheme="https"):
    default={"cookie":cut.LEGACY_COOKIE+"="+L+"; "+cut.PG_COOKIE+"="+P,
             "x-jw-pg-csrf":CSRF,"x-csrf-token":"legacy-csrf",
             "x-org-id":"spoof","x-user-id":"spoof","origin":"https://testserver"}
    default.update(headers or {})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url=scheme+"://testserver") as c:
        return await c.request(method,path,headers=default)

@pytest.mark.asyncio
async def test_read_only_forward_uses_original_dual_boundary():
    with patch.dict(os.environ,ENV,clear=True):
        app,calls=front()
        result=await request(app)
        assert result.status_code==200 and result.json()=={"review":True}
        assert len(calls)==1
        assert calls[0]["cookie"]==cut.UPSTREAM_COOKIE+"="+P
        assert calls[0]["x-csrf-token"]==CSRF
        assert not any(k in calls[0] for k in ("x-jw-pg-csrf","x-org-id","x-user-id"))
        assert (await request(app,"/",method="GET")).json()=={"legacy":True}

@pytest.mark.asyncio
async def test_no_mutation_or_unknown_route_forwarded():
    with patch.dict(os.environ,ENV,clear=True):
        app,calls=front()
        for path in (bridge.PREFIX+"/finance/bills/a/commands/pay/b",
                     bridge.PREFIX+"/hr/workers/a/register/b",
                     bridge.PREFIX+"/drafts/documents/a/revise/b",
                     bridge.PREFIX+"/hr/workers/a/periods/2026-11/confirm/b",
                     bridge.PREFIX+"/valuation/items/a/receive/b",PATH+"/unknown"):
            assert (await request(app,path)).status_code==403
        assert (await request(app,PATH,method="GET")).status_code==403
        assert (await request(app,PATH+"?org=spoof")).status_code==422
        assert not calls

@pytest.mark.asyncio
async def test_identity_mismatch_member_and_org_denied():
    with patch.dict(os.environ,ENV,clear=True):
        for kwargs in ({"pg":cut.Identity("org-B","actor-A","admin")},
                       {"pg":cut.Identity("org-A","actor-B","admin")},
                       {"pg":cut.Identity("org-A","actor-A","member"),"legacy":cut.Identity("org-A","actor-A","member")},
                       {"orgs":frozenset()}):
            app,calls=front(**kwargs)
            assert (await request(app)).status_code==403
            assert not calls

@pytest.mark.asyncio
async def test_gate_https_cookie_and_csrf_boundaries():
    with patch.dict(os.environ,ENV,clear=True):
        app,calls=front()
        assert (await request(app,scheme="http")).status_code==403
        assert (await request(app,headers={"cookie":cut.LEGACY_COOKIE+"="+L})).status_code==401
        assert (await request(app,headers={"cookie":cut.UPSTREAM_COOKIE+"="+L})).status_code==401
        assert not calls
        assert (await request(app,headers={"x-jw-pg-csrf":"short"})).status_code==403
        assert not calls
        os.environ[bridge.FLAG]=""
        assert (await request(app)).status_code==404
        assert not calls

def test_factory_refuses_without_explicit_gate():
    with patch.dict(os.environ,{},clear=True):
        with pytest.raises(RuntimeError,match="NARUV_V223_BRIDGE_DISABLED"):bridge.create_app()
