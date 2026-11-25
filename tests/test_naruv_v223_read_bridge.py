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
        assert (await request(app,headers={"origin":"https://evil.test"})).status_code==403
        assert (await request(app,headers={"x-jw-pg-csrf":""})).status_code==403
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

@pytest.mark.asyncio
async def test_duplicate_headers_and_websocket_denied():
    with patch.dict(os.environ,ENV,clear=True):
        app,calls=front()
        h=[("cookie",cut.LEGACY_COOKIE+"="+L+"; "+cut.PG_COOKIE+"="+P),
           ("origin","https://testserver"),("x-jw-pg-csrf",CSRF)]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="https://testserver") as c:
            for extra,status in (([("origin","https://testserver")],403),
                                 ([("x-jw-pg-csrf",CSRF)],403),
                                 ([("cookie",cut.UPSTREAM_COOKIE+"="+L)],401),
                                 ([("cookie",cut.PG_COOKIE+"="+P)],401)):
                assert (await c.post(PATH,headers=h+extra)).status_code==status
        sent=[]
        async def send(message):sent.append(message)
        async def receive():raise AssertionError("unexpected receive")
        await app({"type":"websocket","path":PATH},receive,send)
        assert sent==[{"type":"websocket.close","code":1008}]
        assert not calls

@pytest.mark.asyncio
async def test_workspace_gate_and_original_ui_custody():
    with patch.dict(os.environ,ENV,clear=True):
        app,calls=front()
        r=await request(app,bridge.WORKSPACE,method="GET")
        assert r.status_code==200 and "기업 업무 검토" in r.text
        assert "script-src 'self'" in r.headers["content-security-policy"]
        assert r.headers["cache-control"]=="no-store"
        for suffix in ("/app.js","/style.css"):
            assert (await request(app,bridge.WORKSPACE+suffix,method="GET")).status_code==200
        assert (await request(app,bridge.WORKSPACE+"/unknown",method="GET")).status_code==403
        assert (await request(app,bridge.WORKSPACE,method="POST")).status_code==403
        assert (await request(app,bridge.WORKSPACE,method="GET",headers={"cookie":cut.LEGACY_COOKIE+"="+L})).status_code==401
        assert not calls

@pytest.mark.asyncio
async def test_hr_pilot_scope_and_confirmation():
    path=bridge.PREFIX+"/hr/workers/pilot-test/register/pilot-rid"
    ci=cut.Identity("ci-a","actor-A","admin")
    env={**ENV,bridge.HR_PILOT_FLAG:bridge.HR_PILOT_ACK,"GITHUB_ACTIONS":"true",
         "JW_PG_CI_ALLOW":"ONLY_EPHEMERAL_LOCAL_DATABASE","JW_ENV":"dev"}
    with patch.dict(os.environ,env,clear=True):
        app,calls=front(pg=ci,legacy=ci,orgs=frozenset(("ci-a",)))
        # No fixture endpoint in this stub; 404 demonstrates the approved
        # request reached the backend, while disallowed requests stop at 403.
        assert (await request(app,path)).status_code==422
        assert (await request(app,path,headers={"x-naruv-confirm":"yes"})).status_code==404
        for bad in (path.replace("pilot-test","worker-1"),path.replace("pilot-rid","another"),
                    bridge.PREFIX+"/hr/workers/pilot-test/archive/pilot-rid",
                    bridge.PREFIX+"/hr/workers/pilot-test/periods/2026-11/amend/pilot-rid",
                    bridge.PREFIX+"/finance/bills/pilot-bill/commands/pay/pilot-rid"):
            assert (await request(app,bad,headers={"x-naruv-confirm":"yes"})).status_code==403
        for key in (bridge.HR_PILOT_FLAG,"GITHUB_ACTIONS","JW_PG_CI_ALLOW"):
            with patch.dict(os.environ,{key:""}):
                assert (await request(app,path,headers={"x-naruv-confirm":"yes"})).status_code==403
        app,calls=front()
        assert (await request(app,path,headers={"x-naruv-confirm":"yes"})).status_code==403
