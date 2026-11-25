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

def front(pg=A,legacy=A,orgs=frozenset(("org-A",)),pilot_db=None):
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
    return bridge.ReadBridge(wrapped,erp,pilot_db=pilot_db),calls

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
async def test_hr_pilot_scope_and_confirmation(tmp_path):
    db=tmp_path/"isolated.db";db.touch()
    path=bridge.PREFIX+"/hr/workers/pilot-test/register/pilot-rid"
    ci=cut.Identity("ci-a","actor-A","admin")
    env={**ENV,bridge.HR_PILOT_FLAG:bridge.HR_PILOT_ACK,"GITHUB_ACTIONS":"true",
         "JW_PG_CI_ALLOW":"ONLY_EPHEMERAL_LOCAL_DATABASE","JW_ENV":"dev","JARVIS_DB_PATH":str(db)}
    with patch.dict(os.environ,env,clear=True):
        app,calls=front(pg=ci,legacy=ci,orgs=frozenset(("ci-a",)),pilot_db=db)
        # No fixture endpoint in this stub; 404 demonstrates the approved
        # request reached the backend, while disallowed requests stop at 403.
        assert (await request(app,path)).status_code==422
        assert (await request(app,path,headers={"x-naruv-confirm":"yes"})).status_code==404
        nofence,_=front(pg=ci,legacy=ci,orgs=frozenset(("ci-a",)))
        assert (await request(nofence,path,headers={"x-naruv-confirm":"yes"})).status_code==403
        archive=path.replace("/register/","/archive/")
        with patch.dict(os.environ,{bridge.HR_LIFECYCLE_FLAG:bridge.HR_PILOT_ACK}):
            assert (await request(app,archive,headers={"x-naruv-confirm":"yes"})).status_code==404
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


@pytest.mark.asyncio
async def test_pilot_stream_revocation_and_body_bounds(tmp_path):
    db=tmp_path/"isolated.db";db.touch()
    from fastapi import HTTPException
    path=bridge.PREFIX+"/hr/workers/pilot-test/register/pilot-rid"
    ci=cut.Identity("ci-a","actor-A","admin")
    env={**ENV,bridge.HR_PILOT_FLAG:bridge.HR_PILOT_ACK,"GITHUB_ACTIONS":"true",
         "JW_PG_CI_ALLOW":"ONLY_EPHEMERAL_LOCAL_DATABASE","JW_ENV":"dev","JARVIS_DB_PATH":str(db)}
    with patch.dict(os.environ,env,clear=True):
        app,_=front(pg=ci,legacy=ci,orgs=frozenset(("ci-a",)),pilot_db=db)
        live={"legacy":True,"pg":True}
        calls=[]
        def resolve(which):
            def resolver(req):
                if not live[which]:raise HTTPException(401)
                return ci
            return resolver
        app.front.legacy_identity=resolve("legacy")
        app.front.pg_identity=resolve("pg")
        @app.erp.post(path)
        async def write(request:Request):
            calls.append(await request.body())
            return {"ok":True}
        headers={"cookie":cut.LEGACY_COOKIE+"="+L+"; "+cut.PG_COOKIE+"="+P,
                 "origin":"https://testserver","x-jw-pg-csrf":CSRF,
                 "x-naruv-confirm":"yes"}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="https://testserver") as c:
            async def stream(revoke=None):
                yield b'{"worker":'
                if revoke:live[revoke]=False
                yield b'"pilot-test"}'
            for which in ("legacy","pg"):
                live.update(legacy=True,pg=True)
                r=await c.post(path,headers=headers,content=stream(which))
                assert r.status_code==401 and not calls
            live.update(legacy=True,pg=True)
            r=await c.post(path,headers=headers,content=b"x"*(bridge.PILOT_BODY_LIMIT+1))
            assert r.status_code==413 and not calls
            async def delayed():
                import asyncio
                await asyncio.sleep(1)
                yield b"{}"
            with patch.object(bridge,"PILOT_BODY_TIMEOUT",0.01):
                r=await c.post(path,headers=headers,content=delayed())
            assert r.status_code==408 and not calls
            r=await c.post(path,headers=headers,content=stream())
            assert r.status_code==200 and calls==[b'{"worker":"pilot-test"}']

@pytest.mark.asyncio
async def test_pilot_disconnected_body_never_replayed():
    async def receive():
        return {"type":"http.disconnect"}
    with pytest.raises(cut.CutoverRefused) as err:
        await bridge._pilot_body(receive)
    assert err.value.status==400


@pytest.mark.asyncio
async def test_legacy_fence_real_sqlite_contention_and_release(tmp_path):
    import sqlite3
    db=tmp_path/"isolated.db"
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY)")
        c.execute("INSERT INTO sessions VALUES ('active')")
    env={**ENV,bridge.HR_PILOT_FLAG:bridge.HR_PILOT_ACK,"GITHUB_ACTIONS":"true",
         "JW_PG_CI_ALLOW":"ONLY_EPHEMERAL_LOCAL_DATABASE","JW_ENV":"dev",
         "JARVIS_DB_PATH":str(db)}
    with patch.dict(os.environ,env,clear=True):
        for failure in (False,True):
            try:
                async with bridge._legacy_fence(db):
                    with sqlite3.connect(db,timeout=0) as other:
                        assert other.execute("SELECT count(*) FROM sessions").fetchone()==(1,)
                        with pytest.raises(sqlite3.OperationalError,match="locked"):
                            other.execute("DELETE FROM sessions")
                    if failure:raise ValueError("simulated backend failure")
            except ValueError:
                assert failure
            with sqlite3.connect(db,timeout=0) as other:
                other.execute("DELETE FROM sessions")
                other.execute("INSERT INTO sessions VALUES ('active')")
        wrong=tmp_path/"wrong.db";wrong.touch()
        with pytest.raises(cut.CutoverRefused) as err:
            async with bridge._legacy_fence(wrong):pass
        assert err.value.status==403
        with sqlite3.connect(db,timeout=0,isolation_level=None) as other:
            other.execute("BEGIN IMMEDIATE")
            with pytest.raises(cut.CutoverRefused) as err:
                async with bridge._legacy_fence(db):pass
            assert err.value.status==503
