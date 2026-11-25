"""Opt-in read-only bridge across the V22.3 dual-session boundary.

Read-only by default. A separately gated disposable CI-only HR workflow
may exercise synthetic worker setup/attendance/confirmation. No trade, payment,
production write or ledger migration. Original cutover and PG guards unchanged.
"""
import asyncio
import os
import re
import sqlite3
import tempfile
from contextlib import asynccontextmanager
import anyio
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse,Response
from pathlib import Path
from . import naruv_integrated_review as integrated
from . import pg_cinema_cutover_front_v223 as cut

FLAG="NARUV_V223_READ_BRIDGE"
ACK="ISOLATED_SYNTHETIC_READ_ONLY"
HR_PILOT_FLAG="NARUV_V223_HR_CI_PILOT"
HR_PILOT_ACK="DISPOSABLE_FIXTURE_ONLY"
HR_LIFECYCLE_FLAG="NARUV_V223_HR_CI_LIFECYCLE"
PILOT_ORGS=frozenset(("ci-a","ci-b"))
PREFIX=integrated.PREFIX
WORKSPACE='/naruv-workspace'
ASSETS=Path(__file__).resolve().parent/'naruv_workspace'
IDENT=r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"
PERIOD=r"[0-9]{4}-(?:0[1-9]|1[0-2])"
READ_PATHS=tuple(re.compile(PREFIX+pattern,re.ASCII) for pattern in (
    "/valuation/overview",
    "/valuation/audit",
    "/valuation/bills/"+IDENT+"/reconcile",
    "/valuation/sources/"+IDENT+"/items/"+IDENT+"/stock/"+IDENT,
    "/inventory/sources/"+IDENT+"/items/"+IDENT+"/stock/"+IDENT,
    "/finance/bills/"+IDENT+"/inspect",
    "/drafts/documents/"+IDENT,
    "/drafts/payroll/"+IDENT+"/"+PERIOD,
    "/hr/workers/list",
    "/hr/workers/"+IDENT+"/inspect",
    "/hr/workers/"+IDENT+"/periods/"+PERIOD+"/review",
))

# Deliberately narrow: only new synthetic HR identifiers, not arbitrary staff.
PILOT_WORKER=r"pilot-[a-z0-9-]{1,40}"
PILOT_REQUEST=r"pilot-[a-z0-9-]{1,80}"
PILOT_ROOT=PREFIX+"/hr/workers/"+PILOT_WORKER
PILOT_PATHS=tuple(re.compile(PILOT_ROOT+suffix,re.ASCII) for suffix in (
    "/register/"+PILOT_REQUEST,
    "/periods/"+PERIOD+"/create/"+PILOT_REQUEST,
    "/periods/"+PERIOD+"/attendance/"+PILOT_REQUEST,
    "/periods/"+PERIOD+"/confirm/"+PILOT_REQUEST,
))

# Pilot HR JSON is small. Bound both streaming bytes and total receive time.
PILOT_BODY_LIMIT=65536
PILOT_BODY_TIMEOUT=5.0

async def _pilot_body(receive):
    async def collect():
        data=bytearray()
        while True:
            message=await receive()
            if message.get("type")!="http.request":
                raise cut.CutoverRefused("naruv_pilot_body_incomplete",400)
            chunk=message.get("body",b"")
            if len(chunk)>PILOT_BODY_LIMIT-len(data):
                raise cut.CutoverRefused("naruv_pilot_body_too_large",413)
            data.extend(chunk)
            if not message.get("more_body",False):
                return bytes(data)
            # Yield even if a malformed transport supplies endless empty chunks.
            await asyncio.sleep(0)
    try:
        body=await asyncio.wait_for(collect(),timeout=PILOT_BODY_TIMEOUT)
    except asyncio.TimeoutError as exc:
        raise cut.CutoverRefused("naruv_pilot_body_timeout",408) from exc
    used=False
    async def replay():
        nonlocal used
        if not used:
            used=True
            return {"type":"http.request","body":body,"more_body":False}
        return await receive()
    return replay

LIFECYCLE_PATHS=tuple(re.compile(PILOT_ROOT+suffix,re.ASCII) for suffix in (
    "/archive/"+PILOT_REQUEST,
    "/periods/"+PERIOD+"/amend/"+PILOT_REQUEST,
))

def lifecycle_enabled():
    return pilot_enabled() and os.getenv(HR_LIFECYCLE_FLAG)==HR_PILOT_ACK

@asynccontextmanager
async def _legacy_fence(path):
    """Serialize SQLite revocations against a disposable PG write only.

    A RESERVED SQLite writer lock excludes other connections' writes, including
    session deletion, staff disable and role changes. It does not create a
    distributed transaction, prevent time-based expiry, or authorize production.
    """
    if not pilot_enabled() or path is None:
        raise cut.CutoverRefused("naruv_pilot_fence_required",403)
    p=Path(path)
    try:
        resolved=p.resolve(strict=True)
        root=Path(tempfile.gettempdir()).resolve(strict=True)
        configured=Path(os.environ["JARVIS_DB_PATH"]).resolve(strict=True)
        if (p.is_symlink() or not resolved.is_relative_to(root) or resolved.parent==root
            or resolved.name!="isolated.db" or resolved!=configured or not resolved.is_file()):
            raise ValueError("not disposable")
    except (OSError,KeyError,ValueError) as exc:
        raise cut.CutoverRefused("naruv_pilot_fence_required",403) from exc
    def acquire():
        db=None
        try:
            db=sqlite3.connect(resolved.as_uri()+"?mode=rw",uri=True,timeout=1.0,
                               isolation_level=None,check_same_thread=False)
            db.execute("BEGIN IMMEDIATE")
            return db
        except sqlite3.Error as exc:
            if db is not None:db.close()
            raise cut.CutoverRefused("naruv_pilot_fence_busy",503) from exc
    def release(db):
        try:db.rollback()
        finally:db.close()
    # Keep the lock until the ASGI backend and its PG transaction have exited.
    # Shield cleanup against cancellation. No lock held while receiving a body.
    with anyio.CancelScope(shield=True):
        db=await anyio.to_thread.run_sync(acquire)
        try:yield
        finally:await anyio.to_thread.run_sync(release,db)

def pilot_enabled():
    return (enabled() and os.getenv(HR_PILOT_FLAG)==HR_PILOT_ACK
            and os.getenv("GITHUB_ACTIONS")=="true"
            and os.getenv("JW_PG_CI_ALLOW")=="ONLY_EPHEMERAL_LOCAL_DATABASE"
            and os.getenv("JW_ENV","").lower() in ("dev","development","test"))

def is_pilot_path(path):
    return any(p.fullmatch(path) for p in PILOT_PATHS) or (lifecycle_enabled() and any(p.fullmatch(path) for p in LIFECYCLE_PATHS))

def enabled():
    return os.getenv(FLAG)==ACK and integrated._available(True,True)

def is_read_path(path):
    return any(p.fullmatch(path) for p in READ_PATHS)

class ReadBridge:
    def __init__(self,front,erp,*,pilot_db=None):
        if not isinstance(front,cut.CutoverFront):raise TypeError("V223_FRONT_REQUIRED")
        self.front=front
        self.erp=erp
        self.pilot_db=pilot_db

    async def __call__(self,scope,receive,send):
        path=scope.get("path","")
        workspace=path==WORKSPACE or path.startswith(WORKSPACE+"/")
        if not workspace and not (path==PREFIX or path.startswith(PREFIX+"/")):
            return await self.front(scope,receive,send)
        if scope.get("type")=="websocket":
            return await send({"type":"websocket.close","code":1008})
        if scope.get("type")!="http":
            raise RuntimeError("NARUV_BRIDGE_UNSUPPORTED_SCOPE")
        try:
            pilot=not workspace and is_pilot_path(path) and pilot_enabled()
            if not enabled():raise cut.CutoverRefused("naruv_bridge_disabled",404)
            if scope.get("scheme")!="https":raise cut.CutoverRefused("https_required",403)
            if workspace:
                if scope.get("method")!="GET" or path not in (WORKSPACE,WORKSPACE+"/app.js",WORKSPACE+"/style.css"):
                    raise cut.CutoverRefused("naruv_read_scope_only",403)
            elif scope.get("method")!="POST" or not (is_read_path(path) or pilot):
                raise cut.CutoverRefused("naruv_read_scope_only",403)
            if scope.get("query_string"):raise cut.CutoverRefused("naruv_read_scope_only",422)
            request=Request(scope)
            if not workspace:
                origins=request.headers.getlist("origin")
                if len(origins)!=1 or origins[0] not in integrated.v90._origins():
                    raise cut.CutoverRefused("origin_denied",403)
                csrf=request.headers.getlist("x-jw-pg-csrf")
                if len(csrf)!=1 or not 16<=len(csrf[0])<=512 or not csrf[0].isascii():
                    raise cut.CutoverRefused("invalid_pg_csrf",403)
            # Inspect every Cookie header, including a hidden old session in a
            # second header that the framework's cookie parser may ignore.
            if any(part.partition(b"=")[0].strip()==cut.UPSTREAM_COOKIE.encode("ascii")
                   for key,value in scope.get("headers",()) if key.lower()==b"cookie"
                   for part in value.split(b";")):
                raise cut.CutoverRefused("old_session_relogin_required",401)
            # Never trust actor/org values from browser input or a single store.
            legacy=await self.front._identity(scope,cut.LEGACY_COOKIE,self.front.legacy_identity)
            pg=await self.front._identity(scope,cut.PG_COOKIE,self.front.pg_identity)
            if (legacy.org_id,legacy.actor_id,legacy.role)!=(pg.org_id,pg.actor_id,pg.role):
                raise cut.CutoverRefused("identity_mismatch",403)
            if pg.role!="admin" or pg.org_id not in self.front.enabled_orgs():
                raise cut.CutoverRefused("naruv_org_denied",403)
            if pilot:
                if pg.org_id not in PILOT_ORGS or not pilot_enabled():
                    raise cut.CutoverRefused("naruv_pilot_denied",403)
                if request.headers.getlist("x-naruv-confirm")!=["yes"]:
                    raise cut.CutoverRefused("naruv_pilot_confirmation_required",422)
                # Finish bounded client input before the final identity checks.
                # A slow upload must not widen the authorization race window.
                receive=await _pilot_body(receive)
                async with _legacy_fence(self.pilot_db):
                    # Recheck inside the SQLite writer fence, not before it.
                    legacy_now=await self.front._identity(scope,cut.LEGACY_COOKIE,self.front.legacy_identity)
                    pg_now=await self.front._identity(scope,cut.PG_COOKIE,self.front.pg_identity)
                    if legacy_now!=legacy or pg_now!=pg:
                        raise cut.CutoverRefused("identity_mismatch",403)
                    if (not pilot_enabled() or not is_pilot_path(path)
                        or pg.org_id not in self.front.enabled_orgs()):
                        raise cut.CutoverRefused("naruv_pilot_denied",403)
                    return await self.front._forward(self.erp,scope,receive,send,cut.PG_COOKIE)
            # Separate PG cookie and PG CSRF forwarded by the original boundary;
            # the real NARUV backend repeats authorization under PG RLS.
            if not enabled() or pg.org_id not in self.front.enabled_orgs():
                raise cut.CutoverRefused("naruv_bridge_disabled",404)
            if workspace:
                asset,kind={WORKSPACE:("index.html","text/html"),WORKSPACE+"/app.js":("app.js","application/javascript"),WORKSPACE+"/style.css":("style.css","text/css")}[path]
                return await Response((ASSETS/asset).read_bytes(),media_type=kind,headers={
                    "Cache-Control":"no-store","X-Content-Type-Options":"nosniff",
                    "X-Frame-Options":"DENY","Referrer-Policy":"no-referrer",
                    "Strict-Transport-Security":"max-age=31536000",
                    "Content-Security-Policy":"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'"
                })(scope,receive,send)
            return await self.front._forward(self.erp,scope,receive,send,cut.PG_COOKIE)
        except cut.CutoverRefused as exc:
            return await JSONResponse({"code":exc.code},status_code=exc.status,headers={
                "Cache-Control":"no-store","X-Content-Type-Options":"nosniff",
                "X-Frame-Options":"DENY","Referrer-Policy":"no-referrer",
                "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'"
            })(scope,receive,send)

def create_app():
    if not enabled():raise RuntimeError("NARUV_V223_BRIDGE_DISABLED")
    front=cut.create_app()
    erp=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    if not integrated.register_integrated_review(erp,include_drafts=True,include_hr=True):
        raise RuntimeError("NARUV_V223_BRIDGE_DISABLED")
    @erp.middleware("http")
    async def security(request,call_next):
        response=await call_next(request)
        response.headers["Cache-Control"]="no-store"
        response.headers["X-Content-Type-Options"]="nosniff"
        response.headers["X-Frame-Options"]="DENY"
        response.headers["Referrer-Policy"]="no-referrer"
        response.headers["Content-Security-Policy"]="default-src 'none'; frame-ancestors 'none'"
        response.headers["Strict-Transport-Security"]="max-age=31536000"
        return response
    return ReadBridge(front,erp)
