"""Opt-in read-only bridge across the V22.3 dual-session boundary.

No trade or ERP mutation is forwarded. The approved UI, original cutover and
PG guards are unchanged. Not a production entrypoint or ledger migration.
"""
import os
import re
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse
from . import naruv_integrated_review as integrated
from . import pg_cinema_cutover_front_v223 as cut

FLAG="NARUV_V223_READ_BRIDGE"
ACK="ISOLATED_SYNTHETIC_READ_ONLY"
PREFIX=integrated.PREFIX
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

def enabled():
    return os.getenv(FLAG)==ACK and integrated._available(True,True)

def is_read_path(path):
    return any(p.fullmatch(path) for p in READ_PATHS)

class ReadBridge:
    def __init__(self,front,erp):
        if not isinstance(front,cut.CutoverFront):raise TypeError("V223_FRONT_REQUIRED")
        self.front=front
        self.erp=erp

    async def __call__(self,scope,receive,send):
        path=scope.get("path","")
        if not (path==PREFIX or path.startswith(PREFIX+"/")):
            return await self.front(scope,receive,send)
        if scope.get("type")=="websocket":
            return await send({"type":"websocket.close","code":1008})
        if scope.get("type")!="http":
            raise RuntimeError("NARUV_BRIDGE_UNSUPPORTED_SCOPE")
        try:
            if not enabled():raise cut.CutoverRefused("naruv_bridge_disabled",404)
            if scope.get("scheme")!="https":raise cut.CutoverRefused("https_required",403)
            if scope.get("method")!="POST" or not is_read_path(path):
                raise cut.CutoverRefused("naruv_read_scope_only",403)
            if scope.get("query_string"):raise cut.CutoverRefused("naruv_read_scope_only",422)
            request=Request(scope)
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
            # Separate PG cookie and PG CSRF forwarded by the original boundary;
            # the real NARUV backend repeats authorization under PG RLS.
            if not enabled() or pg.org_id not in self.front.enabled_orgs():
                raise cut.CutoverRefused("naruv_bridge_disabled",404)
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
