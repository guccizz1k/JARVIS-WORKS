"""Default-off multi-line quote conversion; uses immutable source snapshot."""
import os
import json
from fastapi import APIRouter,HTTPException,Request,Response
from starlette.concurrency import run_in_threadpool
from . import naruv_bundle_review as bundle
from . import naruv_native_file_preview as preview
from . import naruv_native_write_review as write
from . import pg_v90_integrated_entry as v90
PREFIX=preview.PREFIX+"/quote-bundles"
def enabled():
    return bundle.enabled() and os.getenv("NARUV_QUOTE_BUNDLE_REVIEW")=="ISOLATED_SYNTHETIC_ONLY"
def _call(token,csrf,prior,key,rid=None,payload=None):
    import psycopg
    if not enabled():raise HTTPException(404,"QB_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            if preview._verify_identity(identity,csrf)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            if rid is None:cur.execute("SELECT naruv_quote_bundle.preview(%s,%s)",(key,csrf))
            else:cur.execute("SELECT naruv_quote_bundle.convert(%s,%s,%s::jsonb,true,%s)",(key,rid,json.dumps(payload,ensure_ascii=False,separators=(",",":")),csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or row[0].get("production_authorized") is not False:raise HTTPException(503,"QB_UNAVAILABLE")
            return row[0]
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason=="QB_NOT_FOUND":raise HTTPException(404,reason) from None
        if reason in ("QB_SCOPE","QB_INPUT","QB_MAPPING"):raise HTTPException(422,reason) from None
        if reason in ("QB_STALE","QB_CONFLICT","INV_INSUFFICIENT","QB_SOURCE_FROZEN"):raise HTTPException(409,reason) from None
        raise write._db_error(exc) from None
def create_router():
    router=APIRouter(prefix=PREFIX,tags=["NARUV isolated quote conversion"])
    @router.post("/quotes/{key}/preview")
    async def read(key:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"QB_DISABLED")
        token,csrf,_=write._request(request,key,needs_digest=False)
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,key)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/bundles/{key}/convert/{rid}")
    async def convert(key:str,rid:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"QB_DISABLED")
        token,csrf,_=write._request(request,key,rid,needs_digest=False)
        if preview._one_header(request,"x-naruv-confirm","")!="yes":raise HTTPException(422,"QB_CONFIRM_REQUIRED")
        if preview._one_header(request,"content-type","")!="application/json":raise HTTPException(415,"QB_CONTENT_TYPE")
        prior=await run_in_threadpool(write._auth,token,csrf)
        data=await bundle._body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,key,rid,data)
        response.headers["Cache-Control"]="no-store"
        return result
    return router
def register_quote_bundle(app):
    if not enabled():return False
    v90._origins()
    app.include_router(create_router())
    return True
