"""Default-off warehouse moving-average valuation review."""
import json
import os
from fastapi import APIRouter,HTTPException,Request,Response
from starlette.concurrency import run_in_threadpool
from . import naruv_production_review as production
from . import naruv_native_file_preview as preview
from . import naruv_native_write_review as write
from . import pg_v90_integrated_entry as v90
PREFIX=preview.PREFIX+"/valuation"
def enabled():
    return production.enabled() and os.getenv("NARUV_VALUATION_REVIEW")=="ISOLATED_SYNTHETIC_ONLY"
def _call(token,csrf,prior,item,source=None,warehouse=None,rid=None,payload=None):
    import psycopg
    if not enabled():raise HTTPException(404,"COST_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            if preview._verify_identity(identity,csrf)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            if rid is None:cur.execute("SELECT naruv_valuation.inspect(%s,%s,%s,%s)",(source,item,warehouse,csrf))
            else:cur.execute("SELECT naruv_valuation.receive(%s,%s,%s::jsonb,true,%s)",(item,rid,json.dumps(payload,ensure_ascii=False,separators=(",",":")),csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or row[0].get("production_authorized") is not False:raise HTTPException(503,"COST_UNAVAILABLE")
            return row[0]
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason=="INV_NOT_FOUND":raise HTTPException(404,reason) from None
        if reason in ("COST_INPUT","PROD_INPUT","INV_INPUT","INV_UNIT_REQUIRED"):raise HTTPException(422,reason) from None
        if reason in ("COST_CONFLICT","COST_CAPACITY","INV_CAPACITY","INV_CONFLICT","INV_INSUFFICIENT"):raise HTTPException(409,reason) from None
        raise write._db_error(exc) from None
def create_router():
    router=APIRouter(prefix=PREFIX,tags=["NARUV isolated valuation"])
    @router.post("/items/{item}/receive/{rid}")
    async def receive(item:str,rid:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"COST_DISABLED")
        token,csrf,_=write._request(request,item,rid,needs_digest=False)
        if preview._one_header(request,"x-naruv-confirm","")!="yes":raise HTTPException(422,"COST_CONFIRM_REQUIRED")
        if preview._one_header(request,"content-type","")!="application/json":raise HTTPException(415,"COST_CONTENT_TYPE")
        prior=await run_in_threadpool(write._auth,token,csrf)
        data=await production._body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,item,rid=rid,payload=data)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/sources/{source}/items/{item}/stock/{warehouse}")
    async def inspect(source:str,item:str,warehouse:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"COST_DISABLED")
        token,csrf,_=write._request(request,source,item,warehouse,needs_digest=False)
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,item,source=source,warehouse=warehouse)
        response.headers["Cache-Control"]="no-store"
        return result
    return router
def register_valuation(app):
    if not enabled():return False
    v90._origins()
    app.include_router(create_router())
    return True
