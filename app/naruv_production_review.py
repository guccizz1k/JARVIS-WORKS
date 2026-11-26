"""Default-off single-level BOM and atomic production quantity review."""
import asyncio
import json
import os
from fastapi import APIRouter,HTTPException,Request,Response
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from . import naruv_quote_bundle_review as quote_bundle
from . import naruv_native_file_preview as preview
from . import naruv_native_write_review as write
from . import naruv_inventory_review as inventory
from . import pg_v90_integrated_entry as v90
PREFIX=preview.PREFIX+"/production"
LIMIT=16384
def enabled():
    return quote_bundle.enabled() and os.getenv("NARUV_PRODUCTION_REVIEW")=="ISOLATED_SYNTHETIC_ONLY"
async def _body(request):
    length=preview._one_header(request,"content-length")
    if length is not None:
        if not length.isascii() or not length.isdecimal() or len(length)>10:raise HTTPException(400,"PROD_LENGTH")
        if int(length)>LIMIT:raise HTTPException(413,"PROD_BODY_LIMIT")
    buf=bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(buf)+len(chunk)>LIMIT:raise HTTPException(413,"PROD_BODY_LIMIT")
                buf.extend(chunk)
    except TimeoutError:
        raise HTTPException(408,"UPLOAD_TIMEOUT") from None
    except ClientDisconnect:
        raise HTTPException(400,"UPLOAD_INCOMPLETE") from None
    if length is not None and len(buf)!=int(length):raise HTTPException(400,"PROD_LENGTH")
    try:
        data=json.loads(buf.decode("utf-8"),object_pairs_hook=inventory._pairs,parse_constant=inventory._reject_constant)
        if type(data) is not dict:raise ValueError("shape")
        for key,val in data.items():
            if key=="lines":
                if type(val) is not list or not 1<=len(val)<=20:raise ValueError("lines")
                if any(type(row) is not dict or any(type(v) not in (str,int) for v in row.values()) for row in val):raise ValueError("line")
            elif type(val) not in (str,int):raise ValueError("value")
        return data
    except (ValueError,UnicodeError,RecursionError):
        raise HTTPException(422,"PROD_INPUT") from None
def _call(token,csrf,prior,key,action,rid=None,payload=None):
    import psycopg
    if not enabled():raise HTTPException(404,"PROD_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            if preview._verify_identity(identity,csrf)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            if action=="inspect":cur.execute("SELECT naruv_production.inspect(%s,%s)",(key,csrf))
            elif action=="requirements":cur.execute("SELECT naruv_production.requirements(%s,%s::jsonb,%s)",(key,json.dumps(payload,ensure_ascii=False,separators=(",",":")),csrf))
            else:cur.execute("SELECT naruv_production.command(%s,%s,%s,%s::jsonb,true,%s)",(key,rid,action,json.dumps(payload,ensure_ascii=False,separators=(",",":")),csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or row[0].get("production_authorized") is not False:raise HTTPException(503,"PROD_UNAVAILABLE")
            return row[0]
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason in ("PROD_NOT_FOUND","INV_NOT_FOUND"):raise HTTPException(404,reason) from None
        if reason in ("PROD_INPUT","PROD_CYCLE","INV_UNIT_REQUIRED"):raise HTTPException(422,reason) from None
        if reason in ("PROD_CONFLICT","PROD_TERMINAL","PROD_OVER_QUANTITY","PROD_CAPACITY","INV_INSUFFICIENT","INV_CAPACITY","INV_CONFLICT"):raise HTTPException(409,reason) from None
        raise write._db_error(exc) from None
def create_router():
    router=APIRouter(prefix=PREFIX,tags=["NARUV isolated production"])
    @router.post("/{key}/commands/{action}/{rid}")
    async def command(key:str,action:str,rid:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"PROD_DISABLED")
        if action not in ("define","open","complete","cancel"):raise HTTPException(422,"PROD_INPUT")
        token,csrf,_=write._request(request,key,rid,needs_digest=False)
        if preview._one_header(request,"x-naruv-confirm","")!="yes":raise HTTPException(422,"PROD_CONFIRM_REQUIRED")
        if preview._one_header(request,"content-type","")!="application/json":raise HTTPException(415,"PROD_CONTENT_TYPE")
        prior=await run_in_threadpool(write._auth,token,csrf)
        data=await _body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,key,action,rid,data)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/{key}/inspect")
    async def inspect(key:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"PROD_DISABLED")
        token,csrf,_=write._request(request,key,needs_digest=False)
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,key,"inspect")
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/boms/{key}/requirements")
    async def requirements(key:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"PROD_DISABLED")
        token,csrf,_=write._request(request,key,needs_digest=False)
        if preview._one_header(request,"content-type","")!="application/json":raise HTTPException(415,"PROD_CONTENT_TYPE")
        prior=await run_in_threadpool(write._auth,token,csrf)
        data=await _body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,key,"requirements",payload=data)
        response.headers["Cache-Control"]="no-store"
        return result
    return router
def register_production(app):
    if not enabled():return False
    v90._origins()
    app.include_router(create_router())
    return True
