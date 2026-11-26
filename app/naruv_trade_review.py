"""Default-off trade document review API. Single-line synthetic PG17 only."""
import json
import os
import asyncio
from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from . import naruv_native_file_preview as preview
from . import naruv_native_write_review as write
from . import naruv_inventory_review as inventory
from . import pg_v90_integrated_entry as v90

PREFIX=preview.PREFIX+"/trade"
LIMIT=4096

def enabled():
    return inventory.enabled() and os.getenv("NARUV_TRADE_REVIEW")=="ISOLATED_SYNTHETIC_ONLY"

async def _body(request):
    length=preview._one_header(request,"content-length")
    if length is not None:
        if not length.isascii() or not length.isdecimal() or len(length)>10:
            raise HTTPException(400,"TRADE_LENGTH")
        if int(length)>LIMIT:
            raise HTTPException(413,"TRADE_BODY_LIMIT")
    buf=bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(buf)+len(chunk)>LIMIT:
                    raise HTTPException(413,"TRADE_BODY_LIMIT")
                buf.extend(chunk)
    except TimeoutError:
        raise HTTPException(408,"UPLOAD_TIMEOUT") from None
    except ClientDisconnect:
        raise HTTPException(400,"UPLOAD_INCOMPLETE") from None
    if length is not None and len(buf)!=int(length):
        raise HTTPException(400,"TRADE_LENGTH")
    try:
        data=json.loads(buf.decode("utf-8"),object_pairs_hook=inventory._pairs,parse_constant=inventory._reject_constant)
        if type(data) is not dict:
            raise ValueError("shape")
        # Reject bool/float before PostgreSQL JSONB normalization can obscure type.
        for key in ("quantity","unit_price"):
            if key in data and type(data[key]) is not int:
                raise ValueError("quantity type")
        if any(type(v) not in (str,int) for v in data.values()):
            raise ValueError("shape")
        return data
    except (ValueError,UnicodeError,RecursionError):
        raise HTTPException(422,"TRADE_INPUT") from None

def _call(token,csrf,prior,doc,action,rid=None,payload=None):
    import psycopg
    if not enabled():
        raise HTTPException(404,"TRADE_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            if preview._verify_identity(identity,csrf)!=prior:
                raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            if action=="inspect":
                cur.execute("SELECT naruv_trade.inspect(%s,%s)",(doc,csrf))
            else:
                cur.execute("SELECT naruv_trade.command(%s,%s,%s,%s::jsonb,true,%s)",
                    (doc,rid,action,json.dumps(payload,ensure_ascii=False,separators=(",",":")),csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or row[0].get("production_authorized") is not False:
                raise HTTPException(503,"TRADE_UNAVAILABLE")
            return row[0]
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason in ("TRADE_NOT_FOUND","INV_NOT_FOUND"):
            raise HTTPException(404,reason) from None
        if reason in ("TRADE_INPUT","TRADE_QUOTE_SCOPE","INV_UNIT_REQUIRED"):
            raise HTTPException(422,reason) from None
        if reason in ("TRADE_CONFLICT","TRADE_TERMINAL","TRADE_OVER_QUANTITY","INV_INSUFFICIENT","INV_CAPACITY","INV_CONFLICT"):
            raise HTTPException(409,reason) from None
        raise write._db_error(exc) from None

def create_router():
    router=APIRouter(prefix=PREFIX,tags=["NARUV isolated trade documents"])
    @router.post("/documents/{doc}/commands/{action}/{rid}")
    async def command(doc:str,action:str,rid:str,request:Request,response:Response):
        if not enabled():
            raise HTTPException(404,"TRADE_DISABLED")
        if action not in ("open","fulfill","cancel"):
            raise HTTPException(422,"TRADE_INPUT")
        token,csrf,_=write._request(request,doc,rid,needs_digest=False)
        if preview._one_header(request,"x-naruv-confirm","")!="yes":
            raise HTTPException(422,"TRADE_CONFIRM_REQUIRED")
        if preview._one_header(request,"content-type","")!="application/json":
            raise HTTPException(415,"TRADE_CONTENT_TYPE")
        prior=await run_in_threadpool(write._auth,token,csrf)
        data=await _body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,doc,action,rid,data)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/documents/{doc}/inspect")
    async def inspect(doc:str,request:Request,response:Response):
        if not enabled():
            raise HTTPException(404,"TRADE_DISABLED")
        token,csrf,_=write._request(request,doc,needs_digest=False)
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,doc,"inspect")
        response.headers["Cache-Control"]="no-store"
        return result
    return router

def register_trade(app):
    if not enabled():
        return False
    v90._origins()
    app.include_router(create_router())
    return True
