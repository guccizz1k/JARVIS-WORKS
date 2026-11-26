"""Default-off isolated integer stock movement API; no production route registration."""
import json
import os
from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from . import naruv_native_file_preview as preview
from . import naruv_native_write_review as write
from . import pg_v90_integrated_entry as v90

PREFIX=preview.PREFIX+"/inventory"

def enabled():
    return write.enabled() and os.getenv("NARUV_INVENTORY_REVIEW")=="ISOLATED_SYNTHETIC_ONLY"

def _pairs(pairs):
    data={}
    for k,v in pairs:
        if k in data:
            raise ValueError("duplicate")
        data[k]=v
    return data

def _reject_constant(value):
    raise ValueError("nonfinite")

def _decode(raw):
    try:
        d=json.loads(raw.decode("utf-8"),object_pairs_hook=_pairs,parse_constant=_reject_constant)
        if type(d) is not dict or set(d)!={"from_warehouse","to_warehouse","quantity"}:
            raise ValueError("shape")
        if type(d["quantity"]) is not int or not 1<=d["quantity"]<=1000000000:
            raise ValueError("quantity")
        for name in ("from_warehouse","to_warehouse"):
            v=d[name]
            if v is not None and (type(v) is not str or not preview.IDENT.fullmatch(v)):
                raise ValueError("warehouse")
        if d["from_warehouse"]==d["to_warehouse"]:
            raise ValueError("same warehouse")
        return d
    except (ValueError,UnicodeError,RecursionError):
        raise HTTPException(422,"INV_INPUT") from None

def _call(token,csrf,prior,action,source,item,identifier,d=None):
    import psycopg
    if not enabled():
        raise HTTPException(404,"INVENTORY_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            if preview._verify_identity(identity,csrf)!=prior:
                raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            if action=="move":
                cur.execute("SELECT naruv_inventory.post_movement(%s,%s,%s,%s,%s,%s,%s)",
                    (source,item,identifier,d["from_warehouse"],d["to_warehouse"],d["quantity"],csrf))
            else:
                cur.execute("SELECT naruv_inventory.read_stock(%s,%s,%s,%s)",(source,item,identifier,csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or row[0].get("production_authorized") is not False:
                raise HTTPException(503,"INV_UNAVAILABLE")
            return row[0]
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason=="INV_NOT_FOUND":
            raise HTTPException(404,reason) from None
        if reason in ("INV_INPUT","INV_UNIT_REQUIRED"):
            raise HTTPException(422,reason) from None
        if reason in ("INV_INSUFFICIENT","INV_CAPACITY","INV_CONFLICT"):
            raise HTTPException(409,reason) from None
        raise write._db_error(exc) from None

def create_router():
    router=APIRouter(prefix=PREFIX,tags=["NARUV isolated inventory"])
    def request_args(request,source,item,identifier):
        if not enabled():
            raise HTTPException(404,"INVENTORY_DISABLED")
        if not all(preview.IDENT.fullmatch(x) for x in (source,item,identifier)):
            raise HTTPException(422,"INV_INPUT")
        return write._request(request,identifier,needs_digest=False)[:2]
    @router.post("/sources/{source}/items/{item}/movements/{request_id}")
    async def move(source:str,item:str,request_id:str,request:Request,response:Response):
        token,csrf=request_args(request,source,item,request_id)
        if preview._one_header(request,"content-type","")!="application/json":
            raise HTTPException(415,"INV_CONTENT_TYPE")
        length=preview._one_header(request,"content-length")
        if length is not None and length.isascii() and length.isdecimal() and len(length)<=10 and int(length)>4096:
            raise HTTPException(413,"INV_BODY_LIMIT")
        prior=await run_in_threadpool(write._auth,token,csrf)
        raw=await preview._bounded_body(request)
        if len(raw)>4096:
            raise HTTPException(413,"INV_BODY_LIMIT")
        data=_decode(raw)
        result=await run_in_threadpool(_call,token,csrf,prior,"move",source,item,request_id,data)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/sources/{source}/items/{item}/stock/{warehouse}")
    async def stock(source:str,item:str,warehouse:str,request:Request,response:Response):
        token,csrf=request_args(request,source,item,warehouse)
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,"read",source,item,warehouse)
        response.headers["Cache-Control"]="no-store"
        return result
    return router

def register_inventory(app):
    if not enabled():
        return False
    v90._origins()
    app.include_router(create_router())
    return True
