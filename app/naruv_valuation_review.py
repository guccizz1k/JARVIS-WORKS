"""Default-off warehouse moving-average valuation review."""
import json
import os
from fastapi import APIRouter,HTTPException,Request,Response
from starlette.concurrency import run_in_threadpool
from . import naruv_production_review as production
from . import naruv_finance_review as finance
from . import naruv_native_file_preview as preview
from . import naruv_native_write_review as write
from . import pg_v90_integrated_entry as v90
PREFIX=preview.PREFIX+"/valuation"
def enabled():
    return production.enabled() and os.getenv("NARUV_VALUATION_REVIEW")=="ISOLATED_SYNTHETIC_ONLY"
def _call(token,csrf,prior,item,source=None,warehouse=None,rid=None,payload=None,bill=None,return_id=None,audit=False,return_qty=None,adjusted=False,refund_ref=None):
    import psycopg
    if not enabled():raise HTTPException(404,"COST_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            if preview._verify_identity(identity,csrf)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            if audit:cur.execute("SELECT naruv_valuation.audit_ledger(%s)",(csrf,))
            elif adjusted:cur.execute("SELECT naruv_valuation.return_adjusted(%s,%s,%s,true,%s,true,%s)",(bill,return_id,return_qty,refund_ref,csrf))
            elif return_id is not None and return_qty is not None:cur.execute("SELECT naruv_valuation.return_quantity(%s,%s,%s,true,%s)",(bill,return_id,return_qty,csrf))
            elif return_id is not None:cur.execute("SELECT naruv_valuation.return_bill(%s,%s,true,%s)",(bill,return_id,csrf))
            elif bill is not None:cur.execute("SELECT naruv_valuation.reconcile_bill(%s,%s)",(bill,csrf))
            elif rid is None:cur.execute("SELECT naruv_valuation.inspect(%s,%s,%s,%s)",(source,item,warehouse,csrf))
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
        if not preview.IDENT.fullmatch(warehouse):raise HTTPException(422,"INVALID_STAGE_SCOPE")
        token,csrf,_=write._request(request,source,item,needs_digest=False)
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,item,source=source,warehouse=warehouse)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/bills/{bill}/reconcile")
    async def reconcile(bill:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"COST_DISABLED")
        token,csrf,_=write._request(request,bill,needs_digest=False)
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,None,bill=bill)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/bills/{bill}/return/{rid}")
    async def return_bill(bill:str,rid:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"COST_DISABLED")
        token,csrf,_=write._request(request,bill,rid,needs_digest=False)
        if preview._one_header(request,"x-naruv-confirm","")!="yes":raise HTTPException(422,"COST_CONFIRM_REQUIRED")
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,None,bill=bill,return_id=rid)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/bills/{bill}/return/{rid}/quantity/{quantity}")
    async def return_partial(bill:str,rid:str,quantity:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"COST_DISABLED")
        token,csrf,_=write._request(request,bill,rid,needs_digest=False)
        if not quantity.isascii() or not quantity.isdecimal() or len(quantity)>6 or not 1<=int(quantity)<=100000:raise HTTPException(422,"COST_INPUT")
        if preview._one_header(request,"x-naruv-confirm","")!="yes":raise HTTPException(422,"COST_CONFIRM_REQUIRED")
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,None,bill=bill,return_id=rid,return_qty=int(quantity))
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/bills/{bill}/return/{rid}/quantity/{quantity}/adjusted")
    async def return_adjusted(bill:str,rid:str,quantity:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"COST_DISABLED")
        token,csrf,_=write._request(request,bill,rid,needs_digest=False)
        if not quantity.isascii() or not quantity.isdecimal() or len(quantity)>6 or not 1<=int(quantity)<=100000:raise HTTPException(422,"COST_INPUT")
        if preview._one_header(request,"x-naruv-confirm","")!="yes":raise HTTPException(422,"COST_CONFIRM_REQUIRED")
        if preview._one_header(request,"content-type","")!="application/json":raise HTTPException(415,"FIN_CONTENT_TYPE")
        prior=await run_in_threadpool(write._auth,token,csrf)
        data=await finance._body(request)
        if set(data)-{"refund_reference"} or ("refund_reference" in data and (type(data["refund_reference"]) is not str or not preview.IDENT.fullmatch(data["refund_reference"]))):
            raise HTTPException(422,"COST_INPUT")
        result=await run_in_threadpool(_call,token,csrf,prior,None,bill=bill,return_id=rid,return_qty=int(quantity),adjusted=True,refund_ref=data.get("refund_reference"))
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/audit")
    async def audit(request:Request,response:Response):
        if not enabled():raise HTTPException(404,"COST_DISABLED")
        token,csrf,_=write._request(request,"audit",needs_digest=False)
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,None,audit=True)
        response.headers["Cache-Control"]="no-store"
        return result
    return router
def register_valuation(app):
    if not enabled():return False
    v90._origins()
    app.include_router(create_router())
    return True
