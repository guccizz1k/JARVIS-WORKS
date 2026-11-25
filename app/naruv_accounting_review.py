"""Default-off accounting inspection and irreversible lab period closing."""
import os
from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from . import naruv_finance_review as finance
from . import naruv_native_file_preview as preview
from . import naruv_native_write_review as write
from . import pg_v90_integrated_entry as v90

PREFIX=preview.PREFIX+"/accounting"
def enabled():
    return finance.enabled() and os.getenv("NARUV_ACCOUNTING_REVIEW")=="ISOLATED_SYNTHETIC_ONLY"

def _call(token,csrf,prior,action,key):
    import psycopg
    if not enabled():raise HTTPException(404,"ACCT_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            if preview._verify_identity(identity,csrf)!=prior:
                raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            if action=="close":
                cur.execute("SELECT naruv_accounting.close_period(%s,true,%s)",(key,csrf))
            else:
                cur.execute("SELECT naruv_accounting.inspect_bill(%s,%s)",(key,csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or row[0].get("production_authorized") is not False:
                raise HTTPException(503,"ACCT_UNAVAILABLE")
            return row[0]
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason=="ACCT_NOT_FOUND":raise HTTPException(404,reason) from None
        if reason=="ACCT_INPUT":raise HTTPException(422,reason) from None
        raise write._db_error(exc) from None

def create_router():
    router=APIRouter(prefix=PREFIX,tags=["NARUV isolated accounting"])
    async def operation(key,request,response,action):
        if not enabled():raise HTTPException(404,"ACCT_DISABLED")
        token,csrf,_=write._request(request,key,needs_digest=False)
        if action=="close" and preview._one_header(request,"x-naruv-confirm","")!="yes":
            raise HTTPException(422,"ACCT_CONFIRM_REQUIRED")
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_call,token,csrf,prior,action,key)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/bills/{key}/inspect")
    async def inspect(key:str,request:Request,response:Response):
        return await operation(key,request,response,"inspect")
    @router.post("/periods/{key}/close")
    async def close(key:str,request:Request,response:Response):
        return await operation(key,request,response,"close")
    return router

def register_accounting(app):
    if not enabled():return False
    v90._origins()
    app.include_router(create_router())
    return True
