"""Synthetic read-only review endpoints. No upload, writes, approval or payment."""
import os
from fastapi import APIRouter,HTTPException,Request,Response
from starlette.concurrency import run_in_threadpool
from . import naruv_valuation_review as valuation
from . import naruv_native_write_review as write
from . import naruv_native_file_preview as preview
from . import pg_v90_integrated_entry as v90
from .naruv_document_review import review_document,ReviewBlocked,digest
from .naruv_payroll_draft import draft_gross,PayrollBlocked

PREFIX=preview.PREFIX+"/drafts"
FLAG="NARUV_DRAFT_REVIEW"
def enabled():
    return valuation.enabled() and os.getenv(FLAG)=="ISOLATED_SYNTHETIC_ONLY"

def _read(token,csrf,prior,kind,key,period=None):
    import psycopg
    if not enabled():raise HTTPException(404,"DRAFT_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            actor,org=preview._verify_identity(identity,csrf)
            if (actor,org)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            if kind=="document":
                cur.execute("SELECT * FROM naruv_draft.document_source(%s,%s)",(key,csrf))
                row=cur.fetchone()
                if row is None:raise HTTPException(404,"DRAFT_SOURCE_NOT_FOUND")
                revision,raw,sha,observations=row
                result=review_document(tenant=org,source_bytes=bytes(raw),registered_sha256=sha,observations=observations)
                result["source_binding_sha256"]=digest({"tenant":org,"document":key,"revision":revision,"review":result["review_sha256"]})
            elif kind=="pay":
                cur.execute("SELECT * FROM naruv_draft.pay_source(%s,%s,%s)",(key,period,csrf))
                row=cur.fetchone()
                if row is None:raise HTTPException(404,"DRAFT_SOURCE_NOT_FOUND")
                revision,rate,bps,days=row
                result=draft_gross(tenant=org,worker=key,period=period,policy_revision=revision,
                                   hourly_krw=rate,minutes_by_day=days,multiplier_bps={"regular":10000,"additional":bps})
            else:raise RuntimeError("DRAFT_KIND")
            # guard() holds the actor fence through transaction end.
            result["persisted"]=False;result["production_authorized"]=False
            return result
    except (ReviewBlocked,PayrollBlocked):
        raise HTTPException(409,"DRAFT_SOURCE_INVALID") from None
    except psycopg.Error as exc:
        raise write._db_error(exc) from None

def create_router():
    router=APIRouter(prefix=PREFIX,tags=["NARUV isolated document and payroll drafts"])
    async def read(kind,key,period,request,response):
        if not enabled():raise HTTPException(404,"DRAFT_DISABLED")
        token,csrf,_=write._request(request,key,period,needs_digest=False)
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_read,token,csrf,prior,kind,key,period)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/documents/{key}")
    async def document(key:str,request:Request,response:Response):
        return await read("document",key,None,request,response)
    @router.post("/payroll/{worker}/{period}")
    async def payroll(worker:str,period:str,request:Request,response:Response):
        import re
        if not re.fullmatch(r"[0-9]{4}-(0[1-9]|1[0-2])",period):raise HTTPException(422,"DRAFT_INPUT")
        return await read("pay",worker,period,request,response)
    return router

def register_drafts(app):
    if not enabled():return False
    v90._origins();app.include_router(create_router());return True
