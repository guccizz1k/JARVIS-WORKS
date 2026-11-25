"""Default-off synthetic attendance and period review; no payroll payment."""
import os
import re
from datetime import date
from fastapi import APIRouter,HTTPException,Request,Response
from starlette.concurrency import run_in_threadpool
from . import naruv_draft_review as drafts
from . import naruv_native_file_preview as preview
from . import naruv_native_write_review as write
from . import naruv_finance_review as finance
from . import pg_v90_integrated_entry as v90

PREFIX=preview.PREFIX+"/hr"
FLAG="NARUV_HR_REVIEW"

def enabled():
    return drafts.enabled() and os.getenv(FLAG)=="ISOLATED_SYNTHETIC_ONLY"

def _validate(period,data):
    if not re.fullmatch(r"[0-9]{4}-(0[1-9]|1[0-2])",period) or set(data)!={"date","regular","additional"}:
        raise HTTPException(422,"HR_INPUT")
    day,a,b=data["date"],data["regular"],data["additional"]
    if (type(day) is not str or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}",day)
        or not day.startswith(period+"-") or type(a) is not int or type(b) is not int
        or not 0<=a<=1440 or not 0<=b<=1440 or a+b>1440):
        raise HTTPException(422,"HR_INPUT")
    try:date.fromisoformat(day)
    except ValueError:raise HTTPException(422,"HR_INPUT") from None

def _admit(token,csrf,prior,worker,period,rid,data):
    import psycopg
    if not enabled():raise HTTPException(404,"HR_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            if preview._verify_identity(identity,csrf)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            cur.execute("SELECT naruv_draft.admit_attendance(%s,%s,%s,%s,%s,%s,true,%s)",
                        (worker,period,rid,data["date"],data["regular"],data["additional"],csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or row[0].get("payment_authorized") is not False or row[0].get("production_authorized") is not False:
                raise HTTPException(503,"HR_UNAVAILABLE")
            return row[0]
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason=="HR_NOT_FOUND":raise HTTPException(404,reason) from None
        if reason=="HR_INPUT":raise HTTPException(422,reason) from None
        if reason in ("HR_CONFLICT","HR_PERIOD_CONFIRMED"):raise HTTPException(409,reason) from None
        raise write._db_error(exc) from None

def _period(token,csrf,prior,worker,period,rid=None,expected=None):
    import psycopg
    if not enabled():raise HTTPException(404,"HR_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            if preview._verify_identity(identity,csrf)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            cur.execute("SELECT naruv_draft.review_period(%s,%s,%s,%s,%s,%s)",
                        (worker,period,rid,expected,rid is not None,csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or any(row[0].get(k) is not False for k in ("payment_authorized","production_authorized","statutory_validated")):
                raise HTTPException(503,"HR_UNAVAILABLE")
            return row[0]
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason=="HR_NOT_FOUND":raise HTTPException(404,reason) from None
        if reason=="HR_INPUT":raise HTTPException(422,reason) from None
        if reason in ("HR_CONFLICT","HR_PERIOD_CONFIRMED"):raise HTTPException(409,reason) from None
        raise write._db_error(exc) from None

def create_router():
    router=APIRouter(prefix=PREFIX,tags=["NARUV isolated attendance"])
    @router.post("/workers/{worker}/periods/{period}/attendance/{rid}")
    async def admit(worker:str,period:str,rid:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"HR_DISABLED")
        token,csrf,_=write._request(request,worker,rid,needs_digest=False)
        if preview._one_header(request,"x-naruv-confirm","")!="yes":raise HTTPException(422,"HR_CONFIRM_REQUIRED")
        if preview._one_header(request,"content-type","")!="application/json":raise HTTPException(415,"HR_CONTENT_TYPE")
        prior=await run_in_threadpool(write._auth,token,csrf)
        data=await finance._body(request)
        _validate(period,data)
        result=await run_in_threadpool(_admit,token,csrf,prior,worker,period,rid,data)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/workers/{worker}/periods/{period}/review")
    async def review(worker:str,period:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"HR_DISABLED")
        token,csrf,_=write._request(request,worker,needs_digest=False)
        prior=await run_in_threadpool(write._auth,token,csrf)
        await write._empty_body(request)
        result=await run_in_threadpool(_period,token,csrf,prior,worker,period)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/workers/{worker}/periods/{period}/confirm/{rid}")
    async def confirm(worker:str,period:str,rid:str,request:Request,response:Response):
        if not enabled():raise HTTPException(404,"HR_DISABLED")
        token,csrf,_=write._request(request,worker,rid,needs_digest=False)
        if preview._one_header(request,"x-naruv-confirm","")!="yes":raise HTTPException(422,"HR_CONFIRM_REQUIRED")
        if preview._one_header(request,"content-type","")!="application/json":raise HTTPException(415,"HR_CONTENT_TYPE")
        prior=await run_in_threadpool(write._auth,token,csrf)
        data=await finance._body(request)
        if set(data)!={"review_sha256"} or type(data["review_sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}",data["review_sha256"]):
            raise HTTPException(422,"HR_INPUT")
        result=await run_in_threadpool(_period,token,csrf,prior,worker,period,rid,data["review_sha256"])
        response.headers["Cache-Control"]="no-store"
        return result
    return router

def register_hr(app):
    if not enabled():return False
    v90._origins();app.include_router(create_router());return True
