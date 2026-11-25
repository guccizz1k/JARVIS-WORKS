"""Synthetic document registration and draft review. No auto posting or payment."""
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
        if getattr(getattr(exc,"diag",None),"message_primary","")=="HR_CONFLICT":
            raise HTTPException(409,"DRAFT_SOURCE_CHANGED") from None
        raise write._db_error(exc) from None

def _admit_document(token,csrf,prior,key,rid,fmt,raw,observations):
    import hashlib,json,psycopg
    if not enabled():raise HTTPException(404,"DRAFT_DISABLED")
    try:
        with v90._pg_validated_cursor(token) as (cur,identity):
            actor,org=preview._verify_identity(identity,csrf)
            if (actor,org)!=prior:raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            sha=hashlib.sha256(raw).hexdigest()
            review=review_document(tenant=org,source_bytes=raw,registered_sha256=sha,observations=observations)
            if any(x.startswith("INVALID_") for x in review["issues"]):raise HTTPException(422,"DOC_INPUT")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            cur.execute("SELECT naruv_draft.admit_document(%s,%s,%s,%s,%s::jsonb,true,%s)",
                        (key,rid,fmt,raw,json.dumps(observations,ensure_ascii=True,separators=(",",":")),csrf))
            row=cur.fetchone()
            if not row or type(row[0]) is not dict or row[0].get("source_sha256")!=sha or row[0].get("posting_authorized") is not False or row[0].get("production_authorized") is not False:
                raise HTTPException(503,"DOC_UNAVAILABLE")
            return row[0]
    except ReviewBlocked:raise HTTPException(422,"DOC_INPUT") from None
    except psycopg.Error as exc:
        reason=getattr(getattr(exc,"diag",None),"message_primary","")
        if reason=="DOC_INPUT":raise HTTPException(422,reason) from None
        if reason in ("DOC_CONFLICT","DOC_CAPACITY"):raise HTTPException(409,reason) from None
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
    @router.post("/documents/{key}/register/{rid}")
    async def register_document(key:str,rid:str,request:Request,response:Response):
        import base64,binascii,json
        from . import naruv_inventory_review as inventory
        if not enabled():raise HTTPException(404,"DRAFT_DISABLED")
        token,csrf,_=write._request(request,key,rid,needs_digest=False)
        if preview._one_header(request,"x-naruv-confirm","")!="yes":raise HTTPException(422,"DOC_CONFIRM_REQUIRED")
        if preview._one_header(request,"content-type","")!="application/json":raise HTTPException(415,"DOC_CONTENT_TYPE")
        prior=await run_in_threadpool(write._auth,token,csrf)
        body=await preview._bounded_body(request)
        try:
            d=json.loads(body.decode("utf-8"),object_pairs_hook=inventory._pairs,parse_constant=inventory._reject_constant)
            if type(d) is not dict or set(d)!={"format","original_base64","observations"}:raise ValueError("shape")
            fmt=d["format"];encoded=d["original_base64"];obs=d["observations"]
            if type(fmt) is not str or fmt not in ("pdf","xlsx") or type(encoded) is not str or len(encoded)>699052 or type(obs) is not list:raise ValueError("shape")
            raw=base64.b64decode(encoded,validate=True)
            if not 5<=len(raw)<=524288 or base64.b64encode(raw).decode("ascii")!=encoded:raise ValueError("bytes")
            if not raw.startswith(b"%PDF-" if fmt=="pdf" else b"PK\\x03\\x04"):raise ValueError("signature")
            if len(json.dumps(obs,ensure_ascii=True,separators=(",",":")))>30000:raise ValueError("observations")
        except (ValueError,UnicodeError,RecursionError,binascii.Error):
            raise HTTPException(422,"DOC_INPUT") from None
        result=await run_in_threadpool(_admit_document,token,csrf,prior,key,rid,fmt,raw,obs)
        response.headers["Cache-Control"]="no-store"
        return result
    return router

def register_drafts(app):
    if not enabled():return False
    v90._origins();app.include_router(create_router());return True
