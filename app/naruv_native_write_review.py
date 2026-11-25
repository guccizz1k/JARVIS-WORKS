"""Isolated native-session durable review transaction API, default off.

Synthetic target only. Separate stage credential and business role. No legacy
route registration or production import; no raw upload stored in this module.
"""
import asyncio
from contextlib import contextmanager
import hmac
import hashlib
import json
import os
import re

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from . import naruv_native_file_preview as preview
from . import pg_v90_integrated_entry as v90
from .erp_migration_file_stage import prepare_file_stage
from .erp_migration_mapping import MappingBlocked
from .erp_migration_preflight import make_target_snapshot

SHA = re.compile(r"[a-f0-9]{64}")
STAGE_ROLE = "naruv_native_stage"
PREFIX = preview.PREFIX
CONFLICTS = {"NARUV_TARGET_CHANGED","NARUV_STAGE_CONFLICT","NARUV_STAGE_EXPIRED",
             "NARUV_BINDING_CHANGED","NARUV_APPROVAL_TERMINAL","NARUV_APPROVAL_REQUIRED",
             "NARUV_RESERVATION_CONFLICT","NARUV_DUPLICATE_ID","COST_PERIOD_CLOSED","COST_RETURN_CONFLICT","ACCT_PERIOD_CLOSED"}
INVALID = {"NARUV_STAGE_INPUT","NARUV_CONFIRM_REQUIRED","NARUV_ROWS_INVALID",
           "NARUV_TARGET_INVALID","NARUV_CAPACITY"}

def enabled():
    return (os.getenv("NARUV_NATIVE_WRITE_REVIEW") == "ISOLATED_SYNTHETIC_ONLY"
            and preview.enabled())

def _ingest_connect():
    if not enabled():
        raise HTTPException(404,"WRITE_REVIEW_DISABLED")
    dsn = os.getenv("NARUV_NATIVE_STAGE_DSN","")
    if not dsn or dsn in (os.getenv("JW_PG_STAGE_DSN"),os.getenv("JW_PG_AUTH_STAGE_DSN")):
        raise HTTPException(503,"SEPARATE_STAGE_LOGIN_REQUIRED")
    import psycopg
    return psycopg.connect(dsn,connect_timeout=5,sslmode="verify-full")

@contextmanager
def _ingest_cursor(token_hash,csrf,prior):
    if not enabled():
        raise HTTPException(404,"WRITE_REVIEW_DISABLED")
    with _ingest_connect() as db:
        with db.transaction(),db.cursor() as cur:
            cur.execute("""SELECT session_user,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,
                         pg_has_role(session_user,'jw_app_dev','MEMBER'),
                         pg_has_role(session_user,'jw_auth_stage_v85','MEMBER'),
                         pg_has_role(session_user,'naruv_native_owner','MEMBER'),
                         pg_has_role(session_user,'naruv_native_stage','MEMBER')
                         FROM pg_catalog.pg_roles WHERE rolname=session_user""")
            r=cur.fetchone()
            if not r or any(r[1:8]) or r[8] is not True or r[0] in (
                "postgres","supabase_admin","service_role","naruv_native_owner",
                "naruv_native_stage","jw_app_dev","jw_auth_stage_v85"):
                raise HTTPException(503,"UNSAFE_STAGE_LOGIN")
            cur.execute("SET LOCAL ROLE naruv_native_stage")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            cur.execute("SELECT pg_catalog.set_config('jw.session_hash',%s,true)",(token_hash,))
            cur.execute("""SELECT current_user,actor_id,org_id,actor_role,csrf_token,org_name
                           FROM jw_dev.stage_identity_v84()""")
            identity=cur.fetchone()
            if not identity or len(identity)!=6 or identity[0]!=STAGE_ROLE or not all(identity[1:]):
                raise HTTPException(401,"SESSION_INVALID")
            if identity[3]!="admin" or type(identity[4]) is not str or not identity[4].isascii() or not hmac.compare_digest(identity[4],csrf):
                raise HTTPException(403,"IMPORT_ADMIN_REQUIRED")
            if (identity[1],identity[2])!=prior:
                raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            yield cur,identity[2]

def _db_error(exc):
    reason=getattr(getattr(exc,"diag",None),"message_primary","")
    if reason=="NARUV_PERMISSION_DENIED":
        return HTTPException(403,reason)
    if reason in ("NARUV_STAGE_MISSING","NARUV_SOURCE_NOT_FOUND"):
        return HTTPException(404,reason)
    if reason in CONFLICTS or getattr(exc,"sqlstate",None)=="23505":
        return HTTPException(409,reason if reason in CONFLICTS else "NARUV_CONFLICT")
    if reason in INVALID:
        return HTTPException(422,reason)
    return HTTPException(503,"NARUV_TRANSACTION_UNAVAILABLE")

def _auth(token_hash,csrf):
    import psycopg
    try:
        return preview._authorize(token_hash,csrf)
    except psycopg.Error as exc:
        raise _db_error(exc) from None

def _stage(token_hash,csrf,prior,source,entity,fmt,stage_id,digests,raw):
    digest,canonical,snapshot=digests
    import psycopg
    try:
        with _ingest_cursor(token_hash,csrf,prior) as (cur,org):
            cur.execute("SELECT * FROM naruv_native_review.read_source(%s,%s,%s)",(source,entity,csrf))
            row=cur.fetchone()
            if not row:
                raise HTTPException(404,"SOURCE_NOT_FOUND")
            target=make_target_snapshot(org,source,entity,row[0],row[1])
            candidate=prepare_file_stage(raw,format=fmt,organization_id=org,source_id=source,entity=entity,target=target)
            if not hmac.compare_digest(candidate.stage_sha256,digest) or not hmac.compare_digest(target.snapshot_sha256,snapshot):
                raise HTTPException(409,"NARUV_PREVIEW_CHANGED")
            rows=json.dumps([dict(x) for x in candidate.canonical_rows],ensure_ascii=False,sort_keys=True,separators=(",",":"))
            if not hmac.compare_digest(hashlib.sha256(rows.encode('utf-8')).hexdigest(),canonical):
                raise HTTPException(409,"NARUV_PREVIEW_CHANGED")
            cur.execute("""SELECT naruv_native_review.store_stage(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (stage_id,source,entity,fmt,candidate.raw_sha256,candidate.byte_count,digest,canonical,
                         candidate.preflight.rows_sha256,snapshot,target.revision,
                         list(target.existing_source_ids),rows,csrf))
            result=cur.fetchone()
            if not result or result[0] not in ("STAGED","ALREADY_STAGED"):
                raise HTTPException(503,"NARUV_TRANSACTION_UNAVAILABLE")
            return {"status":result[0],"stage_id":stage_id,"stage_sha256":digest,
                    "canonical_rows_sha256":canonical,"target_snapshot_sha256":snapshot,
                    "row_count":candidate.preflight.row_count,"row_import_authorized":False}
    except MappingBlocked as exc:
        reason=str(exc)
        raise HTTPException(422,reason if re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}",reason) else "FILE_REJECTED") from None
    except psycopg.Error as exc:
        raise _db_error(exc) from None

def _control(token_hash,csrf,prior,action,stage_id,digests=None,reservation=None):
    digest,canonical,snapshot=digests or (None,None,None)
    import psycopg
    if not enabled():
        raise HTTPException(404,"WRITE_REVIEW_DISABLED")
    try:
        with v90._pg_validated_cursor(token_hash) as (cur,identity):
            if preview._verify_identity(identity,csrf)!=prior:
                raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("SELECT pg_has_role(session_user,'naruv_native_stage','MEMBER'),pg_has_role(session_user,'naruv_native_owner','MEMBER')")
            if cur.fetchone()!=(False,False):
                raise HTTPException(503,"UNSAFE_BUSINESS_LOGIN")
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            if action=="approve":
                cur.execute("SELECT naruv_native_review.approve(%s,%s,%s,%s,true,%s)",(stage_id,digest,canonical,snapshot,csrf))
            elif action=="revoke":
                cur.execute("SELECT naruv_native_review.revoke(%s,%s,%s,%s,%s)",(stage_id,digest,canonical,snapshot,csrf))
            elif action=="commit":
                cur.execute("SELECT naruv_native_review.commit_stage(%s,%s,%s,%s,%s,%s)",(stage_id,digest,canonical,snapshot,reservation,csrf))
            elif action=="inspect":
                cur.execute("SELECT naruv_native_review.inspect(%s,%s,%s)",(stage_id,reservation,csrf))
            else:
                raise RuntimeError("UNRECOGNIZED_CONTROL")
            row=cur.fetchone()
            if not row:
                raise HTTPException(503,"NARUV_TRANSACTION_UNAVAILABLE")
            if action in ("commit","inspect"):
                if type(row[0]) is not dict or row[0].get("row_import_authorized") is not False:
                    raise HTTPException(503,"NARUV_RECEIPT_INVALID")
                return row[0]
            allowed=("APPROVED","ALREADY_APPROVED") if action=="approve" else ("REVOKED","ALREADY_REVOKED")
            if row[0] not in allowed:
                raise HTTPException(503,"NARUV_TRANSACTION_UNAVAILABLE")
            return {"status":row[0],"stage_id":stage_id,"row_import_authorized":False}
    except psycopg.Error as exc:
        raise _db_error(exc) from None

def _request(request,stage_id,reservation=None,needs_digest=True):
    if not enabled():
        raise HTTPException(404,"WRITE_REVIEW_DISABLED")
    if request.query_params or not preview.IDENT.fullmatch(stage_id) or (reservation is not None and not preview.IDENT.fullmatch(reservation)):
        raise HTTPException(422,"INVALID_STAGE_SCOPE")
    if request.url.scheme!="https" or preview._one_header(request,"origin") not in v90._origins():
        raise HTTPException(403,"ORIGIN_DENIED")
    csrf=preview._one_header(request,"x-csrf-token","")
    if not csrf or len(csrf)>512 or not csrf.isascii():
        raise HTTPException(403,"INVALID_CSRF")
    digests=tuple(preview._one_header(request,name,"") for name in
        ("x-naruv-stage-digest","x-naruv-canonical-digest","x-naruv-target-digest"))
    if needs_digest and not all(SHA.fullmatch(d) for d in digests):
        raise HTTPException(422,"INVALID_STAGE_DIGEST")
    if preview._one_header(request,"content-encoding","identity")!="identity":
        raise HTTPException(415,"ENCODING_UNSUPPORTED")
    return v90._session_hash(request),csrf,digests

async def _empty_body(request):
    if preview._one_header(request,"content-length","0")!="0":
        raise HTTPException(413,"CONTROL_BODY_NOT_ALLOWED")
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if chunk:
                    raise HTTPException(413,"CONTROL_BODY_NOT_ALLOWED")
    except TimeoutError:
        raise HTTPException(408,"UPLOAD_TIMEOUT") from None
    except ClientDisconnect:
        raise HTTPException(400,"UPLOAD_INCOMPLETE") from None

def create_router():
    router=APIRouter(prefix=PREFIX,tags=["NARUV isolated native write review"])
    @router.post("/sources/{source}/{entity}/{fmt}/stages/{stage_id}")
    async def stage(source:str,entity:str,fmt:str,stage_id:str,request:Request,response:Response):
        token,csrf,digests=_request(request,stage_id)
        if not preview.IDENT.fullmatch(source) or entity not in ("item","customer") or fmt not in preview.FORMATS:
            raise HTTPException(422,"INVALID_STAGE_SCOPE")
        if preview._one_header(request,"content-type","")!=preview.FORMATS[fmt]:
            raise HTTPException(415,"FILE_CONTENT_TYPE")
        prior=await run_in_threadpool(_auth,token,csrf)
        raw=await preview._bounded_body(request)
        result=await run_in_threadpool(_stage,token,csrf,prior,source,entity,fmt,stage_id,digests,raw)
        response.headers["Cache-Control"]="no-store"
        return result
    async def operation(action,stage_id,request,response,reservation=None):
        token,csrf,digests=_request(request,stage_id,reservation,needs_digest=action!="inspect")
        if action=="approve" and preview._one_header(request,"x-naruv-confirm","")!="yes":
            raise HTTPException(422,"NARUV_CONFIRM_REQUIRED")
        prior=await run_in_threadpool(_auth,token,csrf)
        await _empty_body(request)
        result=await run_in_threadpool(_control,token,csrf,prior,action,stage_id,digests,reservation)
        response.headers["Cache-Control"]="no-store"
        return result
    @router.post("/stages/{stage_id}/approve")
    async def approve(stage_id:str,request:Request,response:Response):
        return await operation("approve",stage_id,request,response)
    @router.post("/stages/{stage_id}/revoke")
    async def revoke(stage_id:str,request:Request,response:Response):
        return await operation("revoke",stage_id,request,response)
    @router.post("/stages/{stage_id}/commit/{reservation_id}")
    async def commit(stage_id:str,reservation_id:str,request:Request,response:Response):
        return await operation("commit",stage_id,request,response,reservation_id)
    @router.post("/stages/{stage_id}/receipt/{reservation_id}")
    async def inspect(stage_id:str,reservation_id:str,request:Request,response:Response):
        return await operation("inspect",stage_id,request,response,reservation_id)
    return router

def register_native_write_review(app):
    if not enabled():
        return False
    v90._origins()
    app.include_router(create_router())
    return True
