"""V19.4 CI-only restricted real upload and explicit review routes.

DO NOT include in the product app. Only registered on disposable PostgreSQL17
for acceptance testing; upstream source of truth (import_engine, V160, V92,
V174) remains unchanged. In production uploads require independently isolated
AV/parser workers; development-only scanner bypass is NOT release evidence.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid

from fastapi import APIRouter, FastAPI, File, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, ConfigDict, Field
import psycopg
from psycopg import errors

from app.import_engine import DocumentError, MAX_FILE_SIZE
from app.pg_import_quote_v160 import _verified_doc
from app import pg_quote_api_v92 as quote, pg_v90_integrated_entry as session
from app.security_hardening import limited_extract, sealed_json

PREFIX="/api/pg-stage/v193"
ID=re.compile(r"^[0-9a-f]{32}$")
MAX_JSON=65536

# Dedicated synthetic reviewer credential is configured only by the disposable CI
# fixture. It must NEVER be supplied to a browser, GitHub logs or business role.
_reviewer_dsn = None

def configure_disposable_approver(dsn: str) -> None:
    global _reviewer_dsn
    if (os.getenv("JW_ENV")!="test"
        or os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE"
        or type(dsn) is not str or "127.0.0.1" not in dsn
        or "jw_ci_v194_approver" not in dsn):
        raise RuntimeError("BLOCKED_V194_REVIEWER_NOT_DISPOSABLE")
    _reviewer_dsn=dsn


class Confirm(BaseModel):
    model_config=ConfigDict(extra="forbid", strict=True)
    preview_digest:str=Field(pattern=r"^[0-9a-f]{64}$")
    confirmed_customer:str=Field(min_length=1,max_length=120)
    confirmed_quote_date:str=Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    confirmed_total_krw:int=Field(ge=1,le=10**15)
    approve:bool


def enabled():
    return (os.getenv("JW_ENV")=="test" and
      os.getenv("JW_PG_CI_ALLOW")=="ONLY_EPHEMERAL_LOCAL_DATABASE" and
      "@127.0.0.1:5432/postgres" in os.getenv("JW_PG_CI_ROOT_DSN","") and
      os.getenv("JW_PG_IMPORT_QUOTE_V160")=="ISOLATED_DEV_APPROVED_IMPORT_QUOTE_ONLY" and
      session.v90_enabled() and quote.enabled() and bool(os.getenv("JW_DATA_KEY")) and bool(_reviewer_dsn))


def _identity(request: Request, cur_identity, csrf=True):
    _,actor,org,role,stored_csrf,_=cur_identity
    if role!="admin":
        raise HTTPException(403,"Only a verified administrator may approve the import")
    if csrf and (not request.headers.get("X-CSRF-Token") or not
           hmac.compare_digest(str(stored_csrf),request.headers["X-CSRF-Token"])):
        raise HTTPException(403,"Invalid CSRF")
    return actor,org


def register(app:FastAPI)->bool:
    if not enabled():
        raise RuntimeError("BLOCKED_V193_NOT_EPHEMERAL_LOCAL_PG17")
    router=APIRouter(prefix=PREFIX,tags=["CI-only-upload-review"])

    @router.post("/imports/preview",status_code=201)
    async def upload(request:Request,response:Response,file:UploadFile=File(...)):
        quote._origin_checked(request)
        with session._pg_validated_cursor(session._session_hash(request)) as (cur,ident):
            actor,org=_identity(request,ident)
            raw=await file.read(MAX_FILE_SIZE+1)
            await file.close()
            if not raw or len(raw)>MAX_FILE_SIZE:
                raise HTTPException(422,"File empty or exceeds 5MiB")
            if not (file.filename or "").lower().endswith((".xlsx",".pdf")):
                raise HTTPException(422,"Unsupported document format")
            try:
                doc=limited_extract(file.filename or "",raw)
            except (DocumentError,ValueError) as exc:
                raise HTTPException(422,"Invalid document") from None
            except RuntimeError:
                raise HTTPException(503,"Document validation unavailable") from None
            if doc.get("record_type")!="quote" or doc.get("missing_fields"):
                raise HTTPException(422,"Complete quote document required")
            digest=hashlib.sha256(json.dumps(doc,ensure_ascii=False,sort_keys=True,
                separators=(",",":"),allow_nan=False).encode()).hexdigest()
            sealed=sealed_json(doc)
            if len(sealed.encode())>MAX_JSON:
                raise HTTPException(422,"Import evidence oversized")
            file_hash=hashlib.sha256(raw).hexdigest()
            preview_id=uuid.uuid4().hex
            try:
                cur.execute("""INSERT INTO jw_dev.import_previews
                  (id,org_id,uploaded_by,file_sha256,normalized_json,
                   preview_digest,status,quote_id)
                  VALUES(%s,%s,%s,%s,%s,%s,'pending',NULL)""",
                  (preview_id,org,actor,file_hash,sealed,digest))
            except errors.UniqueViolation:
                raise HTTPException(409,"Identical source file already uploaded") from None
        response.headers["Cache-Control"]="no-store"
        return {"preview_id":preview_id,"preview_digest":digest,
                "document":doc,"ready_to_confirm":True,
                "reviewed":False,"source_bytes_persisted":False}

    @router.post("/imports/{preview_id}/confirm",status_code=200)
    def confirm(preview_id:str,payload:Confirm,request:Request,response:Response):
        if not ID.fullmatch(preview_id):
            raise HTTPException(404,"Preview unavailable")
        if payload.approve is not True:
            raise HTTPException(422,"Explicit human approval required")
        quote._origin_checked(request)
        with session._pg_validated_cursor(session._session_hash(request)) as (cur,ident):
            actor,org=_identity(request,ident)
            cur.execute("""SELECT normalized_json,preview_digest,status,
                         uploaded_by FROM jw_dev.import_previews
                         WHERE id=%s AND org_id=%s""",(preview_id,org))
            row=cur.fetchone()
            if not row:
                raise HTTPException(404,"Preview unavailable")
            sealed,digest,status,uploader=row
            if actor!=uploader:
                raise HTTPException(403,"Only original reviewer may confirm")
            if status!="pending":
                raise HTTPException(409,"Already confirmed or invalid preview")
            if not hmac.compare_digest(digest,payload.preview_digest):
                raise HTTPException(409,"Preview evidence changed")
            doc,date,items,money=_verified_doc(sealed,digest)
            if (payload.confirmed_customer!=doc["company"] or
                payload.confirmed_quote_date!=date.isoformat() or
                payload.confirmed_total_krw!=money["total"]):
                raise HTTPException(409,"Human review does not match source")
        # Source verification used business reader role. This separately
        # authenticated reviewer cannot be impersonated with SET ROLE by the
        # business login. It alone has UPDATE(status), and the update atomically
        # binds human-checked digest, tenant, actor and pending state.
        try:
            with psycopg.connect(_reviewer_dsn,connect_timeout=5) as review_db:
                login=review_db.execute("""SELECT session_user,rolsuper,rolbypassrls
                  FROM pg_catalog.pg_roles WHERE rolname=session_user""").fetchone()
                if login!=("jw_ci_v194_approver",False,False):
                    raise HTTPException(503,"Unsafe reviewer database role")
                review_db.execute(
                    "SELECT pg_catalog.set_config('jw.approval_org',%s,true)",(org,))
                review_db.execute(
                    "SELECT pg_catalog.set_config('jw.approval_actor',%s,true)",(actor,))
                updated=review_db.execute("""UPDATE jw_dev.import_previews
                     SET status='confirmed'
                     WHERE id=%s AND org_id=%s AND uploaded_by=%s
                       AND status='pending' AND preview_digest=%s
                     RETURNING id""",(preview_id,org,actor,digest)).fetchone()
                if updated!=(preview_id,):
                    raise HTTPException(409,"Concurrent or forged confirmation")
        except psycopg.Error:
            raise HTTPException(503,"Review confirmation storage unavailable") from None
        response.headers["Cache-Control"]="no-store"
        return {"preview_id":preview_id,"confirmed":True,
                "quote_posted":False,"source_digest":digest}

    app.include_router(router)
    return True
