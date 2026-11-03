"""V19.9 CI-only exact DEV-shape restricted real upload and explicit review routes.

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
from datetime import datetime,timezone

from fastapi import APIRouter, FastAPI, File, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, ConfigDict, Field
import psycopg
from psycopg import errors
from psycopg.conninfo import conninfo_to_dict

from app.import_engine import DocumentError, MAX_FILE_SIZE
from app.pg_import_quote_v160 import _verified_doc
from app import pg_quote_api_v92 as quote, pg_v90_integrated_entry as session
from app.security_hardening import limited_extract, sealed_json

PREFIX="/api/pg-stage/v199"
ID=re.compile(r"^[0-9a-f]{32}$")
MAX_JSON=65536

# Dedicated synthetic reviewer credential is configured only by the disposable CI
# fixture. It must NEVER be supplied to a browser, GitHub logs or business role.
_reviewer_dsn = None
_approval_key = None
_writer_dsn = None

def _ci_local_dsn(raw: str, expected_role: str) -> bool:
    """Fail closed: exact parsed local role/host/port/database, no alternate target."""
    if type(raw) is not str:
        return False
    try:
        info = conninfo_to_dict(raw)
    except (ValueError, psycopg.ProgrammingError):
        return False
    allowed = {"host", "port", "dbname", "user", "password",
               "sslmode", "connect_timeout"}
    return (
        set(info).issubset(allowed)
        and info.get("user") == expected_role
        and info.get("host") == "127.0.0.1"
        and info.get("port", "5432") == "5432"
        and info.get("dbname") == "postgres"
    )


def configure_disposable_writer(dsn:str)->None:
    global _writer_dsn
    if (os.getenv("JW_ENV")!="test"
        or os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE"
        or not _ci_local_dsn(dsn, "jw_ci_v199_import_writer")):
        raise RuntimeError("BLOCKED_V199_WRITER_NOT_DISPOSABLE")
    _writer_dsn=dsn


def configure_disposable_approver(dsn: str, key: bytes) -> None:
    global _reviewer_dsn, _approval_key
    if (os.getenv("JW_ENV")!="test"
        or os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE"
        or not _ci_local_dsn(dsn, "jw_ci_v194_approver")
        or type(key) is not bytes or len(key)!=32):
        raise RuntimeError("BLOCKED_V194_REVIEWER_NOT_DISPOSABLE")
    _reviewer_dsn=dsn
    _approval_key=key

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
      _ci_local_dsn(os.getenv("JW_PG_CI_ROOT_DSN",""), "postgres") and
      os.getenv("JW_PG_IMPORT_QUOTE_V160")=="ISOLATED_DEV_APPROVED_IMPORT_QUOTE_ONLY" and
      session.v90_enabled() and quote.enabled() and bool(os.getenv("JW_DATA_KEY")) and bool(_reviewer_dsn) and bool(_approval_key) and bool(_writer_dsn))


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
            name=(file.filename or "")
            # Reject path traversal, backslash and control characters, rather
            # than silently laundering untrusted source filenames.
            if (not 5<=len(name)<=120 or "/" in name or "\\" in name
                or any(ord(ch)<32 or ord(ch)==127 for ch in name)
                or not name.lower().endswith((".xlsx",".pdf"))):
                raise HTTPException(422,"Unsafe or unsupported filename")
            try:
                doc=limited_extract(name,raw)
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
            stamp=datetime.now(timezone.utc).isoformat(timespec="seconds")
            try:
                with psycopg.connect(_writer_dsn,connect_timeout=5) as writer:
                    principal=writer.execute("""SELECT session_user,rolsuper,rolbypassrls
                       FROM pg_catalog.pg_roles
                       WHERE rolname=session_user""").fetchone()
                    if principal!=("jw_ci_v199_import_writer",False,False):
                        raise HTTPException(503,"Untrusted import DB login")
                    # Verified original cookie token hash is the only session
                    # authorization input; RLS resolves tenant and actor from
                    # the existing DB sessions rather than freeform org GUCs.
                    writer.execute("""SELECT pg_catalog.set_config(
                         'jw.session_hash',%s,true)""",
                         (session._session_hash(request),))
                    verified=writer.execute("""SELECT
                       jw_dev.current_org_from_session(),
                       jw_dev.current_actor_from_session_v82()""").fetchone()
                    if verified!=(org,actor):
                        raise HTTPException(403,"Import writer session mismatch")
                    writer.execute("""SELECT pg_catalog.pg_advisory_xact_lock(
                         pg_catalog.hashtextextended(%s,0))""",
                         ("v199:"+org+":"+file_hash,))
                    exists=writer.execute("""SELECT status
                         FROM jw_dev.import_previews
                         WHERE org_id=%s AND file_sha256=%s LIMIT 1""",
                         (org,file_hash)).fetchone()
                    if exists:
                        raise HTTPException(409,"Identical source already registered")
                    writer.execute("""INSERT INTO jw_dev.import_previews
                      (id,org_id,uploaded_by,file_sha256,filename,normalized_json,
                       preview_digest,status,created_at)
                      VALUES(%s,%s,%s,%s,%s,%s,%s,'pending',%s)""",
                      (preview_id,org,actor,file_hash,name,sealed,digest,stamp))
            except errors.UniqueViolation:
                raise HTTPException(409,"Identical source already registered") from None
            except (errors.InsufficientPrivilege,errors.UndefinedColumn):
                raise HTTPException(503,"Import write permissions unavailable") from None
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
                # One-use signed server statement. A caller holding only the
                # reviewer DB credential cannot synthesize this signature.
                facts={"schema":"jw-import-approval-v195","preview_id":preview_id,
                       "org_id":org,"actor_id":actor,"preview_digest":digest,
                       "approved":True,"company":payload.confirmed_customer,
                       "quote_date":payload.confirmed_quote_date,
                       "total_krw":payload.confirmed_total_krw}
                statement=json.dumps(facts,ensure_ascii=False,sort_keys=True,
                    separators=(",",":"),allow_nan=False)
                signature=hmac.new(_approval_key,statement.encode("utf-8"),
                    hashlib.sha256).hexdigest()
                approval_id=uuid.uuid4().hex
                # Stored function executes UPDATE + INSERT in a single
                # transaction. Bad signature or a receipt collision rolls
                # BOTH writes back, without a confirmed-without-receipt row.
                result=review_db.execute("""SELECT jw_dev.v195_confirm_import(
                   %s,%s,%s,%s,%s,%s,%s)""",(
                   preview_id,org,actor,digest,statement,signature,approval_id
                )).fetchone()
                if result!=(approval_id,):
                    raise HTTPException(503,"Approval receipt not committed")
        except psycopg.Error:
            raise HTTPException(409,"Approval denied or already recorded") from None
        response.headers["Cache-Control"]="no-store"
        return {"preview_id":preview_id,"confirmed":True,
                "quote_posted":False,"source_digest":digest,
                "approval_receipt_id":approval_id,
                "receipt_statement_sha256":hashlib.sha256(statement.encode("utf-8")).hexdigest()}

    app.include_router(router)
    return True
