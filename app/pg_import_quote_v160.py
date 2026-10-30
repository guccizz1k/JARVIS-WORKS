"""Opt-in V16.0 PG quote from an already human-confirmed import preview.

This does NOT upload/scan/OCR a document: the existing restricted import engine
owns parsing and explicit user review. A migrated, independently checked, tenant-
bound confirmed preview may become ONE PG quote draft with atomic items/audit.
No new customer is silently registered, and no order/invoice/payment is posted.
"""
from __future__ import annotations

from datetime import date, datetime
from zoneinfo import ZoneInfo
import hashlib
import hmac
import json
import os
import re
import uuid

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from psycopg import errors

from . import pg_quote_api_v92 as quote
from . import pg_v90_integrated_entry as sessions
from .security_hardening import sealed_json, unseal_json

_PREFIX="/api/pg-stage/v160"
_MODE="ISOLATED_DEV_APPROVED_IMPORT_QUOTE_ONLY"
_ID=re.compile(r"^[a-f0-9]{32}$")
_SHA=re.compile(r"^[a-f0-9]{64}$")
_MAX_NORM_BYTES=65536

class ReviewedQuoteImport(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    preview_digest: str=Field(pattern=r"^[a-f0-9]{64}$")
    customer_id: str=Field(pattern=r"^[a-f0-9]{32}$")
    reviewed: bool=Field()
    confirmed_customer: str=Field(min_length=1,max_length=120)
    confirmed_quote_date: date
    confirmed_total_krw: int=Field(ge=1,le=10**15)


def enabled():
    return (os.getenv("JW_PG_IMPORT_QUOTE_V160")==_MODE
            and os.getenv("JW_DATA_KEY")
            and quote.enabled() and sessions.v90_enabled()
            and os.getenv("JW_ENV","").lower() in ("dev","development","test")
            and os.getenv("JW_INSECURE_LOCAL_DEV")!="1")


def _verified_doc(raw: str, stored_digest: str):
    if type(raw) is not str or len(raw.encode("utf-8"))>_MAX_NORM_BYTES:
        raise HTTPException(409,"Import evidence missing or oversized")
    try:
        doc=unseal_json(raw)
        digest=hashlib.sha256(json.dumps(doc,sort_keys=True,
            ensure_ascii=False,separators=(",",":"),allow_nan=False
        ).encode("utf-8")).hexdigest()
    except (RuntimeError,ValueError,UnicodeError,TypeError):
        raise HTTPException(503,"Verified document evidence unavailable") from None
    if (not isinstance(doc,dict) or not isinstance(stored_digest,str)
        or not _SHA.fullmatch(stored_digest)
        or not hmac.compare_digest(stored_digest,digest)
        or doc.get("record_type")!="quote" or doc.get("currency")!="KRW"
        or doc.get("missing_fields")
        or type(doc.get("company")) is not str or not doc["company"].strip()
        or type(doc.get("title")) is not str or not doc["title"].strip()
        or len(doc["title"])>150 or len(doc["company"])>120
        or doc.get("vat_mode") not in ("taxable","exempt")
        or type(doc.get("items")) is not list or not 1<=len(doc["items"])<=40):
        raise HTTPException(409,"Import preview requires manual re-review")
    try:
        day=date.fromisoformat(doc["quote_date"])
    except (ValueError,TypeError,KeyError):
        raise HTTPException(409,"Invalid quote date") from None
    lines=[]
    for row in doc["items"]:
        if not isinstance(row,dict):
            raise HTTPException(409,"Invalid imported item")
        name,qty,price,total=(row.get(k) for k in
                              ("name","quantity","unit_price","line_total"))
        if (type(name) is not str or not name.strip() or len(name)>150
            or type(qty) is not int or not 1<=qty<=100000
            or type(price) is not int or not 0<=price<=1000000000
            or type(total) is not int or total!=qty*price):
            raise HTTPException(409,"Imported line mismatch")
        lines.append((name.strip(),qty,price))
    subtotal=sum(q*p for _,q,p in lines)
    vat=(subtotal+5)//10 if doc["vat_mode"]=="taxable" else 0
    money=doc.get("money")
    if (subtotal<=0 or subtotal>quote._MAX_SUBTOTAL
        or type(money) is not dict
        or {k:money.get(k) for k in ("subtotal","vat","total")}!=
            {"subtotal":subtotal,"vat":vat,"total":subtotal+vat}):
        raise HTTPException(409,"Imported money mismatch")
    return doc,day,lines,money


def create_quote_from_confirmed_import(
    preview_id: str, payload: ReviewedQuoteImport,
    request: Request, response: Response,
):
    if not enabled():
        raise HTTPException(404,"Import conversion unavailable")
    if not _ID.fullmatch(preview_id):
        raise HTTPException(404,"Import preview not found")
    if payload.reviewed is not True:
        raise HTTPException(422,"Explicit review is required")
    quote._origin_checked(request)
    session_hash=sessions._session_hash(request)
    try:
        with sessions._pg_validated_cursor(session_hash) as (cur,identity):
            _,actor,org,actor_role,csrf,_=identity
            if (not request.headers.get("X-CSRF-Token") or
                not hmac.compare_digest(str(csrf),request.headers["X-CSRF-Token"])):
                raise HTTPException(403,"Invalid CSRF token")
            # Lock by immutable preview ID; no UPDATE grant required.
            cur.execute(
              "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(%s,0))",
              ("v160:"+preview_id,))
            cur.execute("""SELECT normalized_json,preview_digest,status,
                                  quote_id,uploaded_by,file_sha256
                           FROM jw_dev.import_previews
                           WHERE id=%s AND org_id=%s""",(preview_id,org))
            row=cur.fetchone()
            if row is None:
                raise HTTPException(404,"Import preview not found")
            encoded,digest,status,linked,uploader,filehash=row
            if status!="confirmed" or linked is not None or (
                actor_role!="admin" and actor!=uploader):
                raise HTTPException(409,"Import cannot be converted")
            if (type(filehash) is not str or not _SHA.fullmatch(filehash)):
                raise HTTPException(409,"Source file hash unavailable")
            if not hmac.compare_digest(digest,payload.preview_digest):
                raise HTTPException(409,"Preview changed; review again")
            doc,day,lines,money=_verified_doc(encoded,digest)
            if (payload.confirmed_customer!=doc["company"] or
                payload.confirmed_quote_date!=day or
                payload.confirmed_total_krw!=money["total"]):
                raise HTTPException(409,"User confirmation differs from source")
            cur.execute("""SELECT count(*) FROM jw_dev.import_previews
                           WHERE org_id=%s AND file_sha256=%s
                             AND status='confirmed'""",(org,filehash))
            if cur.fetchone()!=(1,):
                raise HTTPException(409,"Duplicate source file needs review")
            cur.execute("""SELECT name,business_number FROM jw_dev.customers
                           WHERE id=%s AND org_id=%s""",(payload.customer_id,org))
            customer=cur.fetchone()
            if not customer or customer[0]!=doc["company"] or (
                doc.get("business_number") and
                customer[1]!=doc["business_number"]):
                raise HTTPException(409,"Source customer mismatch")
            import_key="v160:"+org+":"+preview_id
            quote_id=uuid.uuid4().hex
            stamp=datetime.now(ZoneInfo("Asia/Seoul")).isoformat(timespec="seconds")
            cur.execute("""INSERT INTO jw_dev.quotes
                (id,org_id,customer_id,customer_name_snapshot,doc_no,
                 title,status,vat_mode,created_at,updated_at,quote_date,
                 source_import_id,source_document_meta)
                VALUES(%s,%s,%s,%s,%s,%s,'draft',%s,%s,%s,%s,%s,%s)
                ON CONFLICT (source_import_id) DO NOTHING RETURNING id""",
                (quote_id,org,payload.customer_id,doc["company"],
                 "Q-"+stamp[:10].replace("-","")+"-"+quote_id[:10].upper(),
                 doc["title"],doc["vat_mode"],stamp,stamp,day.isoformat(),
                 import_key,sealed_json(doc)))
            result=cur.fetchone()
            if not result:
                # Duplicate from same immutable approved import, never repeat
                # the audit or line items.
                cur.execute("""SELECT id,source_document_meta FROM jw_dev.quotes
                               WHERE org_id=%s AND source_import_id=%s""",
                               (org,import_key))
                existing=cur.fetchone()
                if not existing:
                    raise HTTPException(409,"Import idempotency conflict")
                try:
                    saved=unseal_json(existing[1])
                except (RuntimeError,ValueError,TypeError):
                    raise HTTPException(503,"Existing source unavailable") from None
                if saved!=doc:
                    raise HTTPException(409,"Source mutation conflict")
                response.headers["Cache-Control"]="no-store"
                return {"quote_id":existing[0],"created":False,
                        "draft_only":True,"approval_posted":False,"money":money}
            for position,(name,qty,price) in enumerate(lines):
                cur.execute("""INSERT INTO jw_dev.quote_items
                    (id,quote_id,name,quantity,unit_price,position)
                    VALUES(%s,%s,%s,%s,%s,%s)""",
                    (uuid.uuid4().hex,quote_id,name,qty,price,position))
            cur.execute("""INSERT INTO jw_dev.audit_logs
                (id,org_id,actor_id,entity_type,entity_id,action,
                 detail,created_at)
                VALUES(%s,%s,%s,'quote',%s,'approved_import_to_draft',
                       %s,%s)""",
                (uuid.uuid4().hex,org,actor,quote_id,
                 json.dumps({"preview_id":preview_id,
                             "preview_digest":digest,
                             "source_file_sha256":filehash},
                            separators=(",",":"),sort_keys=True),stamp))
    except (errors.InsufficientPrivilege,errors.UndefinedTable):
        raise HTTPException(503,"Import conversion storage unavailable") from None
    response.status_code=201
    response.headers["Cache-Control"]="no-store"
    return {"quote_id":quote_id,"created":True,"draft_only":True,
            "approval_posted":False,"money":money}


def register_v160_pg_import_quote(app: FastAPI) -> bool:
    requested=os.getenv("JW_PG_IMPORT_QUOTE_V160","")
    if not requested:return False
    if not enabled():raise RuntimeError("BLOCKED: unsafe import conversion opt-in")
    router=APIRouter(prefix=_PREFIX,tags=["review-only imported quote draft"])
    router.add_api_route("/imports/{preview_id}/quote-draft",
                         create_quote_from_confirmed_import,
                         methods=["POST"],response_model=None)
    app.include_router(router)
    return True
