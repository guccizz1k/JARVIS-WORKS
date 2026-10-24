"""V9.2 opt-in PostgreSQL quote CREATE endpoint, isolated development only.

Not registered on app.main, not a production migration or SQLite fallback.
A verified PostgreSQL session and tenant-bound role are required every request.
All inserts, line items and audit record commit atomically. The existing
idx_quotes_source_import unique index handles concurrent idempotent retries.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import pg_v90_integrated_entry as v90

_MODE = "ISOLATED_DEV_QUOTE_V92"
_PREFIX = "/api/pg-stage/v92"
_MAX_SUBTOTAL = 40 * 100000 * 1000000000  # Existing app.main maximum


class QuoteItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=150)
    quantity: int = Field(ge=1, le=100000)
    unit_price: int = Field(ge=0, le=1000000000)

    @field_validator('name')
    @classmethod
    def nonempty_item_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Item name is required')
        return value.strip()


class QuoteDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    request_id: str = Field(pattern=r"^[A-Za-z0-9_-]{8,100}$")
    customer_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=150)
    vat_mode: str = Field(pattern=r"^(taxable|exempt)$")
    items: list[QuoteItem] = Field(min_length=1, max_length=40)

    @field_validator('title')
    @classmethod
    def nonempty_quote_title(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Quote title is required')
        return value.strip()


def enabled() -> bool:
    return (
        os.environ.get("JW_PG_QUOTE_V92") == _MODE
        and v90.v90_enabled()
        and os.environ.get("JW_ENV", "").lower() in ("dev", "development", "test")
        and os.environ.get("JW_INSECURE_LOCAL_DEV") != "1"
    )


def quote_money(items: list[QuoteItem], vat_mode: str) -> dict[str, int]:
    subtotal = sum(item.quantity * item.unit_price for item in items)
    if subtotal > _MAX_SUBTOTAL:
        raise HTTPException(422, "Quote amount exceeds safety limit")
    vat = (subtotal + 5) // 10 if vat_mode == "taxable" else 0
    return {"subtotal": subtotal, "vat": vat, "total": subtotal + vat}


def _fingerprint(payload: QuoteDraft) -> str:
    value = payload.model_dump(exclude={"request_id"})
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _origin_checked(request: Request) -> None:
    origin = request.headers.get("origin", "")
    if origin not in v90._origins():
        raise HTTPException(403, "Cross-origin mutation forbidden")


def create_quote(request: Request, payload: QuoteDraft, response: Response) -> dict:
    if not enabled():
        raise HTTPException(404, "PostgreSQL quote writer disabled")
    _origin_checked(request)
    session_hash = v90._session_hash(request)
    finance = quote_money(payload.items, payload.vat_mode)
    digest = _fingerprint(payload)

    # _pg_validated_cursor always derives org/actor/CSRF from PostgreSQL,
    # never from a request JSON field; it re-verifies session and delegated role.
    with v90._pg_validated_cursor(session_hash) as (cur, identity):
        _, actor, org, _, csrf, _ = identity
        client_csrf = request.headers.get("X-CSRF-Token", "")
        if not client_csrf or not hmac.compare_digest(str(csrf), client_csrf):
            raise HTTPException(403, "Invalid CSRF token")

        cur.execute(
            "SELECT name FROM jw_dev.customers WHERE id=%s AND org_id=%s",
            (payload.customer_id, org),
        )
        customer = cur.fetchone()
        if not customer:
            raise HTTPException(404, "Customer not found in tenant")

        # source_import_id is already UNIQUE in the existing V9.0 PG schema.
        # Hashing the tenant along with the caller-supplied request ID prevents
        # identifier clashes across two companies.
        idem_key = "v92:" + hashlib.sha256(
            (str(org) + "\x00" + payload.request_id).encode("utf-8")
        ).hexdigest()
        quote_id = uuid.uuid4().hex
        stamp = datetime.now(ZoneInfo("Asia/Seoul")).isoformat(timespec="seconds")
        doc_no = "Q-" + datetime.now(ZoneInfo("Asia/Seoul")).strftime("%Y%m%d") + "-" + quote_id[:10].upper()
        meta = json.dumps({"source": "pg-v92", "digest": digest}, separators=(",", ":"))
        cur.execute(
            """INSERT INTO jw_dev.quotes
              (id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,
               vat_mode,created_at,updated_at,source_import_id,source_document_meta)
              VALUES (%s,%s,%s,%s,%s,%s,'draft',%s,%s,%s,%s,%s)
              ON CONFLICT (source_import_id) DO NOTHING RETURNING id""",
            (quote_id, org, payload.customer_id, customer[0], doc_no,
             payload.title.strip(), payload.vat_mode, stamp, stamp, idem_key, meta),
        )
        inserted = cur.fetchone()
        if not inserted:
            # This is a new SQL statement after ON CONFLICT resolution, so a
            # concurrent winner is visible at READ COMMITTED after its commit.
            cur.execute(
                """SELECT id,source_document_meta
                   FROM jw_dev.quotes WHERE source_import_id=%s AND org_id=%s""",
                (idem_key, org),
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(409, "Unable to reconcile duplicate request")
            try:
                same = json.loads(existing[1]).get("digest") == digest
            except (TypeError, ValueError, AttributeError):
                same = False
            if not same:
                raise HTTPException(409, "Request ID reused for different quote")
            response.headers["Cache-Control"] = "no-store"
            return {"quote_id": existing[0], "created": False, "money": finance}

        for position, item in enumerate(payload.items):
            cur.execute(
                """INSERT INTO jw_dev.quote_items
                   (id,quote_id,name,quantity,unit_price,position)
                   VALUES (%s,%s,%s,%s,%s,%s)""",
                (uuid.uuid4().hex, quote_id, item.name.strip(),
                 item.quantity, item.unit_price, position),
            )
        cur.execute(
            """INSERT INTO jw_dev.audit_logs
               (id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
               VALUES (%s,%s,%s,'quote',%s,'create',%s,%s)""",
            (uuid.uuid4().hex, org, actor, quote_id,
             '{"source":"postgres_stage_v92"}', stamp),
        )
    response.status_code = 201
    response.headers["Cache-Control"] = "no-store"
    return {"quote_id": quote_id, "created": True, "money": finance}


def create_router() -> APIRouter:
    router = APIRouter(prefix=_PREFIX, tags=["PG quote create (isolated only)"])
    router.add_api_route("/quotes", create_quote, methods=["POST"], response_model=None)
    return router


def register_v92_quote_api(app: FastAPI) -> bool:
    if not enabled():
        return False
    # Explicit origin configuration validated before route registration.
    v90._origins()
    app.include_router(create_router())
    return True
