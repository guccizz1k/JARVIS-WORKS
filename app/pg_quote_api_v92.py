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
from typing import Literal
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



# A reviewed quote creates a *draft*, never an approved order or payment.
class OrderFromQuote(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    request_id: str = Field(pattern=r"^[A-Za-z0-9_-]{8,100}$")
    quote_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    original_checked: Literal[True]


def create_order_draft(request: Request, payload: OrderFromQuote,
                       response: Response) -> dict:
    if not enabled():
        raise HTTPException(404, "PostgreSQL draft conversion disabled")
    _origin_checked(request)
    with v90._pg_validated_cursor(v90._session_hash(request)) as (cur, identity):
        _, actor, org, _, csrf, _ = identity
        if not hmac.compare_digest(str(csrf), request.headers.get("X-CSRF-Token", "")):
            raise HTTPException(403, "Invalid CSRF")
        cur.execute("""SELECT customer_id,customer_name_snapshot,doc_no,title,
                              status,vat_mode FROM jw_dev.quotes
                       WHERE id=%s AND org_id=%s""", (payload.quote_id, org))
        quote = cur.fetchone()
        if not quote:
            raise HTTPException(404, "Quote absent for this company")
        customer, customer_name, quote_no, title, state, vat_mode = quote
        if state not in ("draft", "sent") or vat_mode not in ("taxable", "exempt"):
            raise HTTPException(409, "Quote state invalid for draft conversion")
        cur.execute("""SELECT id,name,quantity,unit_price,position
                       FROM jw_dev.quote_items WHERE quote_id=%s
                       ORDER BY position,id""", (payload.quote_id,))
        lines = cur.fetchall()
        if not 1 <= len(lines) <= 40 or any(
            type(qty) is not int or not 1 <= qty <= 100000
            or type(price) is not int or not 0 <= price <= 1000000000
            or type(pos) is not int or pos != i
            or not isinstance(name, str) or not name.strip() or len(name) > 150
            for i, (_, name, qty, price, pos) in enumerate(lines)
        ):
            raise HTTPException(409, "Source quote lines cannot be verified")
        subtotal = sum(qty * price for _, _, qty, price, _ in lines)
        if subtotal > _MAX_SUBTOTAL:
            raise HTTPException(409, "Source quote total cannot be verified")
        vat = (subtotal + 5) // 10 if vat_mode == "taxable" else 0
        amount = {"subtotal": subtotal, "vat": vat, "total": subtotal + vat}
        source = [payload.quote_id, customer, quote_no, title, state,
                  vat_mode, [list(line) for line in lines], amount]
        source_sha = hashlib.sha256(json.dumps(
            source, ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        key = "v127:" + hashlib.sha256(
            (str(org) + "\x00" + payload.request_id).encode("utf-8")).hexdigest()
        metadata = json.dumps({"kind": "reviewed_quote_to_order_draft",
                               "source_sha256": source_sha, "request_key": key,
                               "original_checked": True},
                              sort_keys=True, separators=(",", ":"))
        new_id = uuid.uuid4().hex
        stamp = datetime.now(ZoneInfo("Asia/Seoul")).isoformat(timespec="seconds")
        day = stamp[:10]
        cur.execute("""INSERT INTO jw_dev.order_drafts_v127
            (id,org_id,customer_id,quote_id,customer_name_snapshot,doc_no,title,
             status,review_state,vat_mode,due_date,created_at,updated_at,
             order_date,source_import_id,source_document_meta)
            VALUES (%s,%s,%s,%s,%s,%s,%s,'draft','original_checked',%s,'',
                    %s,%s,%s,%s,%s)
            ON CONFLICT DO NOTHING RETURNING id""",
            (new_id, org, customer, payload.quote_id, customer_name,
             "OD-" + day.replace("-", "") + "-" + new_id[:10].upper(),
             title, vat_mode, stamp, stamp, day, key, metadata))
        inserted = cur.fetchone()
        if not inserted:
            cur.execute("""SELECT id,source_import_id,source_document_meta
                           FROM jw_dev.order_drafts_v127
                           WHERE org_id=%s AND (quote_id=%s OR source_import_id=%s)""",
                        (org, payload.quote_id, key))
            old = cur.fetchall()
            if len(old) != 1:
                raise HTTPException(409, "Ambiguous order draft replay")
            try:
                same = (old[0][1] == key
                        and json.loads(old[0][2]) == json.loads(metadata))
            except (ValueError, TypeError, AttributeError):
                same = False
            if not same:
                raise HTTPException(409, "Order source or idempotency conflict")
            response.headers["Cache-Control"] = "no-store"
            return {"order_id": old[0][0], "source_quote_id": payload.quote_id,
                    "created": False, "draft_only": True, "approval_posted": False,
                    "money": amount}
        for line_id, name, qty, price, pos in lines:
            cur.execute("""INSERT INTO jw_dev.order_draft_items_v127
                (id,order_id,source_quote_item_id,name,quantity,unit_price,position)
                VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                (uuid.uuid4().hex, new_id, line_id, name, qty, price, pos))
        cur.execute("""INSERT INTO jw_dev.audit_logs
            (id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
            VALUES (%s,%s,%s,'order_draft',%s,'create_from_checked_quote',%s,%s)""",
            (uuid.uuid4().hex, org, actor, new_id,
             json.dumps({"quote_id": payload.quote_id, "source_sha256": source_sha}),
             stamp))
    response.status_code = 201
    response.headers["Cache-Control"] = "no-store"
    return {"order_id": new_id, "source_quote_id": payload.quote_id,
            "created": True, "draft_only": True, "approval_posted": False,
            "money": amount}


def create_router() -> APIRouter:
    router = APIRouter(prefix=_PREFIX, tags=["PG quote create (isolated only)"])
    router.add_api_route("/quotes", create_quote, methods=["POST"], response_model=None)
    router.add_api_route("/order-drafts", create_order_draft, methods=["POST"], response_model=None)
    return router


def register_v92_quote_api(app: FastAPI) -> bool:
    if not enabled():
        return False
    # Explicit origin configuration validated before route registration.
    v90._origins()
    app.include_router(create_router())
    return True
