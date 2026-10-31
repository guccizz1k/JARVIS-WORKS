"""V17.4 human-confirmed INTERNAL order activation from verified PostgreSQL draft.

Isolated, opt-in DEV stage only. Never settles payments, issues invoices,
claims counterparty agreement, or asserts that source PDF/XLSX was verified.
Reuses V92 session and CSRF gates, immutable review receipt and FORCE RLS.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import uuid
from datetime import datetime
from typing import Literal
from zoneinfo import ZoneInfo

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from psycopg import errors

from app import pg_quote_api_v92 as quotes
from app import pg_v90_integrated_entry as sessions

_GATE = "ISOLATED_DEV_REVIEWED_INTERNAL_ORDER_ONLY"
_PREFIX = "/api/pg-stage/v174"
_ID = re.compile(r"^[a-f0-9]{32}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")


class InternalOrderApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    draft_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    review_receipt_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    preview_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_id: str = Field(pattern=r"^[A-Za-z0-9_-]{8,100}$")
    original_checked: Literal[True]
    register_internal_only: Literal[True]


def enabled() -> bool:
    return (
        os.getenv("JW_PG_INTERNAL_ORDER_V174") == _GATE
        and quotes.enabled() and sessions.v90_enabled()
        and os.getenv("JW_ENV", "").lower() in ("dev", "development", "test")
        and os.getenv("JW_INSECURE_LOCAL_DEV") != "1"
        and os.getenv("JW_RELEASE_APPROVED", "").lower() not in ("yes", "1", "true")
    )


def _source(cur, draft_id: str, org: str) -> dict:
    cur.execute(
        """SELECT id,quote_id,customer_id,customer_name_snapshot,title,
                  status,review_state,vat_mode,source_document_meta
           FROM jw_dev.order_drafts_v127
           WHERE id=%s AND org_id=%s""", (draft_id, org))
    draft = cur.fetchone()
    if not draft:
        raise HTTPException(404, "Order draft not found")
    did, quote_id, customer_id, customer_name, title, status, review, vat, raw = draft
    if (status != "draft" or review != "preview_acknowledged"
            or vat not in ("taxable", "exempt")
            or not isinstance(title, str) or not title.strip()
            or not isinstance(customer_name, str) or not customer_name.strip()):
        raise HTTPException(409, "Unverified draft state")
    try:
        meta = json.loads(raw)
        digest = meta["source_sha256"]
        receipt_id = meta["review_receipt_id"]
        if (not isinstance(meta, dict)
                or meta.get("kind") != "reviewed_quote_to_order_draft"
                or meta.get("source_document_verified") is not False
                or meta.get("quote_preview_acknowledged") is not True
                or not isinstance(digest, str) or not _SHA.fullmatch(digest)
                or not isinstance(receipt_id, str) or not _ID.fullmatch(receipt_id)):
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError):
        raise HTTPException(409, "Draft provenance invalid") from None

    # V17.5: V92 legitimately leaves a reviewed quote in "draft" (or "sent").
    # The V174 "accepted" condition was unreachable from the actual V92 API,
    # and manual fixture seeding concealed that integration defect.
    # Recompute the canonical V92 hash (including quote status, document
    # number and EVERY source line) rather than trusting stored metadata.
    quote, quote_items, _, recomputed_digest = quotes._quote_snapshot(
        cur, org, quote_id)
    if (quote[0] != customer_id or quote[1] != customer_name
            or quote[3] != title or quote[5] != vat
            or not hmac.compare_digest(recomputed_digest, digest)):
        raise HTTPException(409, "Original quote digest or source mismatch")

    cur.execute(
        """SELECT id,source_quote_item_id,name,quantity,unit_price,position
           FROM jw_dev.order_draft_items_v127 WHERE order_id=%s
           ORDER BY position,id LIMIT 41""", (did,))
    draft_items = cur.fetchall()
    if (not 1 <= len(draft_items) <= 40
            or len(draft_items) != len(quote_items)):
        raise HTTPException(409, "Source line count mismatch")
    subtotal = 0
    for i, (draft_line, quote_line) in enumerate(zip(draft_items, quote_items)):
        _, source_line, name, qty, price, position = draft_line
        if (source_line != quote_line[0]
                or (name, qty, price, position) != tuple(quote_line[1:])
                or type(qty) is not int or not 1 <= qty <= 100000
                or type(price) is not int or not 0 <= price <= 1000000000
                or type(position) is not int or position != i
                or not isinstance(name, str) or not name.strip()
                or len(name) > 150):
            raise HTTPException(409, "Order draft differs from source")
        subtotal += qty * price
    if not 1 <= subtotal <= quotes._MAX_SUBTOTAL:
        raise HTTPException(409, "Invalid order amount")
    vat_amount = (subtotal + 5) // 10 if vat == "taxable" else 0
    money = {"subtotal": subtotal, "vat": vat_amount,
             "total": subtotal + vat_amount}

    # Signature commits to every field that can influence an internal order.
    snapshot = [did, quote_id, customer_id, customer_name, title, vat,
                digest, receipt_id, draft_items, quote_items, money]
    encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"))
    preview_sha = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return {
        "draft_id": did, "quote_id": quote_id, "customer_id": customer_id,
        "customer_name": customer_name, "title": title, "vat_mode": vat,
        "items": draft_items, "money": money, "source_sha256": digest,
        "receipt_id": receipt_id, "preview_sha256": preview_sha,
    }


def _receipt(cur, source: dict, org: str, actor: str, receipt_id: str) -> None:
    if not hmac.compare_digest(source["receipt_id"], receipt_id):
        raise HTTPException(409, "Review receipt mismatch")
    cur.execute(
        """SELECT actor_id,source_sha256,created_epoch
           FROM jw_dev.quote_review_receipts_v128
           WHERE id=%s AND org_id=%s AND quote_id=%s""",
        (receipt_id, org, source["quote_id"]))
    row = cur.fetchone()
    if (not row or row[0] != actor
            or row[1] != source["source_sha256"]
            or type(row[2]) is not int
            or not 0 <= int(time.time()) - row[2] <= 86400):
        raise HTTPException(409, "Review receipt missing, expired, or foreign")


def activation_preview(draft_id: str, request: Request, response: Response):
    if not enabled():
        raise HTTPException(404, "Internal order stage unavailable")
    if not _ID.fullmatch(draft_id):
        raise HTTPException(404, "Order draft not found")
    try:
        with sessions._pg_validated_cursor(sessions._session_hash(request)) as (cur, ident):
            if ident[3] != "admin":
                raise HTTPException(403, "Administrator required")
            source = _source(cur, draft_id, ident[2])
            _receipt(cur, source, ident[2], ident[1], source["receipt_id"])
    except (errors.InsufficientPrivilege, errors.UndefinedTable, errors.UndefinedColumn):
        raise HTTPException(503, "Restricted order storage unavailable") from None
    response.headers["Cache-Control"] = "no-store"
    return {
        "draft_id": draft_id, "quote_id": source["quote_id"],
        "customer_name": source["customer_name"], "title": source["title"],
        "vat_mode": source["vat_mode"], "money": source["money"],
        "items": [{"name": v[2], "quantity": v[3], "unit_price": v[4],
                   "position": v[5]} for v in source["items"]],
        "review_receipt_id": source["receipt_id"],
        "preview_sha256": source["preview_sha256"],
        "internal_order_only": True,
        "counterparty_acceptance_independently_verified": False,
        "original_file_verified": False,
        "physical_delivery_verified": False,
        "bank_reconciliation_verified": False,
    }


def register_internal_order(request: Request, payload: InternalOrderApproval,
                            response: Response):
    if not enabled():
        raise HTTPException(404, "Internal order stage unavailable")
    quotes._origin_checked(request)
    try:
        with sessions._pg_validated_cursor(sessions._session_hash(request)) as (cur, ident):
            _, actor, org, role, csrf, _ = ident
            if role != "admin":
                raise HTTPException(403, "Administrator required")
            client_csrf = request.headers.get("X-CSRF-Token", "")
            if not client_csrf or not hmac.compare_digest(str(csrf), client_csrf):
                raise HTTPException(403, "Invalid CSRF")
            source = _source(cur, payload.draft_id, org)
            _receipt(cur, source, org, actor, payload.review_receipt_id)
            if not hmac.compare_digest(source["preview_sha256"],
                                       payload.preview_sha256):
                raise HTTPException(409, "Order preview changed")
            request_key = "v174:" + hashlib.sha256(
                (org + "\x00" + payload.request_id).encode("utf-8")).hexdigest()
            proof = json.dumps({
                "kind": "v174_internal_reviewed_order_only",
                "draft_id": payload.draft_id,
                "quote_id": source["quote_id"],
                "preview_sha256": payload.preview_sha256,
                "review_receipt_id": payload.review_receipt_id,
                "counterparty_verified": False,
                "source_document_verified": False,
                "bank_reconciled": False,
            }, sort_keys=True, separators=(",", ":"))
            cur.execute(
                """SELECT id,quote_id,source_document_meta
                   FROM jw_dev.orders
                   WHERE org_id=%s AND source_import_id=%s""",
                (org, request_key))
            old_key = cur.fetchone()
            if old_key and (old_key[1] != source["quote_id"]
                            or old_key[2] != proof):
                raise HTTPException(409, "Request ID already used for another order")
            oid = uuid.uuid4().hex
            stamp = datetime.now(ZoneInfo("Asia/Seoul")).isoformat(timespec="seconds")
            doc_no = "O-" + stamp[:10].replace("-", "") + "-" + oid[:10].upper()
            cur.execute(
                """INSERT INTO jw_dev.orders
                 (id,org_id,customer_id,quote_id,customer_name_snapshot,
                  doc_no,title,status,review_state,vat_mode,due_date,
                  created_at,updated_at,order_date,source_import_id,
                  source_document_meta)
                 VALUES(%s,%s,%s,%s,%s,%s,%s,'received','acknowledged',%s,
                        '',%s,%s,%s,%s,%s)
                 ON CONFLICT (quote_id) DO NOTHING RETURNING id""",
                (oid, org, source["customer_id"], source["quote_id"],
                 source["customer_name"], doc_no, source["title"],
                 source["vat_mode"], stamp, stamp, stamp[:10],
                 request_key, proof))
            result = cur.fetchone()
            if not result:
                cur.execute(
                    """SELECT id,source_import_id,source_document_meta
                       FROM jw_dev.orders WHERE quote_id=%s AND org_id=%s""",
                    (source["quote_id"], org))
                existing = cur.fetchone()
                if not existing or existing[1:] != (request_key, proof):
                    raise HTTPException(409, "Conflicting order registration")
                response.headers["Cache-Control"] = "no-store"
                return {"order_id": existing[0], "created": False,
                        "internal_order_only": True,
                        "external_acceptance_verified": False,
                        "invoice_issued": False, "payment_recorded": False,
                        "money": source["money"]}
            for _, source_line_id, name, qty, price, position in source["items"]:
                cur.execute(
                    """INSERT INTO jw_dev.order_items
                       (id,order_id,source_quote_item_id,name,
                        quantity,unit_price,position)
                       VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                    (uuid.uuid4().hex, oid, source_line_id, name,
                     qty, price, position))
            cur.execute(
                """INSERT INTO jw_dev.audit_logs
                   (id,org_id,actor_id,entity_type,entity_id,action,
                    detail,created_at)
                   VALUES(%s,%s,%s,'order',%s,
                          'human_approved_internal_order_only',%s,%s)""",
                (uuid.uuid4().hex, org, actor, oid,
                 json.dumps({"draft_id": payload.draft_id,
                             "review_receipt_id": payload.review_receipt_id,
                             "preview_sha256": payload.preview_sha256},
                            sort_keys=True, separators=(",", ":")), stamp))
    except (errors.UniqueViolation, errors.CheckViolation, errors.ForeignKeyViolation):
        raise HTTPException(409, "Order source conflict") from None
    except (errors.InsufficientPrivilege, errors.UndefinedTable, errors.UndefinedColumn):
        raise HTTPException(503, "Restricted order storage unavailable") from None
    response.status_code = 201
    response.headers["Cache-Control"] = "no-store"
    return {
        "order_id": oid, "created": True, "internal_order_only": True,
        "external_acceptance_verified": False, "invoice_issued": False,
        "payment_recorded": False, "money": source["money"],
    }


def register_v174_internal_order(app: FastAPI) -> bool:
    requested = os.getenv("JW_PG_INTERNAL_ORDER_V174", "")
    if not requested:
        return False
    if not enabled():
        raise RuntimeError("BLOCKED: unsafe V174 internal-order opt-in")
    router = APIRouter(prefix=_PREFIX, tags=["reviewed internal order (not legal sale)"])
    router.add_api_route("/order-drafts/{draft_id}/register-preview",
                         activation_preview, methods=["GET"], response_model=None)
    router.add_api_route("/orders/from-reviewed-draft",
                         register_internal_order, methods=["POST"], response_model=None)
    app.include_router(router)
    return True
