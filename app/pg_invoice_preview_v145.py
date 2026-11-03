"""Isolated PostgreSQL order-to-invoice *preview*, never a posting endpoint.

A fulfilled order is not proof of a physical delivery note or human approval.
Every request is scoped to an authenticated PG identity and forced-RLS role.
No database schema, existing finance RPC, or production route is modified.
"""
from __future__ import annotations

import hashlib
import json
import re

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response

from . import pg_quote_api_v92 as quotes
from . import pg_v90_integrated_entry as sessions

_PREFIX = "/api/pg-stage/v145"
_ID = re.compile(r"^[a-f0-9]{32}$")


def build_invoice_preview(order: tuple, lines: list[tuple]) -> dict:
    """Pure, fail-closed arithmetic and source snapshot; no side effects."""
    if not order or len(order) != 9:
        raise HTTPException(503, "Incomplete source order")
    order_id, quote_id, doc_no, customer_id, customer_name, status, review, vat_mode, title = order
    if status != "fulfilled" or review != "acknowledged":
        raise HTTPException(409, "Order requires fulfilled and acknowledged states")
    if (vat_mode not in ("taxable", "exempt")
        or any(not isinstance(s, str) or not s.strip() for s in
               (order_id, quote_id, doc_no, customer_id, customer_name, title))):
        raise HTTPException(503, "Invalid order fields")
    if not 1 <= len(lines) <= 40:
        raise HTTPException(409, "Order has no verified items")
    seen_ids = set()
    items = []
    subtotal = 0
    for position, row in enumerate(lines):
        if not isinstance(row, (tuple, list)) or len(row) != 5:
            raise HTTPException(503, "Invalid order line")
        item_id, name, quantity, unit_price, saved_position = row
        if (not isinstance(item_id, str) or not item_id or item_id in seen_ids
            or not isinstance(name, str) or not name.strip() or len(name) > 150
            or type(quantity) is not int or not 1 <= quantity <= 100000
            or type(unit_price) is not int or not 0 <= unit_price <= 1000000000
            or type(saved_position) is not int or saved_position != position):
            raise HTTPException(503, "Invalid order item")
        seen_ids.add(item_id)
        subtotal += quantity * unit_price
        if subtotal > quotes._MAX_SUBTOTAL:
            raise HTTPException(503, "Order amount exceeds safety limit")
        items.append({"source_order_item_id": item_id, "name": name,
                      "quantity": quantity, "unit_price": unit_price,
                      "position": position})
    if subtotal == 0:
        raise HTTPException(409, "Zero-value invoice requires separate review")
    vat = (subtotal + 5) // 10 if vat_mode == "taxable" else 0
    money = {"subtotal": subtotal, "vat": vat, "total": subtotal + vat}
    canonical = {"order_id": order_id, "source_quote_id": quote_id,
                 "source_order_no": doc_no, "customer_id": customer_id,
                 "customer_name": customer_name, "title": title,
                 "vat_mode": vat_mode, "items": items, "money": money}
    digest = hashlib.sha256(json.dumps(
        canonical, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
    return {**canonical, "source_sha256": digest, "draft_only": True,
            "physical_delivery_verified": False,
            "approved_invoice_posted": False, "payment_posted": False,
            "requires_human_approval": True}


def invoice_preview(order_id: str, request: Request, response: Response) -> dict:
    if not quotes.enabled():
        raise HTTPException(404, "Invoice preview unavailable")
    if not _ID.fullmatch(order_id):
        raise HTTPException(404, "Order not found")
    with sessions._pg_validated_cursor(sessions._session_hash(request)) as (cur, identity):
        org = identity[2]
        cur.execute("""SELECT id,quote_id,doc_no,customer_id,customer_name_snapshot,
                            status,review_state,vat_mode,title
                       FROM jw_dev.orders WHERE id=%s AND org_id=%s""", (order_id, org))
        order = cur.fetchone()
        if not order:
            raise HTTPException(404, "Order not found")
        cur.execute("""SELECT id FROM jw_dev.invoices
                       WHERE order_id=%s AND org_id=%s LIMIT 1""", (order_id, org))
        if cur.fetchone():
            raise HTTPException(409, "Existing invoice must be reviewed")
        cur.execute("""SELECT id,name,quantity,unit_price,position
                       FROM jw_dev.order_items WHERE order_id=%s
                       ORDER BY position,id""", (order_id,))
        result = build_invoice_preview(order, cur.fetchall())
    response.headers["Cache-Control"] = "no-store"
    return result


def register_v145_invoice_preview(app: FastAPI) -> bool:
    if not quotes.enabled():
        return False
    router = APIRouter(prefix=_PREFIX, tags=["Isolated invoice preview, no posting"])
    router.add_api_route("/orders/{order_id}/invoice-preview", invoice_preview,
                         methods=["GET"])
    app.include_router(router)
    return True
