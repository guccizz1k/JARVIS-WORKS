"""V9.3 PostgreSQL-native quote read/list; isolated dev stage, off by default.

Tenant and actor are resolved through the existing database session, never by
client parameters. No SQLite fallback and no production route changes.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request, Response

from . import pg_quote_api_v92 as v92
from . import pg_v90_integrated_entry as v90

_PREFIX = "/api/pg-stage/v92"
_ID = re.compile(r"^[a-f0-9]{32}$")


def _checked(request: Request):
    if not v92.enabled():
        raise HTTPException(404, "PostgreSQL quote reader disabled")
    return v90._pg_validated_cursor(v90._session_hash(request))


def list_quotes(request: Request, response: Response,
                limit: int = Query(default=30, ge=1, le=100)):
    with _checked(request) as (cur, identity):
        org = identity[2]
        cur.execute(
            """SELECT id,doc_no,title,status,vat_mode,customer_name_snapshot,created_at
               FROM jw_dev.quotes
               WHERE org_id=%s ORDER BY created_at DESC,id DESC LIMIT %s""",
            (org, limit),
        )
        rows = cur.fetchall()
    response.headers["Cache-Control"] = "no-store"
    return [
        {"id": row[0], "doc_no": row[1], "title": row[2],
         "status": row[3], "vat_mode": row[4],
         "customer_name": row[5], "created_at": row[6]}
        for row in rows
    ]


def get_quote(quote_id: str, request: Request, response: Response):
    if not _ID.fullmatch(quote_id):
        raise HTTPException(404, "Quote not found")
    with _checked(request) as (cur, identity):
        org = identity[2]
        cur.execute(
            """SELECT id,doc_no,title,status,vat_mode,customer_id,
                      customer_name_snapshot,created_at
               FROM jw_dev.quotes WHERE id=%s AND org_id=%s""",
            (quote_id, org),
        )
        q = cur.fetchone()
        if not q:
            raise HTTPException(404, "Quote not found")
        cur.execute(
            """SELECT name,quantity,unit_price,position
               FROM jw_dev.quote_items WHERE quote_id=%s
               ORDER BY position,id""", (quote_id,),
        )
        rows = cur.fetchall()
        items = []
        subtotal = 0
        for name, qty, price, pos in rows:
            # For older data we enforce the same money invariants as new writes.
            if (not isinstance(qty, int) or not isinstance(price, int)
                    or qty < 1 or qty > 100000 or price < 0 or price > 1000000000):
                raise HTTPException(503, "Invalid persisted quote item")
            subtotal += qty * price
            items.append({"name": name, "quantity": qty,
                          "unit_price": price, "position": pos})
        if not items or subtotal > v92._MAX_SUBTOTAL:
            raise HTTPException(503, "Incomplete persisted quote")
        vat = (subtotal + 5) // 10 if q[4] == "taxable" else 0
        if q[4] not in ("taxable", "exempt"):
            raise HTTPException(503, "Invalid persisted VAT mode")
    response.headers["Cache-Control"] = "no-store"
    return {
        "id": q[0], "doc_no": q[1], "title": q[2], "status": q[3],
        "vat_mode": q[4], "customer_id": q[5],
        "customer_name": q[6], "created_at": q[7],
        "items": items,
        "money": {"subtotal": subtotal, "vat": vat, "total": subtotal + vat},
    }



def get_order_draft(order_id: str, request: Request, response: Response):
    if not _ID.fullmatch(order_id):
        raise HTTPException(404, "Order draft not found")
    with _checked(request) as (cur, identity):
        cur.execute("""SELECT id,quote_id,title,status,review_state,vat_mode
                       FROM jw_dev.order_drafts_v127 WHERE id=%s AND org_id=%s""",
                    (order_id, identity[2]))
        order = cur.fetchone()
        if not order:
            raise HTTPException(404, "Order draft not found")
        if order[3] != "draft" or order[4] != "original_checked":
            raise HTTPException(409, "Order draft status not verifiable")
        cur.execute("""SELECT name,quantity,unit_price,position
                       FROM jw_dev.order_draft_items_v127 WHERE order_id=%s
                       ORDER BY position,id""", (order_id,))
        lines = cur.fetchall()
        if not 1 <= len(lines) <= 40 or any(
            type(q) is not int or not 1 <= q <= 100000
            or type(p) is not int or not 0 <= p <= 1000000000
            or type(pos) is not int or pos != i
            for i, (_, q, p, pos) in enumerate(lines)
        ):
            raise HTTPException(503, "Invalid order draft details")
        subtotal = sum(q * p for _, q, p, _ in lines)
        if order[5] not in ("taxable", "exempt") or subtotal > v92._MAX_SUBTOTAL:
            raise HTTPException(503, "Invalid order draft amount")
        vat = (subtotal + 5) // 10 if order[5] == "taxable" else 0
    response.headers["Cache-Control"] = "no-store"
    return {"id": order[0], "source_quote_id": order[1], "title": order[2],
            "status": order[3], "draft_only": True, "approval_posted": False,
            "money": {"subtotal": subtotal, "vat": vat,
                      "total": subtotal + vat},
            "items": [{"name": name, "quantity": qty, "unit_price": price,
                       "position": pos} for name, qty, price, pos in lines]}


def create_router() -> APIRouter:
    router = APIRouter(prefix=_PREFIX, tags=["PG quote read (isolated only)"])
    router.add_api_route("/quotes", list_quotes, methods=["GET"])
    router.add_api_route("/quotes/{quote_id}", get_quote, methods=["GET"])
    router.add_api_route("/order-drafts/{order_id}", get_order_draft, methods=["GET"])
    return router


def register_v93_quote_reader(app: FastAPI) -> bool:
    if not v92.enabled():
        return False
    app.include_router(create_router())
    return True
