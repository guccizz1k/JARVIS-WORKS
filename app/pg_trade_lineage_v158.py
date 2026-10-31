"""V15.8 read-only tenant-scoped trade lineage in isolated PG-only stage.

Actual linkage: confirmed-file previews -> quote -> orders -> invoices ->
payments, plus optional immutable delivery review. It never treats existence
as approval, verifies no physical delivery, and does not post any finance.
"""
from __future__ import annotations

import os
import re

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from psycopg import errors

from . import pg_quote_api_v92 as quotes
from . import pg_v90_integrated_entry as sessions

_MODE = "ISOLATED_DEV_TRADE_LINEAGE_READ_ONLY"
_PREFIX = "/api/pg-stage/v158"
_ID = re.compile(r"^[0-9a-f]{32}$")
_MAX_ORDERS = 20
_MAX_INVOICES = 20
_MAX_PAYMENTS = 40
_MAX_IMPORTS = 20


def enabled() -> bool:
    return (
        os.getenv("JW_PG_TRADE_LINEAGE_V158") == _MODE
        and quotes.enabled() and sessions.v90_enabled()
        and os.getenv("JW_ENV", "").lower() in {"dev", "development", "test"}
        and os.getenv("JW_INSECURE_LOCAL_DEV") != "1"
    )


def _bounded_rows(cur, statement: str, params: tuple, limit: int) -> list[tuple]:
    cur.execute(statement, (*params, limit + 1))
    result = cur.fetchall()
    if len(result) > limit:
        raise HTTPException(409, "Trade lineage exceeds review limit")
    return result


def _read_lineage(cur, quote_id: str, org: str) -> dict:
    # Both application-side and forced-RLS tenant isolation are required.
    cur.execute(
        """SELECT id,status,customer_id,vat_mode,doc_no,source_import_id
           FROM jw_dev.quotes WHERE id=%s AND org_id=%s""",
        (quote_id, org),
    )
    quote = cur.fetchone()
    if not quote:
        raise HTTPException(404, "Quote not found")

    imports = _bounded_rows(cur,
        """SELECT id,status FROM jw_dev.import_previews
           WHERE quote_id=%s AND org_id=%s
           ORDER BY id LIMIT %s""", (quote_id, org), _MAX_IMPORTS)

    # V16.0 intentionally did not grant UPDATE on import_previews. It stores
    # the immutable approved import identity on quotes.source_import_id, so
    # its confirmed preview has quote_id NULL. Resolve both forms without
    # granting ordinary app SQL UPDATE/INSERT into evidence rows.
    source_key = quote[5]
    if isinstance(source_key, str) and source_key.startswith("v160:"):
        prefix = "v160:" + org + ":"
        if not source_key.startswith(prefix):
            raise HTTPException(409, "Foreign source import reference")
        preview_id = source_key[len(prefix):]
        if not _ID.fullmatch(preview_id):
            raise HTTPException(409, "Invalid source import reference")
        if imports:
            if len(imports) != 1 or imports[0] != (preview_id, "confirmed"):
                raise HTTPException(409, "Source import relation mismatch")
        else:
            imports = _bounded_rows(cur,
                """SELECT id,status FROM jw_dev.import_previews
                   WHERE id=%s AND org_id=%s AND quote_id IS NULL
                     AND status='confirmed'
                   LIMIT %s""", (preview_id, org), 1)
            if imports != [(preview_id, "confirmed")]:
                raise HTTPException(409, "Confirmed source import missing")

    orders = _bounded_rows(cur,
        """SELECT id,status,review_state,customer_id,vat_mode
           FROM jw_dev.orders WHERE quote_id=%s AND org_id=%s
           ORDER BY id LIMIT %s""", (quote_id, org), _MAX_ORDERS)

    cur.execute("SELECT to_regclass('jw_dev.review_delivery_receipts_v151')")
    review_ledger_installed = cur.fetchone()[0] is not None

    order_results = []
    invoice_count = payment_count = 0
    for order_id, state, review_state, customer_id, vat_mode in orders:
        if customer_id != quote[2] or vat_mode != quote[3]:
            raise HTTPException(409, "Inconsistent order-to-quote source")
        # This is a signed-evidence *review* state, not physical delivery.
        evidence = "NOT_CONFIGURED"
        if review_ledger_installed:
            cur.execute(
                """SELECT status FROM jw_dev.review_delivery_receipts_v151
                   WHERE order_id=%s AND org_id=%s""",
                (order_id, org),
            )
            receipt = cur.fetchone()
            evidence = receipt[0] if receipt else "NOT_SUBMITTED"

        invoices = _bounded_rows(cur,
            """SELECT id,status FROM jw_dev.invoices
               WHERE order_id=%s AND org_id=%s
               ORDER BY id LIMIT %s""", (order_id, org), _MAX_INVOICES)
        invoice_results = []
        for invoice_id, invoice_state in invoices:
            payments = _bounded_rows(cur,
                """SELECT id,amount,reversed_at FROM jw_dev.payments
                   WHERE invoice_id=%s AND org_id=%s
                   ORDER BY id LIMIT %s""",
                (invoice_id, org), _MAX_PAYMENTS)
            if any(type(amount) is not int or amount <= 0 for _, amount, _ in payments):
                raise HTTPException(409, "Invalid recorded payment")
            invoice_results.append({
                "invoice_id": invoice_id,
                "status": invoice_state,
                "recorded_payments": len(payments),
                "active_payment_count": sum(v is None for _, _, v in payments),
                "recorded_active_amount_krw":
                    sum(amount for _, amount, v in payments if v is None),
                # This is NOT a reconciliation or invoice approval assertion.
                "reconciled": False,
            })
            payment_count += len(payments)
        invoice_count += len(invoices)
        order_results.append({
            "order_id": order_id,
            "status": state,
            "review_state": review_state,
            "delivery_evidence_review": evidence,
            "physical_delivery_verified": False,
            "invoices": invoice_results,
        })

    return {
        "quote_id": quote[0],
        "quote_status": quote[1],
        "source_imports": [{"preview_id": key, "status": status}
                           for key, status in imports],
        "orders": order_results,
        "counts": {
            "source_imports": len(imports),
            "orders": len(orders),
            "invoices": invoice_count,
            "recorded_payments": payment_count,
        },
        "automated_business_approval": False,
        "official_source_verified": False,
        "payment_reconciliation_verified": False,
    }


def trade_lineage(quote_id: str, request: Request, response: Response) -> dict:
    if not enabled():
        raise HTTPException(404, "Trade lineage disabled")
    if not _ID.fullmatch(quote_id):
        raise HTTPException(404, "Quote not found")
    try:
        with sessions._pg_validated_cursor(sessions._session_hash(request)) as (
            cur, identity,
        ):
            result = _read_lineage(cur, quote_id, identity[2])
    except (errors.InsufficientPrivilege, errors.UndefinedTable,
            errors.UndefinedColumn):
        # Never replace failed RLS/unknown schema with a privileged fallback.
        raise HTTPException(503, "Trade lineage storage unavailable") from None
    response.headers["Cache-Control"] = "no-store"
    return result


def register_v158_trade_lineage(app: FastAPI) -> bool:
    requested = os.getenv("JW_PG_TRADE_LINEAGE_V158", "")
    if not requested:
        return False
    if not enabled():
        raise RuntimeError("BLOCKED: V158 trade-lineage opt-in invalid")
    router = APIRouter(prefix=_PREFIX, tags=["PG read-only trade lineage"])
    router.add_api_route("/quotes/{quote_id}/lineage", trade_lineage,
                         methods=["GET"], response_model=None)
    app.include_router(router)
    return True
