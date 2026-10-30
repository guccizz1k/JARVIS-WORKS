"""V13.2 isolated CI-only authenticated HTTPS finance review routes.

Never registered in the actual WORKS product.  Verifies that genuine v85
PostgreSQL cookie sessions can invoke the original v83 payment ledger RPC
through the low-privilege v90 business role on a synthetic disposable PG17.
"""
from __future__ import annotations

import hmac
import os
from datetime import date, datetime
from zoneinfo import ZoneInfo
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from psycopg import Error as PostgresError

from app import pg_quote_api_v92 as quote
from app import pg_v90_integrated_entry as v90

_PREFIX = "/api/pg-stage/v132/ci-finance"

class Payment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    invoice_id: str = Field(min_length=1, max_length=128)
    amount: int = Field(gt=0, le=10**16)
    reference: str = Field(min_length=8, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")
    note: str = Field(default="", max_length=300)
    paid_at: str = Field(min_length=10, max_length=10, pattern=r"^\d{4}-\d{2}-\d{2}$")

    @field_validator("paid_at")
    @classmethod
    def not_future(cls, value: str):
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("Invalid ISO date") from exc
        if parsed > datetime.now(ZoneInfo("Asia/Seoul")).date():
            raise ValueError("Future settlement disallowed")
        return value

class Reverse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    invoice_id: str = Field(min_length=1, max_length=128)
    payment_id: str = Field(min_length=1, max_length=128)

def enabled() -> bool:
    return (os.environ.get("JW_PG_CI_ALLOW") == "ONLY_EPHEMERAL_LOCAL_DATABASE"
            and os.environ.get("JW_ENV") == "dev"
            and os.environ.get("JW_V93_TRUST_LOCAL_CA") == "EPHEMERAL_RUNNER_ONLY"
            and v90.v90_enabled()
            and quote.enabled()
            and os.environ.get("JW_INSECURE_LOCAL_DEV") != "1")

def _cursor(request: Request, *, mutation: bool):
    # _pg_validated_cursor checks session user, role membership, expiry, actor,
    # organization and CSRF identity from the database on every request.
    if not enabled():
        raise HTTPException(404, "CI finance endpoints disabled")
    if mutation:
        quote._origin_checked(request)
    return v90._pg_validated_cursor(v90._session_hash(request))

def _csrf(request: Request, identity):
    presented = request.headers.get("X-CSRF-Token", "")
    stored = str(identity[4])
    if not presented or not hmac.compare_digest(stored, presented):
        raise HTTPException(403, "Invalid CSRF token")

def _sql_error(exc: PostgresError):
    # Never reveal raw SQL error messages, invoice ids, tenant data or DSNs.
    if exc.sqlstate == "42501":
        raise HTTPException(403, "Payment not permitted") from None
    if exc.sqlstate in ("23514", "23505"):
        raise HTTPException(409, "Conflicting payment request") from None
    raise HTTPException(503, "PostgreSQL payment failed") from None

def register(app) -> bool:
    if not enabled():
        return False
    router = APIRouter(prefix=_PREFIX, tags=["isolated-finance-review"])

    @router.get("/invoices/{invoice_id}")
    def read_invoice(invoice_id: str, request: Request, response: Response):
        if not 1 <= len(invoice_id) <= 128:
            raise HTTPException(404, "Invoice not found")
        with _cursor(request, mutation=False) as (cur, identity):
            cur.execute("""SELECT id,org_id,vat_mode FROM jw_dev.invoices
                           WHERE id=%s AND org_id=%s""", (invoice_id, identity[2]))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Invoice not found")
            cur.execute("""SELECT COALESCE(SUM(amount),0)::bigint
                           FROM jw_dev.payments WHERE invoice_id=%s
                           AND org_id=%s AND reversed_at IS NULL""",
                        (invoice_id, identity[2]))
            paid = cur.fetchone()[0]
        response.headers["Cache-Control"] = "no-store"
        return {"invoice_id": row[0], "paid_amount": paid, "vat_mode": row[2]}

    @router.post("/payments")
    def pay(payload: Payment, request: Request, response: Response):
        try:
            with _cursor(request, mutation=True) as (cur, identity):
                _csrf(request, identity)
                cur.execute("""SELECT jw_dev.record_payment_v83(%s,%s,%s,%s,%s)""",
                            (payload.invoice_id, payload.amount,
                             date.fromisoformat(payload.paid_at), payload.reference, payload.note))
                row = cur.fetchone()
                if not row or not isinstance(row[0], str):
                    raise HTTPException(503, "Missing payment confirmation")
                ident = row[0]
        except PostgresError as exc:
            _sql_error(exc)
        response.headers["Cache-Control"] = "no-store"
        return {"payment_id": ident, "posted": True}

    @router.post("/payments/reverse")
    def reverse(payload: Reverse, request: Request, response: Response):
        try:
            with _cursor(request, mutation=True) as (cur, identity):
                _csrf(request, identity)
                cur.execute("SELECT jw_dev.reverse_payment_v83(%s,%s)",
                            (payload.invoice_id, payload.payment_id))
                if cur.fetchone() != (True,):
                    raise HTTPException(503, "Reversal not confirmed")
        except PostgresError as exc:
            _sql_error(exc)
        response.headers["Cache-Control"] = "no-store"
        return {"reversed": True}

    app.include_router(router)
    return True
