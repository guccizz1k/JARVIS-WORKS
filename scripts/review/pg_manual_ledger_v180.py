"""V18.0 opt-in internal UNRECONCILED manual payment ledger, DEV ONLY.

This IS NOT a bank integration, bank-confirmed settlement, legal invoice
issuance, physical delivery confirmation, or general public finance API.
Reuses V83's existing atomic SECURITY DEFINER RPC, V90 verified PostgreSQL
session, FORCE RLS, V92 CSRF+Origin and tenant-bound immutable audit.
No direct payments table INSERT. No writes to any production route.
"""
from __future__ import annotations

from datetime import date, datetime
import hmac
import os
import re
from typing import Literal
from zoneinfo import ZoneInfo

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from psycopg import Error as PgError

from app import pg_quote_api_v92 as quote
from app import pg_v90_integrated_entry as sessions

_MODE = "ISOLATED_DEV_UNRECONCILED_LEDGER_ONLY"
_PREFIX = "/api/pg-stage/v180"
_ID = re.compile(r"^[a-zA-Z0-9_-]{8,128}$")


class InternalLedgerEntry(BaseModel):
    model_config = ConfigDict(extra="forbid",strict=True)
    invoice_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{8,128}$")
    amount_krw: int = Field(ge=1,le=10**16)
    paid_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    reference: str = Field(pattern=r"^[a-zA-Z0-9_-]{8,100}$")
    note: str = Field(default="",max_length=300)
    invoice_source_checked: Literal[True]
    internal_manual_entry_only: Literal[True]
    bank_reconciliation_verified: Literal[False]
    physical_delivery_independently_verified: Literal[False]

    @field_validator("paid_at")
    @classmethod
    def valid_date(cls, value: str) -> str:
        try:
            day=date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("Invalid ISO date") from exc
        if day > datetime.now(ZoneInfo("Asia/Seoul")).date():
            raise ValueError("Future payment date is forbidden")
        return value


class ReverseInternalLedger(BaseModel):
    model_config = ConfigDict(extra="forbid",strict=True)
    invoice_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{8,128}$")
    payment_id: str = Field(min_length=8,max_length=128)
    reversal_approved: Literal[True]
    internal_manual_entry_only: Literal[True]


def enabled() -> bool:
    return (
        os.getenv("JW_PG_INTERNAL_LEDGER_V180")==_MODE
        and quote.enabled()
        and sessions.v90_enabled()
        and os.getenv("JW_ENV","").lower() in ("dev","development","test")
        and os.getenv("JW_INSECURE_LOCAL_DEV")!="1"
        and os.getenv("JW_RELEASE_APPROVED","").lower() not in ("yes","1","true")
    )


def _csrf(request: Request, identity) -> None:
    token=request.headers.get("X-CSRF-Token","")
    if not token or not hmac.compare_digest(token,str(identity[4])):
        raise HTTPException(403,"Invalid CSRF token")


def _admin(identity) -> None:
    if identity[3] != "admin":
        raise HTTPException(403,"Administrator required")


def _source(cur, invoice_id: str, org: str) -> tuple:
    # All four columns exist in the checked real DEV and disposable PG17
    # finance schemas. The same tenant-bound RLS role performs the reads.
    cur.execute("""SELECT i.id,i.order_id,i.customer_id,i.vat_mode,i.status
       FROM jw_dev.invoices i WHERE i.id=%s AND i.org_id=%s""",
       (invoice_id,org))
    invoice=cur.fetchone()
    if not invoice:
        raise HTTPException(404,"Invoice not found")
    _, order_id, customer_id, vat, state=invoice
    if state!="issued" or vat not in ("taxable","exempt"):
        raise HTTPException(409,"Invoice status requires review")
    cur.execute("""SELECT o.id,o.customer_id,o.status,o.review_state
       FROM jw_dev.orders o WHERE o.id=%s AND o.org_id=%s""",
       (order_id,org))
    source=cur.fetchone()
    if source != (order_id,customer_id,"fulfilled","acknowledged"):
        raise HTTPException(409,"Invoice source order not reviewed and fulfilled")
    # This is an INTERNAL schema consistency check, NOT independent delivery.
    # The V83 RPC separately computes actual adjusted debt and enforces caps.
    return invoice


def _db_error(exc: PgError) -> None:
    if exc.sqlstate=="42501":
        raise HTTPException(403,"Internal payment forbidden") from None
    if exc.sqlstate in ("23505","23503","23514"):
        raise HTTPException(409,"Payment or source record conflict") from None
    raise HTTPException(503,"Restricted finance storage unavailable") from None


def ledger_preview(invoice_id: str,request: Request,response: Response):
    if not enabled():
        raise HTTPException(404,"Internal finance unavailable")
    if not _ID.fullmatch(invoice_id):
        raise HTTPException(404,"Invoice not found")
    try:
        with sessions._pg_validated_cursor(sessions._session_hash(request)) as (cur,identity):
            _admin(identity)
            invoice=_source(cur,invoice_id,identity[2])
            cur.execute("""SELECT amount,reversed_at FROM jw_dev.payments
               WHERE invoice_id=%s AND org_id=%s ORDER BY id LIMIT 102""",
               (invoice_id,identity[2]))
            rows=cur.fetchall()
            if len(rows)>100 or any(
                type(v[0]) is not int or v[0]<=0 for v in rows
            ):
                raise HTTPException(409,"Payment ledger requires independent review")
            active=sum(amount for amount,reversed_at in rows
                       if reversed_at is None)
    except PgError as exc:
        _db_error(exc)
    response.headers["Cache-Control"]="no-store"
    return {
        "invoice_id":invoice_id,"source_order_id":invoice[1],
        "invoice_state_in_database":invoice[4],
        "recorded_active_krw":active,
        "active_payment_count":sum(1 for v in rows if v[1] is None),
        "reversed_payment_count":sum(1 for v in rows if v[1] is not None),
        "internal_ledger_only":True,
        "bank_reconciliation_verified":False,
        "physical_delivery_independently_verified":False,
        "legal_invoice_issuance_independently_verified":False,
        "financial_settlement_verified":False,
    }


def record_manual(request: Request,payload: InternalLedgerEntry,response: Response):
    if not enabled():
        raise HTTPException(404,"Internal finance unavailable")
    quote._origin_checked(request)
    try:
        with sessions._pg_validated_cursor(sessions._session_hash(request)) as (cur,identity):
            _admin(identity)
            _csrf(request,identity)
            _source(cur,payload.invoice_id,identity[2])
            # Existing V83 RPC locks the invoice, rejects overpayment and
            # conflicting replay, writes payment+immutable audit atomically.
            cur.execute("SELECT jw_dev.record_payment_v83(%s,%s,%s,%s,%s)",
               (payload.invoice_id,payload.amount_krw,
                date.fromisoformat(payload.paid_at),
                payload.reference,payload.note))
            row=cur.fetchone()
            if not row or not isinstance(row[0],str) or not row[0]:
                raise HTTPException(503,"Manual ledger entry not confirmed")
            payment_id=row[0]
    except PgError as exc:
        _db_error(exc)
    response.headers["Cache-Control"]="no-store"
    return {
        "payment_id":payment_id,
        "internal_ledger_entry_recorded":True,
        "bank_reconciliation_verified":False,
        "financial_settlement_verified":False,
        "physical_delivery_independently_verified":False,
        "legal_invoice_issuance_independently_verified":False,
    }


def reverse_manual(request: Request,payload: ReverseInternalLedger,response: Response):
    if not enabled():
        raise HTTPException(404,"Internal finance unavailable")
    quote._origin_checked(request)
    try:
        with sessions._pg_validated_cursor(sessions._session_hash(request)) as (cur,identity):
            _admin(identity)
            _csrf(request,identity)
            _source(cur,payload.invoice_id,identity[2])
            cur.execute("SELECT jw_dev.reverse_payment_v83(%s,%s)",
                (payload.invoice_id,payload.payment_id))
            if cur.fetchone()!=(True,):
                raise HTTPException(503,"Reversal not confirmed")
    except PgError as exc:
        _db_error(exc)
    response.headers["Cache-Control"]="no-store"
    return {"reversed":True,"internal_ledger_only":True,
            "bank_reconciliation_verified":False,
            "financial_settlement_verified":False}


def register_v180_ledger(app: FastAPI) -> bool:
    configured=os.getenv("JW_PG_INTERNAL_LEDGER_V180","")
    if not configured:
        return False
    if not enabled():
        raise RuntimeError("BLOCKED: V180 internal ledger opt-in invalid")
    router=APIRouter(prefix=_PREFIX,tags=["Isolated unreconciled manual ledger"])
    router.add_api_route("/invoices/{invoice_id}/ledger-preview",
                         ledger_preview,methods=["GET"],response_model=None)
    router.add_api_route("/manual-payments",record_manual,
                         methods=["POST"],response_model=None)
    router.add_api_route("/manual-payments/reverse",reverse_manual,
                         methods=["POST"],response_model=None)
    app.include_router(router)
    return True
