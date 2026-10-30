"""V16.1 read-only tenant-admin invoice payment balance preview.

Existing invoice, items and payment records ONLY. Reversed payments excluded;
overpayment, malformed lines and missing source order fail closed. Never claims
bank reconciliation, payment settlement, delivery proof or legal invoice posting.
"""
from __future__ import annotations

import os
import re

from fastapi import APIRouter,FastAPI,HTTPException,Request,Response
from psycopg import errors

from . import pg_quote_api_v92 as quotes
from . import pg_v90_integrated_entry as sessions

_MODE="ISOLATED_DEV_INVOICE_BALANCE_READ_ONLY"
_PREFIX="/api/pg-stage/v161"
_ID=re.compile(r"^[a-f0-9]{32}$")


def enabled() -> bool:
    return (os.getenv("JW_PG_INVOICE_BALANCE_V161")==_MODE
            and quotes.enabled() and sessions.v90_enabled()
            and os.getenv("JW_ENV","").lower() in ("dev","development","test")
            and os.getenv("JW_INSECURE_LOCAL_DEV")!="1")


def _preview(cur,invoice_id: str,org: str) -> dict:
    cur.execute("""SELECT id,order_id,status,vat_mode
                   FROM jw_dev.invoices WHERE id=%s AND org_id=%s""",
                (invoice_id,org))
    invoice=cur.fetchone()
    if not invoice:raise HTTPException(404,"Invoice not found")
    _,order_id,state,vat_mode=invoice
    if vat_mode not in ("taxable","exempt"):
        raise HTTPException(409,"Unexpected VAT mode")
    cur.execute("""SELECT id FROM jw_dev.orders
                   WHERE id=%s AND org_id=%s""",(order_id,org))
    if cur.fetchone()!=(order_id,):
        raise HTTPException(409,"Invoice source order unavailable")
    cur.execute("""SELECT name,quantity,unit_price,position
                   FROM jw_dev.invoice_items
                   WHERE invoice_id=%s ORDER BY position,id LIMIT 42""",
                (invoice_id,))
    lines=cur.fetchall()
    if not 1<=len(lines)<=40:
        raise HTTPException(409,"Invoice lines must be reviewed")
    subtotal=0
    for pos,(name,quantity,unit_price,position) in enumerate(lines):
        if (type(name) is not str or not name.strip() or len(name)>150
            or type(quantity) is not int or not 1<=quantity<=100000
            or type(unit_price) is not int or not 0<=unit_price<=1000000000
            or type(position) is not int or position!=pos):
            raise HTTPException(409,"Inconsistent invoice items")
        subtotal+=quantity*unit_price
    if not 1<=subtotal<=quotes._MAX_SUBTOTAL:
        raise HTTPException(409,"Invalid invoice amount")
    vat=(subtotal+5)//10 if vat_mode=="taxable" else 0
    gross=subtotal+vat
    cur.execute("""SELECT id,amount,reversed_at FROM jw_dev.payments
                   WHERE invoice_id=%s AND org_id=%s
                   ORDER BY id LIMIT 102""",(invoice_id,org))
    payments=cur.fetchall()
    if len(payments)>100:
        raise HTTPException(409,"Too many payment records")
    paid=0
    reversed_count=0
    for payment_id,amount,reversed_at in payments:
        if (type(payment_id) is not str or not payment_id
            or type(amount) is not int or amount<=0):
            raise HTTPException(409,"Inconsistent payment record")
        if reversed_at is None:
            paid+=amount
        else:
            reversed_count+=1
    if paid>gross:
        raise HTTPException(409,"Overpayment requires independent review")
    return {
        "invoice_id":invoice_id,"source_order_id":order_id,
        "invoice_status":state,"currency":"KRW",
        "subtotal_krw":subtotal,"vat_krw":vat,"gross_krw":gross,
        "recorded_active_payments_krw":paid,
        "recorded_active_count":len(payments)-reversed_count,
        "reversed_record_count":reversed_count,
        "unpaid_balance_krw":gross-paid,
        "bank_reconciliation_verified":False,
        "delivery_physically_verified":False,
        "payment_posted_by_this_api":False,
        "invoice_posted_by_this_api":False,
    }


def invoice_balance(invoice_id: str,request: Request,response: Response) -> dict:
    if not enabled():raise HTTPException(404,"Invoice balance unavailable")
    if not _ID.fullmatch(invoice_id):
        raise HTTPException(404,"Invoice not found")
    try:
        with sessions._pg_validated_cursor(sessions._session_hash(request)) as (
            cur,identity,
        ):
            if identity[3]!="admin":
                raise HTTPException(403,"Administrator required")
            result=_preview(cur,invoice_id,identity[2])
    except (errors.InsufficientPrivilege,errors.UndefinedTable,
            errors.UndefinedColumn):
        raise HTTPException(503,"Finance read unavailable") from None
    response.headers["Cache-Control"]="no-store"
    return result


def register_v161_invoice_balance(app: FastAPI) -> bool:
    mode=os.getenv("JW_PG_INVOICE_BALANCE_V161","")
    if not mode:return False
    if not enabled():
        raise RuntimeError("BLOCKED: V161 finance preview opt-in invalid")
    router=APIRouter(prefix=_PREFIX,tags=["Isolated read-only invoice balance"])
    router.add_api_route("/invoices/{invoice_id}/balance-preview",invoice_balance,
                         methods=["GET"],response_model=None)
    app.include_router(router)
    return True
