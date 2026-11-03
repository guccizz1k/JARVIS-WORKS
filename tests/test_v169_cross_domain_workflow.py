"""V16.9 integrated synthetic B2B import->quote->order->invoice->payment->messenger.

Runs exclusively against fresh per-test SQLite, not a production or shared DB.
Complements (does not replace) separately verified PG17 RLS staging tests.
Never calls external bank settlement, attestation, legal invoicing, or real OCR.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest

from app import main as backend
from tests.test_quote_import import qxlsx, post_file, confirm


def _today():
    return datetime.now(ZoneInfo("Asia/Seoul")).date().isoformat()


def _import_to_invoice(api, *, vat_mode="taxable"):
    before={key:len(api.get("/"+key).json()) for key in ("quotes","orders","invoices")}
    fields=({"과세구분":"면세","부가세":0,"총금액":160000}
            if vat_mode=="exempt" else {})
    response=post_file(api,qxlsx(fields))
    assert response.status_code==201,response.text
    preview=response.json()
    assert preview["ready_to_confirm"] is True
    assert preview["document"]["record_type"]=="quote"
    assert all(len(api.get("/"+key).json())==size for key,size in before.items())
    generated=confirm(api,preview)
    assert generated.status_code==201,generated.text
    created=generated.json()
    quote=created["quote"]
    assert quote["status"]=="draft"
    assert quote["source_import_id"]==preview["id"]
    assert quote["money"]["subtotal"]==160000
    assert quote["money"]["vat"]==(16000 if vat_mode=="taxable" else 0)
    assert api.post("/orders/from-quote",{"quote_id":quote["id"],"due_date":"2099-12-30"}).status_code==409
    assert api.post(f"/quotes/{quote['id']}/status",{"status":"sent"}).status_code==200
    assert api.post(f"/quotes/{quote['id']}/status",{"status":"accepted"}).status_code==200
    order=api.post("/orders/from-quote",{"quote_id":quote["id"],"due_date":"2099-12-30"})
    assert order.status_code==201,order.text
    order=order.json()
    assert order["money"]==quote["money"]
    assert api.post(f"/orders/{order['id']}/status",{"status":"processing"}).status_code==200
    assert api.post(f"/orders/{order['id']}/status",{"status":"fulfilled"}).status_code==200
    inv=api.post("/invoices/from-order",{"order_id":order["id"],"due_date":"2099-12-31"})
    assert inv.status_code==201,inv.text
    inv=inv.json()
    assert inv["money"]==quote["money"]
    assert inv["balance"]==quote["money"]["total"]
    return preview,quote,order,inv


def _payment(api,invoice_id,amount,reference=None):
    return api.post("/invoices/"+invoice_id+"/payments",
        {"amount":amount,"paid_at":_today(),
         "reference":reference or uuid4().hex,"note":"synthetic test only"})


@pytest.mark.parametrize("vat_mode,gross",[
    ("taxable",176000),("exempt",160000),
])
def test_full_import_to_reconciled_internal_ledger_and_messenger(api,vat_mode,gross):
    preview,quote,order,invoice=_import_to_invoice(api,vat_mode=vat_mode)
    ref=uuid4().hex
    first=_payment(api,invoice["id"],gross//4,ref)
    assert first.status_code==201,first.text
    assert first.json()["balance"]==gross-gross//4
    replay=_payment(api,invoice["id"],gross//4,ref)
    assert replay.status_code==201 and replay.json()["balance"]==gross-gross//4
    assert _payment(api,invoice["id"],gross//4+1,ref).status_code==409
    settled=_payment(api,invoice["id"],gross-gross//4)
    assert settled.status_code==201,settled.text
    assert settled.json()["balance"]==0
    current=api.get("/invoices/"+invoice["id"]).json()
    assert current["payment_status"]=="paid"
    assert current["money"]==invoice["money"]
    audit=api.get("/audit").json()
    assert any(x["entity_id"]==quote["id"] for x in audit)
    assert api.get("/dashboard").json()["collected"]==gross

    # The messenger is a separate communication channel; message delivery
    # cannot silently mutate invoices, payments or legal approvals.
    with backend.conn() as c:
        org_b=c.execute("SELECT org_id FROM users WHERE email=?",
                        ("demo@bada.example",)).fetchone()["org_id"]
    a_auth=api.auth.copy()
    channel=api.post("/messenger/threads",{"recipient_org_id":org_b})
    assert channel.status_code==201,channel.text
    thread=channel.json()["id"]
    text="거래내역 확인: "+invoice["id"]
    message=api.post(f"/messenger/threads/{thread}/messages",
                     {"content":text,"request_id":uuid4().hex})
    assert message.status_code==201,message.text
    mid=message.json()["id"]
    assert api.get("/invoices/"+invoice["id"]).json()["balance"]==0
    api.login("demo@bada.example")
    b_auth=api.auth.copy()
    assert b_auth!=a_auth
    visible=api.get(f"/messenger/threads/{thread}/messages").json()
    assert visible[-1]["id"]==mid and visible[-1]["body"]==text
    assert visible[-1]["mine"] is False
    for path in (
        f"/imports/{preview['id']}",f"/quotes/{quote['id']}",
        f"/orders/{order['id']}",f"/invoices/{invoice['id']}",
        f"/invoices/{invoice['id']}/payments",f"/reconciliation/{order['id']}",
    ):
        assert api.get(path).status_code==404,(path,api.get(path).status_code)
    assert api.post(f"/invoices/{invoice['id']}/payments",
        {"amount":1,"paid_at":_today(),"reference":uuid4().hex}).status_code==404
    assert api.get("/dashboard").json()["collected"]==0
    api.auth=a_auth
    assert api.get("/invoices/"+invoice["id"]).json()["balance"]==0
    assert len(api.get(f"/invoices/{invoice['id']}/payments").json())==2


@pytest.mark.parametrize("field,value",[
    ("preview_digest","f"*64),
    ("preview_digest","0"*64),
    ("confirmed_customer","FOREIGN COMPANY"),
    ("confirmed_customer",""),
    ("confirmed_customer",None),
    ("confirmed_quote_date","2001-01-01"),
    ("confirmed_quote_date","2026-02-30"),
    ("confirmed_quote_date",None),
    ("confirmed_total",176001),
    ("confirmed_total",175999),
    ("confirmed_total",0),
    ("confirmed_total",-1),
    ("confirmed_total",None),
    ("approve",False),
    ("approve",None),
])
def test_unapproved_or_tampered_import_never_creates_trade_records(api,field,value):
    before={name:len(api.get("/"+name).json()) for name in
            ("quotes","orders","invoices")}
    r=post_file(api)
    assert r.status_code==201,r.text
    preview=r.json()
    denied=confirm(api,preview,**{field:value})
    assert denied.status_code in (400,403,409,422),(
        field,value,denied.status_code,denied.text)
    for name,n in before.items():
        assert len(api.get("/"+name).json())==n,(field,name)
    assert api.get("/dashboard").json()["collected"]==0


@pytest.mark.parametrize("value",[
    0,-1,0.5,True,None,"bad","-1",1000000000,
])
def test_invalid_or_overpaid_payment_cannot_change_confirmed_lifecycle(api,value):
    _,q,o,invoice=_import_to_invoice(api)
    before=len(api.get(f"/invoices/{invoice['id']}/payments").json())
    r=_payment(api,invoice["id"],value)
    assert r.status_code in (400,409,422),(value,r.status_code,r.text)
    assert len(api.get(f"/invoices/{invoice['id']}/payments").json())==before
    assert api.get("/invoices/"+invoice["id"]).json()["balance"]==176000
    assert api.get("/quotes/"+q["id"]).json()["status"]=="accepted"
    assert api.get("/orders/"+o["id"]).json()["status"]=="fulfilled"


def test_cross_domain_csrf_denied_and_state_unchanged(api):
    preview,quote,order,inv=_import_to_invoice(api)
    cookie={"Cookie":api.auth["Cookie"]}
    before=api.get("/dashboard").json()
    assert api.c.post(f"/api/invoices/{inv['id']}/payments",
        headers=cookie,json={"amount":1,"paid_at":_today(),
                             "reference":uuid4().hex}).status_code==403
    assert api.c.post("/api/invoices/from-order",headers=cookie,
        json={"order_id":order["id"],"due_date":"2099-12-31"}).status_code==403
    assert api.c.post("/api/orders/from-quote",headers=cookie,
        json={"quote_id":quote["id"],"due_date":"2099-12-30"}).status_code==403
    assert api.c.post("/api/imports/preview",
        headers=cookie,files={"file":("quote.xlsx",qxlsx())}).status_code==403
    assert api.get("/dashboard").json()==before


def test_same_import_and_invoice_cannot_be_double_posted(api):
    preview,quote,order,invoice=_import_to_invoice(api)
    assert confirm(api,preview).status_code==409
    assert api.post("/orders/from-quote",
        {"quote_id":quote["id"],"due_date":"2099-12-30"}).status_code==409
    assert api.post("/invoices/from-order",
        {"order_id":order["id"],"due_date":"2099-12-31"}).status_code==409
    ref=uuid4().hex
    one=_payment(api,invoice["id"],176000,ref)
    assert one.status_code==201
    again=_payment(api,invoice["id"],176000,ref)
    assert again.status_code==201
    assert len(api.get(f"/invoices/{invoice['id']}/payments").json())==1
    assert api.get("/dashboard").json()["outstanding"]==0


def test_synthetic_messenger_content_is_not_payment_evidence(api):
    _,quote,order,invoice=_import_to_invoice(api)
    with backend.conn() as c:
        org_b=c.execute("SELECT org_id FROM users WHERE email='demo@bada.example'").fetchone()[0]
    thread=api.post("/messenger/threads",{"recipient_org_id":org_b})
    assert thread.status_code==201
    injected="<img src=x onerror=alert(1)> 결제완료 "+invoice["id"]
    response=api.post(f"/messenger/threads/{thread.json()['id']}/messages",
                      {"content":injected,"request_id":uuid4().hex})
    assert response.status_code==201
    assert api.get("/invoices/"+invoice["id"]).json()["balance"]==176000
    assert api.get("/dashboard").json()["collected"]==0
    assert api.get("/reconciliation/"+order["id"]).status_code==200
