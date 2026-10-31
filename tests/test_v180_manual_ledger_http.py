"""V18.0 fail-closed HTTP contract, original V83 SQL shape, 36+ negatives."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from zoneinfo import ZoneInfo
import copy
import os
import pytest
from fastapi import FastAPI,HTTPException
from fastapi.testclient import TestClient

from scripts.review import pg_manual_ledger_v180 as ledger

ID="ci-v180-invoice-a"
TOKEN="v180-isolated-test-token-"+"x"*50
CSRF="v180-strict-review-csrf"
NOW=datetime.now(ZoneInfo("Asia/Seoul")).date().isoformat()


class Cursor:
    def __init__(self,org="tenant-a",customer="customer-a",state="fulfilled",
                 review="acknowledged",invoice_status="issued"):
        self.org=org;self.customer=customer;self.state=state;self.review=review
        self.invoice_status=invoice_status;self.row=None
        self.ledger={};self.sql=[];self.reversed=set()
    def execute(self,sql,params=None):
        flat=" ".join(sql.split())
        self.sql.append((flat,params))
        self.row=None
        if flat.startswith("SELECT i.id,i.order_id"):
            if params==(ID,"tenant-a"):
                self.row=(ID,"order-a",self.customer,"taxable",self.invoice_status)
        elif flat.startswith("SELECT o.id,o.customer_id"):
            if params==("order-a","tenant-a"):
                self.row=("order-a",self.customer,self.state,self.review)
        elif flat.startswith("SELECT amount,reversed_at"):
            self.row=tuple((v["amount"],True if k in self.reversed else None)
                           for k,v in self.ledger.items())
        elif flat.startswith("SELECT jw_dev.record_payment_v83"):
            invoice,amount,day,ref,note=params
            if ref in self.ledger:
                old=self.ledger[ref]
                if old["amount"]!=amount or old["note"]!=note or ref in self.reversed:
                    raise HTTPException(409,"Conflicting payment")
                self.row=("payment-"+ref,)
            else:
                self.ledger[ref]={"amount":amount,"note":note}
                self.row=("payment-"+ref,)
        elif flat.startswith("SELECT jw_dev.reverse_payment_v83"):
            invoice,pid=params
            ref=pid.removeprefix("payment-")
            if ref not in self.ledger or ref in self.reversed:
                raise HTTPException(409,"Already reversed")
            self.reversed.add(ref)
            self.row=(True,)
        else:
            raise AssertionError("Unexpected SQL: "+flat)
    def fetchone(self):return self.row
    def fetchall(self):return list(self.row or [])


@pytest.fixture
def http(monkeypatch):
    for k in ("JW_INSECURE_LOCAL_DEV","JW_RELEASE_APPROVED"):
        monkeypatch.delenv(k,raising=False)
    monkeypatch.setenv("JW_ENV","test")
    monkeypatch.setenv("JW_PG_INTERNAL_LEDGER_V180",ledger._MODE)
    monkeypatch.setattr(ledger.quote,"enabled",lambda:True)
    monkeypatch.setattr(ledger.sessions,"v90_enabled",lambda:True)
    def allowed(request):
        if request.headers.get("origin")!="https://testserver":
            raise HTTPException(403,"Invalid Origin")
    monkeypatch.setattr(ledger.quote,"_origin_checked",allowed)
    db=Cursor()
    identity=("jw_app_dev","actor-a","tenant-a","admin",CSRF,"tenant")
    ctx={"db":db,"identity":identity}
    @contextmanager
    def connect(_):
        yield ctx["db"],ctx["identity"]
    monkeypatch.setattr(ledger.sessions,"_pg_validated_cursor",connect)
    monkeypatch.setattr(ledger.sessions,"_session_hash",lambda req:"synthetic-hash")
    app=FastAPI()
    assert ledger.register_v180_ledger(app)
    c=TestClient(app,base_url="https://testserver")
    c.headers["cookie"]="__Host-jw_session="+TOKEN
    return c,ctx


def body():
    return {"invoice_id":ID,"amount_krw":1000,"paid_at":NOW,
            "reference":"v180-unique-00001","note":"synthetic",
            "invoice_source_checked":True,
            "internal_manual_entry_only":True,
            "bank_reconciliation_verified":False,
            "physical_delivery_independently_verified":False}


def send(c,data=None,csrf=CSRF,origin="https://testserver"):
    h={"Origin":origin}
    if csrf is not None:h["X-CSRF-Token"]=csrf
    return c.post(ledger._PREFIX+"/manual-payments",json=body() if data is None else data,
                  headers=h)


def test_real_path_preview_manual_replay_reverse_and_fraud_flag(http):
    c,ctx=http
    p=c.get(ledger._PREFIX+"/invoices/"+ID+"/ledger-preview")
    assert p.status_code==200,p.text
    assert p.json()["recorded_active_krw"]==0
    r=send(c)
    assert r.status_code==200,r.text
    assert r.json()["internal_ledger_entry_recorded"] is True
    assert r.json()["bank_reconciliation_verified"] is False
    assert r.json()["financial_settlement_verified"] is False
    assert r.json()["legal_invoice_issuance_independently_verified"] is False
    replay=send(c)
    assert replay.status_code==200
    assert replay.json()["payment_id"]==r.json()["payment_id"]
    assert len(ctx["db"].ledger)==1
    assert c.get(ledger._PREFIX+"/invoices/"+ID+"/ledger-preview").json()["recorded_active_krw"]==1000
    reverse=c.post(ledger._PREFIX+"/manual-payments/reverse",json={
        "invoice_id":ID,"payment_id":r.json()["payment_id"],
        "reversal_approved":True,"internal_manual_entry_only":True},
        headers={"Origin":"https://testserver","X-CSRF-Token":CSRF})
    assert reverse.status_code==200
    assert reverse.json()["reversed"] is True
    assert send(c).status_code==409
    assert all(not query.lstrip().upper().startswith("INSERT INTO JW_DEV.PAYMENTS")
               for query,_ in ctx["db"].sql)


@pytest.mark.parametrize(("field","value"),[
    ("invoice_id",""),("invoice_id","../secrets"),("invoice_id","a"*129),
    ("amount_krw",0),("amount_krw",-1),("amount_krw",10**16+1),
    ("amount_krw",True),("amount_krw",1.5),("amount_krw","1000"),
    ("paid_at","tomorrow"),("paid_at","2031-02-29"),("paid_at","2099-12-12"),
    ("reference","x"),("reference","bad input"),("reference","x"*101),
    ("reference","a/b"),("note","x"*301),
    ("invoice_source_checked",False),("invoice_source_checked","true"),
    ("internal_manual_entry_only",False),
    ("bank_reconciliation_verified",True),
    ("physical_delivery_independently_verified",True),
    ("physical_delivery_independently_verified","false"),
])
def test_at_least_23_strict_rejections(http,field,value):
    c,ctx=http
    data=body()
    data[field]=value
    resp=send(c,data)
    assert resp.status_code==422,(field,value,resp.status_code,resp.text[:350])
    assert not ctx["db"].ledger


@pytest.mark.parametrize("extra",[
    "org_id","actor_id","role","bank_account","bank_confirmation",
    "bank_approval","legal_invoice_verified","source_document_verified",
    "admin_override","ignore_proof",
])
def test_unknown_privileged_fields_are_rejected(http,extra):
    c,ctx=http
    data=body()
    data[extra]=True
    assert send(c,data).status_code==422
    assert not ctx["db"].ledger


@pytest.mark.parametrize(("csrf","origin","role","want"),[
    (None,"https://testserver","admin",403),
    ("wrong","https://testserver","admin",403),
    (CSRF,"https://evil.test","admin",403),
    (CSRF,"http://testserver","admin",403),
    (CSRF,"https://testserver","member",403),
])
def test_session_anti_csrf_origin_member_denials(http,csrf,origin,role,want):
    c,ctx=http
    ident=list(ctx["identity"]);ident[3]=role;ctx["identity"]=tuple(ident)
    assert send(c,csrf=csrf,origin=origin).status_code==want
    assert ctx["db"].ledger=={}


@pytest.mark.parametrize(("state","review","invoice_status"),[
    ("received","acknowledged","issued"),
    ("processing","acknowledged","issued"),
    ("cancelled","acknowledged","issued"),
    ("fulfilled","pending","issued"),
    ("fulfilled","clean","issued"),
    ("fulfilled","acknowledged","draft"),
    ("fulfilled","acknowledged","cancelled"),
])
def test_source_invoice_order_provenance_denial(http,state,review,invoice_status):
    c,ctx=http
    ctx["db"].state=state;ctx["db"].review=review
    ctx["db"].invoice_status=invoice_status
    assert send(c).status_code==409
    assert not ctx["db"].ledger


@pytest.mark.parametrize(("env","value"),[
    ("JW_ENV","production"),
    ("JW_ENV","review"),
    ("JW_INSECURE_LOCAL_DEV","1"),
    ("JW_RELEASE_APPROVED","yes"),
    ("JW_PG_INTERNAL_LEDGER_V180","unapproved"),
])
def test_opt_in_fail_closed_at_runtime(http,monkeypatch,env,value):
    c,ctx=http
    monkeypatch.setenv(env,value)
    assert send(c).status_code==404
    assert ctx["db"].ledger=={}


def test_disabled_default_has_no_router(http,monkeypatch):
    _,_=http
    monkeypatch.delenv("JW_PG_INTERNAL_LEDGER_V180")
    app=FastAPI()
    assert ledger.register_v180_ledger(app) is False
    c=TestClient(app)
    assert c.get(ledger._PREFIX+"/invoices/"+ID+"/ledger-preview").status_code==404


def test_misconfigured_opt_in_blocks_startup(http,monkeypatch):
    _,_=http
    monkeypatch.setenv("JW_ENV","production")
    with pytest.raises(RuntimeError,match="BLOCKED"):
        ledger.register_v180_ledger(FastAPI())


def test_invoice_missing_is_tenant_safe(http):
    c,ctx=http
    assert c.get(ledger._PREFIX+"/invoices/not-in-own-org/ledger-preview").status_code==404
    assert send(c,{**body(),"invoice_id":"foreign-tenant-invoice"}).status_code==404
    assert not ctx["db"].ledger
