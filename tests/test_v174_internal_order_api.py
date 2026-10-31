"""V17.4 fail-closed HTTP unit tests for real SQL contract (in-memory cursor oracle).

The cursor is a deterministic transaction mock; these tests are NOT real PG.
Real PG17 RLS and HTTP must be tested separately, without fake company identity.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import json
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from scripts.review import pg_order_activation_v174 as mod

ORG = "a"*32
OTHER = "b"*32
ACTOR = "1"*32
QA = "c"*32
DRAFT = "d"*32
RECEIPT = "e"*32
SOURCE = "f"*64
CSRF = "v174-test-xsrf-token"
TOKEN = "v174-isolated-cookie-" + "x"*50


class Cursor:
    def __init__(self, db, context):
        self.db = db
        self.context = context
        self.row = None
        self.rows = []
    def execute(self, sql, params=None):
        self.row = None
        self.rows = []
        sql = " ".join(sql.split())
        if "FROM jw_dev.order_drafts_v127" in sql:
            v = self.db["draft"]
            if v and params == (DRAFT, ORG):
                self.row = (DRAFT, QA, "cust-a", "Example A",
                            v["title"], v["status"], v["review"],
                            v["vat"], v["meta"])
        elif "FROM jw_dev.quotes WHERE" in sql:
            q = self.db["quote"]
            if params == (QA, ORG) and q:
                self.row = (QA, "cust-a", "Example A", q["title"],
                            q["status"], q["vat"])
        elif "FROM jw_dev.order_draft_items_v127" in sql:
            if params == (DRAFT,):
                self.rows = self.db["lines"]
        elif "FROM jw_dev.quote_items" in sql:
            if params == (QA,):
                self.rows = self.db["q_lines"]
        elif "FROM jw_dev.quote_review_receipts_v128" in sql:
            if params == (RECEIPT, ORG, QA):
                self.row = self.db["receipt"]
        elif sql.startswith("SELECT id,quote_id,source_document_meta FROM jw_dev.orders"):
            org, key = params
            found = next((x for x in self.db["orders"]
                          if x["org"] == org and x["request_key"] == key), None)
            if found:
                self.row = (found["id"], found["quote"], found["proof"])
        elif sql.startswith("INSERT INTO jw_dev.orders"):
            oid, org, customer, quote, snapshot, docno, title, vat, created, updated, day, key, proof = params
            if self.db["crash"] == "order":
                raise RuntimeError("Injected PG order insert failure")
            if not any(x["quote"] == quote for x in self.db["orders"]):
                self.db["orders"].append({"id":oid,"org":org,"quote":quote,
                                          "request_key":key,"proof":proof,
                                          "customer":customer})
                self.row = (oid,)
        elif sql.startswith("SELECT id,source_import_id,source_document_meta FROM jw_dev.orders"):
            quote, org = params
            x = next((x for x in self.db["orders"]
                      if x["quote"] == quote and x["org"] == org), None)
            if x:
                self.row = (x["id"],x["request_key"],x["proof"])
        elif sql.startswith("INSERT INTO jw_dev.order_items"):
            if self.db["crash"] == "line":
                raise RuntimeError("Injected PG line insert failure")
            self.db["posted_lines"].append(params)
        elif sql.startswith("INSERT INTO jw_dev.audit_logs"):
            if self.db["crash"] == "audit":
                raise RuntimeError("Injected PG audit insert failure")
            self.db["audit"].append(params)
        else:
            raise AssertionError(f"Unexpected SQL pattern: {sql[:150]}")
    def fetchone(self):
        return self.row
    def fetchall(self):
        return self.rows


@pytest.fixture
def stage(monkeypatch):
    meta=json.dumps({
        "kind":"reviewed_quote_to_order_draft", "source_sha256":SOURCE,
        "review_receipt_id":RECEIPT,
        "quote_preview_acknowledged":True,"source_document_verified":False,
    })
    db={
        "draft":{"title":"Approved internal quote","status":"draft",
                 "review":"preview_acknowledged","vat":"taxable","meta":meta},
        "quote":{"title":"Approved internal quote","status":"accepted","vat":"taxable"},
        "lines":[("l"*32,"i"*32,"Widget",2,3500,0)],
        "q_lines":[("i"*32,"Widget",2,3500,0)],
        "receipt":(ACTOR,SOURCE,int(time.time())),
        "orders":[],"posted_lines":[],"audit":[],"crash":None,
    }
    ctx={"org":ORG,"actor":ACTOR,"role":"admin"}
    monkeypatch.setenv("JW_ENV","test")
    monkeypatch.setenv("JW_PG_INTERNAL_ORDER_V174",
                       "ISOLATED_DEV_REVIEWED_INTERNAL_ORDER_ONLY")
    monkeypatch.delenv("JW_INSECURE_LOCAL_DEV",raising=False)
    monkeypatch.delenv("JW_RELEASE_APPROVED",raising=False)
    monkeypatch.setattr(mod.quotes,"enabled",lambda:True)
    monkeypatch.setattr(mod.sessions,"v90_enabled",lambda:True)
    monkeypatch.setattr(mod.sessions,"_origins",
                        lambda:frozenset({"https://testserver"}))
    @contextmanager
    def postgres_restricted_cursor(session_hash):
        assert len(session_hash)==64
        working=deepcopy(db)
        cur=Cursor(working,ctx)
        yield cur,("jw_app_dev",ctx["actor"],ctx["org"],ctx["role"],CSRF,
                   "Synthetic Company A")
        db.update(working)
    monkeypatch.setattr(mod.sessions,"_pg_validated_cursor",postgres_restricted_cursor)
    app=FastAPI()
    assert mod.register_v174_internal_order(app)
    client=TestClient(app,base_url="https://testserver")
    client.headers["Cookie"]="__Host-jw_session="+TOKEN
    return client,db,ctx


def preview(client):
    return client.get("/api/pg-stage/v174/order-drafts/"+DRAFT+"/register-preview")


def body(client, request_id="request-v174-000001"):
    p=preview(client)
    assert p.status_code==200,p.text
    return {
        "draft_id":DRAFT,"review_receipt_id":RECEIPT,
        "preview_sha256":p.json()["preview_sha256"],
        "request_id":request_id,
        "original_checked":True,
        "register_internal_only":True,
    }


def post(client, p, headers=None):
    h={"Origin":"https://testserver","X-CSRF-Token":CSRF}
    h.update(headers or {})
    return client.post("/api/pg-stage/v174/orders/from-reviewed-draft",
                       json=p,headers=h)


def test_real_http_approval_only_registers_internal_received_order(stage):
    client,db,_=stage
    p=preview(client)
    assert p.status_code==200
    assert p.json()["money"]=={"subtotal":7000,"vat":700,"total":7700}
    assert p.json()["original_file_verified"] is False
    assert p.json()["counterparty_acceptance_independently_verified"] is False
    assert p.json()["bank_reconciliation_verified"] is False
    r=post(client,body(client))
    assert r.status_code==201,r.text
    assert r.json()["created"] is True
    assert r.json()["internal_order_only"] is True
    assert r.json()["external_acceptance_verified"] is False
    assert r.json()["invoice_issued"] is False
    assert r.json()["payment_recorded"] is False
    assert len(db["orders"])==1
    assert len(db["posted_lines"])==1
    assert len(db["audit"])==1
    assert r.headers["cache-control"]=="no-store"


def test_idempotent_retry_no_double_order_lines_or_audit(stage):
    client,db,_=stage
    p=body(client)
    r1=post(client,p)
    r2=post(client,p)
    assert (r1.status_code,r2.status_code)==(201,200),(r1.text,r2.text)
    assert r2.json()["order_id"]==r1.json()["order_id"]
    assert r2.json()["created"] is False
    assert len(db["orders"])==len(db["posted_lines"])==len(db["audit"])==1


@pytest.mark.parametrize(("key","value"),[
    ("original_checked",False),
    ("register_internal_only",False),
    ("original_checked",None),
    ("register_internal_only",None),
    ("draft_id","bad"),
    ("review_receipt_id","foreign"),
    ("preview_sha256","invalid"),
    ("request_id","short"),
    ("request_id",True),
    ("request_id","x"*101),
    ("preview_sha256",True),
    ("register_internal_only","true"),
])
def test_malformed_or_unchecked_approval_never_writes(stage,key,value):
    c,db,_=stage
    data=body(c)
    data[key]=value
    r=post(c,data)
    assert r.status_code==422,(key,r.status_code,r.text)
    assert db["orders"]==db["audit"]==db["posted_lines"]==[]


@pytest.mark.parametrize(("key","value"),[
    ("status","draft"),
    ("status","sent"),
    ("status","rejected"),
    ("vat","exempt"),
    ("title","Altered title"),
])
def test_unaccepted_or_changed_quote_is_denied(stage,key,value):
    c,db,_=stage
    db["quote"][key]=value
    r=preview(c)
    assert r.status_code==409 and db["orders"]==[]


@pytest.mark.parametrize(("key","value"),[
    ("status","processing"),
    ("review","pending"),
    ("vat","unknown"),
    ("title"," "),
    ("meta","invalid json"),
    ("meta",'{"source_sha256":"f"}'),
])
def test_tampered_draft_is_denied(stage,key,value):
    c,db,_=stage
    db["draft"][key]=value
    assert preview(c).status_code==409
    assert db["orders"]==[]


@pytest.mark.parametrize(("key","value"),[
    ("q_lines",[("i"*32,"Widget",3,3500,0)]),
    ("q_lines",[("wrong","Widget",2,3500,0)]),
    ("q_lines",[]),
    ("lines",[]),
    ("lines",[("l"*32,"i"*32,"Widget",0,3500,0)]),
    ("lines",[("l"*32,"i"*32,"Widget",2,-1,0)]),
    ("lines",[("l"*32,"i"*32,"Widget",2,3500,1)]),
    ("lines",[("l"*32,"i"*32," ",2,3500,0)]),
])
def test_source_line_replaced_and_malformed_denied(stage,key,value):
    c,db,_=stage
    db[key]=value
    assert preview(c).status_code==409
    assert not db["orders"]


@pytest.mark.parametrize(("failure","expected"),[
    ("foreign_org",404),
    ("member",403),
    ("foreign_actor",409),
    ("stale_receipt",409),
    ("digest_changed",409),
])
def test_server_verified_identity_and_immutable_review(stage,failure,expected):
    c,db,context=stage
    if failure=="foreign_org":context["org"]=OTHER
    elif failure=="member":context["role"]="member"
    elif failure=="foreign_actor":context["actor"]="9"*32
    elif failure=="stale_receipt":db["receipt"]=(ACTOR,SOURCE,int(time.time())-86500)
    elif failure=="digest_changed":db["receipt"]=(ACTOR,"0"*64,int(time.time()))
    assert preview(c).status_code==expected
    assert not db["orders"]


def test_bad_preview_digest_and_bad_review_receipt_denied(stage):
    c,db,_=stage
    p=body(c)
    p["preview_sha256"]="f"*64
    assert post(c,p).status_code==409
    p=body(c)
    p["review_receipt_id"]="a"*32
    assert post(c,p).status_code==409
    assert not db["orders"]


def test_missing_csrf_origin_and_cookie_never_write(stage):
    c,db,_=stage
    p=body(c)
    assert post(c,p,{"X-CSRF-Token":""}).status_code==403
    assert post(c,p,{"Origin":"https://evil.invalid"}).status_code==403
    c.headers.pop("Cookie")
    assert post(c,p).status_code==401
    assert not db["orders"]


def test_wrong_replay_key_or_changed_request_conflicts(stage):
    c,db,_=stage
    p=body(c)
    assert post(c,p).status_code==201
    p["request_id"]="other-request-id"
    assert post(c,p).status_code==409
    assert len(db["orders"])==len(db["audit"])==1


@pytest.mark.parametrize("phase",["order","line","audit"])
def test_transaction_rolls_back_every_partially_failed_write(stage,phase):
    c,db,_=stage
    p=body(c)
    db["crash"]=phase
    with pytest.raises(RuntimeError,match="Injected PG"):
        post(c,p)
    assert not db["orders"] and not db["posted_lines"] and not db["audit"]


def test_default_off_production_disabled(monkeypatch):
    monkeypatch.delenv("JW_PG_INTERNAL_ORDER_V174",raising=False)
    assert mod.register_v174_internal_order(FastAPI()) is False
    monkeypatch.setenv("JW_PG_INTERNAL_ORDER_V174",
                       "ISOLATED_DEV_REVIEWED_INTERNAL_ORDER_ONLY")
    monkeypatch.setenv("JW_ENV","production")
    with pytest.raises(RuntimeError,match="unsafe"):
        mod.register_v174_internal_order(FastAPI())
