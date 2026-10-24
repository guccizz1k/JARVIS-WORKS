"""V9.2 isolated PostgreSQL quote endpoint: no mock acceptance is called a live DB pass."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import pg_quote_api_v92 as mod

TOKEN = "stage-session-token-" + "x" * 45
CSRF = "ci-stage-csrf-secret"


class Cursor:
    def __init__(self, state, org):
        self.state, self.org = state, org
        self.record = None
    def execute(self, sql, params=None):
        self.record = None
        if sql.startswith("SELECT name FROM jw_dev.customers"):
            self.record=("Sample customer",) if params == ("cust-a","org-a") else None
        elif sql.startswith("INSERT INTO jw_dev.quotes"):
            quote_id, org, customer_id, _, _, title, mode, _, _, idem, meta=params
            if idem not in self.state["quotes"]:
                self.state["quotes"][idem]={"id":quote_id,"org":org,"title":title,
                                            "mode":mode,"meta":meta}
                self.record=(quote_id,)
        elif sql.startswith("SELECT id,source_document_meta"):
            key, org=params
            q=self.state["quotes"].get(key)
            self.record=(q["id"],q["meta"]) if q and q["org"]==org else None
        elif sql.startswith("INSERT INTO jw_dev.quote_items"):
            self.state["items"].append(params)
        elif sql.startswith("INSERT INTO jw_dev.audit_logs"):
            self.state["audit"].append(params)
        else:
            raise AssertionError("Unexpected SQL in isolated oracle")
    def fetchone(self):
        return self.record


@pytest.fixture()
def stage(monkeypatch):
    store={"quotes":{},"items":[],"audit":[]}
    org=["org-a"]
    monkeypatch.setenv("JW_PG_QUOTE_V92","ISOLATED_DEV_QUOTE_V92")
    monkeypatch.setenv("JW_ENV","dev")
    monkeypatch.delenv("JW_INSECURE_LOCAL_DEV",raising=False)
    monkeypatch.setattr(mod.v90,"v90_enabled",lambda:True)
    monkeypatch.setattr(mod.v90,"_origins",lambda:frozenset({"https://testserver"}))
    @contextmanager
    def db_cursor(token_hash):
        assert len(token_hash)==64
        working=deepcopy(store)
        cursor=Cursor(working,org[0])
        identity=("jw_app_dev","user-a",org[0],"member",CSRF,"Company A")
        yield cursor,identity
        store.update(working)
    monkeypatch.setattr(mod.v90,"_pg_validated_cursor",db_cursor)
    app=FastAPI()
    assert mod.register_v92_quote_api(app)
    client=TestClient(app,base_url="https://testserver")
    client.cookies.set("__Host-jw_session",TOKEN,secure=True)
    return client,store,org


def payload(request_id="unique-request-001"):
    return {"request_id":request_id,"customer_id":"cust-a","title":"Validated quote",
            "vat_mode":"taxable","items":[{"name":"A","quantity":3,"unit_price":101},
                                           {"name":"B","quantity":2,"unit_price":503}]}


def request(client, data=None, headers=None):
    h={"origin":"https://testserver","X-CSRF-Token":CSRF}
    h.update(headers or {})
    return client.post("/api/pg-stage/v92/quotes",json=payload() if data is None else data,headers=h)


def test_sql_form_insert_math_and_one_transaction(stage):
    client,store,_=stage
    r=request(client)
    assert r.status_code==201,r.text
    assert r.json()["created"] is True
    assert r.json()["money"]=={"subtotal":1309,"vat":131,"total":1440}
    assert len(store["quotes"])==1 and len(store["items"])==2 and len(store["audit"])==1
    assert r.headers["cache-control"]=="no-store"


def test_same_request_retry_returns_same_id_without_duplicate_audit(stage):
    c,s,_=stage
    a=request(c); b=request(c)
    assert a.status_code==201 and b.status_code==200
    assert b.json()["created"] is False
    assert a.json()["quote_id"]==b.json()["quote_id"]
    assert len(s["quotes"])==1 and len(s["items"])==2 and len(s["audit"])==1


def test_same_request_different_financial_payload_conflicts(stage):
    c,s,_=stage
    assert request(c).status_code==201
    different=payload()
    different["items"][0]["unit_price"]=102
    r=request(c,different)
    assert r.status_code==409
    assert len(s["quotes"])==1


def test_missing_or_wrong_csrf_never_writes(stage):
    c,s,_=stage
    assert request(c,headers={"X-CSRF-Token":""}).status_code==403
    assert request(c,headers={"X-CSRF-Token":"wrong"}).status_code==403
    assert s["quotes"]=={}


def test_cross_site_origin_is_rejected(stage):
    c,s,_=stage
    assert request(c,headers={"origin":"https://evil.test"}).status_code==403
    assert s["quotes"]=={}


def test_missing_cookie_rejected_before_db(stage):
    c,s,_=stage
    c.cookies.clear()
    assert request(c).status_code==401
    assert s["quotes"]=={}


def test_foreign_customer_denied_before_writes(stage):
    c,s,_=stage
    bad=payload()
    bad["customer_id"]="foreign-customer"
    assert request(c,bad).status_code==404
    assert s["quotes"]=={}


def test_same_key_is_tenant_scoped(stage):
    c,s,org=stage
    assert request(c).status_code==201
    org[0]="org-b"
    assert request(c).status_code==404  # customer belongs to org A
    assert len(s["quotes"])==1


@pytest.mark.parametrize("qty,price",[(0,100),(100001,100),(-1,100),(1,-1),(True,100),(1,True)])
def test_invalid_financial_lines_fail_closed(stage,qty,price):
    c,s,_=stage
    bad=payload()
    bad["items"][0]["quantity"]=qty
    bad["items"][0]["unit_price"]=price
    assert request(c,bad).status_code==422
    assert s["quotes"]=={}


def test_no_body_org_or_actor_override(stage):
    c,s,_=stage
    extra=payload()
    extra["org_id"]="org-b"
    extra["actor_id"]="admin"
    assert request(c,extra).status_code==422
    assert not s["quotes"]


def test_no_production_registration(monkeypatch):
    monkeypatch.setenv("JW_PG_QUOTE_V92","ISOLATED_DEV_QUOTE_V92")
    monkeypatch.setenv("JW_ENV","production")
    monkeypatch.setattr(mod.v90,"v90_enabled",lambda:True)
    assert not mod.register_v92_quote_api(FastAPI())


def test_default_off(monkeypatch):
    monkeypatch.delenv("JW_PG_QUOTE_V92",raising=False)
    monkeypatch.setenv("JW_ENV","dev")
    assert not mod.register_v92_quote_api(FastAPI())


def test_exempt_quote_vat_is_zero(stage):
    c,s,_=stage
    data=payload()
    data["vat_mode"]="exempt"
    r=request(c,data)
    assert r.status_code==201
    assert r.json()["money"]=={"subtotal":1309,"vat":0,"total":1309}


def test_overflow_raises_without_write(stage):
    c,s,_=stage
    data=payload()
    data["items"]=[{"name":"bulk","quantity":100000,"unit_price":1000000000}]*40
    assert request(c,data).status_code==422
    assert s["quotes"]=={}


def test_fail_closed_db_rollback_mid_items(stage,monkeypatch):
    c,s,_=stage
    original=Cursor.execute
    def fail_on_item(self,sql,params=None):
        if sql.startswith("INSERT INTO jw_dev.quote_items"):
            raise RuntimeError("Simulated DB crash before audit commit")
        return original(self,sql,params)
    monkeypatch.setattr(Cursor,"execute",fail_on_item)
    with pytest.raises(RuntimeError,match="Simulated DB crash"):
        request(c)
    assert s["quotes"]=={} and not s["items"] and not s["audit"]
