"""V15.8 actual FastAPI TestClient contract for linked trade lifecycle."""
from contextlib import contextmanager
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from psycopg import errors

from app import pg_trade_lineage_v158 as mod

QUOTE="a"*32
ORG="b"*32
ORDER="c"*32
INVOICE="d"*32


class LinkedCursor:
    def __init__(self, *, org=ORG, omit=False, bad_order=False, review=False,
                 too_many=False, denied=False):
        self.org=org
        self.omit=omit
        self.bad_order=bad_order
        self.review=review
        self.too_many=too_many
        self.denied=denied
        self.results=[]
        self.calls=[]

    def execute(self, statement, params=None):
        if self.denied:raise errors.InsufficientPrivilege("synthetic denied")
        self.calls.append((statement,params))
        if "FROM jw_dev.quotes" in statement:
            self.results=[(QUOTE,"draft","e"*32,"taxable","Q-123")] if not self.omit else []
        elif "FROM jw_dev.import_previews" in statement:
            self.results=[("f"*32,"confirmed")]
        elif "FROM jw_dev.orders" in statement:
            self.results=[(ORDER,"fulfilled","acknowledged",
                           "e"*32 if not self.bad_order else "9"*32,"taxable")]
            if self.too_many:self.results*=21
        elif "to_regclass(" in statement:
            self.results=[("jw_dev.review_delivery_receipts_v151",) if self.review else (None,)]
        elif "FROM jw_dev.review_delivery_receipts" in statement:
            self.results=[("PENDING_HUMAN_REVIEW",)]
        elif "FROM jw_dev.invoices" in statement:
            self.results=[(INVOICE,"open")]
        elif "FROM jw_dev.payments" in statement:
            self.results=[("1"*32,800,None),("2"*32,600,"reversed")]
        else:
            raise AssertionError("Unrecognized query: "+statement)
        if params is not None:
            assert params[1]==self.org, "Missing explicit tenant parameter"

    def fetchone(self):
        return self.results[0] if self.results else None

    def fetchall(self):
        return self.results


@pytest.fixture
def stage(monkeypatch):
    monkeypatch.setattr(mod, "enabled", lambda:True)
    monkeypatch.setattr(mod.sessions,"_session_hash",lambda _: "fake-session")
    cur=LinkedCursor()

    @contextmanager
    def cursor(_):
        yield cur,("jw_app_dev","f"*32,ORG,"admin","csrf","Org")
    monkeypatch.setattr(mod.sessions,"_pg_validated_cursor",cursor)
    app=FastAPI()
    router=mod.APIRouter(prefix=mod._PREFIX)
    router.add_api_route("/quotes/{quote_id}/lineage",mod.trade_lineage,
                         methods=["GET"],response_model=None)
    app.include_router(router)
    return TestClient(app),cur,monkeypatch


def test_full_lineage_never_claims_payments_reconciled(stage):
    client,cur,_=stage
    res=client.get("/api/pg-stage/v158/quotes/"+QUOTE+"/lineage")
    assert res.status_code==200,res.text
    data=res.json()
    assert data["counts"]=={"source_imports":1,"orders":1,"invoices":1,"recorded_payments":2}
    assert data["orders"][0]["delivery_evidence_review"]=="NOT_CONFIGURED"
    assert data["orders"][0]["physical_delivery_verified"] is False
    assert data["orders"][0]["invoices"][0]["recorded_active_amount_krw"]==800
    assert data["orders"][0]["invoices"][0]["reconciled"] is False
    assert data["payment_reconciliation_verified"] is False
    assert data["automated_business_approval"] is False
    assert res.headers["cache-control"]=="no-store"
    assert len(cur.calls)==6
    assert all("INSERT " not in sql and "UPDATE " not in sql for sql,_ in cur.calls)


def test_review_ledger_is_scoped_and_only_pending(stage):
    client,cur,_=stage
    cur.review=True
    res=client.get("/api/pg-stage/v158/quotes/"+QUOTE+"/lineage")
    assert res.status_code==200
    assert res.json()["orders"][0]["delivery_evidence_review"]=="PENDING_HUMAN_REVIEW"
    assert any("review_delivery_receipts" in sql for sql,_ in cur.calls)


def test_missing_quote_returns_404(stage):
    client,cur,_=stage
    cur.omit=True
    assert client.get("/api/pg-stage/v158/quotes/"+QUOTE+"/lineage").status_code==404


@pytest.mark.parametrize("bad",["foo", "F"*32, "a"*31, "a"*33, "a"*31+"-"])
def test_invalid_quote_ids_are_not_queried(stage,bad):
    client,cur,_=stage
    assert client.get("/api/pg-stage/v158/quotes/"+bad+"/lineage").status_code==404
    assert cur.calls==[]


def test_inconsistent_source_is_never_accepted(stage):
    client,cur,_=stage
    cur.bad_order=True
    assert client.get("/api/pg-stage/v158/quotes/"+QUOTE+"/lineage").status_code==409


def test_overlimit_records_cannot_silently_truncate(stage):
    client,cur,_=stage
    cur.too_many=True
    assert client.get("/api/pg-stage/v158/quotes/"+QUOTE+"/lineage").status_code==409


def test_missing_privileges_fail_closed(stage):
    client,cur,_=stage
    cur.denied=True
    resp=client.get("/api/pg-stage/v158/quotes/"+QUOTE+"/lineage")
    assert resp.status_code==503
    assert "synthetic" not in resp.text


def test_disabled_by_default_and_wrong_mode(monkeypatch):
    monkeypatch.delenv("JW_PG_TRADE_LINEAGE_V158",raising=False)
    app=FastAPI()
    assert mod.register_v158_trade_lineage(app) is False
    assert not any("/v158" in r.path for r in app.routes)
    monkeypatch.setenv("JW_PG_TRADE_LINEAGE_V158","incorrect")
    with pytest.raises(RuntimeError):
        mod.register_v158_trade_lineage(app)
