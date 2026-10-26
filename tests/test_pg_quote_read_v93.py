"""V9.3 read/list contract: genuine PG session, tenant scoping, no fallback."""
from __future__ import annotations
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from app import pg_quote_read_v93 as stage
from app import pg_quote_api_v92 as writer

@pytest.mark.parametrize("val",["../evil","a"*33,"A"*32,"<bad>"])
def test_invalid_id_rejected_before_db(val,monkeypatch):
    monkeypatch.setattr(writer,"enabled",lambda:True)
    app=FastAPI()
    stage.register_v93_quote_reader(app)
    client=TestClient(app,base_url="https://testserver")
    response=client.get("/api/pg-stage/v92/quotes/"+val)
    assert response.status_code in (404,422)

def test_stage_default_off(monkeypatch):
    monkeypatch.setattr(writer,"enabled",lambda:False)
    app=FastAPI()
    assert not stage.register_v93_quote_reader(app)
    assert not app.routes or not any("/api/pg-stage/v92/quotes" in getattr(r,"path","") for r in app.routes)

def test_no_session_denies_valid_quote_id(monkeypatch):
    monkeypatch.setattr(writer,"enabled",lambda:True)
    app=FastAPI()
    stage.register_v93_quote_reader(app)
    client=TestClient(app,base_url="https://testserver")
    response=client.get("/api/pg-stage/v92/quotes/"+"a"*32)
    assert response.status_code==401

def test_read_sql_is_tenant_bound():
    import inspect
    code=inspect.getsource(stage.get_quote)+inspect.getsource(stage.list_quotes)
    assert code.count("org_id=%s")>=2
    assert "jw_dev.quotes" in code
    assert "from . import pg_v90_integrated_entry" in inspect.getsource(stage)
    assert "app.main" not in code
