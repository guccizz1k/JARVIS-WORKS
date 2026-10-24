"""Real ephemeral PG17 + FastAPI HTTPS-test-origin quote transaction acceptance.

This exercises production PG validation SQL and the actual V9.2 route against
two independent nonprivileged DB sessions and forced RLS. The TestClient HTTPS
origin is emulated, not a deployed browser or actual Supabase server CA.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import secrets

import psycopg
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import pg_quote_api_v92 as quote
from app import pg_v90_integrated_entry as v90
from scripts import ci_v90_postgres_browser as fixture

ROOT = Path(__file__).resolve().parents[1]

def req_id():
    return "ci-v92-" + secrets.token_hex(10)

def payload(request_id:str, customer:str="ci-customer-a", title:str="Finance PG17"):
    return {
        "request_id":request_id,"customer_id":customer,"title":title,
        "vat_mode":"taxable",
        "items":[{"name":"Proof A","quantity":3,"unit_price":101},
                 {"name":"Proof B","quantity":2,"unit_price":503}]
    }

def request(client:TestClient, body:dict, company:str="A"):
    return client.post("/api/pg-stage/v92/quotes",json=body,
        headers={"origin":"https://testserver","X-CSRF-Token":fixture.CSRF[company]})

def make_client(app:FastAPI, company:str):
    client=TestClient(app,base_url="https://testserver")
    client.cookies.set("__Host-jw_session",fixture.TOKENS[company])
    return client

def stage_restrictions()->None:
    if os.environ.get("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE" or os.environ.get("JW_ENV")!="review":
        raise RuntimeError("BLOCKED: disposable PostgreSQL CI only")
    fixture.require_disposable()

def main()->int:
    stage_restrictions()
    fixture.bootstrap()
    with psycopg.connect(fixture.root_dsn,autocommit=True) as db:
        db.execute((ROOT/"db/review/ci_v92_quote_ephemeral.sql").read_text())

    # Require the real validated cursor from app.pg_v90_integrated_entry.
    os.environ.update({
       "JW_ENV":"dev",
       "JW_PG_STAGE_V84":"ISOLATED_DEV_READ_ONLY",
       "JW_PG_AUTH_V85":"ISOLATED_DEV_AUTH_ONLY",
       "JW_PG_MESSENGER_V90":"ISOLATED_DEV_MESSENGER_ONLY",
       "JW_PG_QUOTE_V92":"ISOLATED_DEV_QUOTE_V92",
       "JW_V90_ALLOWED_ORIGINS":"https://testserver",
    })
    os.environ.pop("JW_INSECURE_LOCAL_DEV",None)
    v90.stage._connect=lambda:psycopg.connect(fixture.TRADE_DSN,connect_timeout=5)
    assert quote.enabled()
    app=FastAPI()
    assert quote.register_v92_quote_api(app)
    a=make_client(app,"A")
    b=make_client(app,"B")
    c=make_client(app,"C")
    key=req_id()
    first=request(a,payload(key))
    assert first.status_code==201, first.text
    result=first.json()
    assert result["money"]=={"subtotal":1309,"vat":131,"total":1440}
    second=request(a,payload(key))
    assert second.status_code==200 and second.json()["quote_id"]==result["quote_id"]
    assert second.json()["created"] is False

    wrong=dict(payload(key))
    wrong["title"]="Changed after first POST"
    assert request(a,wrong).status_code==409
    assert request(b,payload(req_id())).status_code==404
    assert request(c,payload(req_id())).status_code==404
    assert request(b,payload(req_id(),customer="ci-customer-b")).status_code==201
    assert request(a,payload(req_id()),company="B").status_code==403
    no_csrf=a.post("/api/pg-stage/v92/quotes",json=payload(req_id()),
        headers={"origin":"https://testserver"})
    assert no_csrf.status_code==403
    foreign_origin=a.post("/api/pg-stage/v92/quotes",json=payload(req_id()),
        headers={"origin":"https://evil.test","X-CSRF-Token":fixture.CSRF["A"]})
    assert foreign_origin.status_code==403

    # Different independent DB backends contend for the UNIQUE idempotency
    # constraint. The winning ID, line items and audit must occur once.
    concurrent=req_id()
    with ThreadPoolExecutor(max_workers=2) as pool:
        f1=pool.submit(request,make_client(app,"A"),payload(concurrent))
        f2=pool.submit(request,make_client(app,"A"),payload(concurrent))
        outcomes=[f1.result(timeout=12),f2.result(timeout=12)]
    assert sorted(x.status_code for x in outcomes)==[200,201],[(x.status_code,x.text) for x in outcomes]
    ids={x.json()["quote_id"] for x in outcomes}
    assert len(ids)==1
    with psycopg.connect(fixture.root_dsn) as admin:
        q=admin.execute("SELECT id,org_id,title FROM jw_dev.quotes WHERE id=%s",(result["quote_id"],)).fetchone()
        assert q and q[1]=="ci-a"
        counts=admin.execute(
            """SELECT
               (SELECT count(*) FROM jw_dev.quote_items WHERE quote_id=%s),
               (SELECT count(*) FROM jw_dev.audit_logs WHERE entity_type='quote' AND entity_id=%s)""",
            (result["quote_id"],result["quote_id"])).fetchone()
        assert counts==(2,1),counts
        concurrency_id=next(iter(ids))
        counts=admin.execute(
           "SELECT count(*) FROM jw_dev.quote_items WHERE quote_id=%s",(concurrency_id,)).fetchone()[0]
        audit=admin.execute(
           "SELECT count(*) FROM jw_dev.audit_logs WHERE entity_id=%s",(concurrency_id,)).fetchone()[0]
        assert counts==2 and audit==1

        # Create a trigger to inject deterministic transactional failure.
        # It exists only in the newly initialized disposable CI database.
        admin.execute("""CREATE FUNCTION jw_dev.ci_reject_quote_item() RETURNS trigger
          LANGUAGE plpgsql AS $$
          BEGIN
            IF NEW.name='INJECT_ROLLBACK' THEN
              RAISE EXCEPTION 'simulated quote-item failure';
            END IF;
            RETURN NEW;
          END $$""")
        admin.execute("""CREATE TRIGGER ci_v92_fail BEFORE INSERT ON jw_dev.quote_items
           FOR EACH ROW EXECUTE FUNCTION jw_dev.ci_reject_quote_item()""")
        admin.commit()

    rollback=req_id()
    faulty=payload(rollback)
    faulty["items"][1]["name"]="INJECT_ROLLBACK"
    try:
        request(a,faulty)
    except Exception as exc:
        assert "simulated quote-item failure" in str(exc)
    else:
        raise AssertionError("Injected SQL rollback was not triggered")

    with psycopg.connect(fixture.root_dsn) as admin:
        bad_key="v92:"+__import__("hashlib").sha256(("ci-a\x00"+rollback).encode()).hexdigest()
        left=admin.execute("SELECT count(*) FROM jw_dev.quotes WHERE source_import_id=%s",(bad_key,)).fetchone()[0]
        assert left==0,"Partial quote survived an injected SQL exception"
        policies=admin.execute("""
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='jw_dev' AND c.relname IN ('customers','quotes','quote_items','audit_logs')
             AND c.relrowsecurity AND c.relforcerowsecurity""").fetchone()[0]
        assert policies==4
    print("PASS: real PG17 V9.2 FastAPI POST with verified PG session, 2-tenant RLS, exact KRW/VAT, CSRF & Origin")
    print("PASS: 2 genuine nonprivileged concurrent PostgreSQL transactions, unique request-id, one audit and two items")
    print("PASS: injected item SQL failure rolls back quote+items+audit atomically, no persisted residue")
    print("LIMIT: isolated DB, TestClient HTTPS origin; NOT deployed TLS, real Supabase CA, or production finance rollout")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
