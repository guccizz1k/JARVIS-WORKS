"""Real PostgreSQL 17 V15.1-15.5 signed delivery HTTP integration test.

MUST run only against a freshly provisioned, disposable 127.0.0.1 Postgres 17
GitHub Actions service. Uses synthetic issuer keys and actors, so does NOT
certify physical delivery nor authorize production issuer key enrollment.
NO Supabase DSNs, NO migrations, NO permanent data outside ephemeral runner.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
import hashlib
import hmac
import os
import secrets
import time

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import pg_delivery_review_api_v154 as delivery
from app import pg_v90_integrated_entry as entry
from app.pg_delivery_evidence_gate_v147 import _FIELDS, _json
from app.pg_invoice_preview_v145 import build_invoice_preview

ROOT = Path(__file__).resolve().parents[1]
ORDER_A, ORDER_B = "c"*32, "d"*32
ORG_A, ORG_B = "a"*32, "b"*32
LINE_A, LINE_B = "3"*32, "4"*32
DISPATCH_KEY = secrets.token_bytes(32)
RECEIPT_KEY = secrets.token_bytes(32)
TOKENS = {x: secrets.token_urlsafe(48) for x in ("A","B","M")}
CSRF = {x: secrets.token_urlsafe(22) for x in ("A","B","M")}
DSN = os.getenv("JW_PG_CI_ROOT_DSN","")
TRADE_DSN = ""


def disposable_root_check():
    if os.getenv("JW_PG_CI_ALLOW") != "ONLY_EPHEMERAL_LOCAL_DATABASE":
        raise RuntimeError("BLOCKED: not authorized isolated PG17")
    d = conninfo_to_dict(DSN)
    if (d.get("host")!="127.0.0.1" or d.get("port","5432")!="5432"
        or d.get("dbname")!="postgres" or d.get("user")!="postgres"):
        raise RuntimeError("BLOCKED: nonlocal or non-disposable PostgreSQL")
    with psycopg.connect(DSN) as conn:
        assert int(conn.execute("SHOW server_version_num").fetchone()[0])//10000==17
        assert conn.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname<>'postgres' AND rolname !~ '^pg_'"
        ).fetchone()==(0,)
        assert conn.execute(
            "SELECT count(*) FROM pg_database WHERE NOT datistemplate AND datname<>'postgres'"
        ).fetchone()==(0,)
        assert conn.execute("SELECT to_regclass('jw_dev.orders')").fetchone()==(None,)


def bootstrap():
    global TRADE_DSN
    disposable_root_check()
    passwd=secrets.token_urlsafe(36)
    with psycopg.connect(DSN,autocommit=True) as conn:
        with conn.cursor() as c:
            # All review file references are pre-created with the least authority.
            for role in (
                "jw_app_dev","jw_auth_stage_v85","anon","authenticated",
                "jw_stage1_trade_20261030","jw_stage1_auth_20261030"
            ):
                c.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOINHERIT NOBYPASSRLS").format(
                    sql.Identifier(role)))
            c.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOBYPASSRLS "
                              "NOSUPERUSER NOCREATEROLE NOCREATEDB PASSWORD {}").format(
                sql.Identifier("jw_ci_v157_trade"),sql.Literal(passwd)))
            c.execute("GRANT jw_app_dev TO jw_ci_v157_trade WITH INHERIT FALSE, SET TRUE")
            c.execute((ROOT/"scripts/review/v157_disposable_pg17_source.sql").read_text())
            c.execute((ROOT/"scripts/review/v151_private_review_ledger_candidate.sql").read_text())
            c.execute((ROOT/"scripts/review/v153_restricted_review_writer_candidate.sql").read_text())
            for name,actor in (("A","1"*32),("B","2"*32),("M","9"*32)):
                c.execute("""INSERT INTO jw_dev.sessions
                  (token_hash,user_id,expires_at,csrf_token,created_at)
                  VALUES(%s,%s,(now()+interval '2 hours')::text,%s,now()::text)""",
                  (sha256(TOKENS[name].encode()).hexdigest(),actor,CSRF[name]))
    TRADE_DSN=make_conninfo(DSN,user="jw_ci_v157_trade",password=passwd)
    with psycopg.connect(TRADE_DSN) as trade:
        assert trade.execute("SELECT session_user").fetchone()==("jw_ci_v157_trade",)
        assert trade.execute(
            "SELECT pg_has_role(session_user,'jw_auth_stage_v85','MEMBER')"
        ).fetchone()==(False,)


def configure():
    os.environ.update({
        "JW_ENV":"test",
        "JW_PG_STAGE_V84":"ISOLATED_DEV_READ_ONLY",
        "JW_PG_AUTH_V85":"ISOLATED_DEV_AUTH_ONLY",
        "JW_PG_MESSENGER_V90":"ISOLATED_DEV_MESSENGER_ONLY",
        "JW_PG_QUOTE_V92":"ISOLATED_DEV_QUOTE_V92",
        "JW_PG_DELIVERY_REVIEW_V154":"ISOLATED_DEV_SIGNED_RECEIPT_REVIEW_ONLY",
        # No real issuer is accepted. This ACK is confined to this disposable
        # process to exercise otherwise blocked code with synthetic HMAC.
        "JW_V154_ISSUER_INDEPENDENCE_ACK":"EXTERNAL_ISSUER_KEYS_VERIFIED",
        "JW_V154_DISPATCH_VERIFY_KEY_HEX":DISPATCH_KEY.hex(),
        "JW_V154_RECEIPT_VERIFY_KEY_HEX":RECEIPT_KEY.hex(),
        "JW_V90_ALLOWED_ORIGINS":"https://testserver",
    })
    os.environ.pop("JW_INSECURE_LOCAL_DEV",None)
    entry.stage._connect=lambda:psycopg.connect(TRADE_DSN,connect_timeout=5)
    assert delivery.enabled()
    app=FastAPI()
    assert delivery.register_v154_delivery_review(app)
    return app


def client(app,name):
    c=TestClient(app,base_url="https://testserver")
    c.cookies.set("__Host-jw_session",TOKENS[name],domain="testserver",path="/")
    return c


def proof_pair(order_id,org_id,line_id,now=None):
    current=now or int(time.time())
    # Canonical hash comes from the REAL V14.5 invoice source calculator.
    order=(order_id,"e"*32 if org_id==ORG_A else "f"*32,
           "O-A" if org_id==ORG_A else "O-B",
           "0"*32 if org_id==ORG_A else "8"*32,
           "Customer A" if org_id==ORG_A else "Customer B",
           "fulfilled","acknowledged","taxable",
           "Synthetic Delivery A" if org_id==ORG_A else "Synthetic Delivery B")
    preview=build_invoice_preview(order,[(line_id,
          "Synthetic line A" if org_id==ORG_A else "Synthetic line B",2,3500,0)])
    def sign(purpose,key,signer):
        p={"schema":"jw-delivery-evidence-v147","purpose":purpose,
           "issuer":"approved-dispatch-attestor-v1" if purpose=="dispatch"
                 else "approved-receipt-attestor-v1",
           "order_id":order_id,"org_id":org_id,
           "source_sha256":preview["source_sha256"],
           "document_sha256":hashlib.sha256((purpose+order_id).encode()).hexdigest(),
           "items":[{"source_order_item_id":line_id,"delivered_quantity":2}],
           "signer_id":signer,"nonce":secrets.token_hex(16),
           "issued_at":current-10,"expires_at":current+600}
        assert set(p)==_FIELDS
        return {**p,"signature":hmac.new(key,_json(p),hashlib.sha256).hexdigest()}
    return {"dispatch_proof":sign("dispatch",DISPATCH_KEY,"5"*32),
            "recipient_proof":sign("receipt",RECEIPT_KEY,"6"*32)}


def send(client_obj,order,packet,company):
    return client_obj.post(
        "/api/pg-stage/v154/orders/"+order+"/delivery-review",
        headers={"origin":"https://testserver","X-CSRF-Token":CSRF[company]},
        json=packet)


def assertions():
    with psycopg.connect(DSN) as admin:
        return admin.execute("""SELECT
          (SELECT count(*) FROM jw_dev.review_delivery_receipts_v151),
          (SELECT count(*) FROM jw_dev.review_delivery_nonces_v151),
          (SELECT count(*) FROM jw_dev.review_delivery_items_v151),
          (SELECT count(*) FROM jw_dev.audit_logs),
          (SELECT count(*) FROM jw_dev.invoices)
        """).fetchone()


def main():
    bootstrap()
    app=configure()
    a,b,m=client(app,"A"),client(app,"B"),client(app,"M")
    assert a.get("/api/pg-stage/v155/review-console").status_code==200
    assert m.get("/api/pg-stage/v155/review-console").status_code==403
    packet=proof_pair(ORDER_A,ORG_A,LINE_A)
    review_url="/api/pg-stage/v154/orders/"+ORDER_A+"/delivery-review"
    assert b.get(review_url).status_code==404
    assert m.get(review_url).status_code==403
    assert a.get(review_url).status_code==404
    assert send(m,ORDER_A,packet,"M").status_code==403
    assert a.post(review_url,headers={"origin":"https://testserver"},
                  json=packet).status_code==403
    assert a.post(review_url,headers={"origin":"https://evil.invalid.test",
                  "X-CSRF-Token":CSRF["A"]},json=packet).status_code==403
    wrong=dict(packet)
    wrong["dispatch_proof"]={**packet["dispatch_proof"],"signature":"f"*64}
    assert send(a,ORDER_A,wrong,"A").status_code==409
    assert assertions()==(0,0,0,0,0)

    # Two real independent PostgreSQL TCP sessions compete for ONE order and
    # the same proof. Exactly one review/audit may survive.
    with ThreadPoolExecutor(max_workers=2) as pool:
        f1=pool.submit(send,client(app,"A"),ORDER_A,packet,"A")
        f2=pool.submit(send,client(app,"A"),ORDER_A,packet,"A")
        pair=[f1.result(timeout=17),f2.result(timeout=17)]
    assert sorted(x.status_code for x in pair)==[201,409],[
        (x.status_code,x.text[:300]) for x in pair]
    assert assertions()==(1,2,1,1,0),assertions()
    read=a.get(review_url)
    assert read.status_code==200,read.text
    assert read.json()["status"]=="PENDING_HUMAN_REVIEW"
    assert not read.json()["physical_delivery_verified"]
    assert not read.json()["invoice_posted"]
    assert not read.json()["payment_posted"]
    assert b.get(review_url).status_code==404
    assert send(a,ORDER_A,packet,"A").status_code==409
    assert assertions()==(1,2,1,1,0)

    # Inject a PostgreSQL audit exception for company B to verify rollback
    # of all prior receipt, nonces and line writes (not only unit mocks).
    with psycopg.connect(DSN) as admin:
        admin.execute("""CREATE FUNCTION jw_dev.ci_v157_deny_audit()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.org_id=repeat('b',32) THEN
            RAISE EXCEPTION 'CI_V157_INJECT_AUDIT_ROLLBACK';
          END IF; RETURN NEW;
        END $$""")
        admin.execute("""CREATE TRIGGER ci_v157_fail_audit BEFORE INSERT
            ON jw_dev.audit_logs FOR EACH ROW
            EXECUTE FUNCTION jw_dev.ci_v157_deny_audit()""")
    try:
        send(b,ORDER_B,proof_pair(ORDER_B,ORG_B,LINE_B),"B")
    except Exception as exc:
        assert "CI_V157_INJECT_AUDIT_ROLLBACK" in str(exc),str(exc)[:300]
    else:
        raise AssertionError("Audit failure did not abort response transaction")
    assert assertions()==(1,2,1,1,0),assertions()
    with psycopg.connect(DSN) as admin:
        for table in ("review_delivery_receipts_v151",
                      "review_delivery_nonces_v151",
                      "review_delivery_items_v151"):
            assert admin.execute(sql.SQL(
                "SELECT count(*) FROM jw_dev.{} WHERE order_id=%s"
              ).format(sql.Identifier(table)),(ORDER_B,)).fetchone()==(0,)
        assert admin.execute("SELECT count(*) FROM pg_policies WHERE schemaname='jw_dev' AND policyname LIKE 'v153_%'").fetchone()==(6,)
        assert admin.execute("SELECT relforcerowsecurity FROM pg_class WHERE oid='jw_dev.review_delivery_receipts_v151'::regclass").fetchone()==(True,)
    print("PASS_V157_REAL_PG17_TWO_TCP_DELIVERY_POST_ONE_201_ONE_409",flush=True)
    print("PASS_V157_REAL_HTTP_GET_A_ADMIN_B_FOREIGN_MEMBER_FORBIDDEN",flush=True)
    print("PASS_V157_DB_ATOMIC_RECEIPT_NONCE_LINE_AUDIT_AND_INJECTED_ROLLBACK",flush=True)
    print("PASS_V157_NO_INVOICE_NO_PAYMENT_NO_PHYSICAL_DELIVERY_CLAIM",flush=True)
    print("LIMIT: synthetic issuer HMAC, isolated PostgreSQL only; NOT certification or hosted HTTPS",flush=True)


if __name__=="__main__":
    main()
