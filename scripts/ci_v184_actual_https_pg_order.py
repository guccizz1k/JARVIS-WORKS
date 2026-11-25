"""V18.4 genuine TLS HTTP -> restricted PostgreSQL17 quote/review/draft/order.

Hard isolation: only the existing disposable local 127.0.0.1 PG17 GitHub runner;
no Supabase, Render DB, imported customer files, bank, invoices or production.
Uses current V92 and V174 product handlers, not mock HTTP/TestClient.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import os
import subprocess
import time

import httpx
import psycopg
import uvicorn
from fastapi import FastAPI

from scripts import ci_v174_real_pg_internal_order as existing
from scripts import ci_v157_real_pg_delivery_http as fixture
from app import pg_quote_api_v92 as quotes
from scripts.review import pg_order_activation_v174 as order

HOST = "https://localhost:8767"
ACK = "ONLY_EPHEMERAL_LOCAL_DATABASE"
CSRF_ORIGIN = {"Origin": HOST}


def prepare() -> FastAPI:
    # The original V174 bootstrap refuses non-local or previously populated DB.
    existing.install()
    with psycopg.connect(fixture.DSN) as root:
        root.execute("ALTER TABLE jw_dev.quotes ADD COLUMN source_import_id text")
        root.execute("ALTER TABLE jw_dev.quotes ADD COLUMN source_document_meta text NOT NULL DEFAULT '{}'")
        root.execute("CREATE UNIQUE INDEX v184_quote_idempotency ON jw_dev.quotes(source_import_id)")
        root.execute("GRANT SELECT ON jw_dev.customers TO jw_app_dev")
        root.execute("GRANT INSERT ON jw_dev.quotes,jw_dev.quote_items TO jw_app_dev")
        root.execute("""CREATE POLICY v184_customers_read ON jw_dev.customers
                    FOR SELECT TO jw_app_dev USING(org_id=jw_dev.current_org_from_session())""")
        root.execute("""CREATE POLICY v184_quote_insert ON jw_dev.quotes
                    FOR INSERT TO jw_app_dev WITH CHECK(
                      org_id=jw_dev.current_org_from_session()
                      AND EXISTS(SELECT 1 FROM jw_dev.customers c
                        WHERE c.id=customer_id AND c.org_id=org_id))""")
        root.execute("""CREATE POLICY v184_quote_line_insert ON jw_dev.quote_items
                    FOR INSERT TO jw_app_dev WITH CHECK(
                      EXISTS(SELECT 1 FROM jw_dev.quotes q
                        WHERE q.id=quote_id
                        AND q.org_id=jw_dev.current_org_from_session()))""")
    app=fixture.configure()
    os.environ["JW_V90_ALLOWED_ORIGINS"] = HOST
    os.environ["JW_PG_INTERNAL_ORDER_V174"] = order._GATE
    assert quotes.register_v92_quote_api(app)
    assert order.register_v174_internal_order(app)
    return app


def request_headers(actor: str, write: bool = False) -> dict[str,str]:
    headers={"Cookie":"__Host-jw_session="+fixture.TOKENS[actor],
             "Cache-Control":"no-store"}
    if write:
        headers.update(CSRF_ORIGIN)
        headers["X-CSRF-Token"]=fixture.CSRF[actor]
    return headers


def assert_response(res: httpx.Response, status: int, label: str) -> dict:
    assert res.status_code==status,(label,res.status_code,res.text[:220])
    return res.json()


def run_live(client: httpx.Client) -> None:
    def get(path: str, actor: str = "A"):
        return client.get(HOST+path,headers=request_headers(actor))
    def post(path: str, body: dict, actor: str = "A", headers=None):
        return client.post(HOST+path,json=body,
                           headers=headers or request_headers(actor,True))
    qpath="/api/pg-stage/v92/quotes"
    quote_body={"request_id":"v184-real-tls-quote-01",
                "customer_id":"0"*32,"title":"V184 Real TLS internal quote",
                "vat_mode":"taxable",
                "items":[{"name":"Synthetic pump","quantity":2,"unit_price":3500},
                         {"name":"Synthetic seal","quantity":1,"unit_price":1800}]}
    assert post(qpath,quote_body,headers=request_headers("A")).status_code==403
    assert post(qpath,quote_body,headers={
        **request_headers("A",True),"Origin":"https://forged.invalid.test"
    }).status_code==403
    assert post(qpath,quote_body,"B").status_code==404
    created=assert_response(post(qpath,quote_body),201,"create")
    assert created["created"] is True
    assert created["money"]=={"subtotal":8800,"vat":880,"total":9680}
    qid=created["quote_id"]
    assert len(qid)==32 and qid!=("7"*32)
    repeated=assert_response(post(qpath,quote_body),200,"repeat")
    assert repeated["quote_id"]==qid and repeated["created"] is False
    assert post(qpath,{**quote_body,"title":"changed-request-payload"}).status_code==409

    preview_path="/api/pg-stage/v92/quote-review-previews/"+qid
    assert get(preview_path,"B").status_code==404
    preview=assert_response(get(preview_path),200,"review-preview")
    assert preview["money"]["total"]==9680
    assert preview["source_document_verified"] is False
    ack_path="/api/pg-stage/v92/quote-reviews"
    ack_body={"quote_id":qid,"preview_sha256":preview["preview_sha256"],
              "preview_checked":True}
    assert post(ack_path,ack_body,headers=request_headers("A")).status_code==403
    assert post(ack_path,{**ack_body,"preview_sha256":"0"*64}).status_code==409
    reviewed=assert_response(post(ack_path,ack_body),201,"acknowledged-preview")
    rid=reviewed["review_receipt_id"]
    draft_path="/api/pg-stage/v92/order-drafts"
    draft_body={"request_id":"v184-quote-to-draft-01",
                "quote_id":qid,"review_receipt_id":rid,"original_checked":True}
    assert post(draft_path,draft_body,"B").status_code in (403,404)
    assert post(draft_path,{**draft_body,"review_receipt_id":"b"*32}).status_code==409
    draft=assert_response(post(draft_path,draft_body),201,"draft")
    assert draft["draft_only"] is True
    did=draft["order_id"]
    activate_path="/api/pg-stage/v174/order-drafts/"+did+"/register-preview"
    assert get(activate_path,"B").status_code==404
    assert get(activate_path,"M").status_code==403
    checked=assert_response(get(activate_path),200,"internal-order-review")
    assert checked["money"]["total"]==9680
    approve_body={"draft_id":did,"review_receipt_id":rid,
                  "preview_sha256":checked["preview_sha256"],
                  "request_id":"v184-reviewed-order-01",
                  "original_checked":True,"register_internal_only":True}
    target="/api/pg-stage/v174/orders/from-reviewed-draft"
    assert post(target,approve_body,headers=request_headers("A")).status_code==403
    assert post(target,approve_body,"M").status_code==403
    assert post(target,{**approve_body,"preview_sha256":"f"*64}).status_code==409
    first=assert_response(post(target,approve_body),201,"internal-order-create")
    assert first["internal_order_only"] is True and first["created"] is True
    assert first["invoice_issued"] is False and first["payment_recorded"] is False
    assert first["external_acceptance_verified"] is False
    replay=assert_response(post(target,approve_body),200,"order-idempotent-retry")
    assert replay["created"] is False and replay["order_id"]==first["order_id"]

    # 20 separate foreign quote IDs through actual TLS and restricted DB RLS.
    for i in range(20):
        missing=f"{i+1:032x}"
        assert get("/api/pg-stage/v92/quote-review-previews/"+missing).status_code==404
    with psycopg.connect(fixture.DSN) as root:
        assert root.execute("SELECT count(*) FROM jw_dev.quotes WHERE id=%s",(qid,)).fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.quote_items WHERE quote_id=%s",(qid,)).fetchone()==(2,)
        assert root.execute("SELECT count(*) FROM jw_dev.order_drafts_v127 WHERE id=%s",(did,)).fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.orders WHERE id=%s",(first["order_id"],)).fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.order_items WHERE order_id=%s",(first["order_id"],)).fetchone()==(2,)
        assert root.execute("""SELECT count(*) FROM jw_dev.audit_logs
                               WHERE entity_id=%s AND action='human_approved_internal_order_only'""",
                            (first["order_id"],)).fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.invoices").fetchone()==(0,)
        assert root.execute("SELECT to_regclass('jw_dev.payments')").fetchone()==(None,)
    print("PASS_V184_REAL_TLS_PG17_QUOTE_REVIEW_DRAFT_INTERNAL_ORDER",flush=True)
    print("PASS_V184_REAL_TLS_RLS_CSRF_ORIGIN_IDEMPOTENCY_20_NEGATIVES",flush=True)
    print("LIMIT_V184_DISPOSABLE_GITHUB_POSTGRES_ONLY_NOT_HOSTED_RENDER_FULL_FLOW",flush=True)
    print("LIMIT_V184_NO_LEGAL_INVOICE_BANK_SETTLEMENT_MESSENGER_WRITE",flush=True)


def main() -> None:
    if (os.getenv("JW_ENV")!="review"
        or os.getenv("JW_PG_CI_ALLOW")!=ACK
        or os.getenv("JW_PG_CI_ROOT_DSN","").find("@127.0.0.1:5432/postgres")<0):
        raise RuntimeError("BLOCKED_V184_ONLY_DISPOSABLE_GITHUB_POSTGRES")
    app=prepare()
    with TemporaryDirectory(prefix="jw-v184-tls-") as tmp:
        key=Path(tmp)/"key.pem"
        cert=Path(tmp)/"cert.pem"
        subprocess.run(["openssl","req","-x509","-nodes","-newkey","rsa:2048",
                        "-keyout",str(key),"-out",str(cert),"-days","1",
                        "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost"],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        server=uvicorn.Server(uvicorn.Config(
            app,host="127.0.0.1",port=8767,ssl_keyfile=str(key),ssl_certfile=str(cert),
            log_level="error",access_log=False))
        worker=Thread(target=server.run,daemon=True)
        worker.start()
        try:
            for _ in range(100):
                if server.started:break
                time.sleep(.1)
            assert server.started,"V184 ephemeral HTTPS server unavailable"
            with httpx.Client(verify=str(cert),trust_env=False,
                              follow_redirects=False,timeout=20) as client:
                run_live(client)
        finally:
            server.should_exit=True
            worker.join(timeout=12)
            assert not worker.is_alive(),"V184 HTTPS server did not close"

if __name__=="__main__":
    main()
