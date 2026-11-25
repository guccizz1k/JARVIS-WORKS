"""V19.1 approved import -> quote -> human review -> internal order, real TLS/PG17.

A genuine HTTPS network request exercises EXISTING V160, V92, and V174 route
handlers with forced RLS and separate limited PostgreSQL business credentials.
The source preview is synthetic and *already confirmed*; this is not an actual
upload, independent OCR, physical delivery, invoice issuance, or bank proof.
Never run against Render/Supabase or a shared database.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
import time
import uuid

from cryptography.fernet import Fernet
import httpx
import psycopg
import uvicorn

from app.import_engine import verify
from app.security_hardening import sealed_json
from app import pg_import_quote_v160 as import_api
from scripts import ci_v184_actual_https_pg_order as quote_flow
from scripts import ci_v157_real_pg_delivery_http as fixture

HOST="https://localhost:8769"
ACK="ONLY_EPHEMERAL_LOCAL_DATABASE"
PREVIEW=uuid.uuid4().hex
INVOICE_UNVERIFIED=True


def prepare():
    if (os.getenv("JW_ENV")!="review" or
        os.getenv("JW_PG_CI_ALLOW")!=ACK or
        "@127.0.0.1:5432/postgres" not in os.getenv("JW_PG_CI_ROOT_DSN","")):
        raise RuntimeError("BLOCKED_V191_NOT_APPROVED_DISPOSABLE_PG17")
    fixture.disposable_root_check()
    os.environ["JW_DATA_KEY"]=Fernet.generate_key().decode("ascii")
    app=quote_flow.prepare()
    with psycopg.connect(fixture.DSN) as root:
        root.execute("ALTER TABLE jw_dev.customers ADD COLUMN business_number text NOT NULL DEFAULT ''")
        root.execute("ALTER TABLE jw_dev.quotes ADD COLUMN quote_date text")
        root.execute("""CREATE TABLE jw_dev.import_previews(
          id text PRIMARY KEY,org_id text NOT NULL,uploaded_by text NOT NULL,
          file_sha256 text NOT NULL, normalized_json text NOT NULL,
          preview_digest text NOT NULL,status text NOT NULL,
          quote_id text)""")
        root.execute("ALTER TABLE jw_dev.import_previews ENABLE ROW LEVEL SECURITY")
        root.execute("ALTER TABLE jw_dev.import_previews FORCE ROW LEVEL SECURITY")
        root.execute("GRANT SELECT ON jw_dev.import_previews TO jw_app_dev")
        root.execute("""CREATE POLICY v191_import_read ON jw_dev.import_previews
            FOR SELECT TO jw_app_dev
            USING(org_id=jw_dev.current_org_from_session())""")
    doc=verify(
        {"document_kind":"견적서","company":"Customer A",
         "quote_date":"2026-10-31","vat_mode":"taxable","subtotal":7000,
         "vat":700,"total":7700,"title":"V191 reviewed synthetic document"},
        [{"name":"Synthetic hardware","quantity":2,"unit_price":3500,
          "line_total":7000,"sku":"V191","unit":"ea"}])
    doc["filename"]="synthetic-reviewed.xlsx"
    doc["format"]="xlsx"
    digest=sha256(json.dumps(doc,ensure_ascii=False,sort_keys=True,
       separators=(",",":")).encode()).hexdigest()
    with psycopg.connect(fixture.DSN) as root:
        root.execute("""INSERT INTO jw_dev.import_previews
          (id,org_id,uploaded_by,file_sha256,normalized_json,preview_digest,status)
          VALUES(%s,%s,%s,%s,%s,%s,'confirmed')""",
          (PREVIEW,fixture.ORG_A,"1"*32,
           sha256(b"V191-SYNTHETIC-NOT-REAL-FILE").hexdigest(),sealed_json(doc),digest))
    os.environ["JW_PG_IMPORT_QUOTE_V160"]=import_api._MODE
    assert import_api.register_v160_pg_import_quote(app),(
        "V191_EXISTING_IMPORT_ROUTER_NOT_REGISTERED")
    return app,digest


def check(res,code,label):
    assert res.status_code==code,(label,res.status_code,res.text[:240])
    return res.json()


def headers(actor="A",write=False):
    return quote_flow.request_headers(actor,write)


def acceptance(client,digest):
    route="/api/pg-stage/v160/imports/"+PREVIEW+"/quote-draft"
    body={"preview_digest":digest,"customer_id":"0"*32,"reviewed":True,
      "confirmed_customer":"Customer A","confirmed_quote_date":"2026-10-31",
      "confirmed_total_krw":7700}
    def submit(data=body,who="A",h=None):
        return client.post(HOST+route,json=data,headers=h or headers(who,True))
    assert submit(h=headers("A")).status_code==403
    assert submit(who="B").status_code==404
    assert submit({**body,"reviewed":False}).status_code==422
    assert submit({**body,"confirmed_total_krw":7701}).status_code==409
    assert submit({**body,"confirmed_customer":"forged supplier"}).status_code==409
    assert submit({**body,"preview_digest":"f"*64}).status_code==409
    assert submit(h={**headers("A",True),"Origin":"https://attacker.invalid"}).status_code==403
    for i in range(20):
        absent=f"{i+1:032x}"
        res=client.post(HOST+"/api/pg-stage/v160/imports/"+absent+"/quote-draft",
          json=body,headers=headers("A",True))
        assert res.status_code==404,("V191_FOREIGN_IMPORTED_ID",i,res.status_code)

    created=check(submit(),201,"approved-import-to-quote")
    qid=created["quote_id"]
    assert len(qid)==32 and created["draft_only"] is True
    assert created["approval_posted"] is False
    assert created["money"]=={"subtotal":7000,"vat":700,"total":7700}
    replay=check(submit(),200,"approved-import-replay")
    assert replay["quote_id"]==qid and replay["created"] is False

    # 12 simultaneous REAL HTTPS request replays. They must not create
    # multiple quotes or audit rows for this single confirmed source.
    with ThreadPoolExecutor(max_workers=6) as pool:
        repeated=list(pool.map(lambda _: (
             (res:=submit()).status_code,
              res.json().get("quote_id") if res.status_code==200 else None),
              range(12)))
    assert all(code==200 and q==qid for code,q in repeated),(
        "V191_DOUBLE_CONVERTED_IMPORTED_SOURCE",repeated)

    prefix="/api/pg-stage/v92"
    get=lambda path,who="A":client.get(HOST+prefix+path,headers=headers(who))
    post=lambda path,payload,who="A":client.post(
       HOST+prefix+path,json=payload,headers=headers(who,True))
    preview_path="/quote-review-previews/"+qid
    assert get(preview_path,"B").status_code==404
    preview=check(get(preview_path),200,"server-generated-review")
    assert preview["money"]["total"]==7700
    assert preview["source_document_verified"] is False
    review_body={"quote_id":qid,"preview_sha256":preview["preview_sha256"],
                 "preview_checked":True}
    assert post("/quote-reviews",{**review_body,"preview_sha256":"0"*64}).status_code==409
    reviewed=check(post("/quote-reviews",review_body),201,"human-review-receipt")
    rid=reviewed["review_receipt_id"]

    draft_body={"request_id":"v191-reviewed-document-to-draft",
                "quote_id":qid,"review_receipt_id":rid,"original_checked":True}
    draft=check(post("/order-drafts",draft_body),201,"source-linked-draft")
    did=draft["order_id"]
    assert draft["draft_only"] is True

    orderpath="/api/pg-stage/v174"
    review_url=orderpath+"/order-drafts/"+did+"/register-preview"
    assert client.get(HOST+review_url,headers=headers("B")).status_code==404
    checked=check(client.get(HOST+review_url,headers=headers("A")),
                  200,"order-review")
    assert checked["money"]["total"]==7700
    order_body={"draft_id":did,"review_receipt_id":rid,
      "preview_sha256":checked["preview_sha256"],
      "request_id":"v191-human-approved-internal-order",
      "original_checked":True,"register_internal_only":True}
    target=HOST+orderpath+"/orders/from-reviewed-draft"
    def activate(data=order_body,actor="A"):
        return client.post(target,json=data,headers=headers(actor,True))
    assert activate(actor="B").status_code==404
    assert activate({**order_body,"preview_sha256":"f"*64}).status_code==409
    assert activate({**order_body,"original_checked":False}).status_code==422
    order=check(activate(),201,"internal-order")
    assert order["created"] is True and order["internal_order_only"] is True
    assert order["invoice_issued"] is False and order["payment_recorded"] is False
    assert order["external_acceptance_verified"] is False
    check(activate(),200,"internal-order-idempotency")

    with psycopg.connect(fixture.DSN) as root:
        def count(stmt,params):
            return root.execute(stmt,params).fetchone()[0]
        assert count("SELECT count(*) FROM jw_dev.quotes WHERE id=%s",(qid,))==1
        assert count("SELECT count(*) FROM jw_dev.quote_items WHERE quote_id=%s",(qid,))==1
        assert count("SELECT count(*) FROM jw_dev.order_drafts_v127 WHERE id=%s",(did,))==1
        assert count("SELECT count(*) FROM jw_dev.orders WHERE id=%s",(order["order_id"],))==1
        assert count("SELECT count(*) FROM jw_dev.order_items WHERE order_id=%s",
                     (order["order_id"],))==1
        assert count("""SELECT count(*) FROM jw_dev.audit_logs WHERE
              entity_id=%s AND action='approved_import_to_draft'""",(qid,))==1
        assert count("""SELECT count(*) FROM jw_dev.audit_logs WHERE
              entity_id=%s AND action='human_approved_internal_order_only'""",
              (order["order_id"],))==1
        assert count("SELECT count(*) FROM jw_dev.invoices",())==0
        assert root.execute("SELECT to_regclass('jw_dev.payments')").fetchone()==(None,)
        assert count("""SELECT count(*) FROM jw_dev.quotes WHERE
          id=%s AND org_id=%s AND source_import_id=%s""",
          (qid,fixture.ORG_A,"v160:"+fixture.ORG_A+":"+PREVIEW))==1
    print("PASS_V191_REAL_TLS_PG17_CONFIRMED_ENCRYPTED_IMPORT_QUOTE_REVIEW_ORDER",flush=True)
    print("PASS_V191_20_FORGED_PREVIEWS_AND_CSRF_RLS_APPROVAL_SOURCE_CHECKS",flush=True)
    print("PASS_V191_12_CONCURRENT_REAL_TLS_IMPORT_REPLAYS_EXACTLY_ONE_ORDER",flush=True)
    print("LIMIT_V191_NO_ACTUAL_UPLOAD_OCR_OR_OFFICIAL_INVOICE_BANK_MESSENGER",flush=True)


def main():
    app,digest=prepare()
    with TemporaryDirectory(prefix="jw-v191-tls-") as tmp:
        key,cert=Path(tmp)/"key.pem",Path(tmp)/"cert.pem"
        subprocess.run(["openssl","req","-x509","-nodes","-newkey","rsa:2048",
          "-keyout",str(key),"-out",str(cert),"-days","1",
          "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost"],
          check=True,capture_output=True,timeout=15)
        server=uvicorn.Server(uvicorn.Config(app,host="127.0.0.1",port=8769,
          ssl_keyfile=str(key),ssl_certfile=str(cert),access_log=False,log_level="error"))
        thread=Thread(target=server.run,daemon=True)
        thread.start()
        try:
            for _ in range(100):
                if server.started:break
                time.sleep(.1)
            assert server.started,"V191_HTTPS_SERVER_NOT_READY"
            with httpx.Client(verify=str(cert),trust_env=False,
                 follow_redirects=False,timeout=20) as client:
                acceptance(client,digest)
        finally:
            server.should_exit=True
            thread.join(timeout=15)
            assert not thread.is_alive(),"V191_EPHEMERAL_SERVER_NOT_STOPPED"


if __name__=="__main__":
    main()
