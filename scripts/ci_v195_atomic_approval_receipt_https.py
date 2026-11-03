"""V19.5 dual-role and signed atomic receipt actual XLSX upload -> PG17 pending -> human confirm -> quote -> order.

Real verified HTTPS network and real constrained PostgreSQL17, no TestClient.
All input is generated synthetic test content. All changes isolated to review.
No real Supabase, Render, customer data, bank or physical delivery.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import hashlib
import hmac
import json
from io import BytesIO
from pathlib import Path
import secrets
from psycopg import sql
from psycopg.conninfo import make_conninfo
from tempfile import TemporaryDirectory
from threading import Thread
import os
import subprocess
import time

import httpx
import psycopg
import uvicorn
from openpyxl import Workbook

from scripts import ci_v191_https_approved_import_to_order as old
from scripts import ci_v157_real_pg_delivery_http as fixture
from scripts.review import pg_import_preview_v195 as review

HOST="https://localhost:8772"


def xlsx():
    wb=Workbook()
    sheet=wb.active
    for i,(key,value) in enumerate([
      ("문서종류","견적서"),("거래처","Customer A"),
      ("사업자등록번호",""),("견적일","2026-10-31"),
      ("견적번호","Q-V193-SYNTHETIC"),("과세구분","과세"),
      ("제목","V193 synthetic live uploaded quotation"),
      ("공급가액",160000),("부가세",16000),("총금액",176000),
    ],1):
        sheet.cell(i,1,key)
        sheet.cell(i,2,value)
    sheet.append(["품목명","수량","단가","금액"])
    sheet.append(["Synthetic pump",3,45000,135000])
    sheet.append(["Synthetic seal",2,12500,25000])
    buf=BytesIO()
    wb.save(buf)
    return buf.getvalue()


def h(actor="A",mutate=False):
    out={"Cookie":"__Host-jw_session="+fixture.TOKENS[actor]}
    if mutate:
        out["Origin"]=HOST
        out["X-CSRF-Token"]=fixture.CSRF[actor]
    return out


def expect(res,code,label):
    assert res.status_code==code,(label,res.status_code,res.text[:350])
    return res.json()


def prepare():
    if os.getenv("JW_ENV")!="review" or os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE" or "@127.0.0.1:5432/postgres" not in os.getenv("JW_PG_CI_ROOT_DSN",""):
        raise RuntimeError("BLOCKED_V193_NONDISPOSABLE_DATABASE")
    fixture.disposable_root_check()
    app,_=old.prepare()
    with psycopg.connect(fixture.DSN) as db:
        db.execute((Path(__file__).resolve().parent/
                  "review/v193_disposable_import_write_policies.sql").read_text())
        # The one-off auth principal is NOT a member of the trade or auth
        # roles. A separate connection with its own random CI-only password.
        pw=secrets.token_urlsafe(40)
        db.execute(sql.SQL("""CREATE ROLE jw_ci_v194_approver
          LOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER NOCREATEROLE NOCREATEDB
          PASSWORD {}""").format(sql.Literal(pw)))
        db.execute((Path(__file__).resolve().parent/
                  "review/v194_disposable_separate_reviewer.sql").read_text())
        proof_key=secrets.token_bytes(32)
        db.execute((Path(__file__).resolve().parent/
                  "review/v195_disposable_atomic_approval_receipt.sql").read_text())
        db.execute("INSERT INTO jw_dev.v195_approval_secrets(name,secret) "
                   "VALUES('active',%s)",(proof_key,))
    reviewer_dsn=make_conninfo(fixture.DSN,user="jw_ci_v194_approver",password=pw)
    review.configure_disposable_approver(reviewer_dsn, proof_key)
    os.environ["JW_V90_ALLOWED_ORIGINS"]=HOST
    assert review.register(app)
    return app


def actual_http(client):
    endpoint=HOST+review.PREFIX+"/imports/preview"
    data=xlsx()
    content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    def upload(actor="A",headers=None,raw=data,name="v193_synthetic.xlsx"):
        return client.post(endpoint,headers=headers if headers is not None else h(actor,True),
          files={"file":(name,raw,content_type)})
    assert upload(headers=h("A")).status_code==403
    assert upload("M").status_code==403
    assert upload(headers={**h("A",True),"Origin":"https://forged.invalid"}).status_code==403
    assert upload(raw=b"bad-file-not-xlsx").status_code==422
    assert upload(raw=b"").status_code==422
    assert upload(name="malicious.exe").status_code==422
    assert upload(raw=b"x"*(5*1024*1024+1)).status_code==422
    created=expect(upload(),201,"actual-xlsx-bytes-to-pg-pending")
    pid=created["preview_id"]
    digest=created["preview_digest"]
    doc=created["document"]
    assert doc["company"]=="Customer A"
    assert doc["money"]=={"subtotal":160000,"vat":16000,"total":176000}
    assert created["reviewed"] is False
    assert created["source_bytes_persisted"] is False
    assert upload().status_code==409,"Duplicate original byte source must not reupload"
    # Independently challenge the business login with the SAME real
    # session identity: neither SQL privilege nor direct SET ROLE can confirm.
    with psycopg.connect(fixture.DSN) as admin:
        assert admin.execute("""SELECT has_column_privilege(
          'jw_app_dev','jw_dev.import_previews','status','UPDATE')""").fetchone()==(False,)
        assert admin.execute("""SELECT has_table_privilege(
          'jw_ci_v194_approver','jw_dev.import_previews','DELETE')""").fetchone()==(False,)
        assert admin.execute("""SELECT has_column_privilege(
          'jw_ci_v194_approver','jw_dev.import_previews',
          'normalized_json','UPDATE')""").fetchone()==(False,)
        assert admin.execute("""SELECT pg_has_role('jw_ci_v157_trade',
           'jw_ci_v194_approver','MEMBER')""").fetchone()==(False,)
    with psycopg.connect(fixture.TRADE_DSN) as limited:
        with limited.transaction():
            limited.execute("SET LOCAL ROLE jw_app_dev")
            limited.execute("SELECT pg_catalog.set_config('jw.session_hash',%s,true)",
              (sha256(fixture.TOKENS["A"].encode()).hexdigest(),))
            for i in range(20):
                value=pid if i==0 else f"{i+1:032x}"
                try:
                    with limited.transaction():
                        limited.execute("""UPDATE jw_dev.import_previews
                            SET status='confirmed' WHERE id=%s""",(value,))
                except psycopg.errors.InsufficientPrivilege:
                    pass
                else:
                    raise AssertionError("V194_TRADE_ROLE_CAN_SELF_APPROVE")
    with psycopg.connect(fixture.DSN) as admin:
        assert admin.execute("SELECT status FROM jw_dev.import_previews WHERE id=%s",
                    (pid,)).fetchone()==("pending",)
    print("PASS_V195_20_DIRECT_DB_APPROVAL_BYPASS_ATTEMPTS_DENIED",flush=True)
    route=HOST+review.PREFIX+"/imports/"+pid+"/confirm"
    body={"preview_digest":digest,"confirmed_customer":"Customer A",
       "confirmed_quote_date":"2026-10-31","confirmed_total_krw":176000,"approve":True}
    def confirm(payload=body,actor="A",headers=None):
        return client.post(route,json=payload,
           headers=headers if headers is not None else h(actor,True))
    # A compromised reviewer SQL login cannot directly issue a status UPDATE,
    # insert a receipt, or read signing material. Twenty individually forged
    # signed-RPC attempts must all fail without modifying the pending preview.
    statement=json.dumps({"schema":"jw-import-approval-v195",
        "preview_id":pid,"org_id":fixture.ORG_A,"actor_id":"1"*32,
        "preview_digest":digest,"approved":True,"company":"Customer A",
        "quote_date":"2026-10-31","total_krw":176000},
        ensure_ascii=False,sort_keys=True,separators=(",",":"))
    with psycopg.connect(review._reviewer_dsn) as approver:
        for sql_query in (
          "SELECT secret FROM jw_dev.v195_approval_secrets",
          "SELECT id FROM jw_dev.v195_approval_receipts",
          "UPDATE jw_dev.import_previews SET status='confirmed' WHERE id=%s"
        ):
            try:
                with approver.transaction():
                    if "%s" in sql_query:
                        approver.execute(sql_query,(pid,))
                    else:
                        approver.execute(sql_query)
            except psycopg.errors.InsufficientPrivilege:
                pass
            else:
                raise AssertionError("V195_REVIEWER_HAS_FORBIDDEN_DIRECT_TABLE_ACCESS")
        for i in range(20):
            fake_sig=f"{i+1:064x}"
            try:
                with approver.transaction():
                    approver.execute("""SELECT jw_dev.v195_confirm_import(
                      %s,%s,%s,%s,%s,%s,%s)""",(
                      pid,fixture.ORG_A,"1"*32,digest,statement,fake_sig,
                      secrets.token_hex(16)))
            except psycopg.errors.InsufficientPrivilege:
                pass
            else:
                raise AssertionError("V195_INVALID_HMAC_ACCEPTED")
    with psycopg.connect(fixture.DSN) as root:
        assert root.execute("SELECT status FROM jw_dev.import_previews WHERE id=%s",
          (pid,)).fetchone()==("pending",)
        assert root.execute("SELECT count(*) FROM jw_dev.v195_approval_receipts",
          ()).fetchone()==(0,)
    print("PASS_V195_20_FORGED_SIGNED_RPC_APPROVALS_AND_DIRECT_ROLE_WRITES_DENIED",
          flush=True)
    assert confirm(headers=h("A")).status_code==403
    assert confirm(actor="B").status_code==404
    assert confirm(actor="M").status_code==403
    assert confirm({**body,"approve":False}).status_code==422
    assert confirm({**body,"confirmed_customer":"Fake"}).status_code==409
    assert confirm({**body,"confirmed_total_krw":1}).status_code==409
    assert confirm({**body,"preview_digest":"f"*64}).status_code==409
    assert confirm(headers={**h("A",True),"Origin":"https://forged.invalid"}).status_code==403
    for i in range(20):
        bad_id=f"{i+1:032x}"
        assert client.post(HOST+review.PREFIX+"/imports/"+bad_id+"/confirm",
            json=body,headers=h("A",True)).status_code==404
    # Approval is visible in SQL, but cannot create a quote or order before explicit second review.
    with psycopg.connect(fixture.DSN) as root:
        assert root.execute("""SELECT status,uploaded_by,file_sha256,
             normalized_json FROM jw_dev.import_previews WHERE id=%s""",
             (pid,)).fetchone()[0]=="pending"
        assert root.execute("SELECT count(*) FROM jw_dev.quotes WHERE source_import_id IS NOT NULL").fetchone()==(0,)
    first=expect(confirm(),200,"user-confirm-preview")
    assert first["confirmed"] is True and first["quote_posted"] is False
    receipt_id=first["approval_receipt_id"]
    assert len(receipt_id)==32
    with psycopg.connect(fixture.DSN) as root:
        rows=root.execute("""SELECT id,preview_id,org_id,actor_id,
           preview_digest,statement,signature
           FROM jw_dev.v195_approval_receipts WHERE preview_id=%s""",
           (pid,)).fetchall()
        assert len(rows)==1,rows
        id_,src,org,actor,source_hash,signed_statement,signature=rows[0]
        assert (id_,src,org,actor,source_hash)==(
            receipt_id,pid,fixture.ORG_A,"1"*32,digest)
        assert hmac.compare_digest(signature,hmac.new(
            review._approval_key,signed_statement.encode(),hashlib.sha256
        ).hexdigest()),"V195_RECEIPT_SIGNATURE_MISMATCH"
        assert first["receipt_statement_sha256"]==hashlib.sha256(
            signed_statement.encode()).hexdigest()
        for query in (
          "UPDATE jw_dev.v195_approval_receipts SET signature=%s WHERE id=%s",
          "DELETE FROM jw_dev.v195_approval_receipts WHERE id=%s"
        ):
            try:
                with root.transaction():
                    if query.startswith("UPDATE"):
                        root.execute(query,("f"*64,receipt_id))
                    else:root.execute(query,(receipt_id,))
            except psycopg.errors.InsufficientPrivilege:
                pass
            else:
                raise AssertionError("V195_RECEIPT_MUTATION_ALLOWED")
        assert root.execute("SELECT count(*) FROM jw_dev.v195_approval_receipts",
                            ()).fetchone()==(1,)

    # Force an audit receipt UNIQUE violation AFTER the status UPDATE inside
    # the SECURITY DEFINER function. PostgreSQL must roll back the whole
    # function call, leaving the second preview PENDING with no receipt.
    second=secrets.token_hex(16)
    with psycopg.connect(fixture.DSN) as root:
        row=root.execute("""SELECT org_id,uploaded_by,preview_digest
          FROM jw_dev.import_previews WHERE id=%s""",(pid,)).fetchone()
        assert row==(fixture.ORG_A,"1"*32,digest)
        root.execute("""INSERT INTO jw_dev.import_previews(
          id,org_id,uploaded_by,file_sha256,normalized_json,
          preview_digest,status,quote_id)
          SELECT %s,org_id,uploaded_by,%s,normalized_json,
                 preview_digest,'pending',NULL
          FROM jw_dev.import_previews WHERE id=%s""",
          (second,hashlib.sha256(secrets.token_bytes(32)).hexdigest(),pid))
    conflict=json.dumps({
      "schema":"jw-import-approval-v195","preview_id":second,
      "org_id":fixture.ORG_A,"actor_id":"1"*32,
      "preview_digest":digest,"approved":True,
      "company":"Customer A","quote_date":"2026-10-31",
      "total_krw":176000
    },ensure_ascii=False,sort_keys=True,separators=(",",":"))
    collision_signature=hmac.new(review._approval_key,conflict.encode(),
                                 hashlib.sha256).hexdigest()
    try:
        with psycopg.connect(review._reviewer_dsn) as approver:
            approver.execute("""SELECT jw_dev.v195_confirm_import(
              %s,%s,%s,%s,%s,%s,%s)""",(
              second,fixture.ORG_A,"1"*32,digest,
              conflict,collision_signature,receipt_id))
    except psycopg.errors.UniqueViolation:
        pass
    else:
        raise AssertionError("V195_DUPLICATE_RECEIPT_DID_NOT_ABORT")
    with psycopg.connect(fixture.DSN) as root:
        assert root.execute("SELECT status FROM jw_dev.import_previews WHERE id=%s",
            (second,)).fetchone()==("pending",),"V195_PARTIAL_APPROVAL_COMMIT"
        assert root.execute("SELECT count(*) FROM jw_dev.v195_approval_receipts",
            ()).fetchone()==(1,),"V195_ORPHANED_OR_DUPLICATED_RECEIPT"
    print("PASS_V195_FORCED_AUDIT_INSERT_FAILURE_ATOMIC_ROLLBACK",flush=True)
    print("PASS_V195_SINGLE_COMMITTED_HMAC_RECEIPT_AND_IMMUTABLE_AUDIT",
          flush=True)

    # RLS UPDATE USING(status=pending) may conceal a confirmed row (404) instead of 409.
    assert confirm().status_code in (404,409),"Repeated approval must fail closed"

    url=HOST+"/api/pg-stage/v160/imports/"+pid+"/quote-draft"
    convert={"preview_digest":digest,"customer_id":"0"*32,"reviewed":True,
      "confirmed_customer":"Customer A","confirmed_quote_date":"2026-10-31",
      "confirmed_total_krw":176000}
    def post(path,payload,actor="A"):
        return client.post(HOST+path,json=payload,headers=h(actor,True))
    assert post("/api/pg-stage/v160/imports/"+pid+"/quote-draft",convert,"B").status_code==404
    assert post("/api/pg-stage/v160/imports/"+pid+"/quote-draft",
                 {**convert,"reviewed":False}).status_code==422
    q=expect(post("/api/pg-stage/v160/imports/"+pid+"/quote-draft",convert),
             201,"approved-document-to-draft-quote")
    quote_id=q["quote_id"]
    assert q["money"]["total"]==176000 and q["approval_posted"] is False
    with ThreadPoolExecutor(max_workers=6) as pool:
        replies=list(pool.map(lambda _:post("/api/pg-stage/v160/imports/"+pid+
             "/quote-draft",convert),range(12)))
    assert all(r.status_code==200 and r.json().get("quote_id")==quote_id
               for r in replies),("V193_DOUBLE_CONVERSION",[(r.status_code,r.text[:80]) for r in replies])

    prefix="/api/pg-stage/v92"
    get=lambda path,actor="A":client.get(HOST+prefix+path,headers=h(actor))
    preview=expect(get("/quote-review-previews/"+quote_id),200,"review-pg-quote")
    assert preview["source_document_verified"] is False
    check={"quote_id":quote_id,"preview_sha256":preview["preview_sha256"],"preview_checked":True}
    rev=expect(post(prefix+"/quote-reviews",check),201,"actual-reviewed-quote")
    receipt=rev["review_receipt_id"]
    draft_body={"request_id":"v193-actual-upload-internal-draft","quote_id":quote_id,
                "review_receipt_id":receipt,"original_checked":True}
    draft=expect(post(prefix+"/order-drafts",draft_body),201,"approved-draft")
    draft_id=draft["order_id"]
    assert draft["draft_only"] is True
    target="/api/pg-stage/v174"
    reg=expect(client.get(HOST+target+"/order-drafts/"+draft_id+"/register-preview",
           headers=h()),200,"internal-order-preview")
    assert reg["money"]["total"]==176000
    payload={"draft_id":draft_id,"review_receipt_id":receipt,
      "preview_sha256":reg["preview_sha256"],
      "request_id":"v193-human-internal-order",
      "original_checked":True,"register_internal_only":True}
    order=expect(post(target+"/orders/from-reviewed-draft",payload),201,
                 "actual-file-to-internal-order")
    assert order["internal_order_only"] is True and order["invoice_issued"] is False
    assert order["payment_recorded"] is False
    with psycopg.connect(fixture.DSN) as root:
        assert root.execute("SELECT status FROM jw_dev.import_previews WHERE id=%s",
            (pid,)).fetchone()==("confirmed",)
        assert root.execute("SELECT count(*) FROM jw_dev.quotes WHERE id=%s",
            (quote_id,)).fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.quote_items WHERE quote_id=%s",
            (quote_id,)).fetchone()==(2,)
        assert root.execute("SELECT count(*) FROM jw_dev.orders WHERE id=%s",
            (order["order_id"],)).fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.order_items WHERE order_id=%s",
            (order["order_id"],)).fetchone()==(2,)
        assert root.execute("SELECT count(*) FROM jw_dev.invoices").fetchone()==(0,)
        assert root.execute("SELECT to_regclass('jw_dev.payments')").fetchone()==(None,)
        assert root.execute("""SELECT count(*) FROM jw_dev.audit_logs
          WHERE entity_id=%s AND action='approved_import_to_draft'""",
          (quote_id,)).fetchone()==(1,)
        assert root.execute("""SELECT count(*) FROM jw_dev.audit_logs
          WHERE entity_id=%s AND action='human_approved_internal_order_only'""",
          (order["order_id"],)).fetchone()==(1,)
    print("PASS_V195_REAL_HTTPS_SIGNED_ATOMIC_APPROVAL_RECEIPT_QUOTE_ORDER",flush=True)
    print("PASS_V195_20_FAKE_CONFIRM_IDS_AND_20_DIRECT_ROLE_BYPASS_DENIED",flush=True)
    print("PASS_V195_12_REAL_TLS_CONCURRENT_REPLAYS_ONE_QUOTE_ORDER_AUDIT",flush=True)
    print("LIMIT_V195_REVIEW_ONLY_HMAC_IS_SERVER_RECEIPT_NOT_REAL_HUMAN_ATTESTATION",flush=True)


def main():
    app=prepare()
    with TemporaryDirectory(prefix="jw-v195-https-") as td:
        key=Path(td)/"key.pem"
        cert=Path(td)/"cert.pem"
        subprocess.run(["openssl","req","-x509","-nodes","-newkey","rsa:2048",
          "-keyout",str(key),"-out",str(cert),"-days","1",
          "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost"],
          check=True,capture_output=True,timeout=15)
        server=uvicorn.Server(uvicorn.Config(app,host="127.0.0.1",port=8772,
          ssl_keyfile=str(key),ssl_certfile=str(cert),log_level="error",access_log=False))
        worker=Thread(target=server.run,daemon=True)
        worker.start()
        try:
            for _ in range(100):
                if server.started:break
                time.sleep(.1)
            assert server.started,"V193_HTTPS_BOOT_FAILED"
            with httpx.Client(verify=str(cert),trust_env=False,
                     follow_redirects=False,timeout=35) as client:
                actual_http(client)
        finally:
            server.should_exit=True
            worker.join(timeout=15)
            assert not worker.is_alive(),"V193_SERVER_SHUTDOWN_FAILED"


if __name__=="__main__":
    main()
