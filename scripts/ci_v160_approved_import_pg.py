"""Actual PostgreSQL 17 approved-preview to draft quote HTTP acceptance.

This uses a freshly bootstrapped disposable GitHub Actions PostgreSQL 17,
real forced RLS and restricted trade login, encrypted synthetic evidence, and
the exact existing import normalization engine. Never shared DEV/production.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os

from cryptography.fernet import Fernet
import psycopg
from app.import_engine import verify
from app.security_hardening import sealed_json
from app import pg_import_quote_v160 as target
from app import pg_quote_api_v92 as order_quote
from pathlib import Path
from scripts import ci_v157_real_pg_delivery_http as fixture

PREVIEW="5"*32
CUSTOMER="0"*32


def bootstrap_import():
    with psycopg.connect(fixture.DSN) as root:
        root.execute("""ALTER TABLE jw_dev.customers
                     ADD COLUMN business_number text NOT NULL DEFAULT ''""")
        for column in (
            "customer_name_snapshot text NOT NULL DEFAULT ''",
            "title text NOT NULL DEFAULT ''",
            "status text NOT NULL DEFAULT 'draft'",
            "vat_mode text NOT NULL DEFAULT 'taxable'",
            "created_at text NOT NULL DEFAULT ''",
            "updated_at text NOT NULL DEFAULT ''",
            "quote_date text",
            "source_import_id text UNIQUE",
            "source_document_meta text NOT NULL DEFAULT '{}'",
        ):
            root.execute("ALTER TABLE jw_dev.quotes ADD COLUMN "+column)
        root.execute("""CREATE TABLE jw_dev.quote_items (
            id text PRIMARY KEY,quote_id text NOT NULL REFERENCES jw_dev.quotes(id),
            name text NOT NULL,quantity bigint NOT NULL,
            unit_price bigint NOT NULL,position bigint NOT NULL,
            UNIQUE(quote_id,position))""")
        root.execute("""CREATE TABLE jw_dev.import_previews (
            id text PRIMARY KEY,org_id text NOT NULL,uploaded_by text NOT NULL,
            file_sha256 text NOT NULL,normalized_json text NOT NULL,
            preview_digest text NOT NULL,status text NOT NULL,
            quote_id text)""")
        for table in ("quote_items","import_previews"):
            root.execute(f"ALTER TABLE jw_dev.{table} ENABLE ROW LEVEL SECURITY")
            root.execute(f"ALTER TABLE jw_dev.{table} FORCE ROW LEVEL SECURITY")
        root.execute("""GRANT SELECT ON jw_dev.customers,jw_dev.import_previews,
              jw_dev.quotes TO jw_app_dev""")
        root.execute("GRANT SELECT ON jw_dev.quote_items TO jw_app_dev")
        root.execute("""CREATE POLICY ci_v160_quote_item_select
            ON jw_dev.quote_items FOR SELECT TO jw_app_dev
            USING(EXISTS(SELECT 1 FROM jw_dev.quotes q WHERE q.id=quote_id
                AND q.org_id=jw_dev.current_org_from_session()))""")
        root.execute("""GRANT INSERT ON jw_dev.quotes,jw_dev.quote_items,
              jw_dev.audit_logs TO jw_app_dev""")
        root.execute("""CREATE POLICY ci_v160_customer_read ON jw_dev.customers
            FOR SELECT TO jw_app_dev
            USING(org_id=jw_dev.current_org_from_session())""")
        root.execute("""CREATE POLICY ci_v160_quote_read ON jw_dev.quotes
            FOR SELECT TO jw_app_dev
            USING(org_id=jw_dev.current_org_from_session())""")
        root.execute("""CREATE POLICY ci_v160_quote_insert ON jw_dev.quotes
            FOR INSERT TO jw_app_dev
            WITH CHECK(org_id=jw_dev.current_org_from_session())""")
        root.execute("""CREATE POLICY ci_v160_quote_item_insert
            ON jw_dev.quote_items FOR INSERT TO jw_app_dev WITH CHECK(
            EXISTS(SELECT 1 FROM jw_dev.quotes q WHERE q.id=quote_id
            AND q.org_id=jw_dev.current_org_from_session()))""")
        root.execute("""CREATE POLICY ci_v160_import_read ON jw_dev.import_previews
            FOR SELECT TO jw_app_dev
            USING(org_id=jw_dev.current_org_from_session())""")
        root.execute((Path(__file__).resolve().parents[1]/
           "scripts/ci_v127_ephemeral_order.sql").read_text())

    meta={"document_kind":"견적서","company":"Customer A",
          "quote_date":"2026-10-31","vat_mode":"taxable","subtotal":7000,
          "vat":700,"total":7700,"title":"Synthetic reviewed quotation"}
    rows=[{"name":"Widget A","quantity":2,"unit_price":3500,
           "line_total":7000,"sku":"A","unit":"ea"}]
    doc=verify(meta,rows)
    doc["filename"]="synthetic-reviewed.xlsx"
    doc["format"]="xlsx"
    digest=sha256(json.dumps(doc,ensure_ascii=False,sort_keys=True,
             separators=(",",":")).encode()).hexdigest()
    file_hash=sha256(b"fake-fixture-only-no-real-upload").hexdigest()
    with psycopg.connect(fixture.DSN) as root:
        root.execute("""INSERT INTO jw_dev.import_previews
          (id,org_id,uploaded_by,file_sha256,normalized_json,
           preview_digest,status,quote_id)
          VALUES(%s,%s,%s,%s,%s,%s,'confirmed',NULL)""",
          (PREVIEW,fixture.ORG_A,"1"*32,file_hash,sealed_json(doc),digest))
    return digest,file_hash


def main():
    fixture.bootstrap()
    os.environ["JW_DATA_KEY"]=Fernet.generate_key().decode()
    digest,file_hash=bootstrap_import()
    app=fixture.configure()
    os.environ["JW_PG_IMPORT_QUOTE_V160"]="ISOLATED_DEV_APPROVED_IMPORT_QUOTE_ONLY"
    assert target.register_v160_pg_import_quote(app)
    assert order_quote.register_v92_quote_api(app)
    a=fixture.client(app,"A")
    b=fixture.client(app,"B")
    url="/api/pg-stage/v160/imports/"+PREVIEW+"/quote-draft"
    body={"preview_digest":digest,"customer_id":CUSTOMER,"reviewed":True,
          "confirmed_customer":"Customer A",
          "confirmed_quote_date":"2026-10-31",
          "confirmed_total_krw":7700}
    hdr={"Origin":"https://testserver","X-CSRF-Token":fixture.CSRF["A"]}
    denied=b.post(url,json=body,headers={"Origin":"https://testserver",
           "X-CSRF-Token":fixture.CSRF["B"]})
    assert denied.status_code==404,(denied.status_code,denied.text[:500])
    assert a.post(url,json={**body,"reviewed":False},headers=hdr).status_code==422
    assert a.post(url,json={**body,"confirmed_total_krw":7701},
                  headers=hdr).status_code==409
    assert a.post(url,json={**body,"confirmed_customer":"wrong"},
                  headers=hdr).status_code==409
    assert a.post(url,json={**body,"preview_digest":"f"*64},
                  headers=hdr).status_code==409
    assert a.post(url,json=body,headers={"Origin":"https://testserver"}).status_code==403
    assert a.post(url,json=body,headers={"Origin":"https://hostile.test",
           "X-CSRF-Token":fixture.CSRF["A"]}).status_code==403

    result=a.post(url,json=body,headers=hdr)
    assert result.status_code==201,(result.status_code,result.text[:700])
    quote_id=result.json()["quote_id"]
    assert len(quote_id)==32 and result.json()["draft_only"] is True
    assert result.json()["approval_posted"] is False
    assert result.json()["money"]=={"subtotal":7000,"vat":700,"total":7700}
    repeat=a.post(url,json=body,headers=hdr)
    assert repeat.status_code==200,(repeat.status_code,repeat.text[:400])
    assert repeat.json()["quote_id"]==quote_id
    assert repeat.json()["created"] is False
    # The exact existing V12.7/V12.8 source-review APIs must accept the new
    # imported draft only after a fresh server-generated human review receipt.
    preview=a.get("/api/pg-stage/v92/quote-review-previews/"+quote_id)
    assert preview.status_code==200,(preview.status_code,preview.text[:500])
    quote_review=preview.json()
    assert quote_review["money"]=={"subtotal":7000,"vat":700,"total":7700}
    assert quote_review["source_document_verified"] is False
    unchecked=a.post("/api/pg-stage/v92/quote-reviews",headers=hdr,
        json={"quote_id":quote_id,"preview_sha256":quote_review["preview_sha256"],
              "preview_checked":False})
    assert unchecked.status_code==422,unchecked.text[:350]
    forged=a.post("/api/pg-stage/v92/quote-reviews",headers=hdr,
        json={"quote_id":quote_id,"preview_sha256":"f"*64,"preview_checked":True})
    assert forged.status_code==409,forged.text[:350]
    ack=a.post("/api/pg-stage/v92/quote-reviews",headers=hdr,
        json={"quote_id":quote_id,"preview_sha256":quote_review["preview_sha256"],
              "preview_checked":True})
    assert ack.status_code==201,(ack.status_code,ack.text[:450])
    receipt_id=ack.json()["review_receipt_id"]
    order_body={"request_id":"v160-reviewed-quote",
                "quote_id":quote_id,"original_checked":True,
                "review_receipt_id":receipt_id}
    draft=a.post("/api/pg-stage/v92/order-drafts",
                 headers=hdr,json=order_body)
    assert draft.status_code==201,(draft.status_code,draft.text[:500])
    order_id=draft.json()["order_id"]
    assert draft.json()["draft_only"] is True
    assert draft.json()["approval_posted"] is False
    retry=a.post("/api/pg-stage/v92/order-drafts",headers=hdr,json=order_body)
    assert retry.status_code==200,(retry.status_code,retry.text[:400])
    assert retry.json()["created"] is False and retry.json()["order_id"]==order_id
    assert b.get("/api/pg-stage/v92/quote-review-previews/"+quote_id).status_code==404

    with psycopg.connect(fixture.DSN) as root:
        source=root.execute("""SELECT source_import_id,status,source_document_meta
                     FROM jw_dev.quotes WHERE id=%s""",(quote_id,)).fetchone()
        assert source[0]=="v160:"+fixture.ORG_A+":"+PREVIEW
        assert source[1]=="draft" and source[2].startswith("ENC1:")
        assert root.execute("SELECT count(*) FROM jw_dev.quote_items WHERE quote_id=%s",
                            (quote_id,)).fetchone()==(1,)
        actions=root.execute("""SELECT action FROM jw_dev.audit_logs
                          WHERE entity_id=%s ORDER BY action""",(quote_id,)).fetchall()
        assert actions==[("approved_import_to_draft",),
                         ("human_preview_acknowledged",)],actions
        assert root.execute("""SELECT count(*) FROM jw_dev.audit_logs
                          WHERE entity_id=%s""",(order_id,)).fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.order_drafts_v127 WHERE id=%s",
                            (order_id,)).fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.order_draft_items_v127 WHERE order_id=%s",
                            (order_id,)).fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.orders").fetchone()==(2,)
        assert root.execute("SELECT count(*) FROM jw_dev.invoices").fetchone()==(0,)
        assert root.execute("SELECT count(*) FROM jw_dev.payments").fetchone()==(0,) if root.execute(
            "SELECT to_regclass('jw_dev.payments')").fetchone()[0] is not None else True
    print("PASS_V160_REAL_PG17_CONFIRMED_ENCRYPTED_IMPORT_TO_QUOTE",flush=True)
    print("PASS_V160_RLS_CSRF_ORIGIN_REVIEW_AND_IDEMPOTENT_AUDIT",flush=True)
    print("PASS_V160_REAL_PG17_IMPORT_QUOTE_REVIEW_ORDER_DRAFT",flush=True)
    print("PASS_V160_REVIEW_RECEIPT_CSFR_IDEMPOTENCY_SOURCE_LINK",flush=True)
    print("PASS_V160_NO_APPROVED_ORDER_INVOICE_PAYMENT_AUTO_POST",flush=True)
    print("LIMIT: synthetic normalized approved fixture, not an actual file "
          "upload through a verified PG import/approval service",flush=True)


if __name__=="__main__":
    main()
