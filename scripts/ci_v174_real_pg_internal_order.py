"""V17.4 real disposable PostgreSQL 17 HTTP internal-order acceptance.

Requires the authorized empty 127.0.0.1 GitHub Actions PostgreSQL 17 service.
No shared Supabase database, Render, bank or legal invoice. Uses verified
V15.7 isolated restricted PostgreSQL login with force RLS.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import time

import psycopg

from scripts import ci_v157_real_pg_delivery_http as fixture
from scripts.review import pg_order_activation_v174 as activation

Q = "7"*32
D = "5"*32
R = "6"*32
I = "8"*32
# Independent V92 canonical hash, not derived from the V174 writer.
SRC = hashlib.sha256(json.dumps([
    Q, "0"*32, "Q-V174", "Human Approved Quote", "draft", "taxable",
    [[I, "Synthetic hardware", 2, 3500, 0]],
    {"subtotal":7000,"vat":700,"total":7700},
], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
URL = "/api/pg-stage/v174"


def install():
    # Never run this DDL outside freshly provisioned disposable PG17.
    fixture.disposable_root_check()
    fixture.bootstrap()
    with psycopg.connect(fixture.DSN) as root:
        for col in (
            "customer_name_snapshot text NOT NULL DEFAULT ''",
            "title text NOT NULL DEFAULT ''",
            "status text NOT NULL DEFAULT 'draft'",
            "vat_mode text NOT NULL DEFAULT 'taxable'",
            "created_at text NOT NULL DEFAULT ''",
            "updated_at text NOT NULL DEFAULT ''",
        ):
            root.execute("ALTER TABLE jw_dev.quotes ADD COLUMN "+col)
        root.execute("""CREATE TABLE jw_dev.quote_items (
            id text PRIMARY KEY,quote_id text NOT NULL REFERENCES jw_dev.quotes(id),
            name text NOT NULL,quantity bigint NOT NULL,unit_price bigint NOT NULL,
            position bigint NOT NULL,UNIQUE(quote_id,position))""")
        for col in (
            "due_date text NOT NULL DEFAULT ''",
            "created_at text NOT NULL DEFAULT ''",
            "updated_at text NOT NULL DEFAULT ''",
            "order_date text NOT NULL DEFAULT ''",
            "source_import_id text",
            "source_document_meta text NOT NULL DEFAULT '{}'",
        ):
            root.execute("ALTER TABLE jw_dev.orders ADD COLUMN "+col)
        root.execute("CREATE UNIQUE INDEX ci_v174_order_q_unique ON jw_dev.orders(quote_id)")
        root.execute("""CREATE UNIQUE INDEX ci_v174_order_key_unique
                      ON jw_dev.orders(source_import_id)""")
        root.execute("""ALTER TABLE jw_dev.order_items ADD COLUMN
                       source_quote_item_id text REFERENCES jw_dev.quote_items(id)""")
        root.execute("ALTER TABLE jw_dev.quote_items ENABLE ROW LEVEL SECURITY")
        root.execute("ALTER TABLE jw_dev.quote_items FORCE ROW LEVEL SECURITY")
        root.execute("""GRANT SELECT ON jw_dev.quotes,jw_dev.quote_items TO jw_app_dev""")
        root.execute("""GRANT INSERT ON jw_dev.orders,jw_dev.order_items TO jw_app_dev""")
        root.execute("""CREATE POLICY ci_v174_quote_read ON jw_dev.quotes
            FOR SELECT TO jw_app_dev
            USING(org_id=jw_dev.current_org_from_session())""")
        root.execute("""CREATE POLICY ci_v174_item_read ON jw_dev.quote_items
            FOR SELECT TO jw_app_dev
            USING(EXISTS (SELECT 1 FROM jw_dev.quotes q
               WHERE q.id=quote_id AND q.org_id=jw_dev.current_org_from_session()))""")
        root.execute("""CREATE POLICY ci_v174_order_insert ON jw_dev.orders
            FOR INSERT TO jw_app_dev
            WITH CHECK(org_id=jw_dev.current_org_from_session()
              AND EXISTS(SELECT 1 FROM jw_dev.quotes q
                WHERE q.id=jw_dev.orders.quote_id AND q.org_id=jw_dev.orders.org_id
                AND q.customer_id=jw_dev.orders.customer_id))""")
        root.execute("""CREATE POLICY ci_v174_order_item_insert ON jw_dev.order_items
            FOR INSERT TO jw_app_dev
            WITH CHECK(EXISTS(SELECT 1 FROM jw_dev.orders o
                JOIN jw_dev.quote_items q ON q.id=source_quote_item_id
                WHERE o.id=order_id AND o.org_id=jw_dev.current_org_from_session()
                AND q.quote_id=o.quote_id))""")
        root.execute((Path(__file__).resolve().parents[1]/
                      "scripts/ci_v127_ephemeral_order.sql").read_text())
        source_meta = json.dumps({
            "kind":"reviewed_quote_to_order_draft",
            "source_sha256":SRC,"review_receipt_id":R,
            "source_document_verified":False,
            "quote_preview_acknowledged":True,
        },sort_keys=True,separators=(",",":"))
        root.execute("""INSERT INTO jw_dev.quotes
            (id,org_id,customer_id,customer_name_snapshot,doc_no,title,
             status,vat_mode,created_at,updated_at)
            VALUES(%s,%s,%s,'Customer A','Q-V174','Human Approved Quote',
                   'draft','taxable',now()::text,now()::text)""",
            (Q,fixture.ORG_A,"0"*32))
        root.execute("""INSERT INTO jw_dev.quote_items
             (id,quote_id,name,quantity,unit_price,position)
             VALUES(%s,%s,'Synthetic hardware',2,3500,0)""",(I,Q))
        root.execute("""INSERT INTO jw_dev.quote_review_receipts_v128
          (id,org_id,actor_id,quote_id,source_sha256,created_epoch)
          VALUES(%s,%s,%s,%s,%s,%s)""",
          (R,fixture.ORG_A,"1"*32,Q,SRC,int(time.time())))
        root.execute("""INSERT INTO jw_dev.order_drafts_v127
           (id,org_id,customer_id,quote_id,customer_name_snapshot,doc_no,title,
            status,review_state,vat_mode,due_date,created_at,updated_at,
            order_date,source_import_id,source_document_meta)
           VALUES(%s,%s,%s,%s,'Customer A','OD-V174','Human Approved Quote',
             'draft','preview_acknowledged','taxable','',now()::text,
             now()::text,now()::date::text,'v174:review',%s)""",
           (D,fixture.ORG_A,"0"*32,Q,source_meta))
        root.execute("""INSERT INTO jw_dev.order_draft_items_v127
             (id,order_id,source_quote_item_id,name,quantity,unit_price,position)
             VALUES(%s,%s,%s,'Synthetic hardware',2,3500,0)""",
             ("9"*32,D,I))
        assert root.execute("""SELECT count(*) FROM jw_dev.order_drafts_v127
                                WHERE org_id=%s""",
                            (fixture.ORG_A,)).fetchone() == (1,)


def main():
    install()
    app=fixture.configure()
    os.environ["JW_PG_INTERNAL_ORDER_V174"]=activation._GATE
    assert activation.quotes.register_v92_quote_api(app)
    assert activation.register_v174_internal_order(app)
    a,b,m=(fixture.client(app,key) for key in ("A","B","M"))
    target=URL+"/order-drafts/"+D+"/register-preview"
    pa=a.get(target)
    assert pa.status_code==200,(pa.status_code,pa.text[:500])
    v=pa.json()
    assert v["money"]=={"subtotal":7000,"vat":700,"total":7700}
    assert v["original_file_verified"] is False
    assert v["counterparty_acceptance_independently_verified"] is False
    assert b.get(target).status_code==404
    assert m.get(target).status_code==403
    assert a.get(URL+"/order-drafts/"+("a"*32)+"/register-preview").status_code==404
    body={
        "draft_id":D,"review_receipt_id":R,
        "preview_sha256":v["preview_sha256"],
        "request_id":"v174-real-pg-internal-order",
        "original_checked":True,"register_internal_only":True,
    }
    headers={"Origin":"https://testserver","X-CSRF-Token":fixture.CSRF["A"]}
    write=URL+"/orders/from-reviewed-draft"
    assert a.post(write,json=body,headers={"Origin":"https://testserver"}).status_code==403
    assert a.post(write,json=body,headers={**headers,"Origin":"https://hostile.test"}).status_code==403
    assert m.post(write,json=body,headers={"Origin":"https://testserver",
                    "X-CSRF-Token":fixture.CSRF["M"]}).status_code==403
    assert b.post(write,json=body,headers={"Origin":"https://testserver",
                    "X-CSRF-Token":fixture.CSRF["B"]}).status_code==404
    assert a.post(write,json={**body,"original_checked":False},
                  headers=headers).status_code==422
    assert a.post(write,json={**body,"register_internal_only":False},
                  headers=headers).status_code==422
    assert a.post(write,json={**body,"preview_sha256":"0"*64},
                  headers=headers).status_code==409
    assert a.post(write,json={**body,"review_receipt_id":"f"*32},
                  headers=headers).status_code==409

    first=a.post(write,json=body,headers=headers)
    assert first.status_code==201,(first.status_code,first.text[:800])
    doc=first.json()
    assert doc["created"] is True and doc["internal_order_only"] is True
    assert doc["external_acceptance_verified"] is False
    assert doc["invoice_issued"] is False and doc["payment_recorded"] is False
    assert doc["money"]["total"]==7700
    replay=a.post(write,json=body,headers=headers)
    assert replay.status_code==200,(replay.status_code,replay.text[:500])
    assert replay.json()["order_id"]==doc["order_id"]
    assert replay.json()["created"] is False
    assert a.post(write,json={**body,"request_id":"v174-other-key"},
                  headers=headers).status_code==409

    # Commit-order accounting is real restricted-role PG, not a Python mock.
    with psycopg.connect(fixture.DSN) as root:
        assert root.execute("""SELECT status,review_state,org_id,customer_id,
                  quote_id,source_import_id,source_document_meta
                  FROM jw_dev.orders WHERE id=%s""",
                  (doc["order_id"],)).fetchone() == (
                  "received","acknowledged",fixture.ORG_A,"0"*32,Q,
                  "v174:"+__import__("hashlib").sha256(
                    (fixture.ORG_A+"\x00"+body["request_id"]).encode()).hexdigest(),
                  json.dumps({
                    "kind":"v174_internal_reviewed_order_only",
                    "draft_id":D,"quote_id":Q,
                    "preview_sha256":body["preview_sha256"],
                    "review_receipt_id":R,
                    "counterparty_verified":False,
                    "source_document_verified":False,
                    "bank_reconciled":False,
                  },sort_keys=True,separators=(",",":")))
        assert root.execute("""SELECT source_quote_item_id,name,quantity,unit_price,position
          FROM jw_dev.order_items WHERE order_id=%s""",
          (doc["order_id"],)).fetchall()==[(I,"Synthetic hardware",2,3500,0)]
        assert root.execute("""SELECT count(*) FROM jw_dev.orders
                              WHERE quote_id=%s""",(Q,)).fetchone()==(1,)
        assert root.execute("""SELECT count(*) FROM jw_dev.audit_logs
              WHERE entity_id=%s AND action='human_approved_internal_order_only'""",
              (doc["order_id"],)).fetchone()==(1,)
        assert root.execute("SELECT count(*) FROM jw_dev.invoices").fetchone()==(0,)
    print("PASS_V174_REAL_PG17_RESTRICTED_ADMIN_DRAFT_TO_INTERNAL_ORDER",flush=True)
    print("PASS_V174_REAL_PG17_FORCED_RLS_FOREIGN_MEMBER_CSRF_ORIGIN_DENIAL",flush=True)
    print("PASS_V174_REAL_PG17_IDEMPOTENT_RETRY_SOURCE_LINE_AUDIT",flush=True)
    # V17.5: this is the REAL V92 -> V174 API chain, not a seed that
    # manually invents an accepted quote, approval receipt or order draft.
    # The quote remains "draft" exactly as generated by the production V92
    # stage flow. Admin acknowledgement does not prove buyer acceptance.
    q2, i2 = "7"*32, "6"*32
    with psycopg.connect(fixture.DSN) as root:
        root.execute("""INSERT INTO jw_dev.quotes
          (id,org_id,customer_id,customer_name_snapshot,doc_no,title,
           status,vat_mode,created_at,updated_at)
          VALUES(%s,%s,%s,'Customer A','Q-V175','V175 Actual API Chain',
                 'draft','taxable',now()::text,now()::text)""",
          (q2,fixture.ORG_A,"0"*32))
        root.execute("""INSERT INTO jw_dev.quote_items
          (id,quote_id,name,quantity,unit_price,position)
          VALUES(%s,%s,'Source verified line',3,2000,0)""",(i2,q2))
    fresh_preview=a.get("/api/pg-stage/v92/quote-review-previews/"+q2)
    assert fresh_preview.status_code==200,(fresh_preview.status_code,fresh_preview.text[:500])
    source=fresh_preview.json()
    assert source["money"]=={"subtotal":6000,"vat":600,"total":6600}
    ack=a.post("/api/pg-stage/v92/quote-reviews",json={
          "quote_id":q2, "preview_sha256":source["preview_sha256"],
          "preview_checked":True},headers=headers)
    assert ack.status_code==201,(ack.status_code,ack.text[:500])
    receipt=ack.json()["review_receipt_id"]
    real_draft=a.post("/api/pg-stage/v92/order-drafts",json={
          "request_id":"v175-real-v92-to-v174",
          "quote_id":q2,"review_receipt_id":receipt,
          "original_checked":True},headers=headers)
    assert real_draft.status_code==201,(real_draft.status_code,real_draft.text[:500])
    did=real_draft.json()["order_id"]
    assert real_draft.json()["draft_only"] is True
    full_preview=a.get(URL+"/order-drafts/"+did+"/register-preview")
    assert full_preview.status_code==200,(full_preview.status_code,full_preview.text[:500])
    assert full_preview.json()["money"]["total"]==6600
    converted=a.post(write,json={
        "draft_id":did,"review_receipt_id":receipt,
        "preview_sha256":full_preview.json()["preview_sha256"],
        "request_id":"v175-reviewed-actual-v92-order",
        "original_checked":True,"register_internal_only":True,
    },headers=headers)
    assert converted.status_code==201,(converted.status_code,converted.text[:700])
    assert converted.json()["internal_order_only"] is True
    assert converted.json()["external_acceptance_verified"] is False
    with psycopg.connect(fixture.DSN) as root:
        v=root.execute("""SELECT q.status,o.status,o.quote_id FROM jw_dev.quotes q
          JOIN jw_dev.orders o ON o.quote_id=q.id WHERE q.id=%s""",(q2,)).fetchone()
        assert v==("draft","received",q2),v
        assert root.execute("""SELECT count(*) FROM jw_dev.order_items
             WHERE order_id=%s""",(converted.json()["order_id"],)).fetchone()==(1,)
        assert root.execute("""SELECT count(*) FROM jw_dev.invoices""").fetchone()==(0,)
        assert root.execute("""SELECT count(*) FROM jw_dev.payments""").fetchone()==(0,)
    print("PASS_V175_REAL_PG17_V92_QUOTE_ACK_DRAFT_TO_V174_INTERNAL_ORDER_NO_STATUS_HACK",flush=True)
    print("PASS_V175_REAL_PG17_CANONICAL_RECEIPT_DIGEST_AND_AUDIT_FOLLOWS_SOURCE",flush=True)
    print("LIMIT_V174_NOT_OFFICIAL_ACCEPTANCE_DELIVERY_INVOICE_BANK",flush=True)


if __name__=="__main__":
    main()
