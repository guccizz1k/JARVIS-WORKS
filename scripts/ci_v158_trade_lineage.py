"""V15.8 real PostgreSQL stage-only existing-record chain regression.

Invoked in V15.7's disposable real PG17 transaction fixture, AFTER V15.7
delivery concurrency and rollback proof. Never writes a persistent database.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import psycopg
from fastapi.testclient import TestClient

from app import pg_trade_lineage_v158 as lineage


def exercise_real_pg_lineage(app, root_dsn, clients):
    # Root creates ONLY synthetic fixture records in a freshly initialized
    # Actions postgres:17 service. No runtime privilege escalation.
    with psycopg.connect(root_dsn) as root:
        root.execute("ALTER TABLE jw_dev.quotes ADD COLUMN status text NOT NULL DEFAULT 'draft'")
        root.execute("ALTER TABLE jw_dev.quotes ADD COLUMN vat_mode text NOT NULL DEFAULT 'taxable'")
        root.execute("""CREATE TABLE jw_dev.import_previews(
            id text PRIMARY KEY,org_id text NOT NULL,quote_id text NOT NULL,
            status text NOT NULL)""")
        root.execute("""CREATE TABLE jw_dev.payments(
            id text PRIMARY KEY,org_id text NOT NULL,invoice_id text NOT NULL,
            amount bigint NOT NULL,reversed_at text)""")
        root.execute("ALTER TABLE jw_dev.quotes ENABLE ROW LEVEL SECURITY")
        root.execute("ALTER TABLE jw_dev.quotes FORCE ROW LEVEL SECURITY")
        root.execute("ALTER TABLE jw_dev.import_previews ENABLE ROW LEVEL SECURITY")
        root.execute("ALTER TABLE jw_dev.import_previews FORCE ROW LEVEL SECURITY")
        root.execute("ALTER TABLE jw_dev.payments ENABLE ROW LEVEL SECURITY")
        root.execute("ALTER TABLE jw_dev.payments FORCE ROW LEVEL SECURITY")
        root.execute("GRANT SELECT ON jw_dev.quotes,jw_dev.import_previews,jw_dev.payments TO jw_app_dev")
        root.execute("""CREATE POLICY ci_v158_quote_read ON jw_dev.quotes
            FOR SELECT TO jw_app_dev USING (org_id=jw_dev.current_org_from_session())""")
        root.execute("""CREATE POLICY ci_v158_import_read ON jw_dev.import_previews
            FOR SELECT TO jw_app_dev USING (org_id=jw_dev.current_org_from_session())""")
        root.execute("""CREATE POLICY ci_v158_payment_read ON jw_dev.payments
            FOR SELECT TO jw_app_dev USING (org_id=jw_dev.current_org_from_session())""")
        root.execute("""INSERT INTO jw_dev.quotes(id,org_id,customer_id,doc_no)
            VALUES(repeat('e',32),repeat('a',32),repeat('0',32),'Q-A'),
                  (repeat('f',32),repeat('b',32),repeat('8',32),'Q-B')""")
        root.execute("""INSERT INTO jw_dev.import_previews(id,org_id,quote_id,status)
            VALUES(repeat('5',32),repeat('a',32),repeat('e',32),'confirmed')""")
        root.execute("""INSERT INTO jw_dev.invoices(id,org_id,order_id)
            VALUES(repeat('7',32),repeat('b',32),repeat('d',32))""")
        root.execute("""INSERT INTO jw_dev.payments(id,org_id,invoice_id,amount,reversed_at)
            VALUES(repeat('6',32),repeat('b',32),repeat('7',32),2000,NULL),
                  (repeat('9',32),repeat('b',32),repeat('7',32),900,'revoked')""")

    import os
    os.environ["JW_PG_TRADE_LINEAGE_V158"] = "ISOLATED_DEV_TRADE_LINEAGE_READ_ONLY"
    assert lineage.register_v158_trade_lineage(app)
    a,b,m=clients
    url="/api/pg-stage/v158/quotes/"
    def read(client,identifier):
        return client.get(url+identifier+"/lineage")

    ra=read(a,"e"*32)
    assert ra.status_code==200,(ra.status_code,ra.text[:350])
    result_a=ra.json()
    assert result_a["counts"]=={
        "source_imports":1,"orders":1,"invoices":0,"recorded_payments":0}
    assert result_a["source_imports"][0]["status"]=="confirmed"
    assert result_a["orders"][0]["delivery_evidence_review"]=="PENDING_HUMAN_REVIEW"
    assert result_a["orders"][0]["physical_delivery_verified"] is False
    assert result_a["payment_reconciliation_verified"] is False
    assert ra.headers["cache-control"]=="no-store"
    assert read(b,"e"*32).status_code==404
    assert read(a,"f"*32).status_code==404
    assert read(m,"f"*32).status_code==404
    assert read(a,"E"*32).status_code==404
    assert read(a,"not-a-real-quote").status_code==404
    rb=read(b,"f"*32)
    assert rb.status_code==200,(rb.status_code,rb.text[:350])
    result_b=rb.json()
    assert result_b["counts"]=={
        "source_imports":0,"orders":1,"invoices":1,"recorded_payments":2}
    invoice=result_b["orders"][0]["invoices"][0]
    assert invoice["recorded_active_amount_krw"]==2000
    assert invoice["active_payment_count"]==1
    assert invoice["recorded_payments"]==2
    assert invoice["reconciled"] is False
    assert result_b["orders"][0]["delivery_evidence_review"]=="NOT_SUBMITTED"
    assert read(m,"e"*32).status_code==200  # existing member tenant read RLS

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1=pool.submit(read,a,"e"*32)
        f2=pool.submit(read,b,"f"*32)
        results=[f1.result(timeout=10),f2.result(timeout=10)]
    assert [x.status_code for x in results]==[200,200]

    # Never create a payment or invoice just by reading status.
    with psycopg.connect(root_dsn) as root:
        rows=root.execute("""SELECT
          (SELECT count(*) FROM jw_dev.invoices),
          (SELECT count(*) FROM jw_dev.payments),
          (SELECT count(*) FROM jw_dev.audit_logs)
        """).fetchone()
        assert rows==(1,2,1),rows
        assert root.execute("""SELECT count(*) FROM pg_policies
          WHERE schemaname='jw_dev' AND policyname LIKE 'ci_v158_%'""").fetchone()==(3,)
    print("PASS_V158_REAL_PG17_IMPORT_QUOTE_ORDER_INVOICE_PAYMENT_LINEAGE",flush=True)
    print("PASS_V158_REAL_RLS_A_B_MEMBER_AND_UNLINKED_PAYMENT_DENIAL",flush=True)
    print("PASS_V158_INVOICE_READ_ONLY_REVERSED_AMOUNT_NO_RECONCILIATION_CLAIM",flush=True)
