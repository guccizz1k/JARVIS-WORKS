"""Actual isolated PostgreSQL 17 invoice/payment balance HTTP verification.

Fresh localhost-only PG17 service. Synthetic companies, orders, invoice lines,
active and reversed deposits; no bank credentials, payment posting or shared DB.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import psycopg

from app import pg_invoice_balance_v161 as preview
from scripts import ci_v157_real_pg_delivery_http as fixture

IA="7"*32
IB="6"*32
PA="5"*32
RA="9"*32
PB="2"*32


def install_disposable_finance_fixture():
    with psycopg.connect(fixture.DSN) as root:
        for col in (
            "customer_id text NOT NULL DEFAULT ''",
            "status text NOT NULL DEFAULT 'open'",
            "vat_mode text NOT NULL DEFAULT 'taxable'"
        ):
            root.execute("ALTER TABLE jw_dev.invoices ADD COLUMN "+col)
        root.execute("""CREATE TABLE jw_dev.invoice_items(
            id text PRIMARY KEY, invoice_id text NOT NULL
              REFERENCES jw_dev.invoices(id),
            source_order_item_id text,
            name text NOT NULL, quantity bigint NOT NULL,
            unit_price bigint NOT NULL, position bigint NOT NULL,
            UNIQUE(invoice_id,position))""")
        root.execute("""CREATE TABLE jw_dev.payments(
            id text PRIMARY KEY,org_id text NOT NULL,invoice_id text NOT NULL
              REFERENCES jw_dev.invoices(id),
            amount bigint NOT NULL,paid_at text NOT NULL DEFAULT '',
            note text NOT NULL DEFAULT '',created_at text NOT NULL DEFAULT '',
            reference text NOT NULL DEFAULT '',reversed_at text,
            reversed_by text)""")
        for table in ("invoice_items","payments"):
            root.execute(f"ALTER TABLE jw_dev.{table} ENABLE ROW LEVEL SECURITY")
            root.execute(f"ALTER TABLE jw_dev.{table} FORCE ROW LEVEL SECURITY")
        root.execute("GRANT SELECT ON jw_dev.invoice_items,jw_dev.payments TO jw_app_dev")
        root.execute("""CREATE POLICY ci_v161_item_read
            ON jw_dev.invoice_items FOR SELECT TO jw_app_dev
            USING(EXISTS (SELECT 1 FROM jw_dev.invoices inv
               WHERE inv.id=invoice_id
               AND inv.org_id=jw_dev.current_org_from_session()))""")
        root.execute("""CREATE POLICY ci_v161_payment_read
            ON jw_dev.payments FOR SELECT TO jw_app_dev
            USING(org_id=jw_dev.current_org_from_session() AND EXISTS
              (SELECT 1 FROM jw_dev.invoices inv
                WHERE inv.id=invoice_id AND inv.org_id=org_id))""")
        root.execute("""UPDATE jw_dev.orders SET vat_mode='exempt'
                 WHERE id=repeat('d',32)""")
        root.execute("""INSERT INTO jw_dev.invoices(
             id,org_id,order_id,customer_id,status,vat_mode)
             VALUES(%s,%s,%s,%s,'open','taxable'),
                   (%s,%s,%s,%s,'open','exempt')""",
             (IA,fixture.ORG_A,fixture.ORDER_A,"0"*32,
              IB,fixture.ORG_B,fixture.ORDER_B,"8"*32))
        root.execute("""INSERT INTO jw_dev.invoice_items(
              id,invoice_id,source_order_item_id,name,quantity,unit_price,position)
              VALUES(%s,%s,%s,'Synthetic A',2,3500,0),
                    (%s,%s,%s,'Synthetic B',2,3500,0)""",
              ("1"*32,IA,fixture.LINE_A,"3"*32,IB,fixture.LINE_B))
        root.execute("""INSERT INTO jw_dev.payments(
              id,org_id,invoice_id,amount,reversed_at)
              VALUES(%s,%s,%s,3000,NULL),
                    (%s,%s,%s,900,'reversed-test'),
                    (%s,%s,%s,2000,NULL)""",
              (PA,fixture.ORG_A,IA,RA,fixture.ORG_A,IA,
               PB,fixture.ORG_B,IB))


def main():
    fixture.bootstrap()
    install_disposable_finance_fixture()
    app=fixture.configure()
    os.environ["JW_PG_INVOICE_BALANCE_V161"] = (
       "ISOLATED_DEV_INVOICE_BALANCE_READ_ONLY")
    assert preview.register_v161_invoice_balance(app)
    a,b,m=(fixture.client(app,key) for key in ("A","B","M"))
    path=lambda i:"/api/pg-stage/v161/invoices/"+i+"/balance-preview"
    ra=a.get(path(IA))
    assert ra.status_code==200,(ra.status_code,ra.text[:400])
    doc=ra.json()
    assert doc["subtotal_krw"]==7000 and doc["vat_krw"]==700
    assert doc["gross_krw"]==7700
    assert doc["recorded_active_payments_krw"]==3000
    assert doc["unpaid_balance_krw"]==4700
    assert doc["recorded_active_count"]==1
    assert doc["reversed_record_count"]==1
    assert doc["bank_reconciliation_verified"] is False
    assert doc["payment_posted_by_this_api"] is False
    assert doc["invoice_posted_by_this_api"] is False
    assert ra.headers["cache-control"]=="no-store"
    rb=b.get(path(IB))
    assert rb.status_code==200,(rb.status_code,rb.text[:450])
    d=rb.json()
    assert d["gross_krw"]==7000
    assert d["vat_krw"]==0
    assert d["recorded_active_payments_krw"]==2000
    assert d["unpaid_balance_krw"]==5000

    assert a.get(path(IB)).status_code==404
    assert b.get(path(IA)).status_code==404
    assert m.get(path(IA)).status_code==403
    assert m.get(path(IB)).status_code==403
    assert a.get(path("A"*32)).status_code==404
    assert a.get(path("fake")).status_code==404
    from fastapi.testclient import TestClient
    anonymous=TestClient(app,base_url="https://testserver")
    assert anonymous.get(path(IA)).status_code==401

    # Real restricted role must NOT be able to change any finance row.
    with psycopg.connect(fixture.TRADE_DSN) as trade:
        try:
            with trade.transaction():
                trade.execute("SET LOCAL ROLE jw_app_dev")
                trade.execute("""UPDATE jw_dev.payments SET amount=1
                                 WHERE id=%s""",(PA,))
        except psycopg.errors.InsufficientPrivilege:
            pass
        else:
            raise AssertionError("FAIL_V161_APP_ROLE_CAN_REWRITE_PAYMENT")

    with ThreadPoolExecutor(max_workers=2) as pool:
        fa=pool.submit(a.get,path(IA))
        fb=pool.submit(b.get,path(IB))
        assert fa.result(timeout=10).status_code==200
        assert fb.result(timeout=10).status_code==200

    # An inconsistent source order must fail rather than show another
    # customer's outstanding liability under the correct company.
    with psycopg.connect(fixture.DSN) as root:
        root.execute("UPDATE jw_dev.invoices SET customer_id=%s WHERE id=%s",
                     ("8"*32,IA))
    assert a.get(path(IA)).status_code==409
    with psycopg.connect(fixture.DSN) as root:
        root.execute("UPDATE jw_dev.invoices SET customer_id=%s WHERE id=%s",
                     ("0"*32,IA))
        root.execute("UPDATE jw_dev.payments SET amount=8500 WHERE id=%s",(PA,))
    assert a.get(path(IA)).status_code==409
    with psycopg.connect(fixture.DSN) as root:
        root.execute("UPDATE jw_dev.payments SET amount=3000 WHERE id=%s",(PA,))
        root.execute("""UPDATE jw_dev.invoice_items SET quantity=3 WHERE invoice_id=%s""",
                     (IA,))
    assert a.get(path(IA)).status_code==200
    with psycopg.connect(fixture.DSN) as root:
        root.execute("""UPDATE jw_dev.invoice_items SET quantity=2 WHERE invoice_id=%s""",
                     (IA,))
        # More extreme negative input cannot leak into a "0 due" status.
        root.execute("""UPDATE jw_dev.invoice_items SET quantity=0 WHERE invoice_id=%s""",
                     (IB,))
    assert b.get(path(IB)).status_code==409
    with psycopg.connect(fixture.DSN) as root:
        root.execute("""UPDATE jw_dev.invoice_items SET quantity=2 WHERE invoice_id=%s""",
                     (IB,))
        result=root.execute("""SELECT
              (SELECT count(*) FROM jw_dev.invoices),
              (SELECT count(*) FROM jw_dev.invoice_items),
              (SELECT count(*) FROM jw_dev.payments),
              (SELECT count(*) FROM jw_dev.audit_logs)
        """).fetchone()
        assert result==(2,2,3,0),result
    assert a.get(path(IA)).status_code==200
    assert b.get(path(IB)).status_code==200
    print("PASS_V161_REAL_PG17_TENANT_ADMIN_INVOICE_BALANCE",flush=True)
    print("PASS_V161_REVERSED_PAYMENT_EXCLUSION_TAXABLE_EXEMPT",flush=True)
    print("PASS_V161_CROSS_TENANT_MEMBER_ANON_SQL_WRITE_DENIED",flush=True)
    print("PASS_V161_OVERPAYMENT_MISMATCH_INVALID_LINE_FAIL_CLOSED",flush=True)
    print("PASS_V161_NO_POSTING_OR_RECONCILIATION_CLAIM",flush=True)
    print("LIMIT: only synthetic recorded payments; no bank settlement proof",flush=True)


if __name__=="__main__":
    main()
