"""Real disposable PG17 journal, reconciliation and period acceptance."""
import concurrent.futures
import os
from pathlib import Path
import threading
import unittest
import psycopg
from fastapi import FastAPI
from app import naruv_accounting_review as accounting
from scripts import ci_v90_postgres_browser as fixture
ROOT=Path(__file__).resolve().parents[1]

def run_accounting(base):
    class Accounting(base):
        accounting_active=True
        @classmethod
        def setUpClass(cls):
            if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("JW_ENV")!="dev":
                raise RuntimeError("CI_ONLY")
            cls.app=base.app;cls.ingest_dsn=base.ingest_dsn
            os.environ.update(NARUV_NATIVE_WRITE_REVIEW="ISOLATED_SYNTHETIC_ONLY",
                NARUV_INVENTORY_REVIEW="ISOLATED_SYNTHETIC_ONLY",NARUV_TRADE_REVIEW="ISOLATED_SYNTHETIC_ONLY",
                NARUV_FINANCE_REVIEW="ISOLATED_SYNTHETIC_ONLY",NARUV_ACCOUNTING_REVIEW="ISOLATED_SYNTHETIC_ONLY")
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("TRUNCATE naruv_finance.events,naruv_finance.bills")
                c.execute("SELECT set_config('naruv.accounting_ci','DISPOSABLE_ONLY',true)")
                c.execute((ROOT/"db/review/naruv_accounting_ci.sql").read_text())
            if not accounting.register_accounting(cls.app):raise RuntimeError("ACCT_DISABLED")
        def setUp(self):
            super().setUp()
            os.environ["NARUV_ACCOUNTING_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("""INSERT INTO naruv_accounting.periods(org_id,period_start)
                    SELECT id,date_trunc('month',clock_timestamp() AT TIME ZONE 'Asia/Seoul')::date
                    FROM jw_dev.organizations WHERE id IN ('ci-a','ci-b')""")
                self.month=c.execute("SELECT period_start::text FROM naruv_accounting.periods WHERE org_id='ci-a'").fetchone()[0]
        def acct(self,bill="b1",who="A",code=200):
            return self.check(self.call(f"/accounting/bills/{bill}/inspect",who=who),code)
        def close(self,who="A",code=200,month=None,extra=None):
            return self.check(self.call(f"/accounting/periods/{month or self.month}/close",who=who,extra=extra),code)
        def journal_counts(self):
            with psycopg.connect(fixture.root_dsn) as c:
                return c.execute("SELECT (SELECT count(*) FROM naruv_accounting.journals),(SELECT count(*) FROM naruv_accounting.lines)").fetchone()
        def test_acct_purchase_and_payment_reversal(self):
            self.ready()
            a=self.acct();self.assertEqual((a["ap"],a["ar"],a["debit"],a["credit"]),(116,0,116,116))
            self.fin("pay","p1",{"amount":50,"reference":"ref1"})
            self.fin("reverse","rev1",{"payment_request_id":"p1"})
            self.fin("pay","p2",{"amount":116,"reference":"ref2"})
            a=self.acct()
            self.assertEqual((a["ap"],a["outstanding"],a["journal_count"]),(0,0,4))
            self.assertEqual(a["debit"],a["credit"])
            with psycopg.connect(fixture.root_dsn) as c:
                p=c.execute("SELECT account,debit,credit FROM naruv_accounting.lines WHERE event_id='p1' ORDER BY line_no").fetchall()
                r=c.execute("SELECT account,credit,debit FROM naruv_accounting.lines WHERE event_id='rev1' ORDER BY line_no").fetchall()
                self.assertEqual(p,r)
            self.assertEqual(self.journal_counts(),(4,9))
        def test_acct_sale_receivable(self):
            self.seed(price=0,vat="exempt");self.trade("fulfill","f1",{"quantity":1})
            from fastapi.testclient import TestClient
            with TestClient(self.app,base_url="https://testserver") as c:
                c.cookies.set("__Host-jw_session",fixture.TOKENS["A"])
                q=self.check(c.post("/api/pg-stage/v92/quotes",json={"request_id":"acct-sale-q","customer_id":"ci-customer-a",
                    "title":"sale","vat_mode":"taxable","items":[{"name":"Widget","quantity":1,"unit_price":105}]},
                    headers={"origin":"https://testserver","x-csrf-token":fixture.CSRF["A"]}),201)["quote_id"]
            self.trade("open","sale-o",{"kind":"sale","quote_id":q,"source_id":"source-a","item_id":"0001","warehouse_id":"W1"},doc="sale")
            self.trade("fulfill","sale-f",{"quantity":1},doc="sale")
            self.fin("bill","sale-b",{"doc_id":"sale","fulfillment_id":"sale-f"},bill="sale-b")
            a=self.acct("sale-b");self.assertEqual((a["ar"],a["ap"]),(116,0))
            self.fin("pay","sale-p",{"amount":16,"reference":"sale-ref"},bill="sale-b")
            a=self.acct("sale-b");self.assertEqual((a["ar"],a["outstanding"]),(100,100))
            self.assertEqual({x["account"] for x in a["accounts"]},{"AR","SALES","VAT_OUTPUT","CASH_CLEARING"})
        def test_acct_zero_amount_and_partial_rounding(self):
            self.seed(price=0,vat="exempt");self.trade("fulfill","f1",{"quantity":1});self.bill()
            a=self.acct();self.assertEqual((a["debit"],a["credit"],a["outstanding"],a["journal_count"]),(0,0,0,1))
            self.assertEqual(self.journal_counts(),(1,0))
        def test_acct_closed_period_rejects_new_and_retry_survives(self):
            b=self.ready();self.fin("pay","p1",{"amount":10,"reference":"ref1"})
            p=self.close();self.assertEqual(self.close(),p)
            self.assertEqual(self.bill(),b)
            self.fin("pay","p2",{"amount":10,"reference":"ref2"},code=409)
            self.fin("reverse","r1",{"payment_request_id":"p1"},code=409)
            self.trade("fulfill","f2",{"quantity":1})
            self.bill("breq2","f2","b2",code=409)
            self.assertEqual(self.counts_fin(),(1,2));self.assertEqual(self.acct()["outstanding"],106)
        def test_acct_period_tenant_scope(self):
            self.ready();self.close()
            self.seed("B");self.trade("fulfill","f1",{"quantity":1},who="B");self.bill(who="B")
            self.fin("pay","p1",{"amount":20,"reference":"ref1"},who="B")
            self.assertEqual((self.acct()["ap"],self.acct(who="B")["ap"]),(116,96))
            self.acct("absent","B",404)
        def test_acct_close_concurrent_with_payment(self):
            self.ready();bar=threading.Barrier(2)
            def go(i):
                bar.wait(timeout=10)
                if i==0:return self.call(f"/accounting/periods/{self.month}/close")
                return self.call("/finance/bills/b1/commands/pay/p1",{"amount":50,"reference":"ref1"})
            with concurrent.futures.ThreadPoolExecutor(2) as pool:r=list(pool.map(go,range(2)))
            self.assertEqual(r[0].status_code,200);self.assertIn(r[1].status_code,(200,409))
            self.assertEqual(self.acct()["outstanding"],66 if r[1].status_code==200 else 116)
            self.fin("pay","p2",{"amount":1,"reference":"ref2"},code=409)
        def test_acct_journal_failure_rolls_back_bill(self):
            self.seed();self.trade("fulfill","f1",{"quantity":1})
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("""CREATE FUNCTION naruv_accounting.inject_failure() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'SYNTHETIC_ACCT_FAILURE'; END $$""")
                c.execute("CREATE TRIGGER inject_failure BEFORE INSERT ON naruv_accounting.lines FOR EACH ROW EXECUTE FUNCTION naruv_accounting.inject_failure()")
            try:
                self.bill(code=503);self.assertEqual(self.counts_fin(),(0,0));self.assertEqual(self.journal_counts(),(0,0))
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("DROP TRIGGER inject_failure ON naruv_accounting.lines")
                    c.execute("DROP FUNCTION naruv_accounting.inject_failure()")
            self.bill();self.assertEqual(self.journal_counts(),(1,3))
        def test_acct_deferred_balance_constraint_rolls_back(self):
            self.seed();self.trade("fulfill","f1",{"quantity":1})
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("""CREATE FUNCTION naruv_accounting.inject_imbalance() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.line_no=2 THEN NEW.debit:=NEW.debit+1; END IF; RETURN NEW; END $$""")
                c.execute("CREATE TRIGGER inject_imbalance BEFORE INSERT ON naruv_accounting.lines FOR EACH ROW EXECUTE FUNCTION naruv_accounting.inject_imbalance()")
            try:
                self.bill(code=503);self.assertEqual(self.counts_fin(),(0,0));self.assertEqual(self.journal_counts(),(0,0))
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("DROP TRIGGER inject_imbalance ON naruv_accounting.lines")
                    c.execute("DROP FUNCTION naruv_accounting.inject_imbalance()")
            self.bill();self.assertEqual(self.acct()["ap"],116)
        def test_acct_privileges_immutability_and_default_off(self):
            self.ready()
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT count(*) FROM pg_class WHERE relnamespace='naruv_accounting'::regnamespace AND relkind='r' AND relrowsecurity AND relforcerowsecurity").fetchone()[0],3)
                for role in ("jw_app_dev","naruv_native_stage"):
                    self.assertEqual(c.execute("""SELECT has_table_privilege(%s,'naruv_accounting.lines','INSERT'),
                    has_table_privilege(%s,'naruv_accounting.periods','UPDATE'),
                    has_function_privilege(%s,'naruv_accounting.close_period(text,boolean,text)','EXECUTE')""",(role,role,role)).fetchone(),(False,False,role=="jw_app_dev"))
                with self.assertRaisesRegex(psycopg.Error,"NARUV_IMMUTABLE"):
                    c.execute("UPDATE naruv_accounting.lines SET debit=debit")
                c.rollback()
            self.close(extra={"x-naruv-confirm":"no"},code=422)
            self.close(month="0000-01-01",code=422)
            self.close(month="1900-01-01",code=404)
            self.close()
            with psycopg.connect(fixture.root_dsn) as c:
                with self.assertRaisesRegex(psycopg.Error,"ACCT_PERIOD_IMMUTABLE"):
                    c.execute("UPDATE naruv_accounting.periods SET closed_at=NULL,closed_by=NULL WHERE org_id='ci-a'")
                c.rollback()
            os.environ.pop("NARUV_ACCOUNTING_REVIEW",None)
            self.assertFalse(accounting.register_accounting(FastAPI()));self.acct(code=404)
        def test_acct_partial_bill_reconciliation_and_retry(self):
            self.seed()
            for i in range(1,4):
                self.trade("fulfill","f"+str(i),{"quantity":1})
                b=self.bill("breq"+str(i),"f"+str(i),"b"+str(i))
                self.assertEqual(self.bill("breq"+str(i),"f"+str(i),"b"+str(i)),b)
            self.assertEqual(sum(self.acct("b"+str(i))["ap"] for i in range(1,4)),347)
            self.assertEqual(self.journal_counts(),(3,9))
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(Accounting) if n.startswith("test_acct_")]
    if len(names)!=10:raise RuntimeError("ACCT_CASE_COUNT_CHANGED")
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Accounting(n) for n in names))
    if not result.wasSuccessful() or result.testsRun!=10 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:raise SystemExit(1)
    print("NARUV_ACCOUNTING_PASS: 10 isolated PG17 journal and period cases; no statutory accounting acceptance.")
