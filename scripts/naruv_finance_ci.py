"""Real isolated PG17 billing and settlement tests."""
import concurrent.futures
import json
import os
from pathlib import Path
import threading
import unittest
import psycopg
from fastapi import FastAPI
from app import naruv_finance_review as finance
from scripts import ci_v90_postgres_browser as fixture
ROOT=Path(__file__).resolve().parents[1]
RAW=b"sku,item_name,unit\n0001,Widget,EA\n"

def run_finance(base):
    class Finance(base):
        bridge_active=True
        inventory_active=True
        trade_active=True
        finance_active=True
        @classmethod
        def setUpClass(cls):
            if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("JW_ENV")!="dev":
                raise RuntimeError("CI_ONLY")
            cls.app=base.app;cls.ingest_dsn=base.ingest_dsn
            os.environ.update(NARUV_NATIVE_WRITE_REVIEW="ISOLATED_SYNTHETIC_ONLY",
                NARUV_INVENTORY_REVIEW="ISOLATED_SYNTHETIC_ONLY",NARUV_TRADE_REVIEW="ISOLATED_SYNTHETIC_ONLY",
                NARUV_FINANCE_REVIEW="ISOLATED_SYNTHETIC_ONLY")
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("SELECT set_config('naruv.finance_ci','DISPOSABLE_ONLY',true)")
                c.execute((ROOT/"db/review/naruv_finance_ci.sql").read_text())
            if not finance.register_finance(cls.app):raise RuntimeError("FIN_DISABLED")
        def setUp(self):
            super().setUp()
            os.environ.update(NARUV_INVENTORY_REVIEW="ISOLATED_SYNTHETIC_ONLY",
                NARUV_TRADE_REVIEW="ISOLATED_SYNTHETIC_ONLY",NARUV_FINANCE_REVIEW="ISOLATED_SYNTHETIC_ONLY")
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("DELETE FROM jw_dev.quote_items")
                c.execute("DELETE FROM jw_dev.quotes")
                c.execute("DELETE FROM jw_dev.audit_logs")
                c.execute("DELETE FROM jw_dev.customers WHERE id NOT IN ('ci-customer-a','ci-customer-b')")
        def call(self,path,payload=None,who="A",extra=None,raw=None):
            h={"content-type":"application/json","x-naruv-confirm":"yes"}
            if extra:h.update(extra)
            if raw is None:raw=b"" if payload is None else json.dumps(payload).encode()
            return self.req(path,who,raw,extra=h)
        def trade(self,action,rid,payload,doc="p1",who="A",code=200):
            return self.check(self.call(f"/trade/documents/{doc}/commands/{action}/{rid}",payload,who),code)
        def fin(self,action,rid,payload,bill="b1",who="A",code=200,extra=None,raw=None):
            return self.check(self.call(f"/finance/bills/{bill}/commands/{action}/{rid}",payload,who,extra,raw),code)
        def inspect(self,bill="b1",who="A",code=200):
            return self.check(self.call(f"/finance/bills/{bill}/inspect",who=who),code)
        def seed(self,who="A",price=105,qty=3,vat="taxable"):
            src="source-a" if who=="A" else "source-b"
            d=self.stage("stage-1",RAW,src,"item","csv",who)
            self.check(self.approve(d,"stage-1",who),200);self.check(self.commit(d,"stage-1","import-1",who),200)
            self.trade("open","o1",{"kind":"purchase","counterparty_id":"ci-customer-a" if who=="A" else "ci-customer-b",
                "source_id":src,"item_id":"0001","warehouse_id":"W1","quantity":qty,"unit_price":price,"vat_mode":vat},who=who)
        def bill(self,rid="breq",fid="f1",bill="b1",who="A",code=200):
            return self.fin("bill",rid,{"doc_id":"p1","fulfillment_id":fid},bill,who,code)
        def ready(self,price=105):
            self.seed(price=price);self.trade("fulfill","f1",{"quantity":1});return self.bill()
        def counts_fin(self):
            with psycopg.connect(fixture.root_dsn) as c:
                return c.execute("SELECT (SELECT count(*) FROM naruv_finance.bills),(SELECT count(*) FROM naruv_finance.events)").fetchone()
        def test_fin_partial_vat_and_sequence(self):
            self.seed()
            for i in range(1,4):self.trade("fulfill","f"+str(i),{"quantity":1})
            self.bill(fid="f2",code=409)
            rows=[self.bill("breq"+str(i),"f"+str(i),"b"+str(i)) for i in range(1,4)]
            self.assertEqual([r["vat"] for r in rows],[11,10,11])
            self.assertEqual(sum(r["total"] for r in rows),347)
            self.assertEqual(self.counts_fin(),(3,3))
        def test_fin_unfulfilled_and_cancelled_remainder(self):
            self.seed();self.bill(fid="o1",code=404)
            self.trade("fulfill","f1",{"quantity":1});self.trade("cancel","cancel",{})
            self.assertEqual(self.bill()["quantity"],1)
            self.bill("second","cancel","b2",code=404)
            self.bill("duplicate","f1","b2",code=409)
            self.assertEqual(self.counts_fin(),(1,1))
        def test_fin_exact_retry_and_payment_reverse(self):
            b=self.ready();self.assertEqual(b["total"],116)
            p=self.fin("pay","pmt1",{"amount":50,"reference":"ref-1"})
            self.assertEqual(p["outstanding"],66)
            self.fin("pay","pmt2",{"amount":66,"reference":"ref-2"})
            self.assertEqual(self.inspect()["state"],"SETTLED")
            self.assertEqual(self.fin("pay","pmt1",{"amount":50,"reference":"ref-1"}),p)
            self.assertEqual(self.bill(),b)
            r=self.fin("reverse","rev1",{"payment_request_id":"pmt1"})
            self.assertEqual((r["paid"],r["outstanding"]),(66,50))
            self.assertEqual(self.fin("reverse","rev1",{"payment_request_id":"pmt1"}),r)
            self.fin("reverse","rev2",{"payment_request_id":"pmt1"},code=409)
            self.fin("pay","pmt3",{"amount":50,"reference":"ref-1"},code=409)
            self.fin("pay","pmt4",{"amount":50,"reference":"ref-4"})
            self.assertEqual(self.inspect()["state"],"SETTLED")
        def test_fin_overpay_and_conflict(self):
            self.ready()
            self.fin("pay","p1",{"amount":117,"reference":"ref-1"},code=409)
            self.fin("pay","p1",{"amount":10,"reference":"ref-1"})
            self.fin("pay","p1",{"amount":11,"reference":"ref-1"},code=409)
            self.fin("pay","p2",{"amount":10,"reference":"ref-1"},code=409)
            self.assertEqual(self.inspect()["paid"],10)
            self.assertEqual(self.counts_fin(),(1,2))
        def test_fin_concurrent_payments(self):
            self.ready();bar=threading.Barrier(2)
            def go(i):
                bar.wait(timeout=10)
                return self.call(f"/finance/bills/b1/commands/pay/p-{i}",{"amount":80,"reference":f"ref-{i}"})
            with concurrent.futures.ThreadPoolExecutor(2) as pool:rs=list(pool.map(go,range(2)))
            self.assertEqual(sorted(r.status_code for r in rs),[200,409])
            self.assertEqual(self.inspect()["paid"],80)
        def test_fin_concurrent_duplicate_billing(self):
            self.seed();self.trade("fulfill","f1",{"quantity":1});bar=threading.Barrier(2)
            def go(i):
                bar.wait(timeout=10)
                return self.call(f"/finance/bills/b{i}/commands/bill/r{i}",{"doc_id":"p1","fulfillment_id":"f1"})
            with concurrent.futures.ThreadPoolExecutor(2) as pool:rs=list(pool.map(go,range(2)))
            self.assertEqual(sorted(r.status_code for r in rs),[200,409])
            self.assertEqual(self.counts_fin(),(1,1))
        def test_fin_tenant_and_reference_isolation(self):
            self.ready();self.inspect(who="B",code=404)
            self.fin("pay","p1",{"amount":10,"reference":"same"},who="B",code=404)
            self.bill(who="B",code=404)
            self.seed("B");self.trade("fulfill","f1",{"quantity":1},who="B");self.bill(who="B")
            self.fin("pay","p1",{"amount":10,"reference":"same"})
            self.fin("pay","p1",{"amount":20,"reference":"same"},who="B")
            self.assertEqual((self.inspect()["paid"],self.inspect(who="B")["paid"]),(10,20))
        def test_fin_event_failure_rollback(self):
            self.seed();self.trade("fulfill","f1",{"quantity":1})
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("""CREATE FUNCTION naruv_finance.inject_failure() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'SYNTHETIC_FIN_FAILURE'; END $$""")
                c.execute("CREATE TRIGGER inject_failure BEFORE INSERT ON naruv_finance.events FOR EACH ROW EXECUTE FUNCTION naruv_finance.inject_failure()")
            try:
                self.bill(code=503);self.assertEqual(self.counts_fin(),(0,0))
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("DROP TRIGGER inject_failure ON naruv_finance.events")
                    c.execute("DROP FUNCTION naruv_finance.inject_failure()")
            self.bill();self.assertEqual(self.counts_fin(),(1,1))
        def test_fin_zero_exempt_and_sale(self):
            self.seed(price=0,vat="exempt");self.trade("fulfill","f1",{"quantity":1})
            b=self.bill();self.assertEqual((b["total"],b["state"]),(0,"SETTLED"))
            self.fin("pay","p1",{"amount":1,"reference":"ref-1"},code=409)
            from fastapi.testclient import TestClient
            with TestClient(self.app,base_url="https://testserver") as c:
                c.cookies.set("__Host-jw_session",fixture.TOKENS["A"])
                q=self.check(c.post("/api/pg-stage/v92/quotes",json={"request_id":"finance-quote-1","customer_id":"ci-customer-a",
                  "title":"sale","vat_mode":"exempt","items":[{"name":"Widget","quantity":1,"unit_price":105}]},
                  headers={"origin":"https://testserver","x-csrf-token":fixture.CSRF["A"]}),201)["quote_id"]
            self.trade("open","sale-o",{"kind":"sale","quote_id":q,"source_id":"source-a","item_id":"0001","warehouse_id":"W1"},doc="sale")
            self.trade("fulfill","sale-f",{"quantity":1},doc="sale")
            b=self.fin("bill","sale-b",{"doc_id":"sale","fulfillment_id":"sale-f"},bill="sale-b")
            self.assertEqual((b["kind"],b["vat"],b["total"]),("sale",0,105))
        def test_fin_input_permissions_and_default_off(self):
            self.ready()
            for raw in (b'{"amount":true,"reference":"x"}',b'{"amount":1.5,"reference":"x"}',b'{"amount":1,"amount":2,"reference":"x"}'):
                self.fin("pay","p1",{},raw=raw,code=422)
            self.fin("pay","p1",{"amount":1,"reference":"x"},extra={"x-naruv-confirm":"no"},code=422)
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT count(*) FROM pg_class WHERE relnamespace='naruv_finance'::regnamespace AND relkind='r' AND relrowsecurity AND relforcerowsecurity").fetchone()[0],2)
                for role in ("jw_app_dev","naruv_native_stage"):
                    self.assertEqual(c.execute("""SELECT has_table_privilege(%s,'naruv_finance.events','INSERT'),
                       has_function_privilege(%s,'naruv_finance.command(text,text,text,jsonb,boolean,text)','EXECUTE')""",(role,role)).fetchone(),(False,role=="jw_app_dev"))
                with self.assertRaisesRegex(psycopg.Error,"NARUV_IMMUTABLE"):
                    c.execute("UPDATE naruv_finance.bills SET vat=vat")
                c.rollback()
                c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
            self.fin("pay","p1",{"amount":1,"reference":"x"},code=403)
            os.environ.pop("NARUV_FINANCE_REVIEW",None)
            self.assertFalse(finance.register_finance(FastAPI()))
            self.inspect(code=404)
            self.assertEqual(self.counts_fin(),(1,1))
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(Finance) if n.startswith("test_fin_")]
    if len(names)!=10:raise RuntimeError("FIN_CASE_COUNT_CHANGED")
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Finance(n) for n in names))
    if not result.wasSuccessful() or result.testsRun!=10 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:raise SystemExit(1)
    print("NARUV_FINANCE_PASS: 10 isolated PG17 internal billing and settlement cases; no actual payments.")
    return Finance
