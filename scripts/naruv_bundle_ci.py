"""Disposable PG17 atomic multi-line purchase / grouped single-line sales."""
import concurrent.futures
import os
from pathlib import Path
import threading
import unittest
import psycopg
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app import naruv_bundle_review as bundle
from scripts import ci_v90_postgres_browser as fixture
ROOT=Path(__file__).resolve().parents[1]
RAW=b"sku,item_name,unit\n0001,Widget,EA\n0002,Bolt,EA\n"

def run_bundle(base):
    class Bundle(base):
        bundle_active=True
        @classmethod
        def setUpClass(cls):
            if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("JW_ENV")!="dev":raise RuntimeError("CI_ONLY")
            cls.app=base.app;cls.ingest_dsn=base.ingest_dsn
            os.environ["NARUV_BUNDLE_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("SELECT set_config('naruv.bundle_ci','DISPOSABLE_ONLY',true)")
                c.execute((ROOT/"db/review/naruv_bundle_ci.sql").read_text())
            if not bundle.register_bundle(cls.app):raise RuntimeError("BUNDLE_DISABLED")
        def setUp(self):
            super().setUp()
            os.environ["NARUV_BUNDLE_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
        def seed_items(self,who="A"):
            src="source-a" if who=="A" else "source-b"
            d=self.stage("stage-1",RAW,src,"item","csv",who)
            self.check(self.approve(d,"stage-1",who),200);self.check(self.commit(d,"stage-1","import-1",who),200)
        def purchase(self,who="A"):
            return {"lines":[{"kind":"purchase","counterparty_id":"ci-customer-a" if who=="A" else "ci-customer-b",
                "source_id":"source-a" if who=="A" else "source-b","item_id":item,"warehouse_id":"W1",
                "quantity":3,"unit_price":price,"vat_mode":"taxable"} for item,price in (("0001",105),("0002",205))]}
        def cmd(self,action,rid,payload,key="batch",who="A",code=200,extra=None,raw=None):
            return self.check(self.call(f"/bundles/{key}/commands/{action}/{rid}",payload,who,extra,raw),code)
        def look(self,key="batch",who="A",code=200):
            return self.check(self.call(f"/bundles/{key}/inspect",who=who),code)
        def quantities(self,who="A"):
            src="source-a" if who=="A" else "source-b"
            return [self.check(self.req(f"/inventory/sources/{src}/items/{i}/stock/W1",who),200)["quantity"] for i in ("0001","0002")]
        def open_purchase(self):
            self.seed_items();return self.cmd("open","o1",self.purchase())
        def fulfill(self,rid="f1",q1=1,q2=1,code=200):
            return self.cmd("fulfill",rid,{"lines":[{"line_no":1,"quantity":q1},{"line_no":2,"quantity":q2}]},code=code)
        def bill_bundle(self,rid="b1",source="f1",code=200):
            return self.cmd("bill",rid,{"source_request_id":source},code=code)
        def pay_bundle(self,rid="p1",amt1=10,amt2=20,code=200):
            return self.cmd("pay",rid,{"bill_request_id":"b1","lines":[{"line_no":1,"amount":amt1,"reference":rid+"-1"},{"line_no":2,"amount":amt2,"reference":rid+"-2"}]},code=code)
        def counts_bundle(self):
            with psycopg.connect(fixture.root_dsn) as c:
                return c.execute("""SELECT (SELECT count(*) FROM naruv_bundle.headers),
                 (SELECT count(*) FROM naruv_bundle.events),(SELECT count(*) FROM naruv_trade.documents),
                 (SELECT count(*) FROM naruv_inventory.movements),(SELECT count(*) FROM naruv_finance.bills),
                 (SELECT count(*) FROM naruv_accounting.journals)""").fetchone()
        def test_bundle_purchase_fulfill_bill_pay_reverse(self):
            o=self.open_purchase();self.assertEqual(len(o["lines"]),2)
            f=self.fulfill();self.assertEqual(self.quantities(),[1,1])
            b=self.bill_bundle()
            self.assertEqual([x["result"]["total"] for x in b["lines"]],[116,226])
            p=self.pay_bundle()
            self.assertEqual([x["result"]["outstanding"] for x in p["lines"]],[106,206])
            r=self.cmd("reverse","r1",{"source_request_id":"p1"})
            self.assertEqual([x["result"]["outstanding"] for x in r["lines"]],[116,226])
            self.assertEqual(self.fulfill(),f);self.assertEqual(self.bill_bundle(),b);self.assertEqual(self.pay_bundle(),p)
            for x in b["lines"]:
                a=self.acct(x["result"]["bill_id"]);self.assertEqual(a["debit"],a["credit"])
            self.assertEqual(self.counts_bundle(),(1,5,2,2,2,6))
        def test_bundle_open_second_line_failure_is_atomic(self):
            self.seed_items();p=self.purchase();p["lines"][1]["item_id"]="missing"
            self.cmd("open","o1",p,code=404)
            self.assertEqual(self.counts_bundle(),(0,0,0,0,0,0))
            self.cmd("open","o1",self.purchase());self.assertEqual(self.quantities(),[0,0])
        def test_bundle_fulfill_second_line_failure_is_atomic(self):
            self.open_purchase();self.fulfill(q2=4,code=409)
            self.assertEqual(self.quantities(),[0,0])
            self.assertEqual([x["result"]["fulfilled"] for x in self.look()["lines"]],[0,0])
            self.fulfill();self.assertEqual(self.quantities(),[1,1])
        def test_bundle_bill_second_line_failure_rolls_back_journals(self):
            self.open_purchase();self.fulfill()
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("""CREATE FUNCTION naruv_bundle.inject_bill_failure() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.subtotal=205 THEN RAISE EXCEPTION 'SYNTHETIC_BUNDLE_FAILURE'; END IF; RETURN NEW; END $$""")
                c.execute("CREATE TRIGGER inject_bill_failure BEFORE INSERT ON naruv_finance.bills FOR EACH ROW EXECUTE FUNCTION naruv_bundle.inject_bill_failure()")
            try:
                self.bill_bundle(code=503);self.assertEqual(self.counts_bundle(),(1,2,2,2,0,0))
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("DROP TRIGGER inject_bill_failure ON naruv_finance.bills")
                    c.execute("DROP FUNCTION naruv_bundle.inject_bill_failure()")
            self.bill_bundle();self.assertEqual(self.counts_bundle(),(1,3,2,2,2,2))
        def test_bundle_payment_second_line_failure_is_atomic(self):
            self.open_purchase();self.fulfill();b=self.bill_bundle()
            self.pay_bundle(amt2=227,code=409)
            self.assertEqual([self.acct(x["result"]["bill_id"])["outstanding"] for x in b["lines"]],[116,226])
            self.pay_bundle();self.assertEqual(self.counts_bundle(),(1,4,2,2,2,4))
        def test_bundle_cancel_remainder_and_duplicate_lines(self):
            self.open_purchase()
            self.cmd("fulfill","f1",{"lines":[{"line_no":1,"quantity":1},{"line_no":1,"quantity":1}]},code=422)
            self.fulfill();self.cmd("cancel","c1",{})
            self.assertEqual([x["result"]["state"] for x in self.look()["lines"]],["CANCELLED","CANCELLED"])
            self.fulfill("f2",code=409);self.bill_bundle()
            self.assertEqual(self.quantities(),[1,1])
        def test_bundle_concurrent_exact_retry_and_tenant_scope(self):
            self.open_purchase();bar=threading.Barrier(3)
            def go(i):
                bar.wait(timeout=10);return self.fulfill()
            with concurrent.futures.ThreadPoolExecutor(3) as pool:rs=list(pool.map(go,range(3)))
            self.assertTrue(all(r==rs[0] for r in rs));self.assertEqual(self.quantities(),[1,1])
            self.look(who="B",code=404)
            self.cmd("fulfill","f1",{"lines":[{"line_no":1,"quantity":1}]},who="B",code=404)
            self.seed_items("B");self.cmd("open","o1",self.purchase("B"),who="B")
            self.assertEqual(self.quantities("B"),[0,0])
        def test_bundle_grouped_sales_and_reservation(self):
            self.seed_items()
            for i in ("0001","0002"):
                self.check(self.call(f"/inventory/sources/source-a/items/{i}/movements/initial-{i}",{"from_warehouse":None,"to_warehouse":"W1","quantity":4}),200)
            lines=[]
            with TestClient(self.app,base_url="https://testserver") as c:
                c.cookies.set("__Host-jw_session",fixture.TOKENS["A"])
                for i,name in (("0001","Widget"),("0002","Bolt")):
                    q=self.check(c.post("/api/pg-stage/v92/quotes",json={"request_id":"quote-"+i,"customer_id":"ci-customer-a","title":"sale","vat_mode":"taxable","items":[{"name":name,"quantity":3,"unit_price":105}]},
                      headers={"origin":"https://testserver","x-csrf-token":fixture.CSRF["A"]}),201)["quote_id"]
                    lines.append({"kind":"sale","quote_id":q,"source_id":"source-a","item_id":i,"warehouse_id":"W1"})
            self.cmd("open","o1",{"lines":lines})
            self.check(self.call("/inventory/sources/source-a/items/0002/movements/over",{"from_warehouse":"W1","to_warehouse":None,"quantity":2}),409)
            self.fulfill();self.assertEqual(self.quantities(),[3,3]);b=self.bill_bundle()
            self.assertEqual([self.acct(x["result"]["bill_id"])["ar"] for x in b["lines"]],[116,116])
        def test_bundle_private_children_and_ordinary_api(self):
            o=self.open_purchase();cid=o["lines"][0]["result"]["doc_id"]
            self.trade("fulfill","external",{"quantity":1},doc=cid,code=422)
            self.fulfill();b=self.bill_bundle()
            self.fin("pay","external",{"amount":1,"reference":"ext"},bill=b["lines"][0]["result"]["bill_id"],code=422)
            self.fin("bill","external",{"doc_id":cid,"fulfillment_id":"other"},bill="ordinary",code=422)
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT count(*) FROM pg_class WHERE relnamespace='naruv_bundle'::regnamespace AND relkind='r' AND relrowsecurity AND relforcerowsecurity").fetchone()[0],3)
                for role in ("jw_app_dev","naruv_native_stage"):
                    self.assertEqual(c.execute("""SELECT has_function_privilege(%s,'naruv_trade.command_bundle_internal(text,text,text,jsonb,boolean,text)','EXECUTE'),
                     has_function_privilege(%s,'naruv_finance.command_bundle_internal(text,text,text,jsonb,boolean,text)','EXECUTE'),
                     has_table_privilege(%s,'naruv_bundle.lines','UPDATE')""",(role,role,role)).fetchone(),(False,False,False))
            self.trade("open","normal-o",self.purchase()["lines"][0],doc="normal")
            self.trade("fulfill","normal-f",{"quantity":1},doc="normal")
            self.fin("bill","normal-b",{"doc_id":"normal","fulfillment_id":"normal-f"},bill="normal-b")
            self.assertEqual(self.acct("normal-b")["ap"],116)
        def test_bundle_strict_input_mixed_scope_and_default_off(self):
            self.seed_items();p=self.purchase();p["lines"][1]["vat_mode"]="exempt"
            self.cmd("open","o1",p,code=422);self.assertEqual(self.counts_bundle(),(0,0,0,0,0,0))
            self.cmd("open","o1",self.purchase(),extra={"x-naruv-confirm":"no"},code=422)
            self.cmd("open","o1",{},raw=b'{"lines":[{"quantity":true}]}',code=422)
            self.cmd("open","o1",self.purchase(),raw=b"x"*16385,code=413)
            self.cmd("open","o1",self.purchase())
            os.environ.pop("NARUV_BUNDLE_REVIEW",None)
            self.assertFalse(bundle.register_bundle(FastAPI()));self.look(code=404)
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(Bundle) if n.startswith("test_bundle_")]
    if len(names)!=10:raise RuntimeError("BUNDLE_CASE_COUNT_CHANGED")
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Bundle(n) for n in names))
    if not result.wasSuccessful() or result.testsRun!=10 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:raise SystemExit(1)
    print("NARUV_BUNDLE_PASS: 10 isolated PG17 atomic batch cases; no production writes.")
