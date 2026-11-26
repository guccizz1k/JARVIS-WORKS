"""Actual disposable PG17 document / stock integration; no production acceptance."""
import concurrent.futures
import json
import os
from pathlib import Path
import threading
import unittest
import psycopg
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app import naruv_trade_review as trade
from scripts import ci_v90_postgres_browser as fixture

ROOT=Path(__file__).resolve().parents[1]
RAW=b"sku,item_name,unit\n0001,Widget,EA\n"

def run_trade(base):
    class Trade(base):
        bridge_active=True
        inventory_active=True
        trade_active=True
        @classmethod
        def setUpClass(cls):
            if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("JW_ENV")!="dev":
                raise RuntimeError("CI_ONLY")
            cls.app=base.app;cls.ingest_dsn=base.ingest_dsn
            os.environ.update(NARUV_NATIVE_WRITE_REVIEW="ISOLATED_SYNTHETIC_ONLY",
                NARUV_INVENTORY_REVIEW="ISOLATED_SYNTHETIC_ONLY",NARUV_TRADE_REVIEW="ISOLATED_SYNTHETIC_ONLY")
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("SELECT set_config('naruv.trade_ci','DISPOSABLE_ONLY',true)")
                c.execute((ROOT/"db/review/naruv_trade_ci.sql").read_text())
            if not trade.register_trade(cls.app):
                raise RuntimeError("TRADE_DISABLED")
        def setUp(self):
            super().setUp()
            os.environ.update(NARUV_INVENTORY_REVIEW="ISOLATED_SYNTHETIC_ONLY",NARUV_TRADE_REVIEW="ISOLATED_SYNTHETIC_ONLY")
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("DELETE FROM jw_dev.quote_items")
                c.execute("DELETE FROM jw_dev.quotes")
                c.execute("DELETE FROM jw_dev.audit_logs")
                c.execute("DELETE FROM jw_dev.customers WHERE id NOT IN ('ci-customer-a','ci-customer-b')")
        def seed(self,who="A"):
            src="source-a" if who=="A" else "source-b"
            d=self.stage("stage-1",RAW,src,"item","csv",who)
            self.check(self.approve(d,"stage-1",who),200)
            self.check(self.commit(d,"stage-1","import-1",who),200)
        def move(self,rid,frm,to,qty,who="A",code=200):
            src="source-a" if who=="A" else "source-b"
            return self.check(self.req(f"/inventory/sources/{src}/items/0001/movements/{rid}",who,
                json.dumps({"from_warehouse":frm,"to_warehouse":to,"quantity":qty}).encode(),
                extra={"content-type":"application/json"}),code)
        def stock(self,who="A"):
            src="source-a" if who=="A" else "source-b"
            return self.check(self.req(f"/inventory/sources/{src}/items/0001/stock/W1",who),200)["quantity"]
        def quote(self,rid="trade-quote-1",qty=6,name="Widget",multi=False,who="A"):
            p={"request_id":rid,"customer_id":"ci-customer-a" if who=="A" else "ci-customer-b",
               "title":"Review quote","vat_mode":"taxable",
               "items":[{"name":name,"quantity":qty,"unit_price":101}]}
            if multi:p["items"].append({"name":name,"quantity":1,"unit_price":50})
            with TestClient(self.app,base_url="https://testserver") as c:
                c.cookies.set("__Host-jw_session",fixture.TOKENS[who])
                return self.check(c.post("/api/pg-stage/v92/quotes",json=p,
                    headers={"origin":"https://testserver","x-csrf-token":fixture.CSRF[who]}),201)["quote_id"]
        def sale(self,qid,who="A"):
            return {"kind":"sale","quote_id":qid,"source_id":"source-a" if who=="A" else "source-b","item_id":"0001","warehouse_id":"W1"}
        def purchase(self,qty=10):
            return {"kind":"purchase","counterparty_id":"ci-customer-a","source_id":"source-a","item_id":"0001",
                    "warehouse_id":"W1","quantity":qty,"unit_price":101,"vat_mode":"taxable"}
        def cmd(self,doc,rid,action,payload,who="A",code=200,extra=None,raw=None):
            h={"content-type":"application/json","x-naruv-confirm":"yes"}
            if extra:h.update(extra)
            if raw is None:raw=json.dumps(payload).encode()
            return self.check(self.req(f"/trade/documents/{doc}/commands/{action}/{rid}",who,raw,extra=h),code)
        def inspect(self,doc,who="A",code=200):
            return self.check(self.req(f"/trade/documents/{doc}/inspect",who),code)
        def counts_trade(self):
            with psycopg.connect(fixture.root_dsn) as c:
                return c.execute("""SELECT (SELECT count(*) FROM naruv_trade.documents),
                  (SELECT count(*) FROM naruv_trade.events),(SELECT count(*) FROM naruv_inventory.movements)""").fetchone()
        def test_trade_quote_reservation_partial_delivery(self):
            self.seed();self.move("initial",None,"W1",10)
            q=self.quote();p=self.sale(q)
            opened=self.cmd("sale-1","open-1","open",p)
            self.assertEqual((opened["quantity"],opened["subtotal"],opened["vat"],opened["remaining"]),(6,606,61,6))
            self.assertFalse(opened["production_authorized"])
            self.assertEqual(self.stock(),10)
            self.move("manual-bad","W1",None,5,code=409)
            self.move("manual-ok","W1",None,4)
            first=self.cmd("sale-1","delivery-1","fulfill",{"quantity":2})
            self.assertEqual((first["state"],first["fulfilled"],first["remaining"],self.stock()),("PARTIAL",2,4,4))
            self.cmd("sale-1","over","fulfill",{"quantity":5},code=409)
            final=self.cmd("sale-1","delivery-2","fulfill",{"quantity":4})
            self.assertEqual((final["state"],final["remaining"],self.stock()),("DONE",0,0))
            self.assertEqual(self.cmd("sale-1","delivery-1","fulfill",{"quantity":2}),first)
            self.assertEqual(self.inspect("sale-1")["state"],"DONE")
            self.assertEqual(self.counts_trade(),(1,3,4))
        def test_trade_purchase_partial_receipt_cancel(self):
            self.seed();p=self.purchase()
            self.cmd("purchase-1","open-1","open",p)
            r=self.cmd("purchase-1","receive-1","fulfill",{"quantity":4})
            self.assertEqual((r["state"],self.stock()),("PARTIAL",4))
            self.cmd("purchase-1","receive-2","fulfill",{"quantity":7},code=409)
            c=self.cmd("purchase-1","cancel-1","cancel",{})
            self.assertEqual((c["state"],c["fulfilled"],c["remaining"],self.stock()),("CANCELLED",4,0,4))
            self.assertEqual(self.cmd("purchase-1","cancel-1","cancel",{}),c)
            self.cmd("purchase-1","new","fulfill",{"quantity":1},code=409)
        def test_trade_cancel_releases_only_remainder(self):
            self.seed();self.move("initial",None,"W1",10)
            q=self.quote();self.cmd("sale-1","open-1","open",self.sale(q))
            self.cmd("sale-1","deliver","fulfill",{"quantity":2})
            self.move("blocked","W1",None,5,code=409)
            self.cmd("sale-1","cancel","cancel",{})
            self.move("released","W1",None,8)
            self.assertEqual(self.stock(),0)
            self.assertEqual(self.inspect("sale-1")["fulfilled"],2)
        def test_trade_quote_scope_duplicate_and_unavailable_stock(self):
            self.seed();self.move("initial",None,"W1",10)
            q=self.quote(qty=11);self.cmd("too-much","o1","open",self.sale(q),code=409)
            wrong=self.quote("trade-quote-2",name="Wrong")
            self.cmd("wrong","o2","open",self.sale(wrong),code=422)
            multi=self.quote("trade-quote-3",multi=True)
            self.cmd("multi","o3","open",self.sale(multi),code=422)
            valid=self.quote("trade-quote-4",qty=2)
            self.cmd("sale-1","o4","open",self.sale(valid))
            self.cmd("duplicate","o5","open",self.sale(valid),code=409)
            self.assertEqual(self.counts_trade(),(1,1,1))
        def test_trade_tenant_and_counterparty_isolation(self):
            self.seed();self.seed("B")
            self.move("initial",None,"W1",10);self.move("initial",None,"W1",10,"B")
            q=self.quote();self.cmd("sale-1","o1","open",self.sale(q))
            self.inspect("sale-1","B",404)
            self.cmd("sale-1","f1","fulfill",{"quantity":1},"B",404)
            self.cmd("bad","o2","open",self.sale(q,"B"),"B",404)
            self.cmd("bad","o3","open",dict(self.purchase(),counterparty_id="ci-customer-b"),code=404)
            self.assertEqual((self.stock(),self.stock("B")),(10,10))
        def test_trade_concurrent_reservation(self):
            self.seed();self.move("initial",None,"W1",10)
            q1=self.quote();q2=self.quote("trade-quote-2")
            barrier=threading.Barrier(2)
            def go(i):
                barrier.wait(timeout=10)
                p=self.sale([q1,q2][i])
                return self.req(f"/trade/documents/sale-{i}/commands/open/open-{i}","A",json.dumps(p).encode(),
                    extra={"content-type":"application/json","x-naruv-confirm":"yes"})
            with concurrent.futures.ThreadPoolExecutor(2) as pool:out=list(pool.map(go,range(2)))
            self.assertEqual(sorted(r.status_code for r in out),[200,409])
            self.assertEqual(self.counts_trade(),(1,1,1))
        def test_trade_concurrent_receipt_and_idempotency(self):
            self.seed();self.cmd("purchase-1","o1","open",self.purchase(5))
            barrier=threading.Barrier(4)
            def go(i):
                barrier.wait(timeout=10)
                return self.cmd("purchase-1","same","fulfill",{"quantity":5})
            with concurrent.futures.ThreadPoolExecutor(4) as pool:out=list(pool.map(go,range(4)))
            self.assertTrue(all(r==out[0] for r in out));self.assertEqual(self.stock(),5)
            self.cmd("purchase-1","same","fulfill",{"quantity":4},code=409)
            self.assertEqual(self.counts_trade(),(1,2,1))
        def test_trade_event_failure_rolls_back_stock_and_document(self):
            self.seed();self.cmd("purchase-1","o1","open",self.purchase(5))
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("""CREATE FUNCTION naruv_trade.inject_failure() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'SYNTHETIC_TRADE_FAILURE'; END $$""")
                c.execute("CREATE TRIGGER inject_failure BEFORE INSERT ON naruv_trade.events FOR EACH ROW EXECUTE FUNCTION naruv_trade.inject_failure()")
            try:
                self.cmd("purchase-1","f1","fulfill",{"quantity":5},code=503)
                self.assertEqual(self.stock(),0);self.assertEqual(self.inspect("purchase-1")["state"],"OPEN")
                self.assertEqual(self.counts_trade(),(1,1,0))
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("DROP TRIGGER inject_failure ON naruv_trade.events")
                    c.execute("DROP FUNCTION naruv_trade.inject_failure()")
            self.cmd("purchase-1","f1","fulfill",{"quantity":5})
            self.assertEqual(self.stock(),5)
        def test_trade_private_movement_namespace_and_permissions(self):
            self.seed()
            self.move("doc:fake",None,"W1",1,code=422)
            with psycopg.connect(fixture.root_dsn) as c:
                for role in ("jw_app_dev","naruv_native_stage"):
                    self.assertEqual(c.execute("""SELECT has_table_privilege(%s,'naruv_trade.documents','UPDATE'),
                     has_table_privilege(%s,'naruv_trade.events','INSERT'),
                     has_function_privilege(%s,'naruv_inventory.post_movement_internal(text,text,text,text,text,bigint,text)','EXECUTE'),
                     has_function_privilege(%s,'naruv_trade.command(text,text,text,jsonb,boolean,text)','EXECUTE')""",
                     (role,role,role,role)).fetchone(),(False,False,False,role=="jw_app_dev"))
                self.assertEqual(c.execute("SELECT count(*) FROM pg_class WHERE relnamespace='naruv_trade'::regnamespace AND relkind='r' AND relrowsecurity AND relforcerowsecurity").fetchone()[0],2)
            self.assertEqual(self.stock(),0)
        def test_trade_input_revocation_and_default_off(self):
            self.seed()
            for raw in (b'{"quantity":1,"quantity":2}',b'{"quantity":1.5}',b'{"quantity":true}',b'{"quantity":NaN}'):
                self.cmd("p1","r1","fulfill",{},raw=raw,code=422)
            self.cmd("p1","o1","open",self.purchase(),extra={"x-naruv-confirm":"no"},code=422)
            self.cmd("p1","o1","open",self.purchase(),extra={"origin":"https://evil.test"},code=403)
            self.cmd("p1","o1","open",self.purchase(),raw=b"x"*4097,code=413)
            self.cmd("p1","o1","open",self.purchase())
            with psycopg.connect(fixture.root_dsn) as c:c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
            self.cmd("p1","r1","fulfill",{"quantity":1},code=403)
            os.environ.pop("NARUV_TRADE_REVIEW",None)
            self.assertFalse(trade.register_trade(FastAPI()))
            self.inspect("p1",code=404)
            self.assertEqual(self.counts_trade(),(1,1,0))
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(Trade) if n.startswith("test_trade_")]
    if len(names)!=10:raise RuntimeError("TRADE_CASE_COUNT_CHANGED")
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Trade(n) for n in names))
    if not result.wasSuccessful() or result.testsRun!=10 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit(1)
    print("NARUV_TRADE_PASS: 10 isolated PG17 trade, reservation and fulfillment cases; no production writes.")
