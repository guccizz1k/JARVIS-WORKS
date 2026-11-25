"""Actual isolated PG17 inventory + existing native import acceptance."""
import concurrent.futures
import json
import os
from pathlib import Path
import threading
import unittest

import psycopg
from fastapi import FastAPI
from app import naruv_inventory_review as inventory
from scripts import ci_v90_postgres_browser as fixture

ROOT=Path(__file__).resolve().parents[1]
RAW=b"sku,item_name,unit\n0001,Widget,EA\n"

def run_inventory(base):
    class Inventory(base):
        bridge_active=True
        inventory_active=True
        @classmethod
        def setUpClass(cls):
            if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("JW_ENV")!="dev":
                raise RuntimeError("CI_ONLY")
            cls.app=base.app
            cls.ingest_dsn=base.ingest_dsn
            os.environ["NARUV_NATIVE_WRITE_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
            os.environ["NARUV_INVENTORY_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("SELECT set_config('naruv.inventory_ci','DISPOSABLE_ONLY',true)")
                c.execute((ROOT/"db/review/naruv_inventory_ci.sql").read_text())
            if not inventory.register_inventory(cls.app):
                raise RuntimeError("INVENTORY_ROUTE_DISABLED")
        def setUp(self):
            super().setUp()
            os.environ["NARUV_INVENTORY_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("DELETE FROM jw_dev.quote_items")
                c.execute("DELETE FROM jw_dev.quotes")
                c.execute("DELETE FROM jw_dev.audit_logs")
                c.execute("DELETE FROM jw_dev.customers WHERE id NOT IN ('ci-customer-a','ci-customer-b')")
        def seed(self,who="A",raw=RAW,sid="stage-1",fmt="csv"):
            source="source-a" if who=="A" else "source-b"
            d=self.stage(sid,raw,source,"item",fmt,who)
            self.check(self.approve(d,sid,who),200)
            self.check(self.commit(d,sid,"import-"+sid,who),200)
            return source
        def movement(self,rid,frm,to,qty,source="source-a",item="0001",who="A",extra=None,raw=None):
            h={"content-type":"application/json"}
            if extra:h.update(extra)
            if raw is None:
                raw=json.dumps({"from_warehouse":frm,"to_warehouse":to,"quantity":qty}).encode()
            return self.req(f"/inventory/sources/{source}/items/{item}/movements/{rid}",who,raw,extra=h)
        def stock(self,warehouse="W1",source="source-a",item="0001",who="A",code=200):
            return self.check(self.req(f"/inventory/sources/{source}/items/{item}/stock/{warehouse}",who),code)
        def move(self,rid,frm,to,qty,**kw):
            return self.check(self.movement(rid,frm,to,qty,**kw),200)
        def ledger(self):
            with psycopg.connect(fixture.root_dsn) as c:
                return c.execute("SELECT count(*),coalesce(sum(quantity),0) FROM naruv_inventory.movements").fetchone()
        def test_inventory_import_receipt_issue_transfer(self):
            self.seed()
            self.assertEqual(self.stock()["item_id"],"0001")
            self.assertEqual(self.stock()["unit"],"EA")
            self.assertEqual(self.stock()["quantity"],0)
            self.assertEqual(self.move("r1",None,"W1",20)["to_after"],20)
            self.assertEqual(self.move("r2","W1",None,3)["from_after"],17)
            t=self.move("r3","W1","W2",7)
            self.assertEqual((t["from_after"],t["to_after"]),(10,7))
            self.assertEqual((self.stock()["quantity"],self.stock("W2")["quantity"]),(10,7))
            self.assertFalse(t["production_authorized"])
            self.assertEqual(self.ledger(),(3,30))
        def test_inventory_retry_is_original_receipt(self):
            self.seed()
            r=self.move("r1",None,"W1",10)
            self.move("r2",None,"W1",2)
            self.assertEqual(self.move("r1",None,"W1",10),r)
            self.check(self.movement("r1",None,"W1",11),409)
            self.assertEqual(self.stock()["quantity"],12)
            self.assertEqual(self.ledger(),(2,12))
        def test_inventory_transfer_rollback_destination_first(self):
            self.seed();self.move("r1",None,"W2",2)
            r=self.movement("r2","W2","W1",3)
            self.assertEqual(self.check(r,409)["detail"],"INV_INSUFFICIENT")
            self.assertEqual((self.stock()["quantity"],self.stock("W2")["quantity"]),(0,2))
            self.assertEqual(self.ledger(),(1,2))
        def test_inventory_concurrent_issue_prevents_negative(self):
            self.seed();self.move("r1",None,"W1",10)
            b=threading.Barrier(2)
            def go(i):
                b.wait(timeout=10)
                return self.movement("issue-"+str(i),"W1",None,7)
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                rs=list(pool.map(go,range(2)))
            self.assertEqual(sorted(x.status_code for x in rs),[200,409])
            self.assertEqual(self.stock()["quantity"],3)
            self.assertEqual(self.ledger(),(2,17))
        def test_inventory_concurrent_retry_exactly_once(self):
            self.seed()
            b=threading.Barrier(4)
            def go(i):
                b.wait(timeout=10)
                return self.move("same",None,"W1",5)
            with concurrent.futures.ThreadPoolExecutor(4) as pool:
                rs=list(pool.map(go,range(4)))
            self.assertTrue(all(x==rs[0] for x in rs))
            self.assertEqual(self.stock()["quantity"],5)
            self.assertEqual(self.ledger(),(1,5))
        def test_inventory_tenants_and_unavailable_warehouse(self):
            self.seed();self.seed("B")
            self.move("same",None,"W1",8)
            self.move("same",None,"W1",3,source="source-b",who="B")
            self.stock(source="source-a",who="B",code=404)
            self.check(self.movement("bad",None,"W1",1,source="source-b"),404)
            self.check(self.movement("bad",None,"CLOSED",1),404)
            self.check(self.movement("bad",None,"unknown",1),404)
            self.assertEqual(self.stock()["quantity"],8)
            self.assertEqual(self.stock(source="source-b",who="B")["quantity"],3)
        def test_inventory_xlsx_and_missing_unit(self):
            import io
            from openpyxl import Workbook
            w=Workbook();w.active.append(["sku","item_name","unit"]);w.active.append(["0001","Excel item","EA"])
            f=io.BytesIO();w.save(f);w.close()
            self.seed(raw=f.getvalue(),fmt="xlsx")
            self.assertEqual(self.stock()["name"],"Excel item")
            self.move("r1",None,"W1",1)
            raw=b"sku,item_name\n0001,Without unit\n"
            self.seed("B",raw)
            self.assertEqual(self.check(self.movement("r1",None,"W1",1,source="source-b",who="B"),422)["detail"],"INV_UNIT_REQUIRED")
        def test_inventory_malformed_transport_and_revoked_role(self):
            self.seed()
            for raw in (b'{"from_warehouse":null,"to_warehouse":"W1","quantity":true}',
                        b'{"from_warehouse":null,"to_warehouse":"W1","quantity":1.5}',
                        b'{"from_warehouse":null,"to_warehouse":"W1","quantity":1,"quantity":2}',
                        b'{"from_warehouse":null,"to_warehouse":"W1","quantity":NaN}',
                        b'{"from_warehouse":null,"to_warehouse":"W1","quantity":0}'):
                self.check(self.movement("bad",None,"W1",1,raw=raw),422)
            self.check(self.movement("bad","W1","W1",1),422)
            self.check(self.movement("bad",None,"W1",1,raw=b"x"*4097),413)
            self.check(self.movement("bad",None,"W1",1,extra={"origin":"https://evil.test"}),403)
            self.check(self.movement("bad",None,"W1",1,extra={"x-csrf-token":"invalid"}),403)
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
            self.check(self.movement("bad",None,"W1",1),403)
            self.assertEqual(self.ledger(),(0,0))
        def test_inventory_ledger_failure_rolls_back_balances(self):
            self.seed()
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("""CREATE FUNCTION naruv_inventory.inject_failure() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'SYNTHETIC_LEDGER_FAILURE'; END $$""")
                c.execute("CREATE TRIGGER inject_failure BEFORE INSERT ON naruv_inventory.movements FOR EACH ROW EXECUTE FUNCTION naruv_inventory.inject_failure()")
            try:
                self.check(self.movement("r1",None,"W1",5),503)
                self.assertEqual(self.stock()["quantity"],0)
                self.assertEqual(self.ledger(),(0,0))
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("DROP TRIGGER inject_failure ON naruv_inventory.movements")
                    c.execute("DROP FUNCTION naruv_inventory.inject_failure()")
            self.move("r1",None,"W1",5)
        def test_inventory_role_isolation_and_default_off(self):
            self.seed();self.move("r1",None,"W1",1)
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT count(*) FROM pg_class WHERE relnamespace='naruv_inventory'::regnamespace AND relkind='r' AND relrowsecurity AND relforcerowsecurity").fetchone()[0],4)
                for role in ("jw_app_dev","naruv_native_stage"):
                    self.assertEqual(c.execute("""SELECT has_table_privilege(%s,'naruv_inventory.balances','UPDATE'),
                        has_table_privilege(%s,'naruv_inventory.movements','INSERT'),
                        has_function_privilege(%s,'naruv_inventory.post_movement(text,text,text,text,text,bigint,text)','EXECUTE')""",(role,role,role)).fetchone(),(False,False,role=="jw_app_dev"))
                with self.assertRaisesRegex(psycopg.Error,"NARUV_IMMUTABLE"):
                    c.execute("UPDATE naruv_inventory.movements SET quantity=quantity")
                c.rollback()
            os.environ.pop("NARUV_INVENTORY_REVIEW",None)
            self.assertFalse(inventory.register_inventory(FastAPI()))
            self.check(self.movement("r2",None,"W1",1),404)
            os.environ["NARUV_INVENTORY_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
            os.environ["JW_ENV"]="production"
            self.check(self.movement("r2",None,"W1",1),404)
            os.environ["JW_ENV"]="dev"
            self.assertEqual(self.ledger(),(1,1))
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(Inventory) if n.startswith("test_inventory_")]
    if len(names)!=10:raise RuntimeError("INVENTORY_CASE_COUNT_CHANGED")
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Inventory(n) for n in names))
    if not result.wasSuccessful() or result.testsRun!=10 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit(1)
    print("NARUV_INVENTORY_PASS: 10 isolated PG17 inventory and import cases, no production writes.")
