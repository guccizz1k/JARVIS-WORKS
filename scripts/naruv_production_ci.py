"""Real PG17 single-level BOM, reservations and atomic production."""
import concurrent.futures
import os
from pathlib import Path
import threading
import unittest
import psycopg
from fastapi import FastAPI
from app import naruv_production_review as production
from scripts import ci_v90_postgres_browser as fixture
ROOT=Path(__file__).resolve().parents[1]
RAW=b"sku,item_name,unit\n0001,Widget,EA\n0002,Bolt,EA\n0003,Assembly,EA\n"

def run_production(base):
    class Production(base):
        production_active=True
        @classmethod
        def setUpClass(cls):
            if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("JW_ENV")!="dev":raise RuntimeError("CI_ONLY")
            cls.app=base.app;cls.ingest_dsn=base.ingest_dsn
            os.environ.update(NARUV_QUOTE_BUNDLE_REVIEW="ISOLATED_SYNTHETIC_ONLY",NARUV_PRODUCTION_REVIEW="ISOLATED_SYNTHETIC_ONLY")
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("SELECT set_config('naruv.production_ci','DISPOSABLE_ONLY',true)")
                c.execute((ROOT/"db/review/naruv_production_ci.sql").read_text())
            if not production.register_production(cls.app):raise RuntimeError("PROD_DISABLED")
        def setUp(self):
            super().setUp()
            os.environ["NARUV_PRODUCTION_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
        def seed_prod(self,who="A",qty=10):
            src="source-a" if who=="A" else "source-b"
            d=self.stage("stage-1",RAW,src,"item","csv",who)
            self.check(self.approve(d,"stage-1",who),200);self.check(self.commit(d,"stage-1","import-1",who),200)
            for item in ("0001","0002"):
                self.manual("init-"+item,item,None,"W1",qty,who)
        def manual(self,rid,item,frm,to,qty,who="A",code=200):
            src="source-a" if who=="A" else "source-b"
            return self.check(self.call(f"/inventory/sources/{src}/items/{item}/movements/{rid}",{"from_warehouse":frm,"to_warehouse":to,"quantity":qty},who),code)
        def stocks(self,who="A"):
            src="source-a" if who=="A" else "source-b"
            return [self.check(self.req(f"/inventory/sources/{src}/items/{item}/stock/W1",who),200)["quantity"] for item in ("0001","0002","0003")]
        def prod(self,action,rid,payload,key="job",who="A",code=200,extra=None,raw=None):
            return self.check(self.call(f"/production/{key}/commands/{action}/{rid}",payload,who,extra,raw),code)
        def define(self,key="bom",rid="d1",product="0003",lines=None,who="A",code=200):
            if lines is None:lines=[{"material_id":"0001","per_unit":2},{"material_id":"0002","per_unit":1}]
            return self.prod("define",rid,{"source_id":"source-a" if who=="A" else "source-b","product_id":product,"lines":lines},key,who,code)
        def plan(self,qty=3,who="A",key="bom",code=200):
            return self.check(self.call(f"/production/boms/{key}/requirements",{"warehouse_id":"W1","quantity":qty},who),code)
        def open_job(self,qty=3,key="job",rid="o1",who="A",code=200):
            return self.prod("open",rid,{"bom_id":"bom","warehouse_id":"W1","quantity":qty},key,who,code)
        def complete(self,qty=1,rid="c1",who="A",code=200):
            return self.prod("complete",rid,{"quantity":qty},who=who,code=code)
        def inspect_job(self,who="A",code=200):
            return self.check(self.call("/production/job/inspect",who=who),code)
        def counts_prod(self):
            with psycopg.connect(fixture.root_dsn) as c:
                return c.execute("""SELECT (SELECT count(*) FROM naruv_production.boms),
                (SELECT count(*) FROM naruv_production.orders),(SELECT count(*) FROM naruv_production.events),
                (SELECT count(*) FROM naruv_inventory.movements)""").fetchone()
        def ready_prod(self):
            self.seed_prod();self.define();self.open_job()
        def test_prod_plan_partial_full_and_retry(self):
            self.seed_prod();self.define()
            p=self.plan();self.assertEqual([x["required"] for x in p["lines"]],[6,3])
            self.assertEqual([x["shortage"] for x in p["lines"]],[0,0])
            self.open_job();self.assertEqual(self.stocks(),[10,10,0])
            r=self.complete();self.assertEqual((r["state"],r["completed"],self.stocks()),("PARTIAL",1,[8,9,1]))
            self.assertEqual(self.complete(),r)
            self.complete(2,"c2");self.assertEqual(self.stocks(),[4,7,3])
            self.assertEqual(self.inspect_job()["state"],"DONE")
            self.assertEqual(self.counts_prod(),(1,1,4,8))
        def test_prod_shortage_and_atomic_open(self):
            self.seed_prod(qty=3);self.define()
            self.assertEqual([x["shortage"] for x in self.plan()["lines"]],[3,0])
            self.open_job(code=409);self.assertEqual(self.counts_prod(),(1,0,1,2))
            self.manual("more","0001",None,"W1",3)
            self.open_job();self.assertEqual(self.stocks(),[6,3,0])
        def test_prod_cycles_and_duplicate_components(self):
            self.seed_prod()
            self.define(product="0001",lines=[{"material_id":"0001","per_unit":1}],code=422)
            self.define()
            self.define("b2","d2",product="0001",lines=[{"material_id":"0003","per_unit":1}],code=422)
            self.define("b3","d3",product="0002",lines=[{"material_id":"0001","per_unit":1},{"material_id":"0001","per_unit":2}],code=409)
            self.assertEqual(self.counts_prod(),(1,0,1,2))
        def test_prod_sales_and_manual_reservations(self):
            self.ready_prod()
            self.manual("over","0001","W1",None,5,code=409)
            q=self.quote(names=("Widget",),qty=5)
            self.trade("open","sale-o",{"kind":"sale","quote_id":q["quote_id"],"source_id":"source-a","item_id":"0001","warehouse_id":"W1"},doc="sale",code=409)
            q2=self.quote(rid="quote-bundle-2",names=("Widget",),qty=4)
            self.trade("open","sale-o2",{"kind":"sale","quote_id":q2["quote_id"],"source_id":"source-a","item_id":"0001","warehouse_id":"W1"},doc="sale")
            self.complete()
            self.assertEqual(self.stocks(),[8,9,1])
            self.trade("fulfill","sale-f",{"quantity":4},doc="sale")
            self.assertEqual(self.stocks(),[4,9,1])
            self.complete(2,"c2");self.assertEqual(self.stocks(),[0,7,3])
        def test_prod_cancel_remaining_and_overcompletion(self):
            self.ready_prod();self.complete(4,code=409)
            self.complete();self.prod("cancel","x1",{})
            self.assertEqual(self.inspect_job()["completed"],1)
            self.assertEqual(self.inspect_job()["remaining"],0)
            self.complete(1,"c2",code=409)
            self.manual("release","0001","W1",None,8)
            self.assertEqual(self.stocks(),[0,9,1])
        def test_prod_output_failure_rolls_back_all_materials(self):
            self.ready_prod()
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("""CREATE FUNCTION naruv_production.fail_output() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.normalized_id='0003' THEN RAISE EXCEPTION 'SYNTHETIC_PROD_OUTPUT'; END IF; RETURN NEW; END $$""")
                c.execute("CREATE TRIGGER fail_output BEFORE INSERT ON naruv_inventory.movements FOR EACH ROW EXECUTE FUNCTION naruv_production.fail_output()")
            try:
                self.complete(code=503);self.assertEqual(self.stocks(),[10,10,0]);self.assertEqual(self.inspect_job()["completed"],0)
                self.assertEqual(self.counts_prod(),(1,1,2,2))
            finally:
                with psycopg.connect(fixture.root_dsn) as c:
                    c.execute("DROP TRIGGER fail_output ON naruv_inventory.movements")
                    c.execute("DROP FUNCTION naruv_production.fail_output()")
            self.complete();self.assertEqual(self.stocks(),[8,9,1])
        def test_prod_concurrent_open_and_exact_completion(self):
            self.seed_prod();self.define();bar=threading.Barrier(2)
            def go(i):
                bar.wait(timeout=10)
                return self.call(f"/production/job{i}/commands/open/o{i}",{"bom_id":"bom","warehouse_id":"W1","quantity":3})
            with concurrent.futures.ThreadPoolExecutor(2) as pool:rs=list(pool.map(go,range(2)))
            self.assertEqual(sorted(r.status_code for r in rs),[200,409])
            key=rs[0].json()["order_id"] if rs[0].status_code==200 else rs[1].json()["order_id"]
            bar=threading.Barrier(3)
            def finish(i):
                bar.wait(timeout=10);return self.prod("complete","same",{"quantity":1},key=key)
            with concurrent.futures.ThreadPoolExecutor(3) as pool:rows=list(pool.map(finish,range(3)))
            self.assertTrue(all(r==rows[0] for r in rows));self.assertEqual(self.stocks(),[8,9,1])
        def test_prod_tenant_isolation(self):
            self.ready_prod();self.plan(who="B",code=404);self.inspect_job("B",404)
            self.complete(who="B",code=404)
            self.seed_prod("B");self.define(who="B");self.open_job(who="B");self.complete(who="B")
            self.assertEqual(self.stocks("B"),[8,9,1]);self.assertEqual(self.stocks(),[10,10,0])
        def test_prod_permissions_private_namespace_and_default_off(self):
            self.ready_prod();r=self.complete()
            mid=r["movements"][0]["request_id"]
            self.manual(mid,"0001","W1",None,2,code=422)
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT count(*) FROM pg_class WHERE relnamespace='naruv_production'::regnamespace AND relkind='r' AND relrowsecurity AND relforcerowsecurity").fetchone()[0],4)
                for role in ("jw_app_dev","naruv_native_stage"):
                    self.assertEqual(c.execute("""SELECT has_table_privilege(%s,'naruv_production.orders','UPDATE'),
                     has_function_privilege(%s,'naruv_production.command(text,text,text,jsonb,boolean,text)','EXECUTE')""",(role,role)).fetchone(),(False,role=="jw_app_dev"))
                with self.assertRaisesRegex(psycopg.Error,"NARUV_IMMUTABLE"):
                    c.execute("UPDATE naruv_production.components SET per_unit=1")
                c.rollback()
            os.environ.pop("NARUV_PRODUCTION_REVIEW",None)
            self.assertFalse(production.register_production(FastAPI()));self.inspect_job(code=404)
        def test_prod_strict_input_and_role_revocation(self):
            self.ready_prod()
            for raw in (b'{"quantity":true}',b'{"quantity":1.5}',b'{"quantity":1,"quantity":2}',b'{"quantity":0}'):
                self.prod("complete","c1",{},raw=raw,code=422)
            self.prod("complete","c1",{"quantity":1},extra={"x-naruv-confirm":"no"},code=422)
            self.prod("complete","c1",{"quantity":1},raw=b"x"*16385,code=413)
            with psycopg.connect(fixture.root_dsn) as c:c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
            self.complete(code=403)
            self.assertEqual(self.counts_prod(),(1,1,2,2))
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(Production) if n.startswith("test_prod_")]
    if len(names)!=10:raise RuntimeError("PROD_CASE_COUNT_CHANGED")
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Production(n) for n in names))
    if not result.wasSuccessful() or result.testsRun!=10 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:raise SystemExit(1)
    print("NARUV_PRODUCTION_PASS: 10 isolated PG17 BOM and production quantity cases; no inventory valuation.")
