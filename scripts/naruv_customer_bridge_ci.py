"""CI-only bridge acceptance: existing customer read and quote APIs, real PG17.

Run after the original NativeWrite suite on the same disposable CI service.
No production migration, no real ERP data, no deployed browser/TLS acceptance.
"""
import concurrent.futures
import threading
import unittest
from pathlib import Path

import psycopg
from fastapi.testclient import TestClient
from app import pg_api_v84 as customers
from app import pg_quote_api_v92 as quote
from app import pg_quote_read_v93 as reader
from scripts import ci_v90_postgres_browser as fixture

ROOT=Path(__file__).resolve().parents[1]
CUSTOMER=b"customer_id,customer_name,business_number\n0001,Imported Company,012-34-56789\n"

def run_bridge(base):
    class CustomerBridge(base):
        bridge_active=True
        @classmethod
        def setUpClass(cls):
            import os
            if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("JW_ENV")!="dev":
                raise RuntimeError("CI_ONLY")
            cls.app=base.app
            cls.ingest_dsn=base.ingest_dsn
            os.environ["NARUV_NATIVE_WRITE_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
            os.environ["JW_PG_QUOTE_V92"]="ISOLATED_DEV_QUOTE_V92"
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("SELECT set_config('naruv.customer_bridge_ci','DISPOSABLE_ONLY',true)")
                c.execute((ROOT/"db/review/naruv_customer_bridge_ci.sql").read_text())
                c.execute("""INSERT INTO jw_dev.naruv_review_sources
                  VALUES('ci-a','source-a2','customer','rev-a',ARRAY[]::text[],true),
                  ('ci-b','source-b','customer','rev-b',ARRAY[]::text[],true)""")
            if not customers.register_stage_api(cls.app) or not quote.register_v92_quote_api(cls.app) or not reader.register_v93_quote_reader(cls.app):
                raise RuntimeError("LEGACY_ROUTE_REGISTRATION_FAILED")
        def setUp(self):
            super().setUp()
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("DELETE FROM jw_dev.quote_items")
                c.execute("DELETE FROM jw_dev.quotes")
                c.execute("DELETE FROM jw_dev.audit_logs")
                c.execute("DELETE FROM jw_dev.customers WHERE id NOT IN ('ci-customer-a','ci-customer-b')")
        def customer_stage(self,sid="stage-1",raw=CUSTOMER,source="source-a",who="A"):
            d=self.stage(sid,raw,source,"customer","csv",who)
            self.check(self.approve(d,sid,who),200)
            return d
        def client(self,who):
            c=TestClient(self.app,base_url="https://testserver")
            c.cookies.set("__Host-jw_session",fixture.TOKENS[who])
            return c
        def list_customers(self,who):
            with self.client(who) as c:
                return self.check(c.get("/api/pg-stage/v84/customers"),200)
        def bridge_counts(self):
            with psycopg.connect(fixture.root_dsn) as c:
                return c.execute("""SELECT
                  (SELECT count(*) FROM naruv_customer_bridge.crosswalk),
                  (SELECT count(*) FROM jw_dev.customers WHERE id NOT IN ('ci-customer-a','ci-customer-b')),
                  (SELECT count(*) FROM jw_dev.audit_logs WHERE entity_type='customer'),
                  (SELECT count(*) FROM naruv_native_review.records),
                  (SELECT count(*) FROM naruv_native_review.receipts)""").fetchone()
        def seed_customer(self,name,number):
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("""INSERT INTO jw_dev.customers(id,org_id,name,business_number,created_at)
                 VALUES('ci-existing-extra','ci-a',%s,%s,now()::text)""",(name,number))
        def test_bridge_existing_customer_read_and_quote(self):
            d=self.customer_stage()
            receipt=self.check(self.commit(d),200)
            self.assertFalse(receipt["row_import_authorized"])
            a=self.list_customers("A");b=self.list_customers("B")
            imported=[x for x in a if x["name"]=="Imported Company"]
            self.assertEqual(len(imported),1)
            cid=imported[0]["id"]
            self.assertRegex(cid,r"^[a-f0-9]{32}$")
            self.assertEqual(imported[0]["business_number"],"012-34-56789")
            self.assertFalse(any(x["id"]==cid for x in b))
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT source_customer_id,normalized_id,customer_id FROM naruv_customer_bridge.crosswalk").fetchone(),("0001","0001",cid))
                a=c.execute("SELECT org_id,actor_id,entity_id,action,detail::jsonb FROM jw_dev.audit_logs WHERE entity_type='customer'").fetchone()
                self.assertEqual(a[:4],("ci-a","ci-ua",cid,"create"))
                self.assertEqual(a[4]["source_customer_id"],"0001")
            payload={"request_id":"bridge-quote-001","customer_id":cid,"title":"Imported customer quote",
                     "vat_mode":"taxable","items":[{"name":"A","quantity":3,"unit_price":101},{"name":"B","quantity":2,"unit_price":503}]}
            with self.client("A") as c:
                headers={"origin":"https://testserver","X-CSRF-Token":fixture.CSRF["A"]}
                first=self.check(c.post("/api/pg-stage/v92/quotes",json=payload,headers=headers),201)
                again=self.check(c.post("/api/pg-stage/v92/quotes",json=payload,headers=headers),200)
                self.assertEqual(first["quote_id"],again["quote_id"])
                self.assertEqual(first["money"],{"subtotal":1309,"vat":131,"total":1440})
                got=self.check(c.get("/api/pg-stage/v92/quotes/"+first["quote_id"]),200)
                self.assertEqual(got["customer_id"],cid);self.assertEqual(got["customer_name"],"Imported Company")
                self.assertEqual(got["money"],first["money"])
            with self.client("B") as c:
                self.assertEqual(c.get("/api/pg-stage/v92/quotes/"+first["quote_id"]).status_code,404)
                self.check(c.post("/api/pg-stage/v92/quotes",json=payload,
                    headers={"origin":"https://testserver","X-CSRF-Token":fixture.CSRF["B"]}),404)
            self.assertEqual(self.bridge_counts(),(1,1,1,1,1))
        def test_bridge_retry_exactly_once(self):
            d=self.customer_stage();first=self.check(self.commit(d),200)
            self.assertEqual(self.check(self.commit(d),200),first)
            self.assertEqual(self.check(self.req("/stages/stage-1/receipt/request-1"),200),first)
            self.check(self.commit(d,rid="changed"),409)
            self.assertEqual(self.bridge_counts(),(1,1,1,1,1))
        def test_bridge_business_number_collision_preserves_original(self):
            self.seed_customer("Existing Legal Entity","0123456789")
            d=self.customer_stage();self.check(self.commit(d),409)
            self.assertEqual(self.bridge_counts(),(0,1,0,0,0))
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT name,business_number FROM jw_dev.customers WHERE id='ci-existing-extra'").fetchone(),("Existing Legal Entity","0123456789"))
                self.assertEqual(c.execute("SELECT status FROM naruv_native_review.approvals").fetchone()[0],"APPROVED")
        def test_bridge_name_collision_without_number(self):
            self.seed_customer("IMPORTED COMPANY","")
            d=self.customer_stage(raw=b"customer_id,customer_name\n0001,Imported Company\n")
            self.check(self.commit(d),409)
            self.assertEqual(self.bridge_counts(),(0,1,0,0,0))
        def test_bridge_mid_batch_collision_rolls_back_everything(self):
            self.seed_customer("Existing Legal Entity","0123456789")
            raw=b"customer_id,customer_name,business_number\n0001,First Company,999-99-99999\n0002,Second Company,012-34-56789\n"
            d=self.customer_stage(raw=raw);self.check(self.commit(d),409)
            self.assertEqual(self.bridge_counts(),(0,1,0,0,0))
            with psycopg.connect(fixture.root_dsn) as c:
                self.assertEqual(c.execute("SELECT revision,existing_ids FROM jw_dev.naruv_review_sources WHERE org_id='ci-a' AND source_id='source-a' AND entity='customer'").fetchone(),("rev-a",[]))
        def test_bridge_same_number_cross_tenant_isolated(self):
            a=self.customer_stage();b=self.customer_stage("stage-1",source="source-b",who="B")
            self.check(self.commit(a),200);self.check(self.commit(b,who="B"),200)
            aa=[x["id"] for x in self.list_customers("A") if x["name"]=="Imported Company"]
            bb=[x["id"] for x in self.list_customers("B") if x["name"]=="Imported Company"]
            self.assertEqual(len(aa),1);self.assertEqual(len(bb),1);self.assertNotEqual(aa,bb)
            self.assertEqual(self.bridge_counts(),(2,2,2,2,2))
        def test_bridge_concurrent_cross_source_collision(self):
            d=self.customer_stage();q=self.customer_stage("stage-2",CUSTOMER.replace(b"Imported Company",b"Other Company"),"source-a2")
            barrier=threading.Barrier(2)
            def run(args):
                barrier.wait(timeout=10)
                value,sid,rid=args
                return self.commit(value,sid,rid)
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                result=list(pool.map(run,[(d,"stage-1","r1"),(q,"stage-2","r2")]))
            self.assertEqual(sorted(x.status_code for x in result),[200,409])
            self.assertEqual(self.bridge_counts(),(1,1,1,1,1))
        def test_bridge_item_unchanged_and_private_mapping(self):
            d=self.stage();self.check(self.approve(d),200);self.check(self.commit(d),200)
            self.assertEqual(self.bridge_counts(),(0,0,0,1,1))
            q=self.customer_stage("stage-2");self.check(self.commit(q,"stage-2","r2"),200)
            with psycopg.connect(fixture.root_dsn) as c:
                with self.assertRaisesRegex(psycopg.Error,"NARUV_IMMUTABLE"):
                    c.execute("UPDATE naruv_customer_bridge.crosswalk SET customer_id=customer_id")
                c.rollback()
                self.assertEqual(c.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='naruv_customer_bridge.crosswalk'::regclass").fetchone(),(True,True))
                for role in ("jw_app_dev","naruv_native_stage"):
                    self.assertEqual(c.execute("SELECT has_schema_privilege(%s,'naruv_customer_bridge','USAGE'),has_column_privilege(%s,'jw_dev.customers','id','INSERT')",(role,role)).fetchone(),(False,False))
            self.assertEqual(self.bridge_counts(),(1,1,1,2,2))
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(CustomerBridge) if n.startswith("test_bridge_")]
    if len(names)!=8:
        raise RuntimeError("BRIDGE_TEST_COUNT_CHANGED")
    suite=unittest.TestSuite(CustomerBridge(n) for n in names)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun!=8 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit(1)
    print("NARUV_CUSTOMER_BRIDGE_PASS: 8 actual PG17 customer/crosswalk/quote cases, no production writes.")
