"""Actual PG17 quote ID mapping, conversion and cumulative VAT acceptance."""
import concurrent.futures
import os
from pathlib import Path
import threading
import unittest
import psycopg
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app import naruv_quote_bundle_review as qb
from scripts import ci_v90_postgres_browser as fixture
ROOT=Path(__file__).resolve().parents[1]

def run_quote_bundle(base):
    class QuoteBundle(base):
        quote_bundle_active=True
        @classmethod
        def setUpClass(cls):
            if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("JW_ENV")!="dev":raise RuntimeError("CI_ONLY")
            cls.app=base.app;cls.ingest_dsn=base.ingest_dsn
            os.environ.update(NARUV_BUNDLE_REVIEW="ISOLATED_SYNTHETIC_ONLY",NARUV_QUOTE_BUNDLE_REVIEW="ISOLATED_SYNTHETIC_ONLY")
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("SELECT set_config('naruv.quote_bundle_ci','DISPOSABLE_ONLY',true)")
                c.execute((ROOT/"db/review/naruv_quote_bundle_ci.sql").read_text())
            if not qb.register_quote_bundle(cls.app):raise RuntimeError("QB_DISABLED")
        def setUp(self):
            super().setUp()
            os.environ["NARUV_QUOTE_BUNDLE_REVIEW"]="ISOLATED_SYNTHETIC_ONLY"
        def stock_seed(self,qty=5,who="A"):
            self.seed_items(who)
            src="source-a" if who=="A" else "source-b"
            for item in ("0001","0002"):
                self.check(self.call(f"/inventory/sources/{src}/items/{item}/movements/initial-{item}",
                    {"from_warehouse":None,"to_warehouse":"W1","quantity":qty},who),200)
        def quote(self,who="A",rid="quote-bundle-1",names=("Widget","Bolt"),qty=2,vat="taxable"):
            with TestClient(self.app,base_url="https://testserver") as c:
                c.cookies.set("__Host-jw_session",fixture.TOKENS[who])
                return self.check(c.post("/api/pg-stage/v92/quotes",json={"request_id":rid,"customer_id":"ci-customer-a" if who=="A" else "ci-customer-b",
                    "title":"Multi quote","vat_mode":vat,"items":[{"name":n,"quantity":qty,"unit_price":105} for n in names]},
                    headers={"origin":"https://testserver","x-csrf-token":fixture.CSRF[who]}),201)
        def preview_quote(self,qid,who="A",code=200):
            return self.check(self.call(f"/quote-bundles/quotes/{qid}/preview",who=who),code)
        def payload(self,qid,who="A"):
            p=self.preview_quote(qid,who)
            return {"quote_id":qid,"snapshot_sha256":p["snapshot_sha256"],
                "lines":[{"quote_line_id":x["quote_line_id"],"source_id":"source-a" if who=="A" else "source-b",
                    "item_id":"0001" if x["name"]=="Widget" else "0002","warehouse_id":"W1"} for x in p["snapshot"]["lines"]]}
        def convert(self,p,key="batch",rid="o1",who="A",code=200,extra=None):
            return self.check(self.call(f"/quote-bundles/bundles/{key}/convert/{rid}",p,who,extra),code)
        def test_qb_authoritative_full_flow_and_vat(self):
            self.stock_seed();q=self.quote();p=self.payload(q["quote_id"])
            p["lines"].reverse()
            o=self.convert(p);self.assertEqual({k:o[k] for k in ("subtotal","vat","total")},q["money"])
            self.assertEqual([x["result"]["item_id"] for x in o["lines"]],["0001","0002"])
            self.assertEqual(self.convert(p),o)
            self.fulfill();b1=self.bill_bundle()
            self.fulfill("f2");b2=self.bill_bundle("b2","f2")
            rows=[x["result"] for b in (b1,b2) for x in b["lines"]]
            self.assertEqual([x["vat"] for x in rows],[11,10,11,10])
            self.assertEqual(sum(x["total"] for x in rows),q["money"]["total"])
            self.assertEqual(sum(self.acct(x["bill_id"])["ar"] for x in rows),q["money"]["total"])
            self.assertEqual(self.quantities(),[3,3])
        def test_qb_stale_snapshot_and_retry(self):
            self.stock_seed();q=self.quote();p=self.payload(q["quote_id"])
            with psycopg.connect(fixture.root_dsn) as c:c.execute("UPDATE jw_dev.quote_items SET unit_price=205 WHERE id=%s",(p["lines"][0]["quote_line_id"],))
            self.convert(p,code=409);self.assertEqual(self.counts_bundle()[:3],(0,0,0))
            new=self.payload(q["quote_id"]);self.convert(new)
            self.convert(p,code=409)
        def test_qb_duplicate_conversion_concurrent(self):
            self.stock_seed();p=self.payload(self.quote()["quote_id"]);bar=threading.Barrier(2)
            def go(i):
                bar.wait(timeout=10)
                return self.call(f"/quote-bundles/bundles/b{i}/convert/r{i}",p)
            with concurrent.futures.ThreadPoolExecutor(2) as pool:rs=list(pool.map(go,range(2)))
            self.assertEqual(sorted(r.status_code for r in rs),[200,409])
            self.assertEqual(self.counts_bundle()[:3],(1,1,2))
        def test_qb_stock_failure_and_duplicate_item_reservation(self):
            self.stock_seed(qty=3);p=self.payload(self.quote(names=("Widget","Widget"))["quote_id"])
            self.convert(p,code=409);self.assertEqual(self.counts_bundle()[:3],(0,0,0))
            self.assertEqual(self.quantities(),[3,3])
            self.check(self.call("/inventory/sources/source-a/items/0001/movements/extra",{"from_warehouse":None,"to_warehouse":"W1","quantity":1}),200)
            self.convert(p);self.assertEqual(self.counts_bundle()[:3],(1,1,2))
        def test_qb_mapping_incomplete_duplicate_wrong_and_price(self):
            self.stock_seed();p=self.payload(self.quote()["quote_id"])
            self.convert(dict(p,lines=p["lines"][:1]),code=422)
            self.convert(dict(p,lines=[p["lines"][0],p["lines"][0]]),code=422)
            bad=[dict(x) for x in p["lines"]];bad[1]["item_id"]="0001"
            self.convert(dict(p,lines=bad),code=422)
            bad=[dict(x) for x in p["lines"]];bad[0]["unit_price"]=1
            self.convert(dict(p,lines=bad),code=422)
            self.assertEqual(self.counts_bundle()[:3],(0,0,0));self.convert(p)
        def test_qb_source_freeze(self):
            self.stock_seed();qid=self.quote()["quote_id"];p=self.payload(qid);self.convert(p)
            with psycopg.connect(fixture.root_dsn) as c:
                for sql,args in [
                    ("UPDATE jw_dev.quotes SET title='changed' WHERE id=%s",(qid,)),
                    ("UPDATE jw_dev.quote_items SET quantity=3 WHERE id=%s",(p["lines"][0]["quote_line_id"],)),
                    ("INSERT INTO jw_dev.quote_items VALUES('late',%s,'Widget',1,1,99)",(qid,)),
                    ("DELETE FROM jw_dev.quote_items WHERE id=%s",(p["lines"][0]["quote_line_id"],))]:
                    with self.assertRaisesRegex(psycopg.Error,"QB_SOURCE_FROZEN"):c.execute(sql,args)
                    c.rollback()
            self.assertEqual(self.preview_quote(qid)["snapshot_sha256"],p["snapshot_sha256"])
        def test_qb_tenant_scope_and_exempt(self):
            self.stock_seed();qid=self.quote(vat="exempt")["quote_id"];p=self.payload(qid)
            self.preview_quote(qid,"B",404);self.convert(p,who="B",code=404)
            self.convert(p);self.fulfill();b=self.bill_bundle()
            self.assertEqual([x["result"]["vat"] for x in b["lines"]],[0,0])
            self.look(who="B",code=404)
        def test_qb_cancel_partial_vat_and_private_children(self):
            self.stock_seed();p=self.payload(self.quote()["quote_id"]);o=self.convert(p)
            cid=o["lines"][0]["result"]["doc_id"]
            self.trade("fulfill","external",{"quantity":1},doc=cid,code=422)
            self.fulfill();self.cmd("cancel","c1",{});b=self.bill_bundle()
            self.assertEqual(sum(x["result"]["vat"] for x in b["lines"]),21)
            self.assertEqual(self.quantities(),[4,4])
        def test_qb_single_quote_ordinary_behavior(self):
            self.stock_seed();q=self.quote(names=("Widget",))
            self.preview_quote(q["quote_id"],code=422)
            self.trade("open","ordinary-o",{"kind":"sale","quote_id":q["quote_id"],"source_id":"source-a","item_id":"0001","warehouse_id":"W1"},doc="ordinary")
            self.trade("fulfill","ordinary-f",{"quantity":1},doc="ordinary")
            self.fin("bill","ordinary-b",{"doc_id":"ordinary","fulfillment_id":"ordinary-f"},bill="ordinary-b")
            self.assertEqual(self.acct("ordinary-b")["ar"],116)
        def test_qb_permissions_confirmation_default_off(self):
            self.stock_seed();p=self.payload(self.quote()["quote_id"])
            self.convert(p,extra={"x-naruv-confirm":"no"},code=422)
            with psycopg.connect(fixture.root_dsn) as c:
                for role in ("jw_app_dev","naruv_native_stage"):
                    self.assertEqual(c.execute("""SELECT has_table_privilege(%s,'naruv_quote_bundle.conversions','INSERT'),
                      has_function_privilege(%s,'naruv_quote_bundle.convert(text,text,jsonb,boolean,text)','EXECUTE'),
                      pg_has_role(%s,'naruv_quote_fence','MEMBER')""",(role,role,role)).fetchone(),(False,role=="jw_app_dev",False))
            self.convert(p)
            os.environ.pop("NARUV_QUOTE_BUNDLE_REVIEW",None)
            self.assertFalse(qb.register_quote_bundle(FastAPI()));self.preview_quote(p["quote_id"],code=404)
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(QuoteBundle) if n.startswith("test_qb_")]
    if len(names)!=10:raise RuntimeError("QB_CASE_COUNT_CHANGED")
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(QuoteBundle(n) for n in names))
    if not result.wasSuccessful() or result.testsRun!=10 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:raise SystemExit(1)
    print("NARUV_QUOTE_BUNDLE_PASS: 10 isolated PG17 multi-line quote conversion cases; no production writes.")
    return QuoteBundle
