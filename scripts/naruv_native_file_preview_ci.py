"""Actual PG17 native session validation + real CSV/XLSX parser + HTTPS-origin TestClient.

Existing V90/V92 disposable fixtures only; no actual deployment or real customer data.
"""
import io
import os
from pathlib import Path
import unittest

import psycopg
from fastapi import FastAPI
from fastapi.testclient import TestClient
from openpyxl import Workbook
from app import naruv_native_file_preview as mod
from app import pg_v90_integrated_entry as v90
from scripts import ci_v90_postgres_browser as fixture

ROOT=Path(__file__).resolve().parents[1]

class NativePreview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("JW_ENV")!="review":
            raise RuntimeError("CI_ONLY")
        fixture.require_disposable()
        fixture.bootstrap()
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute((ROOT/"db/review/ci_v92_quote_ephemeral.sql").read_text())
            c.execute("SELECT set_config('naruv.preview_ci','DISPOSABLE_ONLY',true)")
            c.execute((ROOT/"db/review/naruv_native_file_preview_ci.sql").read_text())
        os.environ.update(JW_ENV="dev", JW_PG_STAGE_V84="ISOLATED_DEV_READ_ONLY",
            JW_PG_AUTH_V85="ISOLATED_DEV_AUTH_ONLY", JW_PG_MESSENGER_V90="ISOLATED_DEV_MESSENGER_ONLY",
            JW_V90_ALLOWED_ORIGINS="https://testserver",NARUV_NATIVE_FILE_PREVIEW="ISOLATED_READ_ONLY")
        os.environ.pop("JW_INSECURE_LOCAL_DEV",None)
        v90.stage._connect=lambda:psycopg.connect(fixture.TRADE_DSN,connect_timeout=5)
        cls.app=FastAPI()
        assert mod.register_native_file_preview(cls.app)

    def setUp(self):
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("UPDATE jw_dev.users SET role='admin' WHERE id IN ('ci-ua','ci-ub','ci-uc')")
            c.execute("UPDATE jw_dev.sessions SET expires_at=(now()+interval '2 hours')::text")
        self.addCleanup(self.reset_gate)
    def reset_gate(self):
        os.environ["NARUV_NATIVE_FILE_PREVIEW"]="ISOLATED_READ_ONLY"
        os.environ["JW_ENV"]="dev"
    def req(self,who="A",source="source-a",entity="item",fmt="csv",raw=b"sku,item_name,unit\n001,Widget,EA\n",extra=None,query=""):
        with TestClient(self.app,base_url="https://testserver") as c:
            if who is not None:c.cookies.set("__Host-jw_session",fixture.TOKENS[who])
            headers={"origin":"https://testserver","x-csrf-token":fixture.CSRF[who or "A"],"content-type":mod.FORMATS[fmt]}
            if extra:headers.update(extra)
            return c.post(f"{mod.PREFIX}/sources/{source}/{entity}/{fmt}/preview"+query,content=raw,headers=headers)
    def test_csv_and_no_persistence(self):
        r=self.req()
        self.assertEqual(r.status_code,200,r.text)
        d=r.json()
        self.assertEqual(d["rows"],[{"source_item_id":"001","name":"Widget","unit":"EA"}])
        self.assertFalse(d["persisted"]);self.assertFalse(d["row_import_authorized"])
        self.assertEqual(r.headers["cache-control"],"no-store")
        self.assertEqual(self.req().json(),d)
    def test_xlsx(self):
        w=Workbook();w.active.append(["sku","item_name","unit"]);w.active.append(["001","Widget","EA"])
        f=io.BytesIO();w.save(f);w.close()
        r=self.req(fmt="xlsx",raw=f.getvalue())
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()["rows"][0]["source_item_id"],"001")
    def test_customer_field(self):
        r=self.req(entity="customer",raw=b"customer_id,customer_name,business_number\nC001,Sample,012-34-56789\n")
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()["rows"][0]["business_number"],"012-34-56789")
    def test_cross_tenant_and_inactive(self):
        self.assertEqual(self.req(who="B").status_code,404)
        self.assertEqual(self.req(source="source-b").status_code,404)
        self.assertEqual(self.req(source="inactive").status_code,404)
        self.assertEqual(self.req(who="B",source="source-b").status_code,200)
    def test_missing_expired_session(self):
        self.assertEqual(self.req(who=None).status_code,401)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("UPDATE jw_dev.sessions SET expires_at=(now()-interval '1 minute')::text WHERE id='A'")
        self.assertEqual(self.req().status_code,401)
    def test_role_origin_csrf(self):
        self.assertEqual(self.req(extra={"origin":"https://evil.test"}).status_code,403)
        self.assertEqual(self.req(extra={"x-csrf-token":"bad"}).status_code,403)
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
        self.assertEqual(self.req().status_code,403)
    def test_file_limits_and_scope(self):
        self.assertEqual(self.req(raw=b"x"*(mod.MAX_BYTES+1)).status_code,413)
        self.assertEqual(self.req(extra={"content-type":"application/json"}).status_code,415)
        self.assertEqual(self.req(extra={"content-encoding":"gzip"}).status_code,415)
        self.assertEqual(self.req(query="?org_id=ci-b").status_code,422)
        self.assertEqual(self.req(raw=b"sku,item_name\nEXISTING-A,Duplicate\n").status_code,422)
    def test_direct_role_rls_and_write_denial(self):
        import hashlib
        with psycopg.connect(fixture.TRADE_DSN) as c:
            c.execute("SET LOCAL ROLE jw_app_dev")
            c.execute("SELECT set_config('jw.session_hash',%s,true)",(hashlib.sha256(fixture.TOKENS["A"].encode()).hexdigest(),))
            self.assertEqual(c.execute("SELECT count(*) FROM jw_dev.naruv_review_sources WHERE org_id='ci-b'").fetchone()[0],0)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute("UPDATE jw_dev.naruv_review_sources SET active=false")
            c.rollback()
    def test_default_off_and_production_block(self):
        os.environ.pop("NARUV_NATIVE_FILE_PREVIEW",None)
        self.assertFalse(mod.register_native_file_preview(FastAPI()))
        self.assertEqual(self.req().status_code,404)
        os.environ["NARUV_NATIVE_FILE_PREVIEW"]="ISOLATED_READ_ONLY"
        os.environ["JW_ENV"]="production"
        self.assertEqual(self.req().status_code,404)
    def test_changed_revision_changes_binding(self):
        a=self.req().json()["stage_sha256"]
        try:
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("UPDATE jw_dev.naruv_review_sources SET revision='rev-new' WHERE org_id='ci-a' AND source_id='source-a' AND entity='item'")
            self.assertNotEqual(self.req().json()["stage_sha256"],a)
        finally:
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("UPDATE jw_dev.naruv_review_sources SET revision='rev-a' WHERE org_id='ci-a' AND source_id='source-a' AND entity='item'")
if __name__=="__main__":
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(NativePreview)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun!=10 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit(1)
    print("NARUV_NATIVE_PREVIEW_PASS: 10 actual PG17 HTTP origin-emulated cases; no real ERP write.")
