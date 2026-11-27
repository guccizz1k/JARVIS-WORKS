"""Targeted real PG17 tests; run only via existing disposable preview fixture."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import patch
import psycopg
from app import naruv_native_file_preview as mod
from scripts.naruv_native_file_preview_ci import NativePreview, fixture

class PreviewRecheck(NativePreview):
    def paused(self,change,expected):
        entered=Event()
        release=Event()
        parser=mod.prepare_file_stage
        def hold(*a,**kw):
            entered.set()
            if not release.wait(15):raise RuntimeError("PREVIEW_PARSE_TIMEOUT")
            return parser(*a,**kw)
        with patch.object(mod,"prepare_file_stage",hold), ThreadPoolExecutor(max_workers=2) as pool:
            request=pool.submit(self.req)
            try:
                self.assertTrue(entered.wait(8))
                def mutate():
                    with psycopg.connect(fixture.root_dsn) as c:
                        c.execute("SET LOCAL lock_timeout='1s'")
                        change(c)
                pool.submit(mutate).result(timeout=5)
                self.assertFalse(request.done())
            finally:
                release.set()
            response=request.result(timeout=15)
        self.assertEqual(response.status_code,expected,response.text)
        self.assertNotIn("rows",response.json())
        return response
    def test_preview_recheck_revoked_role(self):
        try:
            self.paused(lambda c:c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'"),403)
        finally:
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("UPDATE jw_dev.users SET role='admin' WHERE id='ci-ua'")
    def test_preview_recheck_source_revision(self):
        try:
            self.paused(lambda c:c.execute("UPDATE jw_dev.naruv_review_sources SET revision='rev-paused' WHERE org_id='ci-a' AND source_id='source-a' AND entity='item'"),409)
        finally:
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("UPDATE jw_dev.naruv_review_sources SET revision='rev-a' WHERE org_id='ci-a' AND source_id='source-a' AND entity='item'")
    def test_preview_recheck_source_deactivated(self):
        try:
            self.paused(lambda c:c.execute("UPDATE jw_dev.naruv_review_sources SET active=false WHERE org_id='ci-a' AND source_id='source-a' AND entity='item'"),404)
        finally:
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("UPDATE jw_dev.naruv_review_sources SET active=true WHERE org_id='ci-a' AND source_id='source-a' AND entity='item'")
    def test_preview_recheck_gate_closed(self):
        import os
        entered=Event()
        release=Event()
        parser=mod.prepare_file_stage
        def hold(*a,**kw):
            entered.set()
            if not release.wait(15):raise RuntimeError("PREVIEW_PARSE_TIMEOUT")
            return parser(*a,**kw)
        with patch.object(mod,"prepare_file_stage",hold),ThreadPoolExecutor(max_workers=1) as pool:
            request=pool.submit(self.req)
            try:
                self.assertTrue(entered.wait(8))
                os.environ["NARUV_NATIVE_FILE_PREVIEW"]="OFF"
            finally:release.set()
            response=request.result(timeout=15)
        self.assertEqual(response.status_code,404,response.text)
        self.assertNotIn("rows",response.json())

if __name__=="__main__":
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(PreviewRecheck)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun!=14 or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit(1)
    print("PREVIEW_SHORT_TX_PG17_PASS 14 cases; scope drift and role revocation denied")
