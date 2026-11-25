"""Composition tests: actual FastAPI route constructors, no external DB."""
import os
import re
import unittest
from unittest.mock import patch
from fastapi import FastAPI, APIRouter
from fastapi.testclient import TestClient
from app import naruv_integrated_review as mod

FLAGS={
 "JW_ENV":"dev","JW_PG_STAGE_V84":"ISOLATED_DEV_READ_ONLY",
 "JW_PG_AUTH_V85":"ISOLATED_DEV_AUTH_ONLY","JW_PG_MESSENGER_V90":"ISOLATED_DEV_MESSENGER_ONLY",
 "JW_V90_ALLOWED_ORIGINS":"https://testserver","NARUV_NATIVE_FILE_PREVIEW":"ISOLATED_READ_ONLY",
 "NARUV_NATIVE_WRITE_REVIEW":mod.ACK,"NARUV_INVENTORY_REVIEW":mod.ACK,"NARUV_TRADE_REVIEW":mod.ACK,
 "NARUV_FINANCE_REVIEW":mod.ACK,"NARUV_ACCOUNTING_REVIEW":mod.ACK,"NARUV_BUNDLE_REVIEW":mod.ACK,
 "NARUV_QUOTE_BUNDLE_REVIEW":mod.ACK,"NARUV_PRODUCTION_REVIEW":mod.ACK,"NARUV_VALUATION_REVIEW":mod.ACK,
 mod.FLAG:mod.ACK,
}
class IntegratedReview(unittest.TestCase):
    def setUp(self):
        p=patch.dict(os.environ,FLAGS,clear=True);p.start();self.addCleanup(p.stop)
    def test_exact_route_manifest(self):
        app=FastAPI()
        @app.get("/legacy")
        def legacy():return {"existing":True}
        before=tuple(app.routes)
        self.assertTrue(mod.register_integrated_review(app))
        self.assertEqual(tuple(app.routes[:len(before)]),before)
        expected=set()
        for module in mod.MODULES:
            for route in module.create_router().routes:
                expected.update(mod.route_key(route))
        # Public schema enumerates effective paths on both eager and lazy FastAPI.
        actual={(method.upper(),re.sub(r"\{[^}:]+(?=[:}])","{parameter",path))
                for path,ops in app.openapi()["paths"].items() if path.startswith(mod.PREFIX+"/")
                for method in ops if method in {"post","get","put","delete","patch","head","options","trace"}}
        self.assertEqual(actual,expected)
        self.assertEqual(len(actual),29)
        self.assertIn(("POST",mod.PREFIX+"/valuation/overview"),actual)
        # Exercise every mounted path with the integration gate disabled;
        # a missing route must not pass simply because it returns HTTP 404.
        with TestClient(app,base_url="https://testserver") as c:
            with patch.dict(os.environ,{mod.FLAG:""}):
                for method,path in sorted(actual):
                    concrete=path.replace("{parameter}","probe")
                    r=c.request(method,concrete)
                    self.assertEqual((r.status_code,r.json().get("detail")),(404,"NARUV_INTEGRATION_DISABLED"),path)
            self.assertEqual(c.get("/legacy").json(),{"existing":True})
    def test_default_off_and_each_gate_is_required(self):
        for key in (mod.FLAG,*(k for k in FLAGS if k.startswith("NARUV_") and k!=mod.FLAG)):
            with self.subTest(key=key),patch.dict(os.environ,{key:""}):
                app=FastAPI();before=tuple(app.routes)
                self.assertFalse(mod.register_integrated_review(app))
                self.assertEqual(tuple(app.routes),before)
    def test_production_and_insecure_refused(self):
        for override in ({"JW_ENV":"production"},{"JW_ENV":"prod"},{"JW_INSECURE_LOCAL_DEV":"1"}):
            with patch.dict(os.environ,override):
                app=FastAPI();before=tuple(app.routes)
                self.assertFalse(mod.register_integrated_review(app));self.assertEqual(tuple(app.routes),before)
    def test_invalid_origin_no_partial_registration(self):
        app=FastAPI();before=tuple(app.routes)
        with patch.dict(os.environ,{"JW_V90_ALLOWED_ORIGINS":"http://testserver"}):
            with self.assertRaises(RuntimeError):mod.register_integrated_review(app)
        self.assertEqual(tuple(app.routes),before)
    def test_duplicate_mount_is_refused(self):
        app=FastAPI();self.assertTrue(mod.register_integrated_review(app));before=tuple(app.routes)
        with self.assertRaisesRegex(RuntimeError,"NAMESPACE_OCCUPIED"):mod.register_integrated_review(app)
        self.assertEqual(tuple(app.routes),before)
    def test_parameter_alias_collision(self):
        a=APIRouter(prefix=mod.PREFIX)
        @a.post("/things/{first}")
        def first(first:str):return {}
        @a.post("/things/{second}")
        def second(second:str):return {}
        app=FastAPI();before=tuple(app.routes)
        with patch.object(mod.preview,"create_router",return_value=a):
            with self.assertRaisesRegex(RuntimeError,"ROUTE_COLLISION"):mod.register_integrated_review(app)
        self.assertEqual(tuple(app.routes),before)
    def test_existing_catchall_is_refused(self):
        app=FastAPI()
        @app.get("/{path:path}")
        def fallback(path:str):return {}
        before=tuple(app.routes)
        with self.assertRaisesRegex(RuntimeError,"CATCH_ALL"):mod.register_integrated_review(app)
        self.assertEqual(tuple(app.routes),before)
    def test_runtime_gate_shutdown_blocks_all_mounted_routes(self):
        app=FastAPI();self.assertTrue(mod.register_integrated_review(app))
        with TestClient(app,base_url="https://testserver") as c:
            for key in (mod.FLAG,"NARUV_FINANCE_REVIEW"):
                with patch.dict(os.environ,{key:""}):
                    r=c.post(mod.PREFIX+"/valuation/overview")
                    self.assertEqual((r.status_code,r.json()["detail"]),(404,"NARUV_INTEGRATION_DISABLED"))
                    r=c.post(mod.PREFIX+"/sources/source-a/item/csv/preview")
                    self.assertEqual((r.status_code,r.json()["detail"]),(404,"NARUV_INTEGRATION_DISABLED"))
    def test_arbitrary_catchall_and_parent_mount_refused(self):
        for mounted in (False,True):
            app=FastAPI()
            if mounted:app.mount("/api",FastAPI())
            else:
                @app.post("/{remaining:path}")
                def fallback(remaining:str):return {}
            before=tuple(app.routes)
            with self.assertRaises(RuntimeError):mod.register_integrated_review(app)
            self.assertEqual(tuple(app.routes),before)
    def test_existing_included_namespace_is_refused_even_when_hidden(self):
        app=FastAPI()
        inner=APIRouter()
        @inner.post("/overview",include_in_schema=False)
        def hidden():return {}
        app.include_router(inner,prefix=mod.PREFIX+"/valuation")
        before=tuple(app.routes)
        with self.assertRaisesRegex(RuntimeError,"NAMESPACE_OCCUPIED|UNVERIFIED_ROUTE_TREE"):
            mod.register_integrated_review(app)
        self.assertEqual(tuple(app.routes),before)
    def test_openapi_cache_is_refreshed_after_success(self):
        app=FastAPI()
        self.assertNotIn(mod.PREFIX+"/valuation/overview",app.openapi()["paths"])
        self.assertTrue(mod.register_integrated_review(app))
        self.assertIn(mod.PREFIX+"/valuation/overview",app.openapi()["paths"])
    def test_full_manifest_and_runtime_fence(self):
        with patch.dict(os.environ,{mod.drafts.FLAG:mod.ACK}):
            app=FastAPI()
            self.assertTrue(mod.register_integrated_review(app,include_drafts=True))
            paths=app.openapi()["paths"]
            actual={p for p in paths if p.startswith(mod.PREFIX+"/")}
            self.assertEqual(len(actual),33)
            self.assertIn(mod.PREFIX+"/drafts/documents/{key}",actual)
            self.assertIn(mod.PREFIX+"/drafts/payroll/{worker}/{period}",actual)
            with TestClient(app,base_url="https://testserver") as c:
                with patch.dict(os.environ,{mod.drafts.FLAG:""}):
                    for path in sorted(actual):
                        path=re.sub(r"\{[^}]+\}","probe",path)
                        # Valid period to avoid path-specific validation as a false positive.
                        if "/drafts/payroll/" in path:path=path.rsplit("/",1)[0]+"/2026-11"
                        r=c.post(path)
                        self.assertEqual((r.status_code,r.json().get("detail")),(404,"NARUV_INTEGRATION_DISABLED"),path)
    def test_full_mode_requires_explicit_draft_gate_without_partial_mount(self):
        app=FastAPI();before=tuple(app.routes)
        self.assertFalse(mod.register_integrated_review(app,include_drafts=True))
        self.assertEqual(tuple(app.routes),before)
        with patch.dict(os.environ,{mod.drafts.FLAG:mod.ACK}):
            self.assertTrue(mod.register_integrated_review(app))
            self.assertNotIn(mod.PREFIX+"/drafts/documents/{key}",app.openapi()["paths"])
    def test_hr_full_manifest_and_gate(self):
        with patch.dict(os.environ,{mod.drafts.FLAG:mod.ACK,mod.hr.FLAG:mod.ACK}):
            app=FastAPI()
            self.assertTrue(mod.register_integrated_review(app,include_drafts=True,include_hr=True))
            paths={p for p in app.openapi()["paths"] if p.startswith(mod.PREFIX+"/")}
            self.assertEqual(len(paths),42)
            self.assertIn(mod.PREFIX+"/hr/workers/{worker}/periods/{period}/attendance/{rid}",paths)
            for suffix in ("/register/{rid}","/periods/{period}/create/{rid}","/inspect","/archive/{rid}","/periods/{period}/amend/{rid}"):
                self.assertIn(mod.PREFIX+"/hr/workers/{worker}"+suffix,paths)
            self.assertIn(mod.PREFIX+"/hr/workers/list",paths)
            with TestClient(app,base_url="https://testserver") as c:
                for key in (mod.FLAG,mod.drafts.FLAG,mod.hr.FLAG):
                    with patch.dict(os.environ,{key:""}):
                        for path in sorted(paths):
                            concrete=re.sub(r"\{[^}]+\}","probe",path)
                            if "/drafts/payroll/" in concrete:concrete=concrete.rsplit("/",1)[0]+"/2026-11"
                            r=c.post(concrete)
                            self.assertEqual((r.status_code,r.json().get("detail")),(404,"NARUV_INTEGRATION_DISABLED"),concrete)
    def test_hr_requires_drafts_and_explicit_gate(self):
        app=FastAPI();before=tuple(app.routes)
        with patch.dict(os.environ,{mod.hr.FLAG:mod.ACK,mod.drafts.FLAG:mod.ACK}):
            self.assertFalse(mod.register_integrated_review(app,include_hr=True))
            self.assertEqual(tuple(app.routes),before)
        with patch.dict(os.environ,{mod.drafts.FLAG:mod.ACK}):
            self.assertFalse(mod.register_integrated_review(app,include_drafts=True,include_hr=True))
            self.assertEqual(tuple(app.routes),before)
            self.assertTrue(mod.register_integrated_review(app,include_drafts=True))
            self.assertEqual(len([p for p in app.openapi()["paths"] if p.startswith(mod.PREFIX+"/")]),33)
    def test_dynamic_namespace_shadow_refused(self):
        app=FastAPI()
        @app.post("/api/{module}/{version}/workers/list")
        def shadow(module:str,version:str):return {}
        before=tuple(app.routes)
        with self.assertRaisesRegex(RuntimeError,"DYNAMIC_SHADOW"):mod.register_integrated_review(app)
        self.assertEqual(tuple(app.routes),before)
