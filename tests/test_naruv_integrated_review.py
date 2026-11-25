"""Composition tests: actual FastAPI route constructors, no external DB."""
import os
import unittest
from unittest.mock import patch
from fastapi import FastAPI, APIRouter
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
        actual=set()
        for route in app.routes[len(before):]:actual.update(mod.route_key(route))
        self.assertEqual(actual,expected)
        self.assertEqual(len(actual),29)
        self.assertIn(("POST",mod.PREFIX+"/valuation/overview"),actual)
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
