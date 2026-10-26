import sqlite3
import unittest
from scripts.jw_jteam_integrated_gate import setup,reserve,mark_uncertain,validate_receipts,ab_report,preflight,TOOLS,ROLES
class IntegratedGateTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:",isolation_level=None)
        self.addCleanup(self.db.close)
        setup(self.db)
    def test_reserve_idempotent(self):
        self.assertEqual(reserve(self.db,"2026-10","req",2000),"RESERVED")
        self.assertEqual(reserve(self.db,"2026-10","req",2000),"RESERVED")
        self.assertEqual(self.db.execute("SELECT reserved_krw FROM budget").fetchone()[0],2000)
    def test_cap(self):
        reserve(self.db,"2026-10","a",49000)
        with self.assertRaises(PermissionError):reserve(self.db,"2026-10","b",2000)
    def test_request_id_conflict(self):
        reserve(self.db,"2026-10","a",100)
        with self.assertRaises(ValueError):reserve(self.db,"2026-10","a",200)
    def test_uncertain_reservation_not_released(self):
        reserve(self.db,"2026-10","a",50000)
        mark_uncertain(self.db,"a")
        with self.assertRaises(PermissionError):reserve(self.db,"2026-10","b",1)
    def test_fake_receipts_rejected(self):
        self.assertIn("NO_RECEIPTS",validate_receipts(None))
    def test_same_provider_id_rejected(self):
        data={"sha":"a"*40,"independent_test_run_id":"test","roles":[{"role":r,"provider_response_id":"same","sha":"a"*40,"review_status":"PASS"} for r in ROLES]}
        self.assertIn("SESSION_EVIDENCE",validate_receipts(data))
    def test_ab_requires_real_measurements(self):
        self.assertTrue(all(v=="NOT_RUN" for v in ab_report([]).values()))
    def test_ab_detects_regression(self):
        rows=[{"tool":"Ruff","kind":"MEASURED","baseline_run_id":"x","candidate_run_id":"y","baseline_errors":1,"candidate_errors":2}]
        self.assertEqual(ab_report(rows)["Ruff"],"REGRESSED")
    def test_release_always_blocked(self):
        self.assertEqual(preflight()["release"],"BLOCKED")
if __name__=="__main__":unittest.main()
