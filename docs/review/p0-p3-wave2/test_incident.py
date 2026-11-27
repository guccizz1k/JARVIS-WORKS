"""Offline policy boundaries only; no operational authorization."""
import importlib.util
from pathlib import Path
from datetime import datetime,timezone,timedelta
import unittest
spec=importlib.util.spec_from_file_location("incident",Path(__file__).with_name("incident-evidence.py"))
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class IncidentTests(unittest.TestCase):
    def args(self):
        now=datetime(2026,11,27,12,tzinfo=timezone.utc)
        return dict(expected_source="a"*40,observed_source="a"*40,observed_at=now,now=now,
            window_seconds=60,request_count=100,error_count=1,p95_ms=250,health_ok=True,
            policy=dict(max_age_seconds=60,minimum_requests=100,max_error_bps=100,max_p95_ms=250,window_seconds=60))
    def test_boundary(self):
        r=mod.assess(**self.args())
        self.assertEqual(r["status"],"OBSERVATION_WITHIN_SUPPLIED_LIMITS")
        self.assertTrue(all(r[k] is False for k in ("provider_verified","automatic_rollback","rollback_authorized","production_authorized")))
    def test_incident(self):
        a=self.args();a.update(error_count=2,p95_ms=251,health_ok=False)
        self.assertEqual(mod.assess(**a)["reasons"],["HEALTH_FAILURE","ERROR_RATE_EXCEEDED","LATENCY_EXCEEDED"])
    def test_stale_future_and_insufficient(self):
        for delta in (-61,1):
            a=self.args();a["observed_at"]+=timedelta(seconds=delta)
            self.assertEqual(mod.assess(**a)["status"],"BLOCKED_EVIDENCE")
        for patch in (dict(request_count=99),dict(p95_ms=None),dict(observed_source="b"*40),dict(window_seconds=59)):
            self.assertEqual(mod.assess(**dict(self.args(),**patch))["status"],"BLOCKED_EVIDENCE")
    def test_invalid_values(self):
        for patch in (dict(request_count=True),dict(error_count=101),dict(p95_ms=-1),dict(health_ok=1),dict(policy={})):
            with self.assertRaises(ValueError):mod.assess(**dict(self.args(),**patch))
if __name__=="__main__":unittest.main()
