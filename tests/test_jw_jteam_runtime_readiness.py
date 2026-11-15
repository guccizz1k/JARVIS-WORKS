import json
import unittest
from pathlib import Path
from scripts.jw_jteam_runtime_readiness import readiness, ORDER
TEAM=json.loads((Path(__file__).resolve().parents[1]/"agents/team/jarvis_v1/team.json").read_text(encoding="utf-8"))
class JTeamRuntimeReadinessTests(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(TEAM["display_name"],"J team")
        self.assertEqual(len(TEAM["roles"]),5)
        self.assertTrue(all(len(r["quality_gates"])>=3 for r in TEAM["roles"]))
    def test_no_receipts(self):
        self.assertEqual(readiness(TEAM)["status"],"BLOCKED")
    def test_forged_same_session(self):
        sha="a"*40
        receipts={"sha":sha,"runs":[{"role":r,"session_id":"one","source_sha":sha,"provider_receipt":"claimed"} for r in ORDER]}
        self.assertIn("NONINDEPENDENT_SESSIONS",readiness(TEAM,receipts)["errors"])
    def test_distinct_claims_do_not_authorize_release(self):
        sha="a"*40
        receipts={"sha":sha,"runs":[{"role":r,"session_id":str(i),"source_sha":sha,"provider_receipt":"claimed"} for i,r in enumerate(ORDER)]}
        self.assertEqual(readiness(TEAM,receipts)["release"],"BLOCKED")
        self.assertEqual(readiness(TEAM,receipts)["independent_review"],"NOT_ATTESTED")
    def test_wrong_sha(self):
        sha="a"*40
        receipts={"sha":sha,"runs":[{"role":r,"session_id":str(i),"source_sha":"b"*40,"provider_receipt":"claimed"} for i,r in enumerate(ORDER)]}
        self.assertIn("SHA_MISMATCH",readiness(TEAM,receipts)["errors"])
if __name__=="__main__":unittest.main()
