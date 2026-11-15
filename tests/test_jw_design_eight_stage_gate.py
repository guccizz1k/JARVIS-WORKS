import json
import unittest
from pathlib import Path
from scripts.jw_design_eight_stage_gate import check, STAGES
ROOT=Path(__file__).resolve().parents[1]
MANIFEST=json.loads((ROOT/"agents/team/jarvis_v1/design_pipeline.json").read_text(encoding="utf-8"))
class DesignEightStageTests(unittest.TestCase):
    def test_contract(self):
        self.assertEqual(len(STAGES),8)
        self.assertEqual([x["id"] for x in STAGES],[x["id"] for x in MANIFEST["stages"]])
    def test_missing_evidence_blocks(self):
        result=check(MANIFEST,{})
        self.assertEqual(result["status"],"BLOCKED")
        self.assertEqual(len(result["stage_status"]),8)
    def test_self_report_does_not_certify_browser(self):
        evidence={s["id"]:{key:"example" for key in s["requires"]} for s in STAGES}
        result=check(MANIFEST,evidence)
        self.assertEqual(result["status"],"REVIEW_REQUIRED")
        self.assertFalse(result["independent_browser_verified"])
        self.assertFalse(result["release_authorized"])
    def test_release_policy_tamper_blocks(self):
        manifest={**MANIFEST,"constraints":{**MANIFEST["constraints"],"allow_production_deploy":True}}
        self.assertEqual(check(manifest,{})["status"],"BLOCKED")
    def test_stage_tamper_blocks(self):
        manifest={**MANIFEST,"stages":MANIFEST["stages"][:-1]}
        self.assertEqual(check(manifest,{})["status"],"BLOCKED")
if __name__=="__main__":unittest.main()
