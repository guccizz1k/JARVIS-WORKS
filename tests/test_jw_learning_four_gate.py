import unittest
from scripts.jw_learning_four_gate import assess, GATES

class LearningFourGateTests(unittest.TestCase):
    def test_missing_all_fail_closed(self):
        r = assess({})
        self.assertFalse(r["all_pass"])
        self.assertEqual(set(r["gates"]), set(GATES))
        self.assertTrue(all(x["status"]=="BLOCKED" for x in r["gates"].values()))
    def test_self_report_never_passes(self):
        data = {gate: {"source_commit":"abc","integration_test":"ok","checkpoint_restore_proof":"ok",
                       "model_execution_receipt":"ok","patch_sha":"ok","isolated_test":"ok",
                       "baseline_sha":"ok","candidate_sha":"ok","independent_evaluator":"ok",
                       "regression_report":"ok","same_cases":"ok","skill_provenance":"ok",
                       "independent_results":"ok"} for gate in GATES}
        r=assess(data)
        self.assertFalse(r["all_pass"])
        self.assertTrue(all(x["status"]=="REVIEW_REQUIRED" for x in r["gates"].values()))
    def test_invalid_document_rejected(self):
        with self.assertRaises(ValueError):
            assess([])
    def test_never_authorizes_release(self):
        r=assess({})
        self.assertFalse(r["production_allowed"])
        self.assertFalse(r["main_merge_allowed"])
if __name__=="__main__":
    unittest.main()
