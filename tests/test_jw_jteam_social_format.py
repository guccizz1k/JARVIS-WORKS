import copy
import json
import tempfile
import unittest
from pathlib import Path
from scripts.jw_jteam_social_format import social_brief, read_policy, role_guidance, STEPS

class SocialFormatTests(unittest.TestCase):
    def test_contract(self):
        p = read_policy()
        self.assertEqual(tuple(p["steps"]), STEPS)
        self.assertEqual(p["min_pilot"], 3)
        self.assertTrue(p["no_copy"] and p["no_automatic_posting"])
    def test_absent_policy_fail_closed(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(ValueError, "UNSAFE_POLICY"):
                read_policy(Path(t)/"missing.json")
    def test_tampered_policy_rejected(self):
        p = copy.deepcopy(read_policy()); p["min_pilot"] = 0
        with tempfile.TemporaryDirectory() as t:
            f=Path(t)/"bad.json"; f.write_text(json.dumps(p))
            with self.assertRaisesRegex(ValueError, "POLICY_TAMPERING_OR_SCHEMA"):
                read_policy(f)
    def test_platform(self):
        self.assertEqual(social_brief("유튜브 글")["platforms"], ["youtube"])
        self.assertEqual(social_brief("인스타 릴스")["platforms"], ["instagram"])
        self.assertEqual(social_brief("SNS")["platforms"], ["youtube","instagram"])
    def test_draft_not_published(self):
        b=social_brief("인스타 피드 카피")
        self.assertEqual(b["source_effectiveness"],"NOT_VERIFIED_WITHOUT_INDEPENDENT_SOURCE")
        self.assertEqual(b["publication"],"NOT_RUN")
        self.assertEqual(b["paid_calls"],0)
        self.assertEqual(b["pilot_significance"],"EXPLORATORY_NOT_CAUSAL_PROOF")
        self.assertTrue(all(x["status"]=="NOT_RUN" for x in b["research"]))
    def test_examples_are_unverified(self):
        r=social_brief("유튜브",examples=[{"format_id":"pov","views":2690000,"source":"screenshot"}])
        self.assertEqual(r["example_count"],1)
        self.assertNotIn("2690000",json.dumps(r))
        self.assertIn("NOT_VERIFIED",r["source_effectiveness"])
    def test_examples_injection_rejected(self):
        with self.assertRaisesRegex(ValueError,"UNSAFE_EXAMPLE"):
            social_brief("인스타",examples=[{"format_id":"pov","views":10,"source":"link","password":"oops"}])
    def test_bool_views_rejected(self):
        with self.assertRaisesRegex(ValueError,"UNSAFE_EXAMPLE"):
            social_brief("인스타",examples=[{"format_id":"pov","views":True,"source":"screen"}])
    def test_large_examples_rejected(self):
        with self.assertRaisesRegex(ValueError,"INVALID_EXAMPLES"):
            social_brief("인스타",examples=[{}]*21)
    def test_secret_rejected(self):
        with self.assertRaisesRegex(PermissionError,"SECRET_IN_TASK"):
            social_brief("유튜브 password=abcde")
    def test_role_specific_mandatory(self):
        for role in ("deputy","deputy_manager","manager","director","jarvis_lead"):
            self.assertIn("MANDATORY_SOCIAL_FORMAT_TRANSFER_V132",role_guidance(role))
        with self.assertRaisesRegex(ValueError,"INVALID_ROLE"):
            role_guidance("superadmin")
    def test_bad_task_rejected(self):
        with self.assertRaisesRegex(ValueError,"INVALID_TASK"):
            social_brief(" ")
if __name__=="__main__":unittest.main()
