"""Hard negative-path checks for user-defined seven thinking methods."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from scripts.jw_jteam_thinking import contract, make_plan, role_guidance

class ThinkingMethodsTests(unittest.TestCase):
    def test_seven_distinct_methods_and_no_false_guarantees(self):
        c = contract()
        self.assertEqual(len(c["methods"]), 7)
        self.assertIn("ten_years_in_one_year_guarantee", c["disallowed_claims"])
        self.assertTrue(c["user_autonomy"])
    def test_missing_contract_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, "UNSAFE_THINKING_POLICY"):
                contract(Path(d) / "missing.json")
    def test_modified_contract_blocked(self):
        c = copy.deepcopy(contract())
        c["no_external_calls"] = False
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"changed.json"
            p.write_text(json.dumps(c))
            with self.assertRaisesRegex(ValueError, "THINKING_POLICY_TAMPERED"):
                contract(p)
    def test_skill_plan_stays_unexecuted(self):
        for domain, expected in contract()["default_selection"].items():
            with self.subTest(domain=domain):
                plan = make_plan("합성 테스트 목표", domain=domain)
                self.assertEqual(plan["method"], expected)
                self.assertEqual(plan["status"], "PLAN_ONLY")
                self.assertEqual(plan["actual_improvement"], "NOT_MEASURED")
                self.assertTrue(all(p["execution"] == "NOT_RUN" for p in plan["practice_steps"]))
                self.assertEqual(plan["paid_calls"], 0)
                self.assertEqual(plan["independent_models_executed"], 0)
                self.assertEqual(plan["release"], "BLOCKED")
    def test_all_seven_modes_explicit(self):
        c = contract()
        for name, record in c["methods"].items():
            p = make_plan("반복 가능한 실험", domain=record["domains"][0], method=name)
            self.assertEqual(p["method"], name)
            self.assertEqual(len(p["practice_steps"]), 4)
    def test_personal_methods_opt_in(self):
        for name in ("life_design", "aspiration"):
            out = make_plan("사용자가 선택한 목표", domain="everyday", method=name)
            self.assertTrue(out["user_opt_in_for_personal_goals"])
            self.assertEqual(out["user_autonomy"], "PRESERVED")
    def test_incompatible_domain_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "INCOMPATIBLE_METHOD_DOMAIN"):
            make_plan("UI 버그", domain="software", method="life_design")
    def test_malformed_and_secret_denied(self):
        for goal in ("", " "):
            with self.assertRaisesRegex(ValueError, "INVALID_GOAL"):
                make_plan(goal)
        with self.assertRaisesRegex(PermissionError, "SENSITIVE_GOAL_DENIED"):
            make_plan("password=secret1")
    def test_no_user_goal_echo(self):
        p = make_plan("예민한 사적 목표")
        self.assertNotIn("예민한", json.dumps(p))
    def test_no_claim_actual_brain_change(self):
        for meth, desc in contract()["methods"].items():
            self.assertTrue(all("install your brain" not in a.lower() for a in desc["actions"]))
    def test_roles_receive_evidence_bounds(self):
        for role in ("deputy","deputy_manager","manager","director","jarvis_lead"):
            self.assertIn("JARVIS_SEVEN_METHODS_V136", role_guidance(role))
        with self.assertRaisesRegex(ValueError, "INVALID_ROLE"):
            role_guidance("fake")
if __name__ == "__main__":
    unittest.main()
