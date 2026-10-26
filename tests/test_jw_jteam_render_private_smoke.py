"""Negative and positive proof for Render's no-listener offline J team smoke."""
import unittest
from scripts.jw_jteam_render_private_smoke import main

class RenderPrivateSmokeTests(unittest.TestCase):
    def test_offline_five_roles_without_network(self):
        out=main({})
        self.assertEqual(out["status"],"PASS")
        self.assertEqual(out["roles_simulated"],5)
        self.assertEqual(out["provider_calls"],0)
        self.assertFalse(out["listener"])
        self.assertEqual(out["release"],"BLOCKED")
    def test_refuses_real_secret_present(self):
        with self.assertRaisesRegex(PermissionError,"CLOUD_SMOKE_MUST_NOT_HAVE"):
            main({"OPENAI_API_KEY":"sk-test-should-not-be-present"})
    def test_refuses_paid_execution_flag(self):
        with self.assertRaisesRegex(PermissionError,"CLOUD_SMOKE_MUST_NOT_HAVE"):
            main({"JTEAM_PAID_API_APPROVED":"YES"})
    def test_refuses_fake_budget_attestation(self):
        with self.assertRaisesRegex(PermissionError,"CLOUD_SMOKE_MUST_NOT_HAVE"):
            main({"JTEAM_PROVIDER_BUDGET_ENFORCED":"YES"})

if __name__=="__main__":
    unittest.main()
