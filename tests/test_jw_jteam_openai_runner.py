import contextlib
import io
import unittest
from scripts.jw_jteam_openai_runner import main, require_permission
class RunnerTests(unittest.TestCase):
    def test_dry_run_without_key(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["--task","review"],{}),0)
        self.assertIn('"model_calls": 0',out.getvalue())
    def test_execute_no_approval(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["--task","review","--execute"],{}),3)
        self.assertIn("PAID_API_NOT_APPROVED",out.getvalue())
    def test_approval_but_no_key(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["--task","review","--execute"],{"JTEAM_PAID_API_APPROVED":"YES"}),3)
        self.assertIn("OPENAI_API_KEY_MISSING",out.getvalue())
    def test_budget_guard_required(self):
        from argparse import Namespace
        args=Namespace(execute=True,max_calls=5,max_output_tokens=500,budget_krw=50000)
        with self.assertRaisesRegex(PermissionError,"BUDGET_GUARD"):
            require_permission(args,{"JTEAM_PAID_API_APPROVED":"YES","OPENAI_API_KEY":"test","JTEAM_MODEL":"model"})
    def test_reject_budget_over_cap(self):
        from argparse import Namespace
        args=Namespace(execute=True,max_calls=5,max_output_tokens=500,budget_krw=50001)
        with self.assertRaisesRegex(ValueError,"BUDGET_LIMIT"):
            require_permission(args,{"JTEAM_PAID_API_APPROVED":"YES","OPENAI_API_KEY":"test","JTEAM_MODEL":"model"})
if __name__=="__main__":unittest.main()
