"""J team offline private execution, cost reservation and concurrency regression."""
from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from scripts.jw_jteam_private_cli import run_private, validated_db_path
from scripts.jw_jteam_durable_dispatch import dispatch, setup


class PrivateRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="jteam-v128-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "private.sqlite3"
        self.calls = []
        self.env = {
            "JTEAM_PAID_API_APPROVED": "YES",
            "JTEAM_PROVIDER_BUDGET_ENFORCED": "YES",
            "JTEAM_OPERATOR_PRIVATE_APPROVAL_ID": "synthetic-approval-only",
            "OPENAI_API_KEY": "synthetic-mock-key-never-real",
            "JTEAM_MODEL": "offline-fixture",
            "JTEAM_BUDGET_SCOPE": "2026-10",
        }

    def mock_provider(self, role, task, context, model, key, output_limit):
        self.calls.append(role)
        self.assertEqual(model, "offline-fixture")
        self.assertEqual(key, "synthetic-mock-key-never-real")
        self.assertEqual(context, [])
        return {
            "role": role, "response_id": "fake-" + role,
            "model": model, "status": "completed",
            "usage": {"input_tokens": 8, "output_tokens": 4},
            "output": [{"text": "untrusted synthetic response"}],
        }

    def test_default_dry_run_never_creates_db_or_calls_model(self):
        report = run_private(self.path, "job", "synthetic")
        self.assertEqual(report["actual_model_calls"], 0)
        self.assertEqual(report["status"], "DRY_RUN")
        self.assertFalse(self.path.exists())

    def test_private_five_role_mock_receipts_and_budget(self):
        result = run_private(
            self.path, "job-1", "synthetic task", execute=True, env=self.env,
            provider=self.mock_provider,
        )
        self.assertEqual(result["role_receipts"], 5)
        self.assertEqual(result["release"], "BLOCKED")
        self.assertEqual(result["independent_review"], "NOT_ATTESTED")
        self.assertEqual(self.calls, ["deputy", "deputy_manager", "manager", "director", "jarvis_lead"])
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM usage_events").fetchone()[0], 5)
            self.assertEqual(db.execute("SELECT reserved_krw FROM budget").fetchone()[0], 5000)
            self.assertEqual(db.execute("SELECT count(*) FROM reservations WHERE status='UNCERTAIN'").fetchone()[0], 5)
            receipts = " ".join(row[0] for row in db.execute("SELECT receipt FROM steps"))
            self.assertNotIn("untrusted synthetic response", receipts)
            self.assertNotIn("synthetic task", receipts)
            self.assertNotIn("synthetic-mock-key-never-real", receipts)

    def test_rerun_complete_job_does_not_charge_or_call_again(self):
        run_private(self.path, "job-2", "task", execute=True, env=self.env, provider=self.mock_provider)
        run_private(self.path, "job-2", "task", execute=True, env=self.env, provider=self.mock_provider)
        self.assertEqual(len(self.calls), 5)

    def test_same_job_new_task_refused(self):
        run_private(self.path, "job-3", "first", execute=True, env=self.env, provider=self.mock_provider)
        with self.assertRaisesRegex(ValueError, "TASK_MISMATCH"):
            run_private(self.path, "job-3", "second", execute=True, env=self.env, provider=self.mock_provider)
        self.assertEqual(len(self.calls), 5)

    def test_missing_approval_refuses_before_db(self):
        env = dict(self.env, JTEAM_PAID_API_APPROVED="NO")
        with self.assertRaisesRegex(PermissionError, "NOT_APPROVED"):
            run_private(self.path, "job", "task", execute=True, env=env, provider=self.mock_provider)
        self.assertFalse(self.path.exists())
        self.assertFalse(self.calls)

    def test_billing_guard_refuses(self):
        env = dict(self.env, JTEAM_PROVIDER_BUDGET_ENFORCED="NO")
        with self.assertRaisesRegex(PermissionError, "BUDGET_GUARD"):
            run_private(self.path, "job", "task", execute=True, env=env, provider=self.mock_provider)
        self.assertFalse(self.calls)

    def test_disallow_credentials_in_task(self):
        with self.assertRaisesRegex(PermissionError, "CREDENTIAL"):
            run_private(self.path, "job", "password = secret", execute=True, env=self.env, provider=self.mock_provider)

    def test_private_approval_id_required(self):
        env = dict(self.env)
        env.pop("JTEAM_OPERATOR_PRIVATE_APPROVAL_ID")
        with self.assertRaisesRegex(PermissionError, "PRIVATE_OPERATOR"):
            run_private(self.path, "job", "task", execute=True, env=env, provider=self.mock_provider)

    def test_reject_db_inside_git_checkout(self):
        with self.assertRaisesRegex(PermissionError, "WORKTREE"):
            validated_db_path(Path(__file__).resolve().parents[1] / "unsafe.sqlite3")

    def test_symlinked_sqlite_denied(self):
        linked = Path(self.tmp.name) / "link.sqlite3"
        linked.symlink_to(self.path)
        with self.assertRaisesRegex(PermissionError, "SYMLINK"):
            validated_db_path(linked)

    def test_budget_refuses_many_jobs_held_uncertain(self):
        run_private(self.path, "first", "task", execute=True, env=self.env, provider=self.mock_provider)
        with self.assertRaisesRegex(PermissionError, "BUDGET_EXCEEDED"):
            run_private(self.path, "second", "task", execute=True, env=self.env, provider=self.mock_provider)
        self.assertEqual(len(self.calls), 5)

    def test_duplicate_provider_receipt_fails_closed(self):
        def same_id(role, task, context, model, key, cap):
            ret = self.mock_provider(role, task, context, model, key, cap)
            ret["response_id"] = "same-id"
            return ret
        with self.assertRaisesRegex(ValueError, "DUPLICATE_PROVIDER_RECEIPT"):
            run_private(self.path, "job", "task", execute=True, env=self.env, provider=same_id)
        self.assertEqual(len(self.calls), 2)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT state FROM jobs WHERE id='job'").fetchone()[0], "BLOCKED")

    def test_missing_usage_blocks_and_preserves_uncertain_reservation(self):
        def bad(role, task, context, model, key, cap):
            ret = self.mock_provider(role, task, context, model, key, cap)
            ret["usage"] = {}
            return ret
        with self.assertRaisesRegex(ValueError, "INVALID_PROVIDER_USAGE"):
            run_private(self.path, "job", "task", execute=True, env=self.env, provider=bad)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT state FROM jobs").fetchone()[0], "BLOCKED")
            self.assertEqual(db.execute("SELECT status FROM reservations").fetchone()[0], "UNCERTAIN")

    def test_two_connections_cannot_claim_same_running_role(self):
        with sqlite3.connect(self.path) as db:
            setup(db)
        entered, release = threading.Event(), threading.Event()
        out = []
        def slow_worker(role, task):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test worker timeout")
            return {"receipt_id": role, "input_tokens": 1, "output_tokens": 1}
        def first():
            try:
                with sqlite3.connect(self.path, timeout=2.0) as db:
                    dispatch(db, "shared", "task", worker=slow_worker)
                out.append("DONE")
            except BaseException as exc:
                out.append(type(exc).__name__)
        thread = threading.Thread(target=first)
        thread.start()
        self.assertTrue(entered.wait(4))
        try:
            with sqlite3.connect(self.path, timeout=1.0) as second:
                with self.assertRaisesRegex(PermissionError, "RECONCILIATION_REQUIRED"):
                    dispatch(second, "shared", "task", worker=lambda *_: self.fail("double dispatched"))
        finally:
            release.set()
            thread.join(timeout=8)
        self.assertEqual(out, ["DONE"])


if __name__ == "__main__":
    unittest.main()
