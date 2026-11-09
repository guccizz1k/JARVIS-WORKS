"""Negative and ordering tests for the owner-run Codespace procedure. No database, no network, no secret is touched."""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

from scripts import ci_cinema_pg_v223_codespace_run as run

KST = ZoneInfo("Asia/Seoul")
SHA = "25e73fe9556ad622ed24c605270c45ca08f0cedc"
PASSWORD = "sensitive-password-value"
GOOD_SUMMARY = {
    "verdict": "PASS", "tables": 65, "signature_mismatches": [], "source_is_real_dev_db": True,
    "restore_verified": True, "source_identity_verified": True, "source_role_least_privilege": True,
    "snapshot_consistent": True, "target_proven_ephemeral": True, "wrong_key_rejected": True,
    "decrypt_sha256_matches": True, "partial_dump_restore_rejected": True, "tamper_rejected": True,
    "truncation_rejected": True,
}


class Window(unittest.TestCase):
    def test_renewal_value_is_capped_at_the_approved_limit_not_extended(self):
        at = datetime(2026, 11, 9, 12, 30, tzinfo=KST)
        self.assertEqual(run.renew_value(at), "2026-11-10 09:00:00+09")

    def test_renewal_value_is_shorter_than_24_hours_when_the_limit_is_far(self):
        at = datetime(2026, 11, 9, 5, 0, tzinfo=KST)
        self.assertEqual(run.renew_value(at), "2026-11-10 04:00:00+09")

    def test_nothing_is_renewed_at_or_after_the_limit(self):
        for at in (run.APPROVED_LIMIT, run.APPROVED_LIMIT + timedelta(seconds=1), run.APPROVED_LIMIT + timedelta(days=3)):
            with self.assertRaises(run.Blocked):
                run.renew_value(at)
            with self.assertRaises(run.Blocked):
                run.check_window(at)

    def test_window_report_before_the_limit(self):
        report = run.check_window(datetime(2026, 11, 9, 12, 0, tzinfo=KST))
        self.assertEqual(report["minutes_left"], 21 * 60)


class Commit(unittest.TestCase):
    def test_malformed_sha_is_refused(self):
        for bad in ("", "25e73fe", "Z" * 40, SHA.upper()):
            with self.assertRaises(run.Blocked):
                run.check_commit(bad)

    def test_other_commit_is_refused(self):
        with patch.object(run, "git", return_value="c0aaf68493d5d56b0eda55b125d9d2115c4c14b9"):
            with self.assertRaisesRegex(run.Blocked, "not the reported final commit"):
                run.check_commit(SHA)

    def test_dirty_tree_is_refused(self):
        def fake(*args):
            return SHA if args[0] == "rev-parse" else " M scripts/pg_backup_v223.py"
        with patch.object(run, "git", side_effect=fake):
            with self.assertRaisesRegex(run.Blocked, "uncommitted"):
                run.check_commit(SHA)


class Pins(unittest.TestCase):
    def test_tool_hash_that_differs_from_the_commit_is_refused(self):
        def fake(*args):
            if args[0] == "hash-object":
                return "0" * 40 if args[1] == "scripts/pg_backup_v223.py" else "1" * 40
            return "1" * 40
        with patch.object(run, "git", side_effect=fake):
            with self.assertRaisesRegex(run.Blocked, "pg_backup_v223.py"):
                run.check_pins()

    def test_guard_pin_that_belongs_to_another_commit_is_refused(self):
        wrong = {**run.guard.APPROVED_V223_BACKUP_BLOBS, "scripts/pg_backup_v223.py": "85e8cb1158a47331c7683b98affca46ba7f3e054"}
        with patch.object(run, "git", return_value="1" * 40), patch.object(run.guard, "APPROVED_V223_BACKUP_BLOBS", wrong):
            with self.assertRaisesRegex(run.Blocked, "guard pin mismatch"):
                run.check_pins()

    def test_renew_sql_with_a_wider_window_or_missing_limit_is_refused(self):
        original = run.RENEW_SQL.read_text()
        for broken in (original.replace("interval ''24 hours''", "interval ''7 days''"),
                       original.replace("2026-11-10 09:00:00+09'", "2026-11-17 09:00:00+09'")):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "renew.sql"
                path.write_text(broken)
                with patch.object(run, "git", return_value="1" * 40), patch.object(run, "RENEW_SQL", path):
                    with patch.object(run.guard, "APPROVED_V223_BACKUP_BLOBS", {}):
                        with self.assertRaisesRegex(run.Blocked, "approved absolute limit"):
                            run.check_pins()

    def test_guard_failure_is_refused(self):
        failed = subprocess.CompletedProcess([], 1, "", "")
        with patch.object(run, "git", return_value="1" * 40), patch.object(run.guard, "APPROVED_V223_BACKUP_BLOBS", {}), \
                patch.object(run.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(run.Blocked, "guard failed"):
                run.check_pins()

    def test_consistent_set_passes(self):
        ok = subprocess.CompletedProcess([], 0, "", "")
        pins = {path: "1" * 40 for path in run.guard.APPROVED_V223_BACKUP_BLOBS}
        with patch.object(run, "git", return_value="1" * 40), patch.object(run.guard, "APPROVED_V223_BACKUP_BLOBS", pins), \
                patch.object(run.subprocess, "run", return_value=ok):
            self.assertEqual(run.check_pins()["guard"], "PASS")


class Tools(unittest.TestCase):
    def test_pg16_without_daemon_is_not_ready(self):
        status = {"codespaces": True, "docker_disposable_target_capable": False, "pg_dump_17_plus": False,
                  "pg_restore_17_plus": False, "psql_17_plus": False, "psycopg_present": False, "cryptography_present": True}
        with patch.object(run.preflight, "check", return_value=status):
            with self.assertRaises(run.Blocked) as ctx:
                run.check_tools()
        for name in ("docker_disposable_target_capable", "pg_dump_17_plus", "psycopg_present"):
            self.assertIn(name, str(ctx.exception))

    def test_everything_present_is_ready(self):
        with patch.object(run.preflight, "check", return_value={"a": True, "b": True}):
            self.assertEqual(run.check_tools(), {"a": True, "b": True})

    def test_outside_codespaces_nothing_runs(self):
        with patch.dict(os.environ, {"CODESPACES": "false"}):
            with self.assertRaisesRegex(run.Blocked, "Codespace"):
                run.verify(SHA)


class PrivateInputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.files = {}
        for name in ("creds", "cert", "target"):
            path = Path(self.tmp.name) / name
            path.write_text("x")
            path.chmod(0o600)
            self.files[name] = path
        patcher = patch.multiple(run, CREDS=self.files["creds"], CERT_FILE=self.files["cert"], SECRET_FILE=self.files["target"])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.env = {"JW_PG_ADMIN_DSN": f"postgresql://postgres:{PASSWORD}@db.{run.PROJECT_REF}.supabase.co:5432/postgres"
                                       "?sslmode=verify-full&sslrootcert=/tmp/ca.crt",
                    "JW_PG_BACKUP_KEY": "k" * 44}

    def test_complete_inputs_pass(self):
        self.assertEqual(run.check_private_inputs(self.env)["files_ok"], 3)

    def test_missing_dsn_and_key_are_refused_by_name_without_values(self):
        with self.assertRaises(run.Blocked) as ctx:
            run.check_private_inputs({})
        message = str(ctx.exception)
        self.assertIn("JW_PG_ADMIN_DSN", message)
        self.assertIn("JW_PG_BACKUP_KEY", message)

    def test_weak_tls_is_refused_and_the_password_never_appears(self):
        env = {**self.env, "JW_PG_ADMIN_DSN": self.env["JW_PG_ADMIN_DSN"].replace("verify-full", "require")}
        with self.assertRaises(run.Blocked) as ctx:
            run.check_private_inputs(env)
        self.assertNotIn(PASSWORD, str(ctx.exception))

    def test_other_project_is_refused(self):
        env = {**self.env, "JW_PG_ADMIN_DSN": self.env["JW_PG_ADMIN_DSN"].replace(run.PROJECT_REF, "a" * 20)}
        with self.assertRaisesRegex(run.Blocked, "approved project"):
            run.check_private_inputs(env)

    def test_world_readable_credential_file_is_refused(self):
        self.files["creds"].chmod(0o644)
        with self.assertRaisesRegex(run.Blocked, "backup_role_auth_file_permissions"):
            run.check_private_inputs(self.env)

    def test_missing_ca_file_is_refused(self):
        self.files["cert"].unlink()
        with self.assertRaisesRegex(run.Blocked, "supabase_ca_file"):
            run.check_private_inputs(self.env)

    def test_symlinked_target_file_is_refused(self):
        link = Path(self.tmp.name) / "link"
        link.symlink_to(self.files["target"])
        with patch.object(run, "SECRET_FILE", link):
            with self.assertRaisesRegex(run.Blocked, "restore_target_file"):
                run.check_private_inputs(self.env)


class Summary(unittest.TestCase):
    def test_complete_pass(self):
        self.assertEqual(run.evaluate_summary(GOOD_SUMMARY), [])

    def test_each_missing_proof_blocks_pass(self):
        for key in [k for k in GOOD_SUMMARY if k not in ("tables", "signature_mismatches", "verdict")]:
            self.assertIn(key if key != "source_is_real_dev_db" else "not_real_source",
                          run.evaluate_summary({**GOOD_SUMMARY, key: False}), key)

    def test_wrong_table_count_mismatch_and_verdict(self):
        self.assertIn("tables_not_65", run.evaluate_summary({**GOOD_SUMMARY, "tables": 62}))
        self.assertIn("signature_mismatches", run.evaluate_summary({**GOOD_SUMMARY, "signature_mismatches": ["table:x"]}))
        self.assertIn("verdict", run.evaluate_summary({**GOOD_SUMMARY, "verdict": "PARTIAL: x"}))


class Psql(unittest.TestCase):
    def test_credentials_travel_only_in_the_environment(self):
        seen = {}

        def fake(cmd, **kwargs):
            seen["cmd"], seen["env"] = cmd, kwargs["env"]
            return subprocess.CompletedProcess(cmd, 0, "", "")
        dsn = f"postgresql://postgres:{PASSWORD}@db.{run.PROJECT_REF}.supabase.co:5432/postgres?sslmode=verify-full&sslrootcert=/tmp/ca.crt"
        with patch.dict(os.environ, {"JW_PG_ADMIN_DSN": dsn}), patch.object(run.subprocess, "run", side_effect=fake):
            run.psql("JW_PG_ADMIN_DSN", run.RENEW_SQL, {"valid_until": "2026-11-10 09:00:00+09"})
        self.assertNotIn(PASSWORD, " ".join(seen["cmd"]))
        self.assertIn("valid_until=2026-11-10 09:00:00+09", seen["cmd"])
        self.assertEqual(seen["env"]["PGPASSWORD"], PASSWORD)
        self.assertEqual(seen["env"]["PGSSLMODE"], "verify-full")

    def test_renewal_guard_refusal_is_reported_without_the_driver_text(self):
        refused = subprocess.CompletedProcess([], 3, "", f"ERROR: jw_backup_ro renewal window closed {PASSWORD}")
        with patch.object(run, "psql", return_value=refused):
            with self.assertRaises(run.Blocked) as ctx:
                run.stage_renew()
        self.assertNotIn(PASSWORD, str(ctx.exception))

    def test_renewal_timeout_is_ambiguous_and_closes_the_role(self):
        with patch.object(run, "psql", side_effect=subprocess.TimeoutExpired("psql", 120)):
            with self.assertRaises(run.Ambiguous):
                run.stage_renew()


class Order(unittest.TestCase):
    def fakes(self, calls, fail=None, ambiguous=False):
        def make(name, extra=None):
            def fn():
                calls.append(name)
                if fail == name:
                    raise (run.Ambiguous if ambiguous else run.Blocked)(name + " failed")
                return extra or {}
            return fn
        return {"verify": lambda sha: calls.append("verify") or {}, "stage_target": make("target"), "stage_renew": make("renew"), "stage_login": make("login"),
                "stage_backup": make("backup"), "stage_revoke": make("revoke"), "stage_prove_closed": make("prove")}

    def drive(self, fail=None, ambiguous=False):
        calls: list[str] = []
        with patch.multiple(run, **self.fakes(calls, fail, ambiguous)):
            code, result = run.run_all(SHA)
        return calls, code, result

    def test_full_success_runs_every_stage_in_order(self):
        calls, code, result = self.drive()
        self.assertEqual(calls, ["verify", "target", "renew", "login", "backup", "revoke", "prove"])
        self.assertEqual((code, result["B2_B3"]), (0, "PASS"))

    def test_failed_backup_still_revokes_and_is_not_a_pass(self):
        calls, code, result = self.drive(fail="backup")
        self.assertEqual(calls, ["verify", "target", "renew", "login", "backup", "revoke", "prove"])
        self.assertEqual((code, result["B2_B3"]), (2, "BLOCKED_OR_FAIL"))

    def test_failed_login_skips_backup_but_revokes(self):
        calls, code, _ = self.drive(fail="login")
        self.assertEqual(calls, ["verify", "target", "renew", "login", "revoke", "prove"])
        self.assertEqual(code, 2)

    def test_refused_renewal_changes_nothing_and_revokes_nothing(self):
        calls, code, result = self.drive(fail="renew")
        self.assertEqual(calls, ["verify", "target", "renew"])
        self.assertEqual((code, result["B2_B3"]), (2, "BLOCKED_OR_FAIL"))

    def test_ambiguous_renewal_is_closed_again(self):
        calls, code, _ = self.drive(fail="renew", ambiguous=True)
        self.assertEqual(calls, ["verify", "target", "renew", "revoke", "prove"])
        self.assertEqual(code, 2)

    def test_failed_verify_touches_no_database_stage(self):
        calls: list[str] = []
        fakes = self.fakes(calls)
        fakes["verify"] = lambda sha: (_ for _ in ()).throw(run.Blocked("tools"))
        with patch.multiple(run, **fakes):
            code, result = run.run_all(SHA)
        self.assertEqual(calls, [])
        self.assertEqual((code, result["B2_B3"]), (2, "BLOCKED_OR_FAIL"))

    def test_restore_target_not_ready_stops_before_the_role_is_renewed(self):
        calls, code, result = self.drive(fail="target")
        self.assertEqual(calls, ["verify", "target"])
        self.assertEqual((code, result["B2_B3"]), (2, "BLOCKED_OR_FAIL"))

    def test_revoke_failure_is_never_a_pass(self):
        _, code, result = self.drive(fail="revoke")
        self.assertEqual((code, result["B2_B3"]), (2, "BLOCKED_OR_FAIL"))

    def test_unexpected_driver_error_is_recorded_by_class_only(self):
        calls: list[str] = []
        fakes = self.fakes(calls)

        def boom():
            raise RuntimeError(f"connection string postgresql://u:{PASSWORD}@h/db failed")
        fakes["stage_backup"] = boom
        with patch.multiple(run, **fakes):
            _, result = run.run_all(SHA)
        self.assertNotIn(PASSWORD, repr(result))
        self.assertEqual(result["stages"]["backup_restore_compare"]["status"], "BLOCKED")


class Main(unittest.TestCase):
    def test_all_needs_both_explicit_confirmations_before_anything_runs(self):
        for extra in ([], ["--confirm-approval", "6729950127"], ["--confirm-no-charge"], ["--confirm-approval", "1", "--confirm-no-charge"]):
            with patch.object(run, "run_all") as stage_runner:
                self.assertEqual(run.main(["all", "--expect-sha", SHA, *extra]), 2)
                stage_runner.assert_not_called()

    def test_verify_outside_codespaces_is_blocked_and_touches_nothing(self):
        with patch.dict(os.environ, {"CODESPACES": ""}):
            self.assertEqual(run.main(["verify", "--expect-sha", SHA]), 2)


if __name__ == "__main__":
    unittest.main()
