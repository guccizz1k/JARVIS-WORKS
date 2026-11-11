"""Negative and ordering tests for the owner-run Codespace procedure. No database, no network, no secret is touched."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import quote
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
        at = datetime(2026, 11, 10, 12, 30, tzinfo=KST)
        self.assertEqual(run.renew_value(at), "2026-11-11 09:00:00+09")

    def test_renewal_value_is_shorter_than_24_hours_when_the_limit_is_far(self):
        at = datetime(2026, 11, 10, 5, 0, tzinfo=KST)
        self.assertEqual(run.renew_value(at), "2026-11-11 04:00:00+09")

    def test_nothing_is_renewed_at_or_after_the_limit(self):
        for at in (run.APPROVED_LIMIT, run.APPROVED_LIMIT + timedelta(seconds=1), run.APPROVED_LIMIT + timedelta(days=3)):
            with self.assertRaises(run.Blocked):
                run.renew_value(at)
            with self.assertRaises(run.Blocked):
                run.check_window(at)

    def test_window_report_before_the_limit(self):
        report = run.check_window(datetime(2026, 11, 10, 12, 0, tzinfo=KST))
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
                       original.replace("2026-11-11 09:00:00+09'", "2026-11-17 09:00:00+09'")):
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
                                       f"?sslmode=verify-full&sslrootcert={self.files['cert']}",
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

    def test_approved_pooler_admin_connection_passes(self):
        dsn = (f"postgresql://postgres.{run.PROJECT_REF}:{PASSWORD}@{run.HOST}:{run.PORT}/postgres"
               f"?sslmode=verify-full&sslrootcert={self.files['cert']}")
        self.assertEqual(run.check_private_inputs({**self.env, "JW_PG_ADMIN_DSN": dsn})["files_ok"], 3)

    def test_host_fragment_user_fragment_and_wrong_admin_targets_are_rejected(self):
        approved_host = f"db.{run.PROJECT_REF}.supabase.co"
        attack_dsns = {
            "hostname_prefix_suffix": f"postgresql://postgres:{PASSWORD}@{approved_host}.attacker.example:5432/postgres",
            "project_ref_in_unsupported_hostname": f"postgresql://postgres:{PASSWORD}@fake.{run.PROJECT_REF}.example:5432/postgres",
            "project_ref_only_in_username": f"postgresql://postgres.{run.PROJECT_REF}:{PASSWORD}@attacker.example:5432/postgres",
            "wrong_direct_role": f"postgresql://other-admin:{PASSWORD}@{approved_host}:5432/postgres",
            "wrong_pooler_role": f"postgresql://other-admin.{run.PROJECT_REF}:{PASSWORD}@{run.HOST}:5432/postgres",
            "wrong_port": f"postgresql://postgres:{PASSWORD}@{approved_host}:15432/postgres",
            "wrong_database": f"postgresql://postgres:{PASSWORD}@{approved_host}:5432/otherdb",
            "wrong_pooler_port": f"postgresql://postgres.{run.PROJECT_REF}:{PASSWORD}@{run.HOST}:6543/postgres",
        }
        for name, url in attack_dsns.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(run.Blocked, "exactly match") as ctx:
                    run.check_private_inputs({**self.env, "JW_PG_ADMIN_DSN": url
                                              + f"?sslmode=verify-full&sslrootcert={self.files['cert']}"})
                self.assertNotIn(PASSWORD, str(ctx.exception))

    def test_query_parameters_that_could_redirect_the_raw_url_are_rejected(self):
        base = self.env["JW_PG_ADMIN_DSN"]
        for extra in ("host=attacker.example", "hostaddr=203.0.113.9", "port=6543", "user=other", "dbname=other",
                      "options=-c%20role%3Dother", "service=x", "sslmode=disable", "sslrootcert=/tmp/other.crt"):
            with self.subTest(extra=extra):
                with self.assertRaises(run.Blocked) as ctx:      # repeated sslmode/sslrootcert may already fail an earlier TLS/CA rule
                    run.check_private_inputs({**self.env, "JW_PG_ADMIN_DSN": base + "&" + extra})
                if not extra.startswith("ssl"):
                    self.assertIn("exactly one sslmode and one sslrootcert", str(ctx.exception))
                self.assertNotIn(PASSWORD, str(ctx.exception))

    def test_admin_dsn_without_a_password_is_rejected(self):
        dsn = self.env["JW_PG_ADMIN_DSN"].replace(f":{PASSWORD}@", "@")
        with self.assertRaisesRegex(run.Blocked, "admin password"):
            run.check_private_inputs({**self.env, "JW_PG_ADMIN_DSN": dsn})

    def test_admin_dsn_must_use_the_same_approved_owner_only_ca(self):
        bad_dsn = self.env["JW_PG_ADMIN_DSN"].replace(
            str(self.files["cert"]), "/tmp/arbitrary-root-ca.crt")
        with self.assertRaisesRegex(run.Blocked, "approved owner-only CA file") as ctx:
            run.check_private_inputs({**self.env, "JW_PG_ADMIN_DSN": bad_dsn})
        self.assertNotIn(PASSWORD, str(ctx.exception))

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
            run.psql("JW_PG_ADMIN_DSN", run.RENEW_SQL, {"valid_until": "2026-11-11 09:00:00+09"})
        self.assertNotIn(PASSWORD, " ".join(seen["cmd"]))
        self.assertIn("valid_until=2026-11-11 09:00:00+09", seen["cmd"])
        self.assertEqual(seen["env"]["PGPASSWORD"], PASSWORD)
        self.assertEqual(seen["env"]["PGSSLMODE"], "verify-full")

    def test_renewal_guard_refusal_is_reported_without_the_driver_text(self):
        refused = subprocess.CompletedProcess([], 3, "", f"ERROR: jw_backup_ro renewal window closed {PASSWORD}")
        with patch.object(run, "psql", return_value=refused):
            with self.assertRaises(run.Blocked) as ctx:
                run.stage_renew()
        self.assertNotIn(PASSWORD, str(ctx.exception))

    def test_renewal_timeout_is_ambiguous_and_closes_the_role(self):
        # The timeout test must exercise psql, not fail first on an expired historical approval.
        approved_time = run.APPROVED_LIMIT - run.MAX_WINDOW / 2
        with patch.object(run, "now", return_value=approved_time), \
             patch.object(run, "psql", side_effect=subprocess.TimeoutExpired("psql", 120)):
            with self.assertRaises(run.Ambiguous):
                run.stage_renew()


class Order(unittest.TestCase):
    def fakes(self, calls, fail=None, ambiguous=False, attempted=True):
        def make(name, extra=None):
            def fn(on_attempt=None):
                calls.append(name)
                if name == "renew" and attempted and on_attempt and fail != name:
                    on_attempt()              # the real stage marks the attempt just before psql runs
                if fail == name:
                    if name == "renew" and attempted and on_attempt:
                        on_attempt()          # the privileged subprocess was started before it failed
                    raise (run.Ambiguous if ambiguous else run.Blocked)(name + " failed")
                return extra or {}
            return fn
        return {"verify": lambda sha: calls.append("verify") or {}, "stage_target": make("target"), "stage_renew": make("renew"), "stage_login": make("login"),
                "stage_backup": make("backup"), "stage_revoke": make("revoke"), "stage_prove_closed": make("prove")}

    def drive(self, fail=None, ambiguous=False, attempted=True):
        calls: list[str] = []
        with patch.multiple(run, **self.fakes(calls, fail, ambiguous, attempted)):
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

    def test_failure_before_the_privileged_command_changes_nothing_and_revokes_nothing(self):
        calls, code, result = self.drive(fail="renew", attempted=False)
        self.assertEqual(calls, ["verify", "target", "renew"])
        self.assertEqual((code, result["B2_B3"]), (2, "BLOCKED_OR_FAIL"))

    def test_nonzero_exit_after_the_privileged_command_started_is_still_closed(self):
        # server committed, client reported exit 1 (plain Blocked, not Ambiguous): the role must still be revoked and measured
        calls, code, result = self.drive(fail="renew", ambiguous=False, attempted=True)
        self.assertEqual(calls, ["verify", "target", "renew", "revoke", "prove"])
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


class RenewAttemptMarker(unittest.TestCase):
    def test_marker_fires_before_psql_for_every_failure_mode(self):
        for failure in (subprocess.CompletedProcess([], 1, "", "connection reset by peer"),
                        subprocess.TimeoutExpired("psql", 120), OSError("psql vanished")):
            events: list[str] = []

            def fake(*args, _failure=failure, **kwargs):
                events.append("psql")
                if isinstance(_failure, BaseException):
                    raise _failure
                return _failure
            with patch.object(run, "psql", side_effect=fake), patch.object(run, "renew_value", return_value="2026-11-11 09:00:00+09"):
                with self.assertRaises(run.Ambiguous):
                    run.stage_renew(lambda: events.append("attempt"))
            self.assertEqual(events, ["attempt", "psql"], repr(failure))

    def test_marker_does_not_fire_when_no_window_is_left(self):
        events: list[str] = []
        with patch.object(run, "psql", side_effect=lambda *a, **k: events.append("psql")):
            with patch.object(run, "renew_value", side_effect=run.Blocked("no renewal window")):
                with self.assertRaises(run.Blocked):
                    run.stage_renew(lambda: events.append("attempt"))
        self.assertEqual(events, [])

    def test_stage_message_never_carries_the_psql_error_text(self):
        failed = subprocess.CompletedProcess([], 1, "", f"connection reset {PASSWORD}")
        with patch.object(run, "psql", return_value=failed), patch.object(run, "renew_value", return_value="x"):
            with self.assertRaises(run.Ambiguous) as ctx:
                run.stage_renew()
        self.assertNotIn(PASSWORD, str(ctx.exception))


class Revoke(unittest.TestCase):
    def test_retries_until_applied(self):
        replies = [subprocess.CompletedProcess([], 1, "", ""), subprocess.TimeoutExpired("psql", 120), subprocess.CompletedProcess([], 0, "", "")]

        def fake(*args, **kwargs):
            reply = replies.pop(0)
            if isinstance(reply, BaseException):
                raise reply
            return reply
        with patch.object(run, "psql", side_effect=fake), patch.object(run.time, "sleep"):
            self.assertEqual(run.stage_revoke(), {"revoke": "applied", "attempts": 3})

    def test_gives_up_loudly_after_the_last_attempt(self):
        with patch.object(run, "psql", return_value=subprocess.CompletedProcess([], 1, "", "")) as call, patch.object(run.time, "sleep"):
            with self.assertRaisesRegex(run.Blocked, "REVOCATION FAILED"):
                run.stage_revoke()
        self.assertEqual(call.call_count, run.REVOKE_ATTEMPTS)


class FakeDriverError(Exception):
    def __init__(self, text, sqlstate=None):
        super().__init__(text)
        self.sqlstate = sqlstate


class LoginProof(unittest.TestCase):
    PREFIX = 'connection failed: connection to server at "127.0.0.1", port 5432 failed: '

    def test_classification(self):
        cases = {
            "auth_rejected": [FakeDriverError(self.PREFIX + 'FATAL:  role "jw_backup_ro" is not permitted to log in'),
                              FakeDriverError(self.PREFIX + 'FATAL:  password authentication failed for user "x"'),
                              FakeDriverError("anything", sqlstate="28000"), FakeDriverError("anything", sqlstate="28P01")],
            "transport_or_unknown": [FakeDriverError(self.PREFIX + "Connection refused"),
                                     FakeDriverError('connection failed: could not translate host name "h" to address'),
                                     FakeDriverError(self.PREFIX + "server does not support SSL, but SSL was required"),
                                     FakeDriverError("SSL error: certificate verify failed"),
                                     FakeDriverError("connection failed: timeout expired"),
                                     FakeDriverError(self.PREFIX + "FATAL:  too many connections for role"),
                                     FakeDriverError("boom", sqlstate="08006"), FakeDriverError("boom")],
        }
        for expected, errors in cases.items():
            for exc in errors:
                self.assertEqual(run.classify_login_failure(exc), expected, str(exc))

    def drive(self, login_errors, can_login=False, sessions=0):
        """A stand-in psycopg: login attempts raise the given errors in turn (None = the login works); the admin connection answers."""
        import sys
        import types
        errors = list(login_errors)
        fake = types.ModuleType("psycopg")
        fake.Error = FakeDriverError

        class Conn:
            def __init__(self, admin): self.admin = admin
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def execute(self, sql, params=None):
                answer = (sessions,) if "pg_stat_activity" in sql else (can_login,)
                return types.SimpleNamespace(fetchone=lambda: answer)

        def connect(*args, **kwargs):
            if args:                       # the admin DSN call
                return Conn(True)
            err = errors.pop(0) if errors else errors_last[0]
            if err is None:
                return Conn(False)
            raise err
        errors_last = [login_errors[-1]]
        fake.connect = connect
        with patch.dict(sys.modules, {"psycopg": fake}), patch.object(run, "login_kwargs", return_value={"host": "h"}), \
                patch.object(run.time, "sleep"), patch.dict(os.environ, {"JW_PG_ADMIN_DSN": "postgresql://a:b@h/db"}):
            return run.stage_prove_closed()

    def test_deliberate_nologin_rejection_with_admin_proof_passes(self):
        out = self.drive([FakeDriverError(self.PREFIX + 'FATAL:  role "r" is not permitted to log in')])
        self.assertEqual((out["new_login_refused"], out["refusal"], out["rolcanlogin"]), (True, "auth_rejected", False))

    def test_network_or_tls_outage_is_not_proof_even_when_the_admin_side_looks_closed(self):
        for outage in (FakeDriverError(self.PREFIX + "Connection refused"), FakeDriverError("SSL error: certificate verify failed"),
                       FakeDriverError('could not translate host name "h" to address'), FakeDriverError("connection failed: timeout expired")):
            with self.assertRaisesRegex(run.Blocked, "new_login_refusal_not_verified"):
                self.drive([outage])

    def test_a_transient_outage_followed_by_a_real_rejection_passes(self):
        out = self.drive([FakeDriverError("connection failed: timeout expired"),
                          FakeDriverError(self.PREFIX + 'FATAL:  role "r" is not permitted to log in')])
        self.assertEqual(out["refusal"], "auth_rejected")

    def test_a_login_that_still_works_is_a_failure(self):
        with self.assertRaisesRegex(run.Blocked, "STILL WORKS"):
            self.drive([None])

    def test_admin_side_must_agree(self):
        reject = FakeDriverError(self.PREFIX + 'FATAL:  role "r" is not permitted to log in')
        with self.assertRaisesRegex(run.Blocked, "role not closed"):
            self.drive([reject], can_login=True)
        with self.assertRaisesRegex(run.Blocked, "role not closed"):
            self.drive([reject], sessions=1)


class SecretsInChildOutput(unittest.TestCase):
    PW = "p@ss/w0rd+SECRET9"
    KEY = "K" * 43 + "="
    LEAK = (f"psycopg.OperationalError: connection to postgresql://jw_backup_ro.ref:{PW.replace('@', '%40').replace('/', '%2F')}@h:5432/postgres "
            f"failed; raw {PW}; key={KEY}; also postgresql://other:unlisted-secret-77@x/y password=hunter2hunter2")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "private" / "last_backup_error.log"
        self.env = {"JW_PG_BACKUP_KEY": self.KEY,
                    "JW_PG_SOURCE_DSN": f"postgresql://jw_backup_ro.ref:{PASSWORD}@h:5432/postgres?sslmode=verify-full&sslrootcert=/c",
                    "JW_PG_TARGET_ADMIN_DSN": f"postgresql://postgres:{quote(self.PW, safe='')}@127.0.0.1:55432/postgres"}
        script = "import sys; sys.stderr.write(%r); sys.stdout.write('not json at all ' + %r); sys.exit(1)" % (self.LEAK, self.LEAK)
        for patcher in (patch.object(run, "BACKUP_COMMAND", [sys.executable, "-c", script]),
                        patch.object(run, "backup_env", return_value={**os.environ, **self.env}),
                        patch.object(run, "ERROR_LOG", self.log), patch.object(run, "CREDS", Path(self.tmp.name) / "none")):
            patcher.start()
            self.addCleanup(patcher.stop)

    def assertClean(self, text):
        for needle in (self.PW, self.KEY, PASSWORD, "unlisted-secret-77", "hunter2hunter2", "%40", "w0rd%2B"):
            self.assertNotIn(needle, text, needle)

    def test_blocked_message_and_summary_carry_no_child_output(self):
        with self.assertRaises(run.Blocked) as ctx:
            run.stage_backup()
        self.assertClean(str(ctx.exception))
        self.assertIn("exit code 1", str(ctx.exception))
        self.assertNotIn("psycopg", str(ctx.exception))

    def test_private_log_is_scrubbed_owner_only_and_never_a_symlink_target(self):
        with self.assertRaises(run.Blocked):
            run.stage_backup()
        body = self.log.read_text()
        self.assertClean(body)
        self.assertIn("exit_code=1", body)
        self.assertEqual(stat.S_IMODE(self.log.stat().st_mode), 0o600)

    def test_whole_run_report_stdout_and_summary_file_are_clean(self):
        import contextlib
        import io
        summary_file = Path(self.tmp.name) / "private" / "last_run_summary.json"
        fakes = {"verify": lambda sha: {}, "stage_target": lambda: {}, "stage_renew": lambda on_attempt=None: (on_attempt and on_attempt(), {})[1],
                 "stage_login": lambda: {}, "stage_revoke": lambda: {}, "stage_prove_closed": lambda: {}, "SUMMARY_FILE": summary_file}
        out, err = io.StringIO(), io.StringIO()
        with patch.multiple(run, **fakes), patch.dict(os.environ, self.env), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = run.main(["all", "--expect-sha", SHA, "--confirm-approval", "6755130318", "--confirm-no-charge"])
        self.assertEqual(code, 2)
        self.assertNotIn("B2_B3_PASS", out.getvalue())
        for text in (out.getvalue(), err.getvalue(), summary_file.read_text()):
            self.assertClean(text)
        self.assertIn("BLOCKED_OR_FAIL", out.getvalue())

    def test_scrub_removes_listed_secrets_url_credentials_and_password_settings(self):
        cleaned = run.scrub(self.LEAK, self.env)
        self.assertClean(cleaned)
        self.assertIn("://***@", cleaned)

    def test_a_valid_summary_with_nonzero_exit_still_leaks_nothing(self):
        script = "import sys,json; sys.stderr.write(%r); print(json.dumps({'verdict':'FAIL: x','tables':65,'signature_mismatches':['t']})); sys.exit(1)" % self.LEAK
        with patch.object(run, "BACKUP_COMMAND", [sys.executable, "-c", script]):
            with self.assertRaises(run.Blocked) as ctx:
                run.stage_backup()
        self.assertClean(str(ctx.exception))
        self.assertClean(self.log.read_text())


class Main(unittest.TestCase):
    def test_all_needs_both_explicit_confirmations_before_anything_runs(self):
        for extra in ([], ["--confirm-approval", "6755130318"], ["--confirm-no-charge"], ["--confirm-approval", "1", "--confirm-no-charge"]):
            with patch.object(run, "run_all") as stage_runner:
                self.assertEqual(run.main(["all", "--expect-sha", SHA, *extra]), 2)
                stage_runner.assert_not_called()

    def test_verify_outside_codespaces_is_blocked_and_touches_nothing(self):
        with patch.dict(os.environ, {"CODESPACES": ""}):
            self.assertEqual(run.main(["verify", "--expect-sha", SHA]), 2)


if __name__ == "__main__":
    unittest.main()
