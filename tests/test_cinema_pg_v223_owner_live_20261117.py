"""Offline tests for owner-authorized P1/P0 driver. Never contacts Supabase."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
from zoneinfo import ZoneInfo
from scripts import ci_cinema_pg_v223_owner_live_20261117 as d

KST = ZoneInfo("Asia/Seoul")


class Deadline(unittest.TestCase):
    def test_absolute_deadline_is_fail_closed(self):
        for instant in (d.OWNER_DEADLINE, d.OWNER_DEADLINE+timedelta(seconds=1)):
            with self.assertRaises(d.Blocked):
                d.expiry_value(instant)

    def test_relative_limit_is_below_five_hours(self):
        self.assertEqual(d.MAX_WINDOW, timedelta(hours=4,minutes=59))
        instant = datetime(2026,11,18,9,0,tzinfo=KST)
        self.assertEqual(d.expiry_value(instant),"2026-11-18 13:59:00+09")

    def test_deadline_clips_relative_limit(self):
        instant = datetime(2026,11,20,15,59,tzinfo=KST)
        self.assertEqual(d.expiry_value(instant),"2026-11-20 16:00:00+09")

    def test_sql_alters_only_valid_until_login(self):
        text = d.ROLE_SQL.read_text()
        self.assertEqual(text.count("2026-11-20 16:00:00+09"),1)
        self.assertIn("interval ''5 hours''",text)
        self.assertIn("ALTER ROLE jw_backup_ro VALID UNTIL :'valid_until' LOGIN",text)
        self.assertIn("NOT rolcanlogin",text)
        self.assertIn("pg_stat_activity",text)
        self.assertNotIn("2026-11-11 09:00:00+09",text)


class Pinning(unittest.TestCase):
    def test_wrong_branch_fails_before_source_changes(self):
        with patch.dict(d.os.environ,{"CODESPACES":"true"}), \
             patch.object(d,"git",return_value="bad-branch"):
            with self.assertRaisesRegex(d.Blocked,"wrong_review_branch"):
                d.check_sources()

    def test_not_in_codespaces_fails_before_git(self):
        with patch.dict(d.os.environ,{"CODESPACES":"false"}), \
             patch.object(d,"git") as g:
            with self.assertRaisesRegex(d.Blocked,"approved_codespace_required"):
                d.check_sources()
            g.assert_not_called()


class FailClosedOrdering(unittest.TestCase):
    def test_failed_preflight_never_activates_role(self):
        with patch.object(d,"preflight",side_effect=d.Blocked("unsafe")), \
             patch.object(d.existing,"psql") as psql:
            self.assertEqual(d.run_live(),2)
            psql.assert_not_called()

    def drive(self, psql_return=0, fail_backup=False):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(d,"preflight"), \
                 patch.object(d,"expiry_value",return_value="2026-11-18 12:00:00+09"), \
                 patch.object(d.sys,"stdin",SimpleNamespace(isatty=lambda:True)), \
                 patch("builtins.input",return_value="YES"), \
                 patch.object(d.existing,"psql",return_value=SimpleNamespace(returncode=psql_return)) as ps, \
                 patch.object(d.existing,"stage_login") as login, \
                 patch.object(d.existing,"stage_backup",side_effect=d.Blocked("broken") if fail_backup else None) as backup, \
                 patch.object(d.existing,"stage_revoke") as revoke, \
                 patch.object(d.existing,"stage_prove_closed") as prove, \
                 patch.object(d.existing,"SUMMARY_FILE",Path(tmp)/"summary.json"), \
                 patch.object(d,"git",return_value="f"*40):
                code=d.run_live()
                persisted=list(Path(tmp).glob("owner_b2b3_20261117_*.json"))
                self.assertEqual(len(persisted),1)
                import json
                report=json.loads(persisted[0].read_text())
                revoke.assert_called_once()
                prove.assert_called_once()
                ps.assert_called_once()
                if psql_return:
                    login.assert_not_called()
                    backup.assert_not_called()
                return code,report

    def test_server_rejects_role_enabling_and_still_revokes(self):
        code,report=self.drive(psql_return=1)
        self.assertEqual(code,2)
        self.assertEqual(report["verdict"],"BLOCKED")

    def test_backup_failure_still_revokes(self):
        code,report=self.drive(fail_backup=True)
        self.assertEqual(code,2)
        self.assertEqual(report["verdict"],"BLOCKED")

    def test_success_reports_all_required_stages(self):
        code,report=self.drive()
        self.assertEqual(code,0)
        self.assertEqual(report["verdict"],"PASS")
        self.assertEqual(len(report["stages"]),5)


class ErrorVisibility(unittest.TestCase):
    def test_readonly_closure_proof_never_activates_revokes_or_backs_up(self):
        import io
        from contextlib import redirect_stdout
        cases=(None,'NEW LOGIN STILL WORKS after revocation',
               'role not closed: sessions=1 can_login=True',
               'new_login_refusal_not_verified: private.example password=PRIVATE',
               'unclassified private failure password=PRIVATE')
        for failure in cases:
            with self.subTest(failure=failure), \
                 patch.object(d,'check_sources'),patch.object(d.existing,'check_private_inputs'), \
                 patch.object(d,'load_dashboard_ca'),patch.object(d,'read_password_file'), \
                 patch.object(d.existing,'stage_prove_closed',side_effect=d.existing.Blocked(failure) if failure else None), \
                 patch.object(d.existing,'psql') as activate,patch.object(d.existing,'stage_revoke') as revoke, \
                 patch.object(d.existing,'stage_backup') as backup:
                stream=io.StringIO()
                with redirect_stdout(stream):code=d.check_closed_read_only()
                self.assertEqual(code,2 if failure else 0)
                self.assertNotIn('PRIVATE',stream.getvalue())
                self.assertIn('NO_ROLE_CHANGE_NO_BACKUP',stream.getvalue())
                activate.assert_not_called();revoke.assert_not_called();backup.assert_not_called()

    def test_reviewed_backup_fix_pins_reject_tampered_allowed_paths(self):
        for corrupted in ('scripts/pg_backup_v223.py','scripts/ci_cinema_pg_guard.py',
                          'scripts/ci_cinema_pg_v223_codespace_run.py'):
            with self.subTest(corrupted=corrupted):
                def fake_git(*args):
                    if args==('branch','--show-current'):return d.BRANCH
                    if args==('rev-parse','HEAD') or args==('rev-parse','refs/remotes/origin/'+d.BRANCH):return 'a'*40
                    if args[:2]==('diff','--name-only'):return 'scripts/pg_backup_v223.py\nscripts/ci_cinema_pg_guard.py'
                    if args and args[0]=='rev-parse' and args[1].startswith('HEAD:'):
                        name=args[1][5:]
                        return 'tampered' if name==corrupted else d.REVIEWED_BACKUP_FIX_BLOBS.get(name,'original')
                    if args and args[0]=='rev-parse':return 'original'
                    return ''
                with patch.dict(d.os.environ,{'CODESPACES':'true'}),patch.object(d,'git',side_effect=fake_git):
                    with self.assertRaisesRegex(d.Blocked,'protected_engine_blob_changed'):d.check_sources()

    def test_private_exception_is_never_echoed_from_preflight(self):
        with patch.object(d, "check_sources", side_effect=RuntimeError("password=INTERNAL_SUPER_SECRET")):
            with self.assertRaises(d.Blocked) as ctx:
                d.preflight()
        self.assertEqual(str(ctx.exception), "PREFLIGHT_SOURCE_PIN")
        self.assertNotIn("INTERNAL_SUPER_SECRET", str(ctx.exception))

    def test_detached_checkout_is_only_approved_if_exact_remote_sha(self):
        sha = "f" * 40
        def fake_git(*args):
            if args == ("branch", "--show-current"):
                return ""
            if args == ("rev-parse", "HEAD"):
                return sha
            if args == ("rev-parse", "refs/remotes/origin/" + d.BRANCH):
                return "e" * 40
            return ""
        with patch.dict(d.os.environ, {"CODESPACES": "true"}), patch.object(d, "git", side_effect=fake_git):
            with self.assertRaisesRegex(d.Blocked, "remote_sha_mismatch"):
                d.check_sources()


class OwnerWorktree(unittest.TestCase):
    def test_dirty_report_is_preserved_while_clean_detached_executor_runs(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        with tempfile.TemporaryDirectory() as t:
            parent = Path(t) / "only_ours"
            parent.mkdir()
            important = Path(t) / "pg17_rls_gate_result.txt"
            important.write_text("critical existing owner QA results")
            sha = "e" * 40
            def fake_git(*args, **kwargs):
                if args == ("rev-parse", "HEAD"):
                    return sha
                if args[0] == "status":
                    return ""
                return sha
            seen = []
            def fake_run(argv, **kwargs):
                seen.append((argv, kwargs))
                return SimpleNamespace(returncode=0)
            with patch.object(w, "verify_input_checkout", return_value=sha), \
                 patch.object(w.tempfile, "mkdtemp", return_value=str(parent)), \
                 patch.object(w, "git", side_effect=fake_git), \
                 patch.object(w.subprocess, "run", side_effect=fake_run):
                self.assertEqual(w.main(["check"]), 0)
            self.assertEqual(important.read_text(), "critical existing owner QA results")
            self.assertEqual(len(seen), 3)
            self.assertEqual(seen[0][0][1:4], ["worktree", "add", "--detach"])
            self.assertEqual(seen[1][0][-1], "check")
            self.assertEqual(seen[2][0][1:3], ["worktree", "remove"])
            self.assertFalse(any("reset" in args or "stash" in args or "clean" in args for args, _ in seen))

    def test_wrong_branch_never_creates_isolated_checkout(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        with patch.dict(w.os.environ, {"CODESPACES": "true"}), \
             patch.object(w, "git", return_value="wrong"), \
             patch.object(w.subprocess, "run") as launch:
            self.assertEqual(w.main(["run"]), 2)
            launch.assert_not_called()


class LocalTargetRecovery(unittest.TestCase):
    def test_verified_target_restarts_only_when_approved(self):
        with patch("scripts.ci_cinema_pg_go.ensure_local_docker_daemon") as daemon, \
             patch("scripts.ci_cinema_pg_go.start_verified_disposable", return_value=True) as startup:
            d.verify_local_disposable_started()
        daemon.assert_called_once()
        startup.assert_called_once()

    def test_unrecognized_target_fails_closed(self):
        with patch("scripts.ci_cinema_pg_go.ensure_local_docker_daemon"), \
             patch("scripts.ci_cinema_pg_go.start_verified_disposable", return_value=False):
            with self.assertRaisesRegex(d.Blocked, "approved_local_pg17_container_unavailable"):
                d.verify_local_disposable_started()

    def test_target_refused_before_marker_or_source_login(self):
        with patch.object(d, "check_sources"), \
             patch.object(d, "expiry_value"), \
             patch.object(d.existing, "check_tools"), \
             patch.object(d.existing, "check_private_inputs"), \
             patch.object(d, "load_key"), \
             patch.object(d, "load_dashboard_ca"), \
             patch.object(d, "read_password_file"), \
             patch.object(d, "verify_local_disposable_started", side_effect=d.Blocked("bad image")), \
             patch.object(d.existing, "stage_target") as marker, \
             patch.object(d, "check_live_admin_state") as source:
            with self.assertRaisesRegex(d.Blocked, "PREFLIGHT_LOCAL_PG17_DOCKER"):
                d.preflight()
            marker.assert_not_called()
            source.assert_not_called()


class OwnerPrivateDiagnosis(unittest.TestCase):
    def test_diagnostic_reports_only_machine_code_never_secrets(self):
        import io
        from contextlib import redirect_stdout
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        with tempfile.TemporaryDirectory() as t:
            home = Path(t)
            log = home / ".local/share/jw-v223-restore/last_backup_error.log"
            log.parent.mkdir(parents=True)
            secret = "password=DO_NOT_DISPLAY_THIS_SECRET"
            log.write_text("exit_code=1\n--- stderr (tail) ---\n"
                           "BLOCKED_V223_SOURCE_IDENTITY_NOT_VERIFIED: " + secret)
            log.chmod(0o600)
            stream = io.StringIO()
            with patch.dict(w.os.environ, {"CODESPACES": "true"}), \
                 patch.object(w.Path, "home", return_value=home), \
                 redirect_stdout(stream):
                code = w.diagnose_owner_only()
            self.assertEqual(code,0)
            self.assertIn("B2_DETAIL CODE_BLOCKED_V223_SOURCE_IDENTITY_NOT_VERIFIED", stream.getvalue())
            self.assertNotIn(secret,stream.getvalue())

    def test_diagnosis_rejects_symlink_and_world_readable_private_logs(self):
        import io
        from contextlib import redirect_stdout
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        with tempfile.TemporaryDirectory() as t:
            home=Path(t)
            log=home / ".local/share/jw-v223-restore/last_backup_error.log"
            log.parent.mkdir(parents=True)
            log.write_text("FAIL_V223_UNEXPECTED_FatalException\n")
            log.chmod(0o644)
            stream=io.StringIO()
            with patch.dict(w.os.environ, {"CODESPACES": "true"}), \
                 patch.object(w.Path, "home", return_value=home), \
                 redirect_stdout(stream):
                self.assertEqual(w.diagnose_owner_only(),2)
            self.assertIn("ERROR_LOG_ACCESS_REFUSED",stream.getvalue())

    def test_diagnosis_cannot_claim_full_pass_from_raw_failure_data(self):
        import io
        from contextlib import redirect_stdout
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        with tempfile.TemporaryDirectory() as t:
            home=Path(t)
            log=home / ".local/share/jw-v223-restore/last_backup_error.log"
            log.parent.mkdir(parents=True)
            log.write_text("--- stderr (tail) ---\n"
                "external error: could not connect; FAKE PASS\n")
            log.chmod(0o600)
            stream=io.StringIO()
            with patch.dict(w.os.environ, {"CODESPACES": "true"}), \
                 patch.object(w.Path, "home", return_value=home), \
                 redirect_stdout(stream):
                self.assertEqual(w.diagnose_owner_only(),0)
            self.assertIn("UNCLASSIFIED_BACKUP_FAILURE",stream.getvalue())
            self.assertNotIn("FAKE PASS",stream.getvalue())


class PrivateIncidentClassification(unittest.TestCase):
    def test_summary_failure_has_one_reported_comparison_classification(self):
        import json
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        summary = {'verdict':'PARTIAL: restore not verified','restore_verified':False,
                   'signature_mismatches':['constraints:PRIVATE_OBJECT'],
                   'signature_mismatch_diagnostics':{'constraints':{
                       'missing_in_restore':0,'unexpected_in_restore':0,
                       'different_definition_or_grants':1}}}
        raw='exit_code=1\n--- stdout (tail) ---\n'+json.dumps(summary)+'\n--- stderr (tail) ---\n'
        self.assertEqual(w.classify_private_backup_log(raw),
                         ('SIGNATURE_COMPARISON_REPORTED_FAILURE','CHILD_SUMMARY_HINT'))
        hints=w.extract_backup_summary_indicators(raw)
        self.assertIn('CONSTRAINTS_MISSING_REPORTED_ZERO',hints)
        self.assertIn('CONSTRAINTS_UNEXPECTED_REPORTED_ZERO',hints)
        self.assertIn('CONSTRAINTS_DIFFERENT_REPORTED_NONZERO',hints)
        self.assertNotIn('PRIVATE_OBJECT',str(hints))

    def test_constraint_counts_never_coerce_strings_or_booleans(self):
        import json
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        raw='--- stdout (tail) ---\n'+json.dumps({'signature_mismatch_diagnostics':{
            'constraints':{'missing_in_restore':True,'unexpected_in_restore':'PRIVATE',
                           'different_definition_or_grants':-1}}})+'\n--- stderr (tail) ---\n'
        hints=w.extract_backup_summary_indicators(raw)
        self.assertIn('CONSTRAINTS_COUNTS_INVALID_OR_INCOMPLETE',hints)
        self.assertNotIn('PRIVATE',str(hints))
    def test_nonanchored_engine_error_code_is_safely_extracted(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        label, mode = w.classify_private_backup_log(
            "exit_code=1\n--- stderr (tail) ---\nWARNING: retry; "
            "FAIL_V223_UNEXPECTED_OperationalError: password=PRIVATE\n"
        )
        self.assertEqual((label, mode), ("FAIL_V223_UNEXPECTED_OperationalError", "ENGINE_MACHINE_CODE"))

    def test_unclassified_log_maps_to_fixed_categories(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        examples = (
            ("pg_dump: error: connection failed; secret=abc", "DUMP_ENGINE_ERROR"),
            ("pg_restore: fatal: cannot open file", "RESTORE_ENGINE_ERROR"),
            ("could not translate host name a.secret.host", "DNS_OR_TCP_CONNECT"),
            ("certificate verify failed", "TLS_OR_CERTIFICATE"),
            ("permission denied for schema secret_internal", "DATABASE_PERMISSION"),
            ("No space left on device", "STORAGE_CAPACITY"),
            ("Traceback (most recent call last):", "PYTHON_EXCEPTION"),
        )
        for raw, expected in examples:
            with self.subTest(expected=expected):
                category, mode = w.classify_private_backup_log(raw)
                self.assertEqual((category,mode), (expected,"COARSE_PATTERN"))

    def test_report_stages_are_redacted_and_incident_never_claims_pass(self):
        import io,json
        from contextlib import redirect_stdout
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            directory = home / ".local/share/jw-v223-restore"
            directory.mkdir(parents=True)
            log = directory / "last_backup_error.log"
            log.write_text("exit_code=1\n--- stderr (tail) ---\n"
                           "pg_restore error: secret key and customer names\n")
            log.chmod(0o600)
            report = directory / "owner_b2b3_20261117_112000Z.json"
            report.write_text(json.dumps({
                "verdict": "BLOCKED",
                "stages": {
                    "temporary_login": "PASS",
                    "restricted_tls_login": "PASS",
                    "revoke": "PASS",
                    "closed_verified": "blocked secret path",
                    "unexpected": "SECRET_KEY_SHOULD_NOT_LEAK"
                },
                "secret": "hidden-in-report"
            }))
            report.chmod(0o600)
            stream=io.StringIO()
            with patch.dict(w.os.environ,{"CODESPACES":"true"}),\
                 patch.object(w.Path,"home",return_value=home),\
                 redirect_stdout(stream):
                result=w.diagnose_owner_only()
            shown=stream.getvalue()
            self.assertEqual(result,0)
            self.assertIn("B2_DIAG RESTORE_ENGINE_ERROR",shown)
            self.assertIn("OWNER_INCIDENT_VERDICT BLOCKED",shown)
            self.assertIn("OWNER_STAGE temporary_login REPORTED_PASS",shown)
            self.assertIn("OWNER_STAGE closed_verified NOT_CONFIRMED",shown)
            self.assertNotIn("secret key",shown)
            self.assertNotIn("hidden-in-report",shown)
            self.assertNotIn("SECRET_KEY_SHOULD_NOT_LEAK",shown)


class FailureRootCauseClassification(unittest.TestCase):
    def test_unexpected_exception_class_is_fixed_not_attacker_controlled(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        raw = ("exit_code=1\n--- stderr (tail) ---\n"
               "FAIL_V223_UNEXPECTED_OperationalError\npassword=VERY_SECRET")
        categories = w.classify_private_backup_log_details(raw)
        self.assertIn("UNEXPECTED_OperationalError", categories)
        self.assertIn("CHILD_NONZERO_EXIT", categories)
        self.assertNotIn("VERY_SECRET", str(categories))

    def test_dump_network_error_is_only_printed_as_fixed_categories(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        raw = ("exit_code=1\n--- stdout (tail) ---\n"
               "customer_private_identifiers\n--- stderr (tail) ---\n"
               "pg_dump: error: connection refused 192.0.2.1 password=LEAK")
        categories = w.classify_private_backup_log_details(raw)
        self.assertIn("PATTERN_PG_DUMP", categories)
        self.assertIn("PATTERN_NETWORK_OR_DNS", categories)
        self.assertNotIn("LEAK", str(categories))
        self.assertNotIn("192.0.2.1", str(categories))

    def test_summary_verdict_with_empty_stderr_not_misreported_pass(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        raw = 'exit_code=1\n--- stdout (tail) ---\n{"verdict":"FAIL","signature_mismatches":["rows:sensitive"]}\n--- stderr (tail) ---\n'
        categories = w.classify_private_backup_log_details(raw)
        self.assertIn("STDOUT_VERDICT_FIELD_PRESENT", categories)
        self.assertIn("STDOUT_SIGNATURE_CHECK_PRESENT", categories)
        self.assertIn("CHILD_STDERR_EMPTY", categories)
        self.assertNotIn("PASS", str(categories))

    def test_pretend_secret_in_machine_code_suffix_is_not_disclosed(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        raw = '--- stderr (tail) ---\nBLOCKED_V223_UNLISTED_password_sensitive_value\n'
        self.assertNotIn("password_sensitive_value", str(w.classify_private_backup_log_details(raw)))


class PriorChildJsonFailureCategories(unittest.TestCase):
    """Uses synthetic scrubbed owner-only logs, never real Supabase data."""
    def test_complete_mismatch_list_reports_only_categories(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        raw = (
            "exit_code=1\n--- stdout (tail) ---\n"
            '"restore_verified": false,\n'
            '"signature_mismatches": ["acl:internal_customer_sensitive",'
            '"rows:supersecret_source_row"],\n'
            '"tables": 65,\n'
            '"verdict": "FAIL: restored database differs from source",\n'
            '"wrong_key_rejected": true\n'
            "--- stderr (tail) ---\n"
        )
        result = w.extract_backup_summary_indicators(raw)
        self.assertIn("MISMATCH_ACL", result)
        self.assertIn("MISMATCH_ROWS", result)
        self.assertIn("VERDICT_REPORTED_FAIL", result)
        self.assertIn("FLAG_NOT_TRUE_RESTORE_VERIFIED", result)
        self.assertIn("TABLE_COUNT_REPORTED_65", result)
        self.assertNotIn("supersecret", str(result))
        self.assertNotIn("internal_customer", str(result))

    def test_unparseable_truncated_list_never_guesses_category(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        raw = (
            "exit_code=1\n--- stdout (tail) ---\n"
            '"signature_mismatches": ["rows:PII data that was cut\n'
            '"verdict": "FAIL: restored database differs from source"\n'
            "--- stderr (tail) ---\n"
        )
        result = w.extract_backup_summary_indicators(raw)
        self.assertIn("SIGNATURE_MISMATCHES_TAIL_INCOMPLETE", result)
        self.assertIn("VERDICT_REPORTED_FAIL", result)
        self.assertNotIn("MISMATCH_ROWS", result)
        self.assertNotIn("PII", str(result))

    def test_reported_pass_can_never_be_treated_as_verified_pass(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        raw = (
            'exit_code=1\n--- stdout (tail) ---\n'
            '"signature_mismatches": [],\n'
            '"tables": 65,\n'
            '"verdict": "PASS",\n'
            '"wrong_key_rejected": true\n'
            '--- stderr (tail) ---\n'
        )
        result = w.extract_backup_summary_indicators(raw)
        self.assertIn("VERDICT_REPORTED_PASS_NOT_VERIFIED", result)
        self.assertIn("SIGNATURE_MISMATCHES_REPORTED_NONE", result)
        self.assertNotIn("PASS", result)

    def test_false_required_flags_can_be_read_without_exposing_extra_fields(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        raw = (
            'exit_code=1\n--- stdout (tail) ---\n'
            '"tamper_rejected": false,\n'
            '"partial_dump_restore_rejected": null,\n'
            '"unexpected_key": "secret_DO_NOT_SHOW",\n'
            '"verdict": "PARTIAL: check failed"\n'
            '--- stderr (tail) ---\n'
        )
        result = w.extract_backup_summary_indicators(raw)
        self.assertIn("FLAG_NOT_TRUE_TAMPER_REJECTED", result)
        self.assertIn("FLAG_NOT_TRUE_PARTIAL_DUMP_RESTORE_REJECTED", result)
        self.assertIn("VERDICT_REPORTED_INCOMPLETE", result)
        self.assertNotIn("DO_NOT_SHOW", str(result))

    def test_absent_stdout_does_not_claim_root_cause(self):
        from scripts import ci_cinema_pg_v223_owner_worktree_20261117 as w
        self.assertEqual(w.extract_backup_summary_indicators(
            "exit_code=1\n--- stderr (tail) ---\n"), ["STDOUT_TAIL_NOT_STORED"])



class ClosureProofFailClosed(unittest.TestCase):
    """A wrong password must never masquerade as a closed PostgreSQL role."""

    def test_server_nologin_only(self):
        from scripts import ci_cinema_pg_v223_codespace_run as live
        cases = (
            ("FATAL: role \"jw_backup_ro\" is not permitted to log in", "28000", "auth_rejected"),
            ("FATAL: password authentication failed for user jw_backup_ro", "28P01", "bad_credentials"),
            ("password authentication failed", "28P01", "bad_credentials"),
            ("unrecognized server authentication error", "28000", "auth_unverified"),
            ("SSL error: certificate verify failed", None, "tls_failure"),
            ("could not translate host name", None, "network_failure"),
            ("connection timed out", None, "timeout"),
            ("unknown secret=DO_NOT_SHOW", None, "unknown"),
        )
        for message, state, expected in cases:
            with self.subTest(expected=expected):
                error = Exception(message)
                error.sqlstate = state
                self.assertEqual(live.classify_login_failure_detail(error), expected)
                self.assertEqual(live.classify_login_failure(error),
                                 "auth_rejected" if expected == "auth_rejected" else "transport_or_unknown")

    def test_owner_labels_never_print_exception_secrets(self):
        import io
        from contextlib import redirect_stdout
        for reason, label in (("bad_credentials", "BAD_CREDENTIALS"),
                              ("tls_failure", "TLS_FAILURE"),
                              ("network_failure", "NETWORK_FAILURE"),
                              ("timeout", "TIMEOUT"),
                              ("auth_unverified", "AUTH_REFUSAL_UNVERIFIED")):
            with self.subTest(reason=reason), patch.object(d, "check_sources"), \
                 patch.object(d.existing, "check_private_inputs"), \
                 patch.object(d, "load_dashboard_ca"), patch.object(d, "read_password_file"), \
                 patch.object(d.existing, "stage_prove_closed",
                              side_effect=d.existing.Blocked("new_login_refusal_not_verified: reason=" + reason +
                                                            "; password=DO_NOT_SHOW")):
                out = io.StringIO()
                with redirect_stdout(out):
                    result = d.check_closed_read_only()
                self.assertEqual(result, 2)
                self.assertIn("ROLE_CLOSURE_" + label, out.getvalue())
                self.assertNotIn("DO_NOT_SHOW", out.getvalue())

class SourcePinInspectionSafety(unittest.TestCase):
    def test_inspect_never_mutates_database(self):
        import io
        from contextlib import redirect_stdout
        with patch.object(d, "git", side_effect=d.Blocked("missing_git_ref")), \
             patch.object(d.existing, "stage_backup", side_effect=AssertionError("DB touched")), \
             patch.object(d.existing, "stage_revoke", side_effect=AssertionError("DB touched")), \
             patch.object(d.existing, "psql", side_effect=AssertionError("DB touched")):
            output = io.StringIO()
            with redirect_stdout(output):
                result = d.inspect_source_pin()
        self.assertEqual(result, 2)
        self.assertIn("BLOCKED SOURCE_PIN_REMOTE_SHA", output.getvalue())
        self.assertIn("NO_ROLE_CHANGE_NO_BACKUP", output.getvalue())

    def test_inspect_does_not_change_expired_approval(self):
        with patch.object(d, "git", return_value=""), \
             patch.object(d, "expiry_value", side_effect=d.Blocked("expired")):
            # Inspection must not call the approval/activation code.
            self.assertIn(d.inspect_source_pin(), (0, 2))



class ClosureDiagnosticReadOnly(unittest.TestCase):
    def test_probe_never_runs_mutating_backup_functions(self):
        import io
        import sys
        from contextlib import redirect_stdout
        class FakeError(Exception):
            sqlstate = "28000"
            diag = SimpleNamespace(message_primary="role is not permitted to log in")
        class FakePsycopg:
            Error = FakeError
            @staticmethod
            def connect(**kwargs):
                raise FakeError("password=SECRET host=PRIVATE")
        with patch.object(d, "check_sources"), \
             patch.object(d.existing, "check_private_inputs"), \
             patch.object(d, "load_dashboard_ca"), \
             patch.object(d, "read_password_file"), \
             patch.object(d.existing, "login_kwargs", return_value={}), \
             patch.object(d.existing, "classify_login_failure_detail", return_value="auth_rejected"), \
             patch.dict(sys.modules, {"psycopg": FakePsycopg}), \
             patch.object(d.existing, "psql") as psql, \
             patch.object(d.existing, "stage_revoke") as revoke, \
             patch.object(d.existing, "stage_backup") as backup:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(d.diagnose_closure_read_only(), 2)
            self.assertIn("DIAGNOSTIC SQLSTATE_FAMILY_28", output.getvalue())
            self.assertIn("DIAGNOSTIC_ONLY_CLOSURE_NOT_PROVEN", output.getvalue())
            self.assertNotIn("SECRET", output.getvalue())
            self.assertNotIn("PRIVATE", output.getvalue())
            psql.assert_not_called()
            revoke.assert_not_called()
            backup.assert_not_called()

    def test_probe_fails_closed_before_network_on_missing_inputs(self):
        with patch.object(d, "check_sources", side_effect=RuntimeError("password=SECRET")), \
             patch.object(d.existing, "login_kwargs") as kwargs:
            import io
            from contextlib import redirect_stdout
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(d.diagnose_closure_read_only(), 2)
            self.assertNotIn("SECRET", out.getvalue())
            kwargs.assert_not_called()


class CatalogCommandTests(unittest.TestCase):
    def test_catalog_only_never_proves_login_refusal(self):
        with patch.object(d, "check_sources"), \
             patch.object(d, "probe_admin_closure_catalog_read_only",
                          return_value="CATALOG_CLOSED_NO_SESSIONS"), \
             patch("builtins.print") as output:
            self.assertEqual(d.catalog_closure_read_only(), 0)
        lines = [call.args[0] for call in output.call_args_list]
        self.assertIn("CATALOG_ONLY_NEW_LOGIN_REFUSAL_NOT_PROVEN", lines)
        self.assertIn("NO_ROLE_CHANGE_NO_BACKUP", lines)

    def test_catalog_failure_is_blocked(self):
        with patch.object(d, "check_sources"), \
             patch.object(d, "probe_admin_closure_catalog_read_only",
                          return_value="CATALOG_NOT_CLOSED"):
            self.assertEqual(d.catalog_closure_read_only(), 2)

    def test_source_pin_blocks_before_admin_contact(self):
        with patch.object(d, "check_sources", side_effect=d.Blocked("unsafe")), \
             patch.object(d, "probe_admin_closure_catalog_read_only") as probe:
            self.assertEqual(d.catalog_closure_read_only(), 2)
            probe.assert_not_called()


class AdminClosureCatalogTests(unittest.TestCase):
    def test_missing_admin_dsn_is_blocked(self):
        with patch.dict(d.os.environ, {}, clear=True):
            self.assertEqual(d.probe_admin_closure_catalog_read_only(), "ADMIN_DSN_MISSING")

    def _run_with_rows(self, rows):
        conn = MagicMock()
        conn.__enter__.return_value = conn
        conn.execute.return_value.fetchone.side_effect = rows
        with patch.dict(d.os.environ, {"JW_PG_ADMIN_DSN": "fake"}):
            with patch("psycopg.connect", return_value=conn):
                verdict = d.probe_admin_closure_catalog_read_only()
        return verdict, conn

    def test_readonly_admin_catalog_closed(self):
        verdict, conn = self._run_with_rows([
            ("postgres", "postgres", 170011), (False, True), (0,)
        ])
        self.assertEqual(verdict, "CATALOG_CLOSED_NO_SESSIONS")
        self.assertIn("SET TRANSACTION READ ONLY",
                      [item.args[0] for item in conn.execute.call_args_list])

    def test_untrusted_admin_identity_is_blocked(self):
        verdict, conn = self._run_with_rows([
            ("other", "postgres", 170011)
        ])
        self.assertEqual(verdict, "ADMIN_IDENTITY_UNVERIFIED")

    def test_login_enabled_is_not_closed(self):
        verdict, conn = self._run_with_rows([
            ("postgres", "postgres", 170011), (True, False), (0,)
        ])
        self.assertEqual(verdict, "ROLE_LOGIN_ENABLED")

    def test_active_session_is_not_closed(self):
        verdict, conn = self._run_with_rows([
            ("postgres", "postgres", 170011), (False, True), (1,)
        ])
        self.assertEqual(verdict, "ROLE_ACTIVE_SESSIONS_PRESENT")

    def test_future_expiry_is_not_full_catalog_closure(self):
        verdict, conn = self._run_with_rows([
            ("postgres", "postgres", 170011), (False, False), (0,)
        ])
        self.assertEqual(verdict, "ROLE_NOLOGIN_ZERO_SESSIONS_EXPIRY_FUTURE")


class OriginDirectClosureTests(unittest.TestCase):
    def test_only_exact_origin_role_denial_is_proof(self):
        good = SimpleNamespace(
            sqlstate="28000",
            diag=SimpleNamespace(message_primary='role "jw_backup_ro" is not permitted to log in'),
        )
        self.assertEqual(d.classify_origin_nologin_refusal(good),
                         "ORIGIN_NOLOGIN_REFUSAL_VERIFIED")
        for state, message in (
            ("28000", 'role "other" is not permitted to log in'),
            ("28000", "tenant not found"),
            ("28P01", 'role "jw_backup_ro" is not permitted to log in'),
            ("08006", 'role "jw_backup_ro" is not permitted to log in'),
            (None, 'role "jw_backup_ro" is not permitted to log in'),
        ):
            error = SimpleNamespace(sqlstate=state,
                                    diag=SimpleNamespace(message_primary=message))
            self.assertNotEqual(d.classify_origin_nologin_refusal(error),
                                "ORIGIN_NOLOGIN_REFUSAL_VERIFIED")
        self.assertEqual(d.classify_origin_nologin_refusal(
            SimpleNamespace(sqlstate="28000", diag=None)),
            "AUTH_ERROR_NOT_NOLOGIN_PROOF")

    def _mock_environment(self):
        return [
            patch.object(d, "check_sources"),
            patch.object(d, "load_dashboard_ca"),
            patch.object(d, "read_password_file", return_value="FAKE_PASSWORD_ONLY"),
        ]

    def test_direct_origin_rejection_and_admin_catalog_is_pass(self):
        import psycopg
        from contextlib import ExitStack
        with ExitStack() as stack:
            for item in self._mock_environment():
                stack.enter_context(item)
            admin = stack.enter_context(patch.object(
                d, "probe_admin_closure_catalog_read_only",
                side_effect=["ROLE_NOLOGIN_ZERO_SESSIONS_EXPIRY_FUTURE",
                             "ROLE_NOLOGIN_ZERO_SESSIONS_EXPIRY_FUTURE"]))
            stack.enter_context(patch.object(
                d, "classify_origin_nologin_refusal",
                return_value="ORIGIN_NOLOGIN_REFUSAL_VERIFIED"))
            connect = stack.enter_context(
                patch("psycopg.connect",
                      side_effect=psycopg.OperationalError("secret=DO_NOT_PRINT")))
            output = stack.enter_context(patch("builtins.print"))
            self.assertEqual(d.verify_origin_direct_closed_read_only(), 0)
        args = connect.call_args.kwargs
        self.assertEqual(args["host"], "db." + d.existing.PROJECT_REF + ".supabase.co")
        self.assertEqual(args["user"], d.existing.ROLE)
        self.assertEqual(args["sslmode"], "verify-full")
        self.assertEqual(args["port"], 5432)
        self.assertEqual(admin.call_count, 2)
        printed = "\n".join(str(item.args[0]) for item in output.call_args_list)
        self.assertIn("PASS ORIGIN_DIRECT_NOLOGIN_AND_ADMIN_ZERO_SESSIONS", printed)
        self.assertIn("NOTICE VALID_UNTIL_FUTURE_NOLOGIN_STILL_ENFORCED", printed)
        self.assertNotIn("DO_NOT_PRINT", printed)
        self.assertNotIn("FAKE_PASSWORD_ONLY", printed)

    def test_direct_origin_unknown_auth_is_blocked(self):
        import psycopg
        from contextlib import ExitStack
        with ExitStack() as stack:
            for item in self._mock_environment():
                stack.enter_context(item)
            stack.enter_context(patch.object(
                d, "probe_admin_closure_catalog_read_only",
                side_effect=["CATALOG_CLOSED_NO_SESSIONS", "CATALOG_CLOSED_NO_SESSIONS"]))
            stack.enter_context(patch.object(
                d, "classify_origin_nologin_refusal",
                return_value="BAD_CREDENTIALS_NOT_PROOF"))
            stack.enter_context(patch("psycopg.connect",
                                     side_effect=psycopg.OperationalError("private")))
            self.assertEqual(d.verify_origin_direct_closed_read_only(), 2)

    def test_successful_login_is_urgent_and_never_pass(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for item in self._mock_environment():
                stack.enter_context(item)
            check = stack.enter_context(patch.object(
                d, "probe_admin_closure_catalog_read_only",
                return_value="CATALOG_CLOSED_NO_SESSIONS"))
            conn = MagicMock()
            connect = stack.enter_context(patch("psycopg.connect", return_value=conn))
            self.assertEqual(d.verify_origin_direct_closed_read_only(), 2)
            self.assertEqual(check.call_count, 1)
            connect.assert_called_once()
            conn.execute.assert_not_called()

    def test_unclosed_admin_blocks_before_direct_auth(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for item in self._mock_environment():
                stack.enter_context(item)
            stack.enter_context(patch.object(
                d, "probe_admin_closure_catalog_read_only",
                return_value="ROLE_LOGIN_ENABLED"))
            connect = stack.enter_context(patch("psycopg.connect"))
            self.assertEqual(d.verify_origin_direct_closed_read_only(), 2)
            connect.assert_not_called()

    def test_dirty_worktree_blocks_before_direct_auth(self):
        with patch.object(d, "check_sources", side_effect=d.Blocked("dirty")), \
             patch("psycopg.connect") as connect:
            self.assertEqual(d.verify_origin_direct_closed_read_only(), 2)
            connect.assert_not_called()


class PgStartupFrameTests(unittest.TestCase):
    def test_authentication_sasl_is_only_challenge(self):
        self.assertEqual(d.classify_pg_startup_frame(b"R", b"\x00\x00\x00\x0a"),
                         "STARTUP_AUTH_CHALLENGE")

    def test_authentication_ok_does_not_prove_role_closed(self):
        self.assertEqual(d.classify_pg_startup_frame(b"R", b"\x00\x00\x00\x00"),
                         "STARTUP_AUTH_OK_UNVERIFIED")

    def test_sqlstate_28_from_pooler_is_not_proof(self):
        self.assertEqual(d.classify_pg_startup_frame(
            b"E", b"SERROR\x00C28000\x00Mrole not permitted to log in\x00\x00"),
            "STARTUP_SQLSTATE_28_UNVERIFIED")

    def test_network_sqlstate_is_not_proof(self):
        self.assertEqual(d.classify_pg_startup_frame(
            b"E", b"SERROR\x00C08006\x00Mconnection failed\x00\x00"),
            "STARTUP_SQLSTATE_08_UNVERIFIED")

    def test_incomplete_or_forged_errors_are_blocked(self):
        self.assertEqual(d.classify_pg_startup_frame(b"E", b"C28000"),
                         "STARTUP_MALFORMED_ERROR")
        self.assertEqual(d.classify_pg_startup_frame(b"E", b"C28000\x00C28000\x00"),
                         "STARTUP_ERROR_UNVERIFIED")
        self.assertEqual(d.classify_pg_startup_frame(b"R", b"\x00"),
                         "STARTUP_MALFORMED_AUTH")
        self.assertEqual(d.classify_pg_startup_frame(b"K", b"payload"),
                         "STARTUP_UNEXPECTED_MESSAGE")

    def test_probe_preflight_refuses_missing_tls_and_bad_user(self):
        self.assertEqual(d.probe_pg_startup_read_only({"host": "db.example", "user": "x"}),
                         "STARTUP_PREFLIGHT_UNSUPPORTED")
        self.assertEqual(d.probe_pg_startup_read_only({
            "host": "db.example", "user": "invalid\x00user", "sslmode": "verify-full",
        }), "STARTUP_PREFLIGHT_UNSUPPORTED")

    def test_startup_command_never_claims_closed(self):
        with patch.object(d, "check_sources"), \
             patch.object(d, "load_dashboard_ca"), \
             patch.object(d, "probe_pg_startup_read_only",
                          return_value="STARTUP_AUTH_CHALLENGE") as probe, \
             patch("builtins.print") as output:
            self.assertEqual(d.startup_diagnostic_read_only(), 2)
            probe.assert_called_once()
        lines = [item.args[0] for item in output.call_args_list]
        self.assertIn("STARTUP_ONLY_ORIGIN_ROLE_REFUSAL_NOT_PROVEN", lines)
        self.assertIn("NO_ROLE_CHANGE_NO_BACKUP", lines)

    def test_startup_pin_blocks_before_network(self):
        with patch.object(d, "check_sources", side_effect=d.Blocked("bad")), \
             patch.object(d, "probe_pg_startup_read_only") as probe:
            self.assertEqual(d.startup_diagnostic_read_only(), 2)
            probe.assert_not_called()


class RouteClassificationTests(unittest.TestCase):
    def test_pooler_route_detected_without_secrets(self):
        self.assertEqual(d.classify_postgres_route({
            "host": "aws-0-ap-northeast-2.pooler.supabase.com",
            "user": "jw_backup_ro.projectref",
            "password": "DO_NOT_PRINT",
        }), "SUPABASE_POOLER")

    def test_direct_candidate_is_not_proof(self):
        self.assertEqual(d.classify_postgres_route({
            "host": "db.projectref.supabase.co",
            "user": "jw_backup_ro",
        }), "SUPABASE_DIRECT_CANDIDATE")

    def test_unknown_routes_fail_closed(self):
        self.assertEqual(d.classify_postgres_route({
            "host": "custom.internal", "user": "jw_backup_ro",
        }), "UNKNOWN")
        self.assertEqual(d.classify_postgres_route({}), "UNKNOWN")


class PostgresTlsTests(unittest.TestCase):

    def test_preflight_rejects_unverified_tls_and_bad_port(self):
        self.assertEqual(d.probe_pg_tls_read_only({"host": "private.example", "sslmode": "require", "sslrootcert": "/tmp/ca"}), "TLS_PREFLIGHT_UNSUPPORTED")
        self.assertEqual(d.probe_pg_tls_read_only({"host": "private.example", "sslmode": "verify-full", "sslrootcert": "/tmp/ca", "port": 70000}), "TLS_INVALID_PORT")

    def test_verified_tls_without_database_login(self):
        from unittest.mock import MagicMock
        options = {"host": "private.example", "port": 5432, "sslmode": "verify-full", "sslrootcert": "/tmp/ca"}
        sock = MagicMock()
        sock.recv.return_value = b"S"
        secure = MagicMock()
        secure.version.return_value = "TLSv1.3"
        ctx = MagicMock()
        ctx.wrap_socket.return_value.__enter__.return_value = secure
        with patch("ssl.create_default_context", return_value=ctx) as create, patch("socket.create_connection") as connect:
            connect.return_value.__enter__.return_value = sock
            self.assertEqual(d.probe_pg_tls_read_only(options), "TLS_VERIFIED")
            create.assert_called_once_with(cafile="/tmp/ca")
            ctx.wrap_socket.assert_called_once_with(sock, server_hostname="private.example")
            self.assertEqual(sock.sendall.call_args.args[0], bytes.fromhex("0000000804d2162f"))

    def test_certificate_failure_is_redacted(self):
        import ssl
        options = {"host": "private.example", "sslmode": "verify-full", "sslrootcert": "/tmp/ca"}
        sock = MagicMock()
        sock.recv.return_value = b"S"
        ctx = MagicMock()
        ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("PRIVATE_HOST_AND_PASSWORD")
        with patch("ssl.create_default_context", return_value=ctx), patch("socket.create_connection") as connect:
            connect.return_value.__enter__.return_value = sock
            self.assertEqual(d.probe_pg_tls_read_only(options), "TLS_CERT_VERIFY_FAILED")


class PostgresSslRequestTests(unittest.TestCase):
    def test_supported_rejected_and_no_response(self):
        from unittest.mock import MagicMock
        for answer, expected in ((b"S", "PG_SSL_SUPPORTED"), (b"N", "PG_SSL_REJECTED"), (b"", "PG_NO_RESPONSE"), (b"X", "PG_UNEXPECTED_RESPONSE")):
            sock = MagicMock()
            sock.recv.return_value = answer
            with patch("socket.create_connection") as connect:
                connect.return_value.__enter__.return_value = sock
                self.assertEqual(d.probe_pg_ssl_request_read_only({"host": "private.example", "port": 5432}), expected)
                self.assertEqual(sock.sendall.call_args.args[0], bytes.fromhex("0000000804d2162f"))

    def test_timeout_redacted(self):
        with patch("socket.create_connection", side_effect=TimeoutError("SECRET_PASSWORD")):
            self.assertEqual(d.probe_pg_ssl_request_read_only({"host": "private.example"}), "PG_HANDSHAKE_TIMEOUT")

    def test_invalid_input_does_not_connect(self):
        with patch("socket.create_connection") as connect:
            self.assertEqual(d.probe_pg_ssl_request_read_only({"host": "/tmp/socket"}), "UNSUPPORTED_HOST")
            self.assertEqual(d.probe_pg_ssl_request_read_only({"host": "private.example", "port": 70000}), "INVALID_PORT")
            connect.assert_not_called()


class TransportProbeTests(unittest.TestCase):
    def test_dns_failure_without_disclosing_hostname(self):
        import socket
        with patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "PRIVATE_HOST")):
            self.assertEqual(d.probe_transport_read_only({"host": "PRIVATE_HOST", "port": 5432}), "DNS_ERROR")

    def test_tcp_timeout_without_disclosing_secrets(self):
        with patch("socket.getaddrinfo", return_value=[object()]), \
             patch("socket.create_connection", side_effect=TimeoutError("password=SECRET")):
            self.assertEqual(d.probe_transport_read_only({"host": "private.example", "port": 5432}), "TCP_TIMEOUT")

    def test_tcp_success_without_authentication(self):
        from unittest.mock import MagicMock
        socket_handle = MagicMock()
        with patch("socket.getaddrinfo", return_value=[object()]), \
             patch("socket.create_connection") as connect:
            connect.return_value.__enter__.return_value = socket_handle
            self.assertEqual(d.probe_transport_read_only({"host": "private.example", "port": 5432}), "TCP_REACHABLE")
            connect.assert_called_once_with(("private.example", 5432), timeout=3.0)

    def test_invalid_host_and_port_never_contact_network(self):
        with patch("socket.getaddrinfo") as resolver:
            self.assertEqual(d.probe_transport_read_only({"host": "/tmp/.s.PGSQL.5432"}), "UNSUPPORTED_HOST")
            self.assertEqual(d.probe_transport_read_only({"host": "private.example", "port": "bad"}), "INVALID_PORT")
            resolver.assert_not_called()


class ClosureClientExceptionDiagnostics(unittest.TestCase):
    def test_nested_timeout_classified_without_secrets(self):
        import socket
        secret = "password=NEVER_PRINT_THIS"
        outer = RuntimeError(secret)
        outer.__cause__ = TimeoutError(secret)
        self.assertEqual(d.classify_client_exception_kind(outer), "TIMEOUT")

    def test_dns_exception_is_distinct_from_auth(self):
        import socket
        error = socket.gaierror(-2, "host=NEVER_PRINT_THIS")
        self.assertEqual(d.classify_client_exception_kind(error), "DNS_ERROR")

    def test_unknown_exception_fails_closed(self):
        self.assertEqual(d.classify_client_exception_kind(Exception("password=SECRET")), "UNCLASSIFIED")

    def test_exception_cycle_bounded(self):
        a, b = RuntimeError("secret"), RuntimeError("secret2")
        a.__cause__ = b
        b.__cause__ = a
        self.assertEqual(d.classify_client_exception_kind(a), "UNCLASSIFIED")

    def test_diagnostic_prints_only_fixed_classification(self):
        import io
        import sys
        from contextlib import redirect_stdout
        class FakeError(Exception):
            sqlstate = None
            diag = None
        class FakePsycopg:
            Error = FakeError
            @staticmethod
            def connect(**kwargs):
                err = FakeError("password=NEVER_PRINT_THIS host=PRIVATE")
                err.__cause__ = TimeoutError("password=NEVER_PRINT_THIS")
                raise err
        with patch.object(d, "check_sources"), \
             patch.object(d.existing, "check_private_inputs"), \
             patch.object(d, "load_dashboard_ca"), \
             patch.object(d, "read_password_file"), \
             patch.object(d.existing, "login_kwargs", return_value={}), \
             patch.object(d.existing, "classify_login_failure_detail", return_value="unknown"), \
             patch.dict(sys.modules, {"psycopg": FakePsycopg}):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(d.diagnose_closure_read_only(), 2)
            output = out.getvalue()
            self.assertIn("DIAGNOSTIC CLIENT_EXCEPTION_TIMEOUT", output)
            self.assertIn("DIAGNOSTIC_ONLY_CLOSURE_NOT_PROVEN", output)
            self.assertNotIn("NEVER_PRINT_THIS", output)
            self.assertNotIn("PRIVATE", output)
