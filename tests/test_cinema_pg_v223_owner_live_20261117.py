"""Offline tests for owner-authorized P1/P0 driver. Never contacts Supabase."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
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
        instant = datetime(2026,11,17,9,0,tzinfo=KST)
        self.assertEqual(d.expiry_value(instant),"2026-11-17 13:59:00+09")

    def test_deadline_clips_relative_limit(self):
        instant = datetime(2026,11,17,14,29,tzinfo=KST)
        self.assertEqual(d.expiry_value(instant),"2026-11-17 14:30:00+09")

    def test_sql_alters_only_valid_until_login(self):
        text = d.ROLE_SQL.read_text()
        self.assertEqual(text.count("2026-11-17 14:30:00+09"),2)
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
                 patch.object(d,"expiry_value",return_value="2026-11-17 12:00:00+09"), \
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


if __name__=="__main__":
    unittest.main()
