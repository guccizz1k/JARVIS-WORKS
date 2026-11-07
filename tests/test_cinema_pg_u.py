"""Read-only live role checker fail-closed unit tests; no network in tests."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import ci_cinema_pg_u as u
from scripts.ci_cinema_pg_q import make_verifier


class RoleConnectionTests(unittest.TestCase):
    def test_outside_codespace_blocks_without_reading_secrets(self):
        with patch.dict(os.environ, {"CODESPACES": "false"}), \
             patch.object(u, "read_password_file") as read:
            self.assertEqual(u.main(), 2)
            read.assert_not_called()

    def test_read_secret_requires_private_mode(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "secret.json"
            pw = "ab" * 32
            obj = {"role": u.ROLE, "password": pw, "verifier": make_verifier(pw)}
            path.write_text(json.dumps(obj), encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(u.read_password_file(path), pw)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                u.read_password_file(path)

    def test_scram_verifier_mismatch_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "secret.json"
            pw = "ab" * 32
            path.write_text(json.dumps({"role": u.ROLE, "password": pw,
                                        "verifier": make_verifier("cd" * 32)}))
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                u.read_password_file(path)

    def test_no_credentials_in_failure_message(self):
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(u, "read_password_file", side_effect=ValueError("super-secret-value")):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(u.main(), 2)
            self.assertNotIn("super-secret-value", out.getvalue())

    def test_check_connection_identity_mismatch_blocks_before_role_facts(self):
        from contextlib import nullcontext
        class Connection:
            def transaction(self):
                return nullcontext()
            def execute(self, sql):
                if sql.startswith("SELECT"):
                    return self
                return None
            def fetchone(self):
                return ("postgres", "postgres", "postgres", 170011, "on")
        with patch.object(u, "fetch_role_facts") as facts:
            ok, violations = u.check_connection(Connection())
            self.assertFalse(ok)
            self.assertEqual(violations, ["identity_or_readonly"])
            facts.assert_not_called()

    def test_identity_pinned_and_role_not_broadened(self):
        self.assertEqual(u.PROJECT_REF, "rvymwwzclagvljnofyss")
        self.assertEqual(u.HOST, "aws-0-ap-northeast-2.pooler.supabase.com")
        self.assertEqual(u.PORT, 5432)
        self.assertEqual(u.ROLE, "jw_backup_ro")


if __name__ == "__main__":
    unittest.main()
