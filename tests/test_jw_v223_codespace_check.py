"""Verify the read-only Codespaces preflight is fail closed and secret silent."""
from __future__ import annotations

import contextlib
import io
import os
import unittest
from unittest.mock import patch
from scripts.ops import jw_v223_codespace_check as c


class CodespacePreflight(unittest.TestCase):
    def test_unknown_client_is_not_ready(self):
        with patch.object(c.shutil, "which", return_value=None):
            self.assertEqual(c._major("pg_dump"), 0)

    def test_never_reports_ready_outside_codespaces(self):
        with patch.dict(os.environ, {"CODESPACES": "false"}, clear=False):
            self.assertFalse(c.check()["codespaces"])

    def test_status_output_never_emits_secrets(self):
        with patch.object(c, "check", return_value={"codespaces": False, "dummy": False}), \
             patch.dict(os.environ, {"JW_PG_SOURCE_DSN":
                        "postgresql://secret-user:sensitive-password@secret.example/postgres"},
                        clear=False):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = c.main()
            self.assertEqual(code, 2)
            self.assertNotIn("sensitive-password", buf.getvalue())
            self.assertNotIn("secret-user", buf.getvalue())

    def test_ready_is_tools_only(self):
        with patch.object(c, "check", return_value={"codespaces": True}):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(c.main(), 0)
            self.assertIn("TOOLS_READY_ONLY", buf.getvalue())
            self.assertNotIn("REAL_BACKUP_PASS", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
