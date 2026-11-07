"""Codespaces restore target launcher: safety + fail-closed negative tests."""
from __future__ import annotations

import contextlib
import io
import os
import unittest
from unittest.mock import patch

from scripts import ci_cinema_pg_r as r


class LocalRestoreGate(unittest.TestCase):
    def run_quiet(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = r.main()
        return result, out.getvalue()

    def test_no_codespaces_never_touches_docker(self):
        with patch.dict(os.environ, {"CODESPACES": "false"}), patch.object(r, "docker") as d:
            code, msg = self.run_quiet()
        self.assertEqual(code, 2)
        self.assertIn("BLOCKED", msg)
        d.assert_not_called()

    def test_no_docker_never_touches_credentials(self):
        with patch.dict(os.environ, {"CODESPACES": "true"}), patch.object(r.shutil, "which", return_value=None), \
             patch.object(r, "docker") as d:
            code, msg = self.run_quiet()
        self.assertEqual(code, 2)
        d.assert_not_called()

    def test_existing_local_secret_does_not_launch(self):
        with patch.dict(os.environ, {"CODESPACES": "true"}), patch.object(r.shutil, "which", return_value="/usr/bin/docker"), \
             patch.object(r.SECRET_FILE, "exists", return_value=True), patch.object(r, "docker") as d:
            code, msg = self.run_quiet()
        self.assertEqual(code, 2)
        self.assertIn("already exists", msg)
        d.assert_not_called()

    def test_no_real_source_identifiers_in_script(self):
        from pathlib import Path
        body = Path(r.__file__).read_text()
        self.assertNotIn("JW_PG_SOURCE_DSN", body)
        self.assertNotIn("supabase.co", body)
        self.assertNotIn("BYPASSRLS", body)
        self.assertNotIn("CREATE ROLE", body)

    def test_image_and_binding_are_local_only(self):
        from pathlib import Path
        body = Path(r.__file__).read_text()
        self.assertIn('"127.0.0.1:55432:5432", "postgres:17"', body)
        self.assertIn('os.O_EXCL', body)
        self.assertIn('os.O_NOFOLLOW', body)


if __name__ == "__main__":
    unittest.main()
