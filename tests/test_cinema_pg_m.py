"""Read-only and fail-closed checks of mobile-friendly disposable target marker."""
from __future__ import annotations

import contextlib
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import ci_cinema_pg_m as m


class MarkerGate(unittest.TestCase):
    def test_refuses_outside_codespace(self):
        with patch.dict(os.environ, {"CODESPACES": "false"}), \
                patch.object(m, "read_private_target") as read:
            self.assertEqual(m.main(), 2)
            read.assert_not_called()

    def test_private_file_exact_three_keys(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "local"
            p.write_text(
                "# only local\n"
                "export JW_PG_TARGET_ADMIN_DSN='postgresql://postgres:secret@127.0.0.1:55432/postgres'\n"
                "export JW_PG_TARGET_EPHEMERAL_TOKEN='0123456789abcdef0123456789abcdef'\n"
                "export JW_PG_CI_ALLOW='ONLY_EPHEMERAL_LOCAL_DATABASE'\n",
                encoding="utf-8",
            )
            p.chmod(0o600)
            cfg = m.read_private_target(p)
            self.assertEqual(cfg["JW_PG_CI_ALLOW"], "ONLY_EPHEMERAL_LOCAL_DATABASE")
            p.chmod(0o644)
            with self.assertRaises(ValueError):
                m.read_private_target(p)

    def test_extra_export_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "local"
            p.write_text("export JW_PG_SOURCE_DSN='postgresql://secret@danger'\n", encoding="utf-8")
            p.chmod(0o600)
            with self.assertRaises(ValueError):
                m.read_private_target(p)

    def test_symlink_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "original"
            p.write_text("stub")
            x = Path(d) / "link"
            x.symlink_to(p)
            with self.assertRaises(ValueError):
                m.read_private_target(x)

    def test_no_stdout_secret_on_config_failure(self):
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(m, "read_private_target", side_effect=ValueError("secret-password")):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                result = m.main()
            self.assertEqual(result, 2)
            self.assertNotIn("secret-password", buf.getvalue())

if __name__ == "__main__":
    unittest.main()
