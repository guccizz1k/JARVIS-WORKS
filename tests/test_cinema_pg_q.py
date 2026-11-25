"""Temporary backup account password material: deterministic SCRAM and safety checks."""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
from datetime import timedelta
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout

from scripts import ci_cinema_pg_q as q


class ScramSafety(unittest.TestCase):
    def test_wrong_inputs_rejected(self):
        with self.assertRaises(ValueError):
            q.make_verifier("short")
        with self.assertRaises(ValueError):
            q.make_verifier("a" * 64, salt=b"x")

    def test_scram_verifier_standard_keys(self):
        password = "ab" * 32
        salt = bytes(range(16))
        verifier = q.make_verifier(password, salt)
        self.assertTrue(verifier.startswith("SCRAM-SHA-256$4096:"))
        i, part = verifier.split("$", 2)[1:]
        self.assertEqual(i, "4096:" + base64.b64encode(salt).decode())
        stored, server = part.split(":")
        salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 4096)
        client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        self.assertEqual(base64.b64decode(stored), hashlib.sha256(client_key).digest())
        self.assertEqual(base64.b64decode(server), hmac.new(salted, b"Server Key", hashlib.sha256).digest())

    def test_local_secrets_mode_and_idempotence(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/"secret.json"
            a = q.load_or_create(file)
            b = q.load_or_create(file)
            self.assertEqual(a, b)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            self.assertEqual(len(a["password"]), 64)
            self.assertNotIn(a["password"], a["verifier"])

    def test_insecure_file_denied(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/"secret.json"
            q.load_or_create(file)
            file.chmod(0o644)
            with self.assertRaises(ValueError):
                q.load_or_create(file)

    def test_symlink_denied(self):
        with tempfile.TemporaryDirectory() as d:
            real = Path(d)/"original"
            real.write_text("bad")
            link = Path(d)/"link"
            link.symlink_to(real)
            with self.assertRaises(ValueError):
                q.load_or_create(link)

    def test_no_credential_is_generated_at_or_after_the_approved_expiry(self):
        for offset in (timedelta(0), timedelta(hours=1), timedelta(days=30)):
            with patch.dict(os.environ, {"CODESPACES": "true"}), patch.object(q, "datetime") as clock, \
                 patch.object(q, "load_or_create") as f:
                clock.now.return_value = q.EXPIRY + offset
                self.assertEqual(q.main(), 2)
                f.assert_not_called()

    def test_outside_codespace_no_secret_generation(self):
        with patch.dict(os.environ, {"CODESPACES": "false"}), patch.object(q, "load_or_create") as f:
            self.assertEqual(q.main(), 2)
            f.assert_not_called()

    def test_password_not_printed(self):
        # The clock is frozen one hour before the approved expiry: this test must not depend on the date it runs on.
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(q, "datetime") as clock, \
             patch.object(q, "load_or_create", return_value={"verifier": q.make_verifier("ab"*32), "password": "ab"*32}):
            clock.now.return_value = q.EXPIRY - timedelta(hours=1)
            out = io.StringIO()
            with redirect_stdout(out):
                result=q.main()
            self.assertEqual(result, 0)
            self.assertNotIn("ab"*32, out.getvalue())
            self.assertIn("ALTER ROLE jw_backup_ro PASSWORD 'SCRAM-SHA-256$",out.getvalue())


if __name__ == "__main__":
    unittest.main()
