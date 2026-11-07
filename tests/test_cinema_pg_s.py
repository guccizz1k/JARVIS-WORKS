"""Verify official-host-only, CA-only, fail-closed TLS diagnostic."""
from __future__ import annotations

import contextlib
import io
import os
import ssl
import unittest
from unittest.mock import patch

from scripts import ci_cinema_pg_s as s

class VerifiedCAGate(unittest.TestCase):
    def test_fixed_real_dashboard_host(self):
        self.assertEqual(s.HOST, "aws-0-ap-northeast-2.pooler.supabase.com")
        self.assertEqual(s.PORT, 5432)
        self.assertEqual(s.SSL_REQUEST, bytes.fromhex("0000000804d2162f"))

    def test_missing_dashboard_ca_fails_closed(self):
        with patch.object(s.CERT_FILE, "is_symlink", return_value=False), \\
             patch.object(s.CERT_FILE, "is_file", return_value=False):
            with self.assertRaises(ValueError):
                s.load_dashboard_ca()

    def test_outside_codespaces_denied(self):
        with patch.dict(os.environ, {"CODESPACES": "false"}), \
             patch.object(s, "load_dashboard_ca") as f:
            self.assertEqual(s.main(), 2)
            f.assert_not_called()

    def test_ca_parser_rejects_html(self):
        with self.assertRaises(ValueError):
            s.validate_ca(b"<html>not a cert</html>")

    def test_ca_parser_rejects_unbounded(self):
        with self.assertRaises(ValueError):
            s.validate_ca(b"-----BEGIN CERTIFICATE-----" + b"a" * s.MAX_CERT_BYTES)

    def test_nothing_printed_from_secret_exception(self):
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(s, "load_dashboard_ca", side_effect=ValueError("veryprivate")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(s.main(), 2)
            self.assertNotIn("veryprivate", out.getvalue())

    def test_tls_pass_is_network_only(self):
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(s, "load_dashboard_ca", return_value=b"pem"), \
             patch.object(s, "verify_tls", return_value="CA_CHAIN_AND_HOST_VERIFIED"):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(s.main(), 0)
            self.assertIn("NETWORK_TLS_READY_ONLY", out.getvalue())
            self.assertIn("real database backup NOT RUN", out.getvalue())

    def test_nonverified_tls_denies(self):
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(s, "load_dashboard_ca", return_value=b"pem"), \
             patch.object(s, "verify_tls", return_value="CERT_CHAIN_STILL_INVALID"):
            self.assertEqual(s.main(), 2)

if __name__ == "__main__":
    unittest.main()
