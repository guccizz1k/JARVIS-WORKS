"""Fail-closed no-secret tests for the direct endpoint probe."""
from __future__ import annotations

import contextlib
import io
import os
import socket
import struct
import unittest
from unittest.mock import patch

from scripts import ci_cinema_pg_n as p


class DirectNetworkProbeTests(unittest.TestCase):
    def test_ssl_request_exact_postgresql_protocol(self):
        self.assertEqual(p.PG_SSL_REQUEST, struct.pack("!II", 8, 80877103))

    def test_restrict_host_to_known_dev_project(self):
        self.assertEqual(p.SOURCE_HOST, "db.rvymwwzclagvljnofyss.supabase.co")
        self.assertEqual(p.SOURCE_PORT, 5432)

    def test_not_codespaces_no_network_call(self):
        out = io.StringIO()
        with patch.dict(os.environ, {"CODESPACES": "false"}), patch.object(p, "addresses") as addr:
            with contextlib.redirect_stdout(out):
                self.assertEqual(p.main(), 2)
            addr.assert_not_called()

    def test_ipv6_unavailable_fails_closed(self):
        out = io.StringIO()
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(p, "addresses", return_value=(True, False, [(1, 1, 1, "", ("::1", 5432))])), \
             patch.object(p, "probe_tls", side_effect=OSError("private-dsn-should-not-show")):
            with contextlib.redirect_stdout(out):
                self.assertEqual(p.main(), 2)
        self.assertIn("BLOCKED", out.getvalue())
        self.assertNotIn("private-dsn-should-not-show", out.getvalue())

    def test_tls_verified_is_network_only(self):
        out = io.StringIO()
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(p, "addresses", return_value=(True, False, [(1, 1, 1, "", ("::1", 5432))])), \
             patch.object(p, "probe_tls", return_value="TLS_CA_HOSTNAME_VERIFIED"):
            with contextlib.redirect_stdout(out):
                self.assertEqual(p.main(), 0)
        self.assertIn("NETWORK_READY_ONLY", out.getvalue())
        self.assertNotIn("BACKUP_PASS", out.getvalue())


if __name__ == "__main__":
    unittest.main()
