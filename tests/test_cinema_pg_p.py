"""IPv4 session-pooler probe is read-only, fail-closed, and doesn't assume tenant binding."""
from __future__ import annotations

import contextlib
import io
import os
import socket
import unittest
from unittest.mock import patch

from scripts import ci_cinema_pg_p as p


class SharedPoolerNetworkProbeTests(unittest.TestCase):
    def test_no_network_outside_codespace(self):
        with patch.dict(os.environ, {"CODESPACES": "false"}), patch.object(p, "check") as probe:
            self.assertEqual(p.main(), 2)
            probe.assert_not_called()

    def test_session_port_not_transaction_port(self):
        self.assertEqual(p.PORT, 5432)
        self.assertTrue(all(host.endswith(".pooler.supabase.com") for host in p.CANDIDATES))
        self.assertEqual(len(p.CANDIDATES), 2)

    def test_no_secret_or_sql_access(self):
        from pathlib import Path
        body = Path(p.__file__).read_text(encoding="utf-8")
        self.assertNotIn("PGPASSWORD", body)
        self.assertNotIn("psycopg.connect", body)
        self.assertNotIn("execute_sql", body)
        self.assertNotIn("CREATE ROLE", body)

    def test_positive_is_network_only(self):
        out = io.StringIO()
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(p, "check", side_effect=["TCP_SSL_CA_VERIFIED", "IPV4_DNS_UNAVAILABLE"]), \
             contextlib.redirect_stdout(out):
            self.assertEqual(p.main(), 0)
        self.assertIn("POOLER_IPV4_NETWORK_ONLY=PASS", out.getvalue())
        self.assertIn("TENANT_BINDING=NOT_VERIFIED", out.getvalue())

    def test_no_address_all_fail_closed(self):
        out = io.StringIO()
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(p, "check", return_value="IPV4_TCP_UNREACHABLE"), \
             contextlib.redirect_stdout(out):
            self.assertEqual(p.main(), 2)
        self.assertIn("POOLER_IPV4_NETWORK_ONLY=BLOCKED", out.getvalue())

    def test_dns_failure_is_redacted(self):
        with patch.object(p.socket, "getaddrinfo", side_effect=socket.gaierror("private internal details")):
            self.assertEqual(p.check(p.CANDIDATES[0]), "IPV4_DNS_UNAVAILABLE")

    def test_tls_probe_uses_provided_hostname(self):
        fake = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.2", 5432))
        with patch.object(p.socket, "getaddrinfo", return_value=[fake]), \
             patch.object(p, "probe_tls", return_value="TLS_CA_HOSTNAME_VERIFIED") as tls:
            self.assertEqual(p.check(p.CANDIDATES[0]), "TCP_SSL_CA_VERIFIED")
        tls.assert_called_once_with(fake, host=p.CANDIDATES[0])


if __name__ == "__main__":
    unittest.main()
