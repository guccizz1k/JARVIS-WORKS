"""No source access in CI: negative and positive state tests for non-secret login probe."""
from __future__ import annotations
from contextlib import redirect_stdout
import io
import os
import unittest
from unittest.mock import patch
from scripts import ci_cinema_pg_v as d

class Diagnostics(unittest.TestCase):
    def test_wrong_environment_never_reads_password(self):
        with patch.dict(os.environ, {"CODESPACES": "false"}), patch.object(d, "probe_login") as conn:
            self.assertEqual(d.main(), 2)
            conn.assert_not_called()

    def test_diagnostic_failure_redacts_raw_message(self):
        for sample, expected in [
            ("FATAL: password authentication failed for user jw_backup_ro", "AUTH_PASSWORD_REJECTED"),
            ("connection timed out: sensitive-host", "PSQL_CONNECTION_TIMEOUT"),
            ("FATAL: tenant or user not found", "POOLER_TENANT_OR_USER_REJECTED"),
            ("could not translate host name", "DNS_FAILURE"),
            ("unknown secret password here", "PSQL_OTHER_CONNECTION_ERROR"),
        ]:
            value = d.classify_failure(sample)
            self.assertEqual(value, expected)
            self.assertNotIn("sensitive-host", value)
            self.assertNotIn("secret", value)

    def test_success_message_only_login_not_backup(self):
        out=io.StringIO()
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(d, "probe_login", return_value="PSQL_LIVE_LOGIN_OK"), \
             redirect_stdout(out):
            self.assertEqual(d.main(), 0)
        self.assertIn("SOURCE_AUTH_NETWORK_ONLY_PASS", out.getvalue())
        self.assertNotIn("BACKUP_PASS", out.getvalue())

    def test_timeout_classified_not_masked_as_auth(self):
        out=io.StringIO()
        with patch.dict(os.environ, {"CODESPACES": "true"}), \
             patch.object(d, "probe_login", return_value="PSQL_PROCESS_TIMEOUT"), \
             redirect_stdout(out):
            self.assertEqual(d.main(), 2)
        self.assertIn("SOURCE_PSQL_DIAGNOSTIC=PSQL_PROCESS_TIMEOUT", out.getvalue())

    def test_network_tls_gate_before_process(self):
        from unittest.mock import MagicMock
        cert = MagicMock()
        cert.read_bytes.return_value=b"pem"
        with patch.object(d, "read_password_file", return_value="longsecret"), \
             patch.object(d, "load_dashboard_ca"), \
             patch.object(d, "CERT_FILE", cert), \
             patch.object(d, "verify_tls", return_value="TLS_NOT_VERIFIED"), \
             patch.object(d.shutil if hasattr(d,'shutil') else __import__('shutil'), "which", return_value="/usr/bin/psql"), \
             patch.object(d.subprocess, "run") as run:
            self.assertEqual(d.probe_login(), "TLS_NOT_VERIFIED")
            run.assert_not_called()

    def test_process_environment_no_password_in_args(self):
        import subprocess
        fake=subprocess.CompletedProcess([],0,stdout="jw_backup_ro|jw_backup_ro|postgres|170011\n",stderr="")
        with patch.object(d,"read_password_file",return_value="private-password"), \
             patch.object(d,"load_dashboard_ca"), \
             patch.object(d.CERT_FILE.__class__,"read_bytes",return_value=b"pem"), \
             patch.object(d,"verify_tls",return_value="CA_CHAIN_AND_HOST_VERIFIED"), \
             patch("shutil.which",return_value="/usr/bin/psql"), \
             patch.object(d.subprocess,"run",return_value=fake) as run:
            self.assertEqual(d.probe_login(),"PSQL_LIVE_LOGIN_OK")
        args, kwargs = run.call_args
        self.assertNotIn("private-password", str(args))
        self.assertIn("private-password", str(kwargs["env"]["PGPASSWORD"]))
        self.assertEqual(kwargs["env"]["PGSSLMODE"],"verify-full")
        self.assertEqual(kwargs["env"]["PGUSER"],"jw_backup_ro.rvymwwzclagvljnofyss")
        self.assertIn("ON_ERROR_STOP=1",args[0])

if __name__ == "__main__":
    unittest.main()
