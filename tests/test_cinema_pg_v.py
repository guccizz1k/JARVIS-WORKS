"""No network in CI: bounded, authenticated IPv4 selection and psql state tests."""
from __future__ import annotations
import os
import ssl
import subprocess
import unittest
from unittest.mock import patch
from scripts import ci_cinema_pg_v as d


class Diagnostics(unittest.TestCase):
    def test_source_never_touches_outside_codespaces(self):
        with patch.dict(os.environ,{"CODESPACES":"false"}), patch.object(d,"probe_login") as run:
            self.assertEqual(d.main(),2)
            run.assert_not_called()

    def test_error_taxonomy_redacted(self):
        for message,expected in [
            ("FATAL: password authentication failed for user x", "AUTH_PASSWORD_REJECTED"),
            ("timeout to secret-host", "PSQL_CONNECTION_TIMEOUT"),
            ("FATAL: tenant or user not found", "POOLER_TENANT_OR_USER_REJECTED"),
            ("unknown password value", "PSQL_OTHER_CONNECTION_ERROR"),
        ]:
            result=d.classify_failure(message)
            self.assertEqual(result,expected)
            self.assertNotIn("secret",result)

    def test_verifier_route_missing_denies_login(self):
        with patch("shutil.which",return_value="/usr/bin/psql"), \
             patch.object(d,"read_password_file",return_value="secret"), \
             patch.object(d,"load_dashboard_ca"), \
             patch.object(d,"verified_ipv4",return_value=None), \
             patch.object(d,"try_psql") as try_psql:
            self.assertEqual(d.probe_login(),"NO_VERIFIED_IPV4_ROUTE")
            try_psql.assert_not_called()

    def test_verified_session_success_does_not_try_transaction(self):
        with patch("shutil.which",return_value="/usr/bin/psql"), \
             patch.object(d,"read_password_file",return_value="secret"), \
             patch.object(d,"load_dashboard_ca"), \
             patch.object(d,"verified_ipv4",return_value="192.0.2.1"), \
             patch.object(d,"try_psql",return_value="PSQL_LIVE_LOGIN_OK") as run:
            self.assertEqual(d.probe_login(),"PSQL_LIVE_LOGIN_OK")
            run.assert_called_once_with("secret","192.0.2.1",5432)

    def test_transaction_success_is_not_backup_pass(self):
        with patch("shutil.which",return_value="/usr/bin/psql"), \
             patch.object(d,"read_password_file",return_value="secret"), \
             patch.object(d,"load_dashboard_ca"), \
             patch.object(d,"verified_ipv4",return_value="192.0.2.1"), \
             patch.object(d,"try_psql",side_effect=["PSQL_PROCESS_TIMEOUT","PSQL_LIVE_LOGIN_OK"]) as run:
            self.assertEqual(d.probe_login(),"TRANSACTION_LOGIN_OK_SESSION_PSQL_PROCESS_TIMEOUT")
            self.assertEqual(run.call_count,2)

    def test_auth_failure_does_not_repeat_against_pooler(self):
        with patch("shutil.which",return_value="/usr/bin/psql"), \
             patch.object(d,"read_password_file",return_value="secret"), \
             patch.object(d,"load_dashboard_ca"), \
             patch.object(d,"verified_ipv4",return_value="192.0.2.1"), \
             patch.object(d,"try_psql",return_value="AUTH_PASSWORD_REJECTED") as run:
            self.assertEqual(d.probe_login(),"SESSION_AUTH_PASSWORD_REJECTED")
            run.assert_called_once()

    def test_psql_password_only_in_environment_and_hostname_verified(self):
        mocked=subprocess.CompletedProcess([],0,stdout="jw_backup_ro|jw_backup_ro|postgres|170011\\n",stderr="")
        with patch.object(d.subprocess,"run",return_value=mocked) as run:
            self.assertEqual(d.try_psql("private-password","192.0.2.1",5432),"PSQL_LIVE_LOGIN_OK")
        args,kwargs=run.call_args
        self.assertNotIn("private-password",str(args))
        self.assertEqual(kwargs["env"]["PGHOST"],d.HOST)
        self.assertEqual(kwargs["env"]["PGHOSTADDR"],"192.0.2.1")
        self.assertEqual(kwargs["env"]["PGSSLMODE"],"verify-full")
        self.assertEqual(kwargs["env"]["PGGSSENCMODE"],"disable")

    def test_psql_hard_deadline(self):
        with patch.object(d.subprocess,"run",side_effect=subprocess.TimeoutExpired(["psql"],12)):
            self.assertEqual(d.try_psql("secret","192.0.2.1",5432),"PSQL_PROCESS_TIMEOUT")

    def test_no_verifier_logs_in_main_failure(self):
        with patch.dict(os.environ,{"CODESPACES":"true"}), patch.object(d,"probe_login",side_effect=ValueError("secret")):
            self.assertEqual(d.main(),2)


if __name__ == "__main__":
    unittest.main()
