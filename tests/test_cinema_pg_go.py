"""Mobile owner readiness wrapper: pure security tests, no live Supabase operations."""
import json
import os
import subprocess
from unittest.mock import patch

from scripts import ci_cinema_pg_go as go


def done(code=0, output=""):
    return subprocess.CompletedProcess([], code, output, "")


def test_only_exact_known_untracked_certificate_is_allowed():
    assert go.classify_checkout_status("") == "OK"
    assert go.classify_checkout_status("?? .github/supabase-root-2021.cer\n") == "OK"
    for text in (
        " M app/main.py\n", "?? scripts/fake.py\n",
        "?? .github/supabase-root-2021.cer\n?? scripts/evil.py\n",
        "?? .github/supabase-root-2021.cer.bak\n",
        "?? scripts/__init__.py\n",
        "A  .github/supabase-root-2021.cer\n",
    ):
        assert go.classify_checkout_status(text) == "UNEXPECTED_WORKTREE_CHANGE"


def test_branch_and_exact_remote_head_pins_refuse_divergence():
    head = "a" * 40
    def fake_git(*args, **kwargs):
        cmd = " ".join(args)
        if "--show-toplevel" in cmd:
            return done(output=str(go.ROOT) + "\n")
        if "--porcelain" in cmd:
            return done(output="?? .github/supabase-root-2021.cer\n")
        if args == ("rev-parse", "HEAD"):
            return done(output=head)
        if args == ("rev-parse", go.UPSTREAM):
            return done(output=head)
        if args == ("branch", "--show-current"):
            return done(output="jwb\n")
        return done()
    with patch.dict(os.environ, {"CODESPACES": "true"}), patch.object(go, "git", side_effect=fake_git):
        assert go.validate_owner_checkout() == head
        with patch.object(go, "git", side_effect=lambda *a, **kw: (
            done(output="b"*40) if a == ("rev-parse", go.UPSTREAM) else fake_git(*a, **kw)
        )):
            try:
                go.validate_owner_checkout()
                assert False, "must block stale remote"
            except ValueError as exc:
                assert str(exc) == "UPDATE_NEEDED_GIT_PULL_FF_ONLY"


def test_no_codespace_or_unexpected_arguments_blocks():
    with patch.dict(os.environ, {"CODESPACES": ""}):
        try:
            go.validate_owner_checkout()
            assert False, "should block"
        except ValueError as exc:
            assert str(exc) == "CODESPACE_REQUIRED"
    assert go.main(["--run"]) == 2


def test_unknown_container_never_started():
    malformed = [{"Name": "/jw-v223-restore", "Config": {"Image": "postgres:17"},
                  "HostConfig": {"PortBindings": {"5432/tcp": [
                      {"HostIp": "0.0.0.0", "HostPort": "55432"}] }},
                  "State": {"Running": False}}]
    commands = []
    def fake_command(*args, **kwargs):
        commands.append(args)
        if args[0] == "pg_isready":
            return done(2)
        if "inspect" in args:
            return done(output=json.dumps(malformed))
        raise AssertionError("must not start an unknown/publicly-bound target")
    with patch.object(go, "command", side_effect=fake_command):
        assert go.start_verified_disposable() is False
    assert not any("start" in a for a in commands)


def test_known_local_pg17_is_safe_to_restart_without_recreating():
    valid = [{"Name": "/jw-v223-restore", "Config": {"Image": "postgres:17"},
              "HostConfig": {"PortBindings": {"5432/tcp": [
                  {"HostIp": "127.0.0.1", "HostPort": "55432"}] }},
              "State": {"Running": False}}]
    calls = []
    def fake(*args, **kwargs):
        calls.append(args)
        if args[0] == "pg_isready":
            return done(0 if any("start" in a for a in calls) else 2)
        if "inspect" in args:
            return done(output=json.dumps(valid))
        if "start" in args:
            return done()
        raise AssertionError(args)
    with patch.object(go, "command", side_effect=fake):
        assert go.start_verified_disposable()
    assert sum("start" in a for a in calls) == 1
    assert not any("run" in a or "rm" in a for a in calls)


def test_docker_service_restarted_only_in_codespace_when_missing():
    calls = []
    def fake(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("docker", "info"):
            return done(1)
        if args[:4] == ("sudo", "-n", "service", "docker"):
            return done()
        raise AssertionError(args)
    with patch.dict(os.environ, {"CODESPACES": "true"}), patch.object(go, "command", side_effect=fake):
        assert go.ensure_local_docker_daemon() is None
    assert len(calls) == 2
    calls.clear()
    with patch.dict(os.environ, {"CODESPACES": ""}), patch.object(go, "command", side_effect=fake):
        assert go.ensure_local_docker_daemon() is None
    assert calls == []


def test_live_mode_needs_explicit_owner_tty_and_never_opens_a_worktree_without_it():
    with patch.object(go, "validate_owner_checkout", return_value="a" * 40), \
         patch.object(go.sys.stdin, "isatty", return_value=False), \
         patch.object(go, "git", side_effect=AssertionError("must not run git")):
        assert go.outer(execute_live=True) == 2


def test_live_source_connection_is_never_attempted_without_no_charge_confirmation():
    with patch.dict(os.environ, {"JW_OWNER_NO_CHARGE_VERIFIED": "", "JW_PG_ADMIN_DSN": "unused"}):
        assert go.check_live_admin_login() is False


def test_live_entrypoint_must_delegate_to_original_approved_runner():
    import inspect
    source = inspect.getsource(go.inner)
    assert "runner.main([" in source
    assert '"--confirm-approval", "6755130318"' in source
    assert '"--confirm-no-charge"' in source
    assert "runner.run_all(" not in source
    assert 'print("URGENT_ROLE_REVOCATION_NOT_VERIFIED")' in source


def test_port_answering_is_not_proof_of_container_identity():
    wrong = [{"Name": "/other-container", "Config": {"Image": "postgres:17"},
              "HostConfig": {"PortBindings": {"5432/tcp": [
                  {"HostIp": "127.0.0.1", "HostPort": "55432"}]}},
              "State": {"Running": True}}]
    def fake_command(*args, **kwargs):
        if "inspect" in args:
            return done(output=json.dumps(wrong))
        if args[0] == "pg_isready":
            raise AssertionError("Never trust port alone; inspect identity first")
        raise AssertionError(args)
    with patch.object(go, "command", side_effect=fake_command):
        assert go.start_verified_disposable() is False



def test_private_blocker_codes_are_secret_free_and_precise(tmp_path):
    from scripts import ci_cinema_pg_v223_codespace_run as runner
    local_files = [tmp_path / name for name in ("auth.json", "ca.crt", "restore.sh")]
    for item in local_files:
        item.write_text("TEST ONLY", encoding="utf-8")
        item.chmod(0o600)
    host = runner.HOST
    ref = runner.PROJECT_REF
    good = (f"postgresql://postgres.{ref}:SYNTHETIC_VALUE"
            f"@{host}:5432/postgres?sslmode=verify-full"
            f"&sslrootcert={local_files[1]}")
    env = {"JW_PG_ADMIN_DSN": good, "JW_PG_BACKUP_KEY": "FAKE"}
    with patch.object(runner, "CREDS", local_files[0]), \
         patch.object(runner, "CERT_FILE", local_files[1]), \
         patch.object(runner, "SECRET_FILE", local_files[2]):
        assert go.private_blocker_codes(env) == []
        fail = go.private_blocker_codes({
            **env,
            "JW_PG_ADMIN_DSN": good.replace("sslmode=verify-full", "sslmode=require"),
        })
        assert fail == ["ADMIN_DSN_SSLMODE"]
        fail = go.private_blocker_codes({
            **env,
            "JW_PG_ADMIN_DSN": good.replace(str(local_files[1]), "/wrong/ca"),
        })
        assert fail == ["ADMIN_DSN_CA_PATH"]
        fail = go.private_blocker_codes({
            **env,
            "JW_PG_ADMIN_DSN": good.replace(host, "hostile.invalid"),
        })
        assert "ADMIN_DSN_HOST" in fail
        fail = go.private_blocker_codes({
            **env,
            "JW_PG_ADMIN_DSN": good.replace(":SYNTHETIC_VALUE@", ":[YOUR-PASSWORD]@"),
        })
        assert "ADMIN_DSN_PASSWORD_MISSING_OR_PLACEHOLDER" in fail
        fail = go.private_blocker_codes({
            **env,
            "JW_PG_ADMIN_DSN": good + "&hostaddr=127.0.0.1",
        })
        assert fail == ["ADMIN_DSN_QUERY_PARAMS"]
        fail = go.private_blocker_codes({
            **env,
            "JW_PG_ADMIN_DSN": good.replace(":SYNTHETIC_VALUE@", ":SYNTHE#TIC@"),
        })
        assert "ADMIN_DSN_UNENCODED_HASH" in fail
        local_files[0].chmod(0o644)
        fail = go.private_blocker_codes(env)
        assert "BACKUP_AUTH_FILE_PERMISSIONS" in fail
        assert all("SYNTHETIC_VALUE" not in label and host not in label
                   for label in fail)


def test_private_diagnosis_never_echoes_connection_secret(capsys):
    fake = "postgresql://postgres:TOPSECRET@example.invalid/postgres"
    result = go.private_blocker_codes({"JW_PG_ADMIN_DSN": fake})
    assert result
    assert "TOPSECRET" not in repr(result)
    assert "example.invalid" not in repr(result)
    assert capsys.readouterr().out == ""



def test_unsupported_and_incomplete_admin_urls_are_classified_without_secret_leaks():
    from scripts import ci_cinema_pg_v223_codespace_run as runner
    from scripts import pg_backup_v223
    env = {"JW_PG_ADMIN_DSN": "https://postgres:SECRET@example.com/postgres"}
    assert "ADMIN_DSN_SCHEME" in go.private_blocker_codes(env)
    env["JW_PG_ADMIN_DSN"] = "postgresql:///postgres"
    assert "ADMIN_DSN_HOST_MISSING" in go.private_blocker_codes(env)
    env["JW_PG_ADMIN_DSN"] = "postgresql://postgres:SECRET@[broken/postgres"
    assert "ADMIN_DSN_URL_MALFORMED" in go.private_blocker_codes(env)
    env["JW_PG_ADMIN_DSN"] = ("postgresql://postgres:SECRET@"
                              + runner.HOST + ":5432/postgres?sslmode=verify-full")
    with patch.object(pg_backup_v223, "parse_dsn",
                      side_effect=pg_backup_v223.BackupError("secret must never print")):
        codes = go.private_blocker_codes(env)
    assert "ADMIN_DSN_STRUCTURE_REJECTED" in codes
    assert "SECRET" not in repr(codes)
    assert "secret must never print" not in repr(codes)


def test_live_diagnosis_without_approval_never_connects():
    with patch.dict(os.environ, {"JW_OWNER_NO_CHARGE_VERIFIED": ""}):
        assert go.diagnose_live_admin_login() == "NO_CHARGE_NOT_CONFIRMED"


def test_live_diagnosis_fixed_labels_and_no_secret_output(capsys):
    import sys
    import types
    class FakeConn:
        def __init__(self, row): self.row = row
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def execute(self, sql): return self
        def fetchone(self): return self.row
    class DBError(Exception):
        def __init__(self, state):
            super().__init__("SECRET_DSN_MUST_NOT_LEAK")
            self.sqlstate = state
    rows = [
        (("postgres", "postgres", 170011, True), "PASS"),
        (("postgres.bad", "postgres", 170011, True), "WRONG_ADMIN_ROLE"),
        (("postgres", "other", 170011, True), "WRONG_DATABASE"),
        (("postgres", "postgres", 160011, True), "WRONG_PG_VERSION"),
        (("postgres", "postgres", 170011, None), "BACKUP_ROLE_NOT_FOUND_OR_UNSAFE_STATE"),
        (("postgres", "postgres", 170011, False), "BACKUP_ROLE_ACTIVE_OR_OUTSIDE_APPROVAL"),
    ]
    with patch.dict(os.environ, {"JW_OWNER_NO_CHARGE_VERIFIED": "1", "JW_PG_ADMIN_DSN": "SYNTHETIC_SECRET"}):
        for row, expected in rows:
            with patch.dict(sys.modules, {"psycopg": types.SimpleNamespace(connect=lambda *a, **kw: FakeConn(row))}):
                assert go.diagnose_live_admin_login() == expected
        for state, expected in [("28P01", "PASSWORD_AUTH_REJECTED"),
                                ("28000", "ROLE_AUTH_REJECTED"),
                                ("42501", "INSUFFICIENT_PRIVILEGE"),
                                ("08001", "CONNECTION_REJECTED"),
                                ("XXXXX", "DB_CONNECT_OR_QUERY_FAILURE")]:
            def fail(*a, **kw): raise DBError(state)
            with patch.dict(sys.modules, {"psycopg": types.SimpleNamespace(connect=fail)}):
                assert go.diagnose_live_admin_login() == expected
    output = capsys.readouterr().out
    assert "SECRET" not in output


def test_renew_sql_has_atomic_login_and_closure_guard():
    from scripts import ci_cinema_pg_v223_codespace_run as runner
    sql = runner.TEMP_LOGIN_SQL.read_text(encoding="utf-8")
    assert "NOT rolcanlogin" in sql
    assert "pg_stat_activity" in sql
    assert "ALTER ROLE jw_backup_ro VALID UNTIL :'valid_until' LOGIN;" in sql
    assert "BEGIN;" in sql and "COMMIT;" in sql
    assert " LOGIN;" not in runner.RENEW_SQL.read_text(encoding="utf-8")
    revoke = runner.REVOKE_SQL.read_text(encoding="utf-8")
    assert "ALTER ROLE jw_backup_ro NOLOGIN;" in revoke


def test_precheck_requires_disabled_role_and_no_sessions():
    import inspect
    source = inspect.getsource(go.diagnose_live_admin_login)
    assert "NOT rolcanlogin" in source
    assert "pg_stat_activity" in source
    assert "2026-11-11 09:00:00+09" in source
