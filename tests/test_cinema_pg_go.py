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
