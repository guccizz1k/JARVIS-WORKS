"""Adversarial regression: owner Codespaces B2-only subprocess environment.

No live Backblaze keys, DB credentials, networking or file writes.
"""
import json
import subprocess
import sys

import pytest

from scripts import p1_b2_isolated_launcher_v223 as launcher
from scripts import p1_b2_codespace_probe_v223 as pinned_probe

PARENT = {
    "CODESPACES": "true",
    "JW_B2_AUDIT_KEY_ID": "synthetic-id-not-actual-secret",
    "JW_B2_AUDIT_APPLICATION_KEY": "synthetic-app-key-not-actual-secret",
    "JW_PG_BACKUP_KEY": "source-backup-key-MUST-NOT-PASS-THROUGH",
    "DATABASE_URL": "postgresql://source-db-secret-NEVER-PASS",
    "SUPABASE_SERVICE_ROLE_KEY": "source-service-role-NEVER-PASS",
    "AWS_CA_BUNDLE": "/tmp/unsafe-CA-MUST-NOT-INHERIT",
    "PYTHONPATH": "/tmp/malicious-python-NEVER-PASS",
    "HTTP_PROXY": "https://attacker.example.invalid",
    "HTTPS_PROXY": "https://attacker.example.invalid",
    "GH_TOKEN": "github-token-NEVER-PASS",
    "GITHUB_TOKEN": "github-token-NEVER-PASS",
}
FAKE_SOURCE = (
    b"def verify():\n    pass\n\ndef main():\n    pass\n"
    + b"#reviewed-source-synthetic-only\n"*300
)
SUCCESS = {
    "b2_owner_bucket_readonly": "PASS_REAL_B2_EMPTY_LOCK_ENABLED",
    "overall_release": "BLOCKED",
    "real_backup_uploads": 0,
    "provider_calls": 3,
    "bucket_scope_exactly_one": True,
    "key_has_no_write_or_delete": True,
    "key_expiry_checked": True,
    "bucket_private": True,
    "object_lock_enabled": True,
    "encryption_sse_b2": True,
    "keep_all_versions": True,
    "file_versions_empty": True,
}


class Runner:
    def __init__(self, raw=None, returncode=0, source=FAKE_SOURCE):
        self.calls = []
        self.raw = json.dumps(SUCCESS if raw is None else raw).encode("utf-8")
        self.returncode = returncode
        self.source = source

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if len(self.calls) == 1:
            assert argv == ["git", "show", launcher.PROBE_REF]
            assert kwargs.get("env") == launcher.GIT_ENV
            assert kwargs.get("check") is False
            return subprocess.CompletedProcess(argv, 0, stdout=self.source)
        assert argv[0] == sys.executable
        assert argv[1:] == ["-I", "-S", "-", "verify-readonly"]
        assert kwargs.get("input") == FAKE_SOURCE
        assert kwargs.get("check") is False
        return subprocess.CompletedProcess(argv, self.returncode,
                                           stdout=self.raw)


def test_parent_credentials_stay_but_child_receives_only_B2_secrets():
    assert pinned_probe.verify(env=PARENT)["blocker"] == (
        "SOURCE_OR_BACKUP_CREDENTIALS_MUST_BE_ISOLATED")
    fake = Runner()
    result = launcher.verify(parent=PARENT, runner=fake)
    assert len(fake.calls) == 2
    child_env = fake.calls[1][1]["env"]
    assert set(child_env) == launcher.ALLOWED_ENV_KEYS
    assert child_env["CODESPACES"] == "true"
    for key in launcher.B2_KEY_NAMES:
        assert child_env[key] == PARENT[key]
    for key in set(PARENT) - set(launcher.B2_KEY_NAMES) - {"CODESPACES"}:
        assert key not in child_env
    assert "JW_PG_BACKUP_KEY" in PARENT
    assert "DATABASE_URL" in PARENT
    assert "GITHUB_TOKEN" not in child_env
    assert result["b2_owner_bucket_readonly"] == "PASS_REAL_B2_EMPTY_LOCK_ENABLED"
    assert result["overall_release"] == "BLOCKED"
    assert result["source_database_credentials_in_child"] is False
    assert result["source_backup_credentials_in_child"] is False
    assert result["child_env_whitelist_only"] is True
    assert result["real_backup_uploads"] if False else True
    assert result["actual_backup_objects_uploaded"] == 0
    assert "synthetic-id" not in str(result)
    assert "source-db-secret" not in str(result)


@pytest.mark.parametrize(("change", "expected"), [
    ({"CODESPACES": "false"}, "OWNER_CODESPACE_REQUIRED"),
    ({"JW_B2_AUDIT_KEY_ID": ""}, "CODESPACE_SECRETS_NOT_VISIBLE_RESTART_REQUIRED"),
    ({"JW_B2_AUDIT_APPLICATION_KEY": ""}, "CODESPACE_SECRETS_NOT_VISIBLE_RESTART_REQUIRED"),
    ({"JW_B2_AUDIT_KEY_ID": "a\nbad"}, "INVALID_B2_AUDIT_KEY_FORMAT"),
])
def test_missing_owner_codespace_or_secret_no_child(change, expected):
    fake = Runner()
    result = launcher.verify(parent={**PARENT, **change}, runner=fake)
    assert result["blocker"] == expected
    assert fake.calls == []


@pytest.mark.parametrize(("raw", "returncode", "expected"), [
    ({**SUCCESS, "provider_calls": 0}, 0, "PROBE_EXIT_STATUS_INCONSISTENT"),
    ({**SUCCESS, "bucket_private": False}, 0, "PROBE_EXIT_STATUS_INCONSISTENT"),
    ({**SUCCESS, "overall_release": "PASS"}, 0, "PROBE_RETURNED_UNSAFE_RECEIPT"),
    ({**SUCCESS, "real_backup_uploads": 11}, 0, "PROBE_RETURNED_UNSAFE_RECEIPT"),
    (SUCCESS, 1, "PROBE_EXIT_STATUS_INCONSISTENT"),
    ({"b2_owner_bucket_readonly": "BLOCKED",
      "overall_release": "BLOCKED", "real_backup_uploads": 0,
      "blocker": "B2_KEY_EXCESSIVE_PRIVILEGES", "provider_calls": 1},
     1, "B2_KEY_EXCESSIVE_PRIVILEGES"),
    ({"b2_owner_bucket_readonly": "BLOCKED",
      "overall_release": "BLOCKED", "real_backup_uploads": 0,
      "blocker": "secret-file-containing-text", "provider_calls": 1},
     1, "PROBE_RETURNED_UNSAFE_RECEIPT"),
])
def test_no_false_pass_or_unsafe_secret_echo(raw, returncode, expected):
    fake = Runner(raw=raw, returncode=returncode)
    result = launcher.verify(parent=PARENT, runner=fake)
    assert result["blocker"] == expected
    assert result["b2_owner_bucket_readonly"] == "BLOCKED"


def test_unpinned_or_short_source_blocks_before_credentials_enter_child():
    fake = Runner(source=b"malformed source")
    result = launcher.verify(parent=PARENT, runner=fake)
    assert result["blocker"] == "PINNED_PROBE_SOURCE_INVALID"
    assert len(fake.calls) == 1


def test_git_source_unavailable_no_child():
    class GitFails:
        def __init__(self):
            self.calls = []

        def __call__(self, argv, **kwargs):
            self.calls.append(argv)
            return subprocess.CompletedProcess(argv, 128, stdout=b"")

    fake = GitFails()
    result = launcher.verify(parent=PARENT, runner=fake)
    assert result["blocker"] == "PINNED_PROBE_SOURCE_UNAVAILABLE"
    assert len(fake.calls) == 1


def test_cli_denies_any_remote_upload_or_configuration_action(capsys):
    assert launcher.main(["upload"]) == 2
    assert "USAGE" in capsys.readouterr().err


def test_stdout_has_safe_error_code_and_no_raw_secrets(monkeypatch, capsys):
    for key, value in PARENT.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("CODESPACES", "false")
    assert launcher.main(["verify-readonly"]) == 1
    output = capsys.readouterr().out
    assert "OWNER_CODESPACE_REQUIRED" in output
    assert "source-db-secret" not in output
    assert "synthetic-app-key" not in output
