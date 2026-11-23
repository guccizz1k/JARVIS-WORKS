"""Only synthetic, local-only offsite restore guard tests."""
import os
from pathlib import Path
import subprocess
import pytest

from scripts import p1_owner_offline_restore_v223 as offline


def test_preflight_blocks_nonowner_and_absent_consent(monkeypatch):
    monkeypatch.delenv("CODESPACES", raising=False)
    assert offline._preflight()=="OWNER_CODESPACE_REQUIRED"
    monkeypatch.setenv("CODESPACES", "true")
    monkeypatch.delenv("JW_PG_OFFLINE_RESTORE_ACK", raising=False)
    assert offline._preflight()=="EXPLICIT_OWNER_OFFLINE_RESTORE_ACK_REQUIRED"


@pytest.mark.parametrize("bad", ["tcp://malicious:2375","ssh://operator@remote","npipe:////./pipe/docker_engine"])
def test_remote_docker_host_is_forbidden(monkeypatch,bad):
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_OFFLINE_RESTORE_ACK",offline.ACK)
    monkeypatch.setenv("DOCKER_HOST",bad)
    monkeypatch.setattr(offline.shutil,"which",lambda n:"/usr/bin/docker")
    assert offline._preflight()=="REMOTE_DOCKER_DAEMON_REFUSED"


@pytest.mark.parametrize("raw,reason",[
    (b'ERROR: role "app_reader" does not exist',"MISSING_DISPOSABLE_TARGET_ROLE"),
    (b"ERROR: extension vector is not available","MISSING_EXTENSION_IN_DISPOSABLE_TARGET"),
    (b"ERROR: permission denied","TARGET_PERMISSION_ERROR"),
    (b"ERROR: check constraint violation","RESTORED_DATA_CONSTRAINT_ERROR"),
    (b"ERROR: secret_name.private","RESTORE_FAILED_UNCLASSIFIED"),
])
def test_restore_error_labels_never_leak_identifiers(raw,reason):
    assert offline._restore_reason(raw)==reason


def test_role_matching_rejects_injected_sql_or_nonascii():
    assert offline.ROLE_MISSING_RE.search(b'role "valid_reader" does not exist').group(1)==b'valid_reader'
    assert offline.ROLE_MISSING_RE.search(b'role "valid;DROP ROLE postgres" does not exist') is None
    assert offline.ROLE_MISSING_RE.search(b'role "role-owner" does not exist') is None


def test_preflight_ignores_untrusted_remote_tls(monkeypatch):
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_OFFLINE_RESTORE_ACK",offline.ACK)
    monkeypatch.setenv("DOCKER_TLS_VERIFY","1")
    monkeypatch.setattr(offline.shutil,"which",lambda n:"/usr/bin/docker")
    assert offline._preflight()=="REMOTE_DOCKER_DAEMON_REFUSED"


def test_absent_owner_archives_does_not_start_container(monkeypatch):
    monkeypatch.setattr(offline,"_preflight",lambda:"PASS")
    monkeypatch.setattr(offline.owner,"discover_owner_archive",lambda:([],"NO_PRIVATE_CIPHERTEXT_FOUND"))
    monkeypatch.setattr(offline,"_docker",lambda *a,**kw: (_ for _ in ()).throw(AssertionError("DOCKER_START_NOT_ALLOWED")))
    assert offline.run_offline()["blocker"]=="ARCHIVE_COUNT_NOT_SAFELY_BOUNDED"


def test_offline_report_never_claims_real_source_or_offsite(monkeypatch):
    monkeypatch.setattr(offline,"_preflight",lambda:"OWNER_CODESPACE_REQUIRED")
    r=offline.run_offline()
    assert r["historic_real_source_identity_verified"] is False
    assert r["independent_live_source_signature_compared"] is False
    assert r["remote_storage_proven"] is False
    assert r["overall"]=="BLOCKED"


def test_cli_requires_exact_action(capsys):
    assert offline.main(["run"])==2
    assert "USAGE" in capsys.readouterr().err


@pytest.mark.parametrize("constraint,row,total", [
    ("", "", ""),
    ("0"*63, "1"*64, "22"),
    ("0"*64, "1"*63, "22"),
    ("0"*64, "1"*64, "-1"),
    ("0"*64, "1"*64, "5000001"),
])
def test_untrusted_current_source_reference_rejected(monkeypatch,constraint,row,total):
    monkeypatch.setenv(offline.REFERENCE_CONSTRAINT_ENV,constraint)
    monkeypatch.setenv(offline.REFERENCE_ROW_ENV,row)
    monkeypatch.setenv(offline.REFERENCE_TOTAL_ENV,total)
    with pytest.raises(offline.backup.BackupError, match="INVALID_READONLY_SOURCE_REFERENCE"):
        offline._source_snapshot_reference()


def test_current_source_reference_is_explicit_opt_in(monkeypatch):
    for name in (offline.REFERENCE_CONSTRAINT_ENV, offline.REFERENCE_ROW_ENV,
                 offline.REFERENCE_TOTAL_ENV):
        monkeypatch.delenv(name,raising=False)
    assert offline._source_snapshot_reference() is None
    monkeypatch.setenv(offline.REFERENCE_CONSTRAINT_ENV,"a"*64)
    monkeypatch.setenv(offline.REFERENCE_ROW_ENV,"b"*64)
    monkeypatch.setenv(offline.REFERENCE_TOTAL_ENV,"22")
    assert offline._source_snapshot_reference()==("a"*64,"b"*64,22)


def test_reference_never_yields_historic_attestation(monkeypatch):
    monkeypatch.setattr(offline,"_preflight",lambda:"OWNER_CODESPACE_REQUIRED")
    r=offline.run_offline()
    assert r["historic_real_source_identity_verified"] is False
    assert r["current_source_snapshot_is_historic_attestation"] is False
    assert r["overall"]=="BLOCKED"
