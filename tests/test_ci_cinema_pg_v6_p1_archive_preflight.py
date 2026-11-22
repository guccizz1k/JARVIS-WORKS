"""Local ciphertext-only, no-network negative tests for P1 archive preflight."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path

import pytest

from scripts import ci_cinema_pg_v6_p1_archive_preflight as p
from scripts.pg_backup_v223 import MAGIC


@pytest.fixture
def archive(tmp_path,monkeypatch):
    base = tmp_path / "backups"
    base.mkdir(mode=0o700)
    path = base / p.ARCHIVE_NAME
    payload = MAGIC + b"encrypted-test-payload-not-a-real-backup"
    path.write_bytes(payload)
    path.chmod(0o600)
    monkeypatch.setattr(p, "EXPECTED_SIZE", len(payload))
    monkeypatch.setattr(p, "EXPECTED_SHA256", hashlib.sha256(payload).hexdigest())
    return base, path


def test_exact_ciphertext_and_git_blob_sha(archive):
    base,path=archive
    result=p.verify_existing_archive(base)
    assert result["sha256"]==p.EXPECTED_SHA256
    assert result["bytes"]==p.EXPECTED_SIZE
    assert result["upload_status"]=="NOT_RUN_APPROVAL_REQUIRED"
    expected_blob=hashlib.sha1(b"blob "+str(p.EXPECTED_SIZE).encode()+b"\0"+path.read_bytes()).hexdigest()
    assert result["git_blob_sha1"]==expected_blob


def test_world_readable_ciphertext_is_blocked(archive):
    base,path=archive
    path.chmod(0o644)
    with pytest.raises(p.P1Blocked,match="archive_permissions"):
        p.verify_existing_archive(base)


def test_modified_ciphertext_is_blocked(archive):
    base,path=archive
    data=bytearray(path.read_bytes())
    data[-1]^=1
    path.write_bytes(data)
    with pytest.raises(p.P1Blocked,match="archive_sha256_mismatch"):
        p.verify_existing_archive(base)


def test_bad_magic_is_blocked(archive):
    base,path=archive
    data=bytearray(path.read_bytes())
    data[0]^=1
    path.write_bytes(data)
    with pytest.raises(p.P1Blocked,match="encrypted_header_mismatch"):
        p.verify_existing_archive(base)


def test_missing_archive_blocks(archive):
    base,path=archive
    path.unlink()
    with pytest.raises(p.P1Blocked,match="archive_count_or_location"):
        p.verify_existing_archive(base)


def test_duplicate_archive_blocks(archive):
    base,path=archive
    nested=base/"jw_v223_duplicate"
    nested.mkdir(mode=0o700)
    second=nested / path.name
    second.write_bytes(path.read_bytes())
    second.chmod(0o600)
    with pytest.raises(p.P1Blocked,match="archive_count_or_location"):
        p.verify_existing_archive(base)


def test_symlink_attack_blocks(archive):
    base,path=archive
    target=base/"original.bak"
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(p.P1Blocked,match="archive_symlink_or_type"):
        p.verify_existing_archive(base)


def test_bad_directory_mode_blocks(archive):
    base,path=archive
    base.chmod(0o755)
    with pytest.raises(p.P1Blocked,match="backup_directory_permissions"):
        p.verify_existing_archive(base)


def test_size_mismatch_blocks(archive,monkeypatch):
    base,path=archive
    monkeypatch.setattr(p,"EXPECTED_SIZE",999999)
    with pytest.raises(p.P1Blocked,match="archive_byte_count_mismatch"):
        p.verify_existing_archive(base)


def test_main_no_external_actions_on_failure(monkeypatch,capsys):
    monkeypatch.setattr("scripts.ci_cinema_pg_v6_owner_readonly.verify_sources",lambda:None)
    monkeypatch.setattr("scripts.ci_cinema_pg_v6_postrun_attest.private_receipt",lambda:None)
    monkeypatch.setattr(p,"verify_existing_archive",lambda:(_ for _ in ()).throw(
        p.P1Blocked("archive_sha256_mismatch")))
    assert p.main()==2
    result=capsys.readouterr().out
    assert "NO_UPLOAD_NO_DECRYPT_NO_ROLE_OR_DB_CHANGE" in result
    assert "P1_LOCAL_ENCRYPTED_ARCHIVE_MATCH_PASS" not in result
