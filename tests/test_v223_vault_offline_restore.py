"""Offline existing encrypted vault B3 workflow: pure safety gates, no live secrets."""
import base64
import hashlib
import os

import pytest

from scripts import ci_v223_vault_offline_restore as offline
from scripts import pg_backup_v223 as pb


@pytest.fixture()
def local_archive(tmp_path):
    key = os.urandom(32)
    src = tmp_path / "synthetic-dump.bin"
    src.write_bytes(b"PGDMP" + os.urandom(32768))
    ciphertext = tmp_path / "synthetic-existing.jwpgbk"
    pb.encrypt_file(src, ciphertext, key)
    content = ciphertext.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
    return ciphertext, key, blob


def test_real_encryption_is_inspected_without_decrypting(local_archive):
    encrypted, _, expected = local_archive
    assert offline.verify_vault_file(encrypted, expected) is True


def test_wrong_private_blob_identity_is_rejected(local_archive):
    encrypted, _, _ = local_archive
    with pytest.raises(pb.BackupError, match="GIT_BLOB_MISMATCH"):
        offline.verify_vault_file(encrypted, "0" * 40)


@pytest.mark.parametrize("fake", ["", "not-hex", "a" * 39, "a" * 41])
def test_invalid_git_blob_id_never_authorizes(local_archive, fake):
    encrypted, _, _ = local_archive
    with pytest.raises(pb.BackupError, match="NOT_ALLOWLISTED"):
        offline.verify_vault_file(encrypted, fake)


def test_symlink_and_relative_paths_rejected(local_archive, tmp_path):
    encrypted, _, expected = local_archive
    symlink = tmp_path / "symlink-vault.jwpgbk"
    symlink.symlink_to(encrypted)
    with pytest.raises(pb.BackupError, match="NOT_REGULAR"):
        offline.verify_vault_file(symlink, expected)
    with pytest.raises(pb.BackupError, match="NOT_ALLOWLISTED"):
        offline.verify_vault_file(encrypted.relative_to(tmp_path), expected)


def test_executable_and_unknown_archive_format_are_rejected(local_archive,tmp_path):
    encrypted, _, expected = local_archive
    unknown = tmp_path / "unknown.zip"
    unknown.write_bytes(encrypted.read_bytes())
    with pytest.raises(pb.BackupError, match="NOT_ALLOWLISTED"):
        offline.verify_vault_file(unknown, expected)
    malformed = tmp_path / "invalid-format.jwpgbk"
    malformed.write_bytes(b"WRONGMAGIC" + b"Z" * 128)
    content = malformed.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
    with pytest.raises(pb.BackupError, match="BAD_MAGIC"):
        offline.verify_vault_file(malformed, blob)


def test_private_vault_name_not_exposed_in_receipt(local_archive):
    encrypted, _, expected = local_archive
    result = offline.verify_vault_file(encrypted, expected)
    assert result is True and not isinstance(result, str)


def test_authentic_ciphertext_still_requires_correct_secret(local_archive, tmp_path):
    encrypted, _, expected = local_archive
    assert offline.verify_vault_file(encrypted, expected)
    with pytest.raises(pb.BackupError, match="AUTH_FAILED"):
        pb.decrypt_file(encrypted, tmp_path / "wrong.dump", os.urandom(32))
    assert not (tmp_path / "wrong.dump").exists()


def test_cipher_mutation_and_truncation_rejected_before_pg_restore(local_archive,tmp_path):
    encrypted, key, _ = local_archive
    result = offline._negative_controls(encrypted, key, tmp_path)
    assert result == {
        "tamper_rejected": True,
        "truncation_rejected": True,
        "wrong_key_rejected": True,
    }
    assert not list(tmp_path.glob("*.dump"))


@pytest.mark.parametrize("target", [
    "postgresql://p:pw@db.example.com/postgres",
    "postgresql://p:pw@127.0.0.1/my_customers",
    "postgresql://p:pw@127.0.0.1/production",
])
def test_only_local_explicit_postgres_admin_database(target):
    env = {"JW_PG_CI_ALLOW": "ONLY_EPHEMERAL_LOCAL_DATABASE",
           pb.EPHEMERAL_TOKEN_ENV: "x" * 32}
    with pytest.raises(pb.BackupError, match="OFFLINE_TARGET_MUST_BE_LOCAL_POSTGRES"):
        offline.ephemeral_target_options(target, env)


def test_no_marker_or_owner_ephemeral_declaration_no_restore():
    dsn = "postgresql://p:pw@127.0.0.1/postgres"
    with pytest.raises(pb.BackupError, match="NOT_DECLARED_EPHEMERAL"):
        offline.ephemeral_target_options(dsn, {})
    with pytest.raises(pb.BackupError, match="TARGET_TOKEN_NOT_SET"):
        offline.ephemeral_target_options(
            dsn, {"JW_PG_CI_ALLOW": "ONLY_EPHEMERAL_LOCAL_DATABASE"})
    result = offline.ephemeral_target_options(
        dsn, {"JW_PG_CI_ALLOW": "ONLY_EPHEMERAL_LOCAL_DATABASE",
              pb.EPHEMERAL_TOKEN_ENV: "x" * 32})
    assert result["host"] == "127.0.0.1"


def test_no_key_cannot_contact_target(monkeypatch,capsys,tmp_path):
    monkeypatch.setenv("JW_PG_EXISTING_ARCHIVE",str(tmp_path / "synthetic-existing.jwpgbk"))
    monkeypatch.setenv("JW_PG_TARGET_ADMIN_DSN",
                      "postgresql://p:TOPSECRET@127.0.0.1/postgres")
    monkeypatch.setenv("JW_PG_EXPECT_ARCHIVE_GIT_SHA","f"*40)
    monkeypatch.delenv("JW_PG_BACKUP_KEY",raising=False)
    assert offline.main()==2
    result=capsys.readouterr()
    assert "BLOCKED_V223_BACKUP_KEY_REQUIRED" in result.err
    assert "TOPSECRET" not in result.err + result.out


def test_unexpected_exception_logs_only_exception_class(monkeypatch,capsys):
    monkeypatch.setenv("JW_PG_EXISTING_ARCHIVE","/private/vault/archive-123.jwpgbk")
    monkeypatch.setenv("JW_PG_TARGET_ADMIN_DSN",
                       "postgresql://p:secret123@127.0.0.1/postgres")
    monkeypatch.setenv("JW_PG_EXPECT_ARCHIVE_GIT_SHA","f"*40)
    monkeypatch.setattr(pb,"load_key",lambda:bytes(32))
    def blocked(*_args):
        raise RuntimeError("SECRET-PRIVATE-PASSWORD")
    monkeypatch.setattr(offline,"run",blocked)
    assert offline.main()==2
    result=capsys.readouterr()
    assert "BLOCKED_V223_OFFLINE_UNEXPECTED_RuntimeError" in result.err
    assert "SECRET-PRIVATE-PASSWORD" not in result.err + result.out
