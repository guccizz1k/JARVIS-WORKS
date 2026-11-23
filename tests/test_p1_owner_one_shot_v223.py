"""One-shot owner-only evidence preflight: synthetic data, no network/DB."""
import base64
import hashlib
import json
from pathlib import Path

import pytest

from scripts import pg_backup_v223 as backup
from scripts import p1_owner_one_shot_v223 as one


def _fixture(tmp_path: Path):
    key = backup.AESGCM.generate_key(bit_length=256)
    payload = b"synthetic-offsite-retrieval-fixture" * 100
    original = tmp_path / "source"
    archive = tmp_path / "cipher.jwpgbk"
    original.write_bytes(payload)
    backup.encrypt_file(original, archive, key)
    archive.chmod(0o600)
    result = {
        "JW_PG_ARCHIVE_PATH": str(archive),
        "JW_PG_EXPECT_ARCHIVE_SHA256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "JW_PG_EXPECT_PLAINTEXT_SHA256": hashlib.sha256(payload).hexdigest(),
        "JW_PG_BACKUP_KEY": base64.urlsafe_b64encode(key).decode("ascii"),
    }
    return result, archive


def test_missing_inputs_fail_closed_without_touching_files(tmp_path: Path):
    assert one.execute_one_shot({})["blocker"] == "ARCHIVE_PATH_REQUIRED"
    missing = {"JW_PG_ARCHIVE_PATH": str(tmp_path / "missing")}
    assert one.execute_one_shot(missing)["blocker"] == "INDEPENDENT_CIPHER_SHA256_REQUIRED"
    missing["JW_PG_EXPECT_ARCHIVE_SHA256"] = "0" * 64
    assert one.execute_one_shot(missing)["blocker"] == "BACKUP_KEY_REQUIRED_IN_OWNER_ENV"


def test_independent_local_verification_passes_but_release_fails_closed(tmp_path: Path):
    env, archive = _fixture(tmp_path)
    r = one.execute_one_shot(env)
    assert r["local_archive_auth"] == "PASS"
    assert r["retrieved_archive_auth"] == "BLOCKED"
    assert r["historical_65_table_restore"] == "NOT_RUN"
    assert r["render_live_e2e"] == "NOT_RUN"
    assert r["overall"] == "BLOCKED"
    assert r["blocker"] == "INDEPENDENTLY_RETRIEVED_CIPHERTEXT_REQUIRED"
    assert archive.exists()


def test_downloaded_authenticated_ciphertext_is_not_proof_of_external_origin(tmp_path: Path):
    env, archive = _fixture(tmp_path)
    second = tmp_path / "retrieved"
    second.write_bytes(archive.read_bytes())
    second.chmod(0o600)
    env["JW_PG_RETRIEVED_ARCHIVE_PATH"] = str(second)
    result = one.execute_one_shot(env)
    assert result["local_archive_auth"] == "PASS"
    assert result["retrieved_archive_auth"] == "PASS"
    assert result["external_storage_origin"] == "NOT_VERIFIED"
    assert result["historical_65_table_restore"] == "NOT_RUN"
    assert result["overall"] == "BLOCKED"
    assert result["blocker"] == "EXTERNAL_STORAGE_ATTESTATION_AND_HISTORIC_RESTORE_REQUIRED"


def test_hardlink_is_not_independent_retrieval(tmp_path: Path):
    env, archive = _fixture(tmp_path)
    link = tmp_path / "hardlink"
    link.hardlink_to(archive)
    env["JW_PG_RETRIEVED_ARCHIVE_PATH"] = str(link)
    r = one.execute_one_shot(env)
    assert r["retrieved_archive_auth"] == "BLOCKED"
    assert r["blocker"] == "RETRIEVED_COPY_IS_SAME_FILE"


@pytest.mark.parametrize("fault", ["wrong_key", "wrong_sha", "bad_plain_hash", "cipher_tamper", "world_readable"])
def test_local_integrity_faults_fail_closed(tmp_path: Path, fault):
    env, archive = _fixture(tmp_path)
    if fault == "wrong_key":
        env["JW_PG_BACKUP_KEY"] = base64.urlsafe_b64encode(backup.AESGCM.generate_key(256)).decode()
    elif fault == "wrong_sha":
        env["JW_PG_EXPECT_ARCHIVE_SHA256"] = "0" * 64
    elif fault == "bad_plain_hash":
        env["JW_PG_EXPECT_PLAINTEXT_SHA256"] = "f" * 64
    elif fault == "cipher_tamper":
        b = bytearray(archive.read_bytes())
        b[-4] ^= 1
        archive.write_bytes(b)
    elif fault == "world_readable":
        archive.chmod(0o644)
    r = one.execute_one_shot(env)
    assert r["local_archive_auth"] == "BLOCKED"
    assert r["overall"] == "BLOCKED"
    assert r["blocker"] == "LOCAL_CIPHERTEXT_NOT_AUTHENTICATED"


@pytest.mark.parametrize("fault", ["tamper", "not_private", "symlink"])
def test_retrieved_copy_integrity_faults_fail_closed(tmp_path: Path, fault):
    env, archive = _fixture(tmp_path)
    second = tmp_path / "remote"
    second.write_bytes(archive.read_bytes())
    second.chmod(0o600)
    if fault == "tamper":
        changed = bytearray(second.read_bytes())
        changed[-8] ^= 1
        second.write_bytes(changed)
    if fault == "not_private":
        second.chmod(0o644)
    if fault == "symlink":
        second.unlink()
        second.symlink_to(archive)
    env["JW_PG_RETRIEVED_ARCHIVE_PATH"] = str(second)
    r = one.execute_one_shot(env)
    assert r["retrieved_archive_auth"] == "BLOCKED"
    assert r["overall"] == "BLOCKED"


def test_private_receipt_metadata_is_not_signature_proof(tmp_path: Path):
    env, _ = _fixture(tmp_path)
    receipt = tmp_path / "receipt.json"
    receipt.write_text('{"verdict":"PASS","source":"real_database"}')
    receipt.chmod(0o600)
    env["JW_PG_OWNER_RECEIPT_PATH"] = str(receipt)
    r = one.execute_one_shot(env)
    assert r["private_receipt_metadata"] == "PRESENT_NOT_INDEPENDENTLY_VERIFIED"
    assert r["overall"] == "BLOCKED"


def test_receipt_symlink_is_rejected_even_when_target_private(tmp_path: Path):
    env, _ = _fixture(tmp_path)
    receipt = tmp_path / "receipt"
    receipt.write_text("{}")
    receipt.chmod(0o600)
    link = tmp_path / "receipt_alias"
    link.symlink_to(receipt)
    env["JW_PG_OWNER_RECEIPT_PATH"] = str(link)
    assert one.execute_one_shot(env)["private_receipt_metadata"] == "BLOCKED"


def test_cli_never_prints_key_or_archive_path(tmp_path: Path, monkeypatch, capsys):
    env, archive = _fixture(tmp_path)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    rc = one.main(["check"])
    stdout = capsys.readouterr().out
    assert rc == 1
    obj = json.loads(stdout)
    assert obj["overall"] == "BLOCKED"
    assert str(archive) not in stdout
    assert env["JW_PG_BACKUP_KEY"] not in stdout
    assert env["JW_PG_EXPECT_ARCHIVE_SHA256"] not in stdout


def test_invalid_cli_command_does_not_open_files(capsys):
    assert one.main(["run"]) == 2
    assert "USAGE" in capsys.readouterr().err



def _historical_storage(tmp_path: Path, archive: Path):
    """Mirror historical TMPDIR/jw_v223_*/nonce.jwpgbk without network."""
    root = tmp_path / "backups"
    root.mkdir(mode=0o700)
    folder = root / "jw_v223_abc12345"
    folder.mkdir(mode=0o700)
    saved = folder / "historical.jwpgbk"
    saved.write_bytes(archive.read_bytes())
    saved.chmod(0o600)
    return root, saved


def test_diagnose_auto_discovers_historical_nested_ciphertext(tmp_path: Path, monkeypatch):
    env, archive = _fixture(tmp_path)
    root, saved = _historical_storage(tmp_path, archive)
    monkeypatch.setattr(one, "_owner_backup_dir", lambda: root)
    env.pop("JW_PG_ARCHIVE_PATH")
    result = one.diagnose_one_shot(env)
    assert result["archive_discovery"] == "FOUND_ONE"
    assert result["discovered_private_archive_count"] == 1
    assert result["local_archive_auth"] == "PASS"
    assert result["diagnostic_execution"] == "PASS"
    assert result["overall"] == "BLOCKED"
    assert "INDEPENDENTLY_RETRIEVED_CIPHERTEXT_REQUIRED" in result["blockers"]
    assert str(saved) not in str(result)


def test_diagnose_aggregates_all_independent_missing_evidence(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(one, "_owner_backup_dir", lambda: tmp_path / "absent")
    result = one.diagnose_one_shot({})
    assert result["diagnostic_execution"] == "PASS"
    assert result["archive_discovery"] == "PRIVATE_BACKUP_DIRECTORY_ABSENT_OR_UNSAFE"
    assert "PRIVATE_BACKUP_DIRECTORY_ABSENT_OR_UNSAFE" in result["blockers"]
    assert "INDEPENDENT_CIPHER_SHA256_REQUIRED" in result["blockers"]
    assert "BACKUP_KEY_REQUIRED_IN_OWNER_ENV" in result["blockers"]
    assert "INDEPENDENTLY_RETRIEVED_CIPHERTEXT_REQUIRED" in result["blockers"]
    assert "OFFSITE_STORAGE_PROVIDER_ATTESTATION_NOT_VERIFIED" in result["blockers"]
    assert "HISTORICAL_65_TABLE_INDEPENDENT_RESTORE_NOT_VERIFIED" in result["blockers"]
    assert "RENDER_AUTHENTICATED_LIVE_E2E_NOT_RUN" in result["blockers"]


def test_diagnose_does_not_select_ambiguous_copies(tmp_path: Path, monkeypatch):
    env, archive = _fixture(tmp_path)
    root, saved = _historical_storage(tmp_path, archive)
    (saved.parent / "second.jwpgbk").write_bytes(saved.read_bytes())
    (saved.parent / "second.jwpgbk").chmod(0o600)
    monkeypatch.setattr(one, "_owner_backup_dir", lambda: root)
    env.pop("JW_PG_ARCHIVE_PATH")
    result = one.diagnose_one_shot(env)
    assert result["archive_discovery"] == "MULTIPLE_ARCHIVES"
    assert result["discovered_private_archive_count"] == 2
    assert "MULTIPLE_ARCHIVES_NEED_TRUSTED_RECEIPT_SELECTION" in result["blockers"]
    assert result["local_archive_auth"] == "BLOCKED"
    assert result["diagnostic_execution"] == "PASS"


@pytest.mark.parametrize("attack", ["root_symlink", "folder_symlink", "world_readable", "root_permissive"])
def test_diagnose_discovery_rejects_insecure_historical_storage(tmp_path: Path, monkeypatch, attack):
    env, archive = _fixture(tmp_path)
    root, saved = _historical_storage(tmp_path, archive)
    monkeypatch.setattr(one, "_owner_backup_dir", lambda: root)
    env.pop("JW_PG_ARCHIVE_PATH")
    if attack == "root_symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        monkeypatch.setattr(one, "_owner_backup_dir", lambda: alias)
    elif attack == "folder_symlink":
        linked = root / "jw_v223_fake"
        linked.symlink_to(saved.parent, target_is_directory=True)
        saved.unlink()
    elif attack == "world_readable":
        saved.chmod(0o644)
    elif attack == "root_permissive":
        root.chmod(0o755)
    r = one.diagnose_one_shot(env)
    assert r["archive_discovery"] in ("NO_PRIVATE_CIPHERTEXT_FOUND",
                                      "PRIVATE_BACKUP_DIRECTORY_ABSENT_OR_UNSAFE")
    assert r["local_archive_auth"] == "BLOCKED"


def test_diagnose_preserves_owner_receipt_but_never_trusts_it(tmp_path: Path, monkeypatch):
    env, archive = _fixture(tmp_path)
    root, saved = _historical_storage(tmp_path, archive)
    monkeypatch.setattr(one, "_owner_backup_dir", lambda: root)
    receipt = tmp_path / "owner_b2b3_20261117_20261123.json"
    receipt.write_text('{"verdict":"PASS","signed":"not really"}')
    receipt.chmod(0o600)
    env.pop("JW_PG_ARCHIVE_PATH")
    r = one.diagnose_one_shot(env)
    assert r["private_receipt_metadata"] == "PRESENT_NOT_INDEPENDENTLY_VERIFIED"
    assert r["overall"] == "BLOCKED"


def test_diagnose_cli_returns_success_for_diagnostic_not_backup(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(one, "_owner_backup_dir", lambda: tmp_path / "absent")
    for key in ("JW_PG_ARCHIVE_PATH","JW_PG_BACKUP_KEY","JW_PG_EXPECT_ARCHIVE_SHA256",
                "JW_PG_OWNER_RECEIPT_PATH","JW_PG_RETRIEVED_ARCHIVE_PATH"):
        monkeypatch.delenv(key, raising=False)
    assert one.main(["diagnose"]) == 0
    printed = capsys.readouterr().out
    result = json.loads(printed)
    assert result["diagnostic_execution"] == "PASS"
    assert result["overall"] == "BLOCKED"
    assert "ARCHIVE" in printed
    assert str(tmp_path) not in printed


def test_discovery_does_not_scan_outside_known_owner_dir(tmp_path: Path, monkeypatch):
    env, archive = _fixture(tmp_path)
    root = tmp_path / "backups"
    root.mkdir(mode=0o700)
    outside = tmp_path / "untrusted"
    outside.mkdir(mode=0o700)
    (outside / "malicious.jwpgbk").write_bytes(archive.read_bytes())
    (outside / "malicious.jwpgbk").chmod(0o600)
    (root / "jw_v223_outside").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(one, "_owner_backup_dir", lambda: root)
    assert one.discover_owner_archive() == ([], "NO_PRIVATE_CIPHERTEXT_FOUND")


def test_diagnose_replaces_generic_archive_path_error_with_real_discovery(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(one, "_owner_backup_dir", lambda: tmp_path / "absent")
    result = one.diagnose_one_shot({})
    assert result["blocker"] == "PRIVATE_BACKUP_DIRECTORY_ABSENT_OR_UNSAFE"
    assert "ARCHIVE_PATH_REQUIRED" not in result["blockers"]
    assert result["diagnostic_execution"] == "PASS"
    assert result["overall"] == "BLOCKED"
