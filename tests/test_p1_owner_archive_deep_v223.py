"""Strict privacy/security regressions for owner-local PG17 TOC audit."""
import base64
import json
import os
from pathlib import Path

import pytest

from scripts import pg_backup_v223 as backup
from scripts import p1_owner_one_shot_v223 as one
from scripts import p1_owner_archive_deep_v223 as deep


def _cipher(tmp_path, monkeypatch, payload=b"PGDMP\x01\x0f" + b"synthetic-only"):
    key=backup.AESGCM.generate_key(256)
    file=tmp_path / "cipher.jwpgbk"
    plain=tmp_path / "synthetic-input"
    plain.write_bytes(payload)
    backup.encrypt_file(plain,file,key)
    plain.unlink()
    file.chmod(0o600)
    monkeypatch.setenv("JW_PG_BACKUP_KEY",base64.urlsafe_b64encode(key).decode())
    return file


def _owner_dir(tmp_path, monkeypatch):
    root=tmp_path / "jw-v223-restore"
    root.mkdir(mode=0o700)
    store=root / "backups"
    store.mkdir(mode=0o700)
    nested=store / "jw_v223_fixture"
    nested.mkdir(mode=0o700)
    monkeypatch.setattr(one,"_owner_backup_dir",lambda:store)
    return root,store,nested


@pytest.mark.parametrize("bytes_count",[0,1,1024,1048577])
def test_decrypt_bytes_bounded_never_writes_plaintext(tmp_path,monkeypatch,bytes_count):
    payload=b"PGDMP\x01\x0f"+b"X"*bytes_count
    encrypted=_cipher(tmp_path,monkeypatch,payload)
    files_before=set(tmp_path.iterdir())
    raw=deep.authenticated_plain_in_memory(encrypted)
    assert raw == payload
    raw.clear()
    assert set(tmp_path.iterdir()) == files_before


def test_memory_limit_fails_closed(tmp_path,monkeypatch):
    encrypted=_cipher(tmp_path,monkeypatch,b"PGDMP\x01\x0f"+"x".encode()*100)
    with pytest.raises(backup.BackupError):
        deep.authenticated_plain_in_memory(encrypted,limit=8)


def test_tampered_cipher_and_wrong_key_fail_closed(tmp_path,monkeypatch):
    encrypted=_cipher(tmp_path,monkeypatch)
    monkeypatch.setenv("JW_PG_BACKUP_KEY",base64.urlsafe_b64encode(backup.AESGCM.generate_key(256)).decode())
    with pytest.raises(backup.BackupError):
        deep.authenticated_plain_in_memory(encrypted)
    monkeypatch.delenv("JW_PG_BACKUP_KEY")
    with pytest.raises(backup.BackupError):
        deep.authenticated_plain_in_memory(encrypted)


def test_invalid_pg_header_fails_before_tool(tmp_path,monkeypatch):
    encrypted=_cipher(tmp_path,monkeypatch,b"not-a-pg-archive")
    with pytest.raises(backup.BackupError,match="NOT_PGDMP"):
        deep.authenticated_plain_in_memory(encrypted)


def test_hist_log_categories_never_expose_customer_names(tmp_path,monkeypatch):
    root,store,nested=_owner_dir(tmp_path,monkeypatch)
    log=root/"last_backup_error.log"
    secret="private_name@secret.example.com"
    log.write_text('exit_code=1\n--- stdout (tail) ---\n'
      +'{"signature_mismatches":["acl:'+secret+'","constraints:private_table","rows:secret"],'
      +'"tables":65}\n--- stderr (tail) ---')
    log.chmod(0o600)
    result=deep.historic_log_mismatch_categories()
    assert result["historical_signature_list"]=="REPORTED_NONEMPTY_NOT_PROOF"
    assert result["historical_mismatch_total_reported"]==3
    assert result["historical_mismatch_categories"]==["CONSTRAINTS","ACL","ROWS"]
    assert secret not in str(result)
    assert "private_table" not in str(result)


@pytest.mark.parametrize("invalid",[
  '{"signature_mismatches":["acl:X"', # truncated
  '{"signature_mismatches": {"acl":"foo"}}',
  '{"signature_mismatches": ["acl:X", 999]}',
  '{"signature_mismatches": "untrusted"}',
])
def test_hist_mismatch_invalid_never_credited(tmp_path,monkeypatch,invalid):
    root,store,nested=_owner_dir(tmp_path,monkeypatch)
    log=root/"last_backup_error.log"
    log.write_text("--- stdout (tail) ---\n"+invalid+"\n--- stderr (tail) ---")
    log.chmod(0o600)
    result=deep.historic_log_mismatch_categories()
    assert result["historical_signature_list"] not in ("REPORTED_NONEMPTY_NOT_PROOF","REPORTED_EMPTY_NOT_PROOF")
    assert not result["historical_mismatch_categories"]


def test_not_yet_stored_mismatch_list_cannot_be_invented(tmp_path,monkeypatch):
    _owner_dir(tmp_path,monkeypatch)
    result=deep.historic_log_mismatch_categories()
    assert result["historical_signature_list"]=="UNAVAILABLE"
    assert result["historic_log_independent_proof"] is False


def test_local_toc_classification_does_not_claim_restore(tmp_path,monkeypatch):
    root,store,nested=_owner_dir(tmp_path,monkeypatch)
    sample=_cipher(tmp_path,monkeypatch)
    copy=nested/"synthetic.jwpgbk"
    copy.write_bytes(sample.read_bytes())
    copy.chmod(0o600)
    monkeypatch.setattr(deep.shutil,"which",lambda name: None)
    report=deep.deep_inventory()
    assert report["pg17_toc_examined"]==0
    assert report["toc_probe"]=="PG17_RESTORE_BINARY_MISSING"
    assert report["toc_checks_are_restores"] is False
    assert report["actual_65_table_restore"]=="NOT_RUN"
    assert report["overall"]=="BLOCKED"


def test_toc_counts_never_print_names_and_stale_strings_rejected(monkeypatch):
    import subprocess
    class Result:
        returncode=0
        stdout=(b"1; 1259 150 TABLE jw_dev secret_people hidden_owner\n"
                b"2; 1259 150 TABLE DATA jw_dev secret_people hidden_owner\n"
                b"3; 1259 150 TABLE other_schema other hidden_owner\n"
                b"4; 1259 150 FUNCTION jw_dev secret hidden_owner\n")
        stderr=b"password=secret"
    monkeypatch.setattr(deep.shutil,"which",lambda name:"/mock/pg_restore")
    monkeypatch.setattr(deep.backup,"tool_major",lambda _:17)
    monkeypatch.setattr(subprocess,"run",lambda *a,**k:Result())
    assert deep.pg17_toc_counts(bytearray(b"PGDMP\x01\x0f"))==("PG17_TOC_PARSED_NOT_RESTORED",1)


def test_cli_prints_only_fixed_counters(tmp_path,monkeypatch,capsys):
    root,store,nested=_owner_dir(tmp_path,monkeypatch)
    monkeypatch.delenv("JW_PG_BACKUP_KEY",raising=False)
    assert deep.main(["deep-inventory"])==0
    printed=capsys.readouterr().out
    result=json.loads(printed)
    assert result["overall"]=="BLOCKED"
    assert result["pg17_toc_examined"]==0
    assert str(tmp_path) not in printed
    assert "source_dsn" not in printed


def test_wrong_cli_command_rejected(capsys):
    assert deep.main(["run"])==2
    assert "USAGE" in capsys.readouterr().err
