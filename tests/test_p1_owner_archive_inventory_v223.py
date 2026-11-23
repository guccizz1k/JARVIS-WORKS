"""Read-only inventory tests; synthetic archives, no DB/network or plaintext files."""
import base64
import json
from pathlib import Path

import pytest

from scripts import pg_backup_v223 as p
from scripts import p1_owner_one_shot_v223 as one
from scripts import p1_owner_archive_inventory_v223 as inv


def mk_candidate(tmp_path, name, key, payload=b"PGDMP\x01\x0e" + b"synthetic-not-a-real-pg-dump"):
    src=tmp_path / ("plaintext_"+name)
    src.write_bytes(payload)
    dest=tmp_path / (name + ".jwpgbk")
    p.encrypt_file(src,dest,key)
    dest.chmod(0o600)
    src.unlink()
    return dest


def mk_owner_root(tmp_path, monkeypatch):
    root=tmp_path / "jw-v223-restore"
    root.mkdir(mode=0o700)
    backup=root/"backups"
    backup.mkdir(mode=0o700)
    child=backup/"jw_v223_abcd"
    child.mkdir(mode=0o700)
    monkeypatch.setattr(one,"_owner_backup_dir",lambda: backup)
    return root, backup, child


def test_pg_magic_synthetic_header_and_non_pg_detection(tmp_path):
    key=p.AESGCM.generate_key(256)
    good=mk_candidate(tmp_path,"good",key)
    other=mk_candidate(tmp_path,"other",key,b"this is not postgres")
    assert inv._single_chunk_postgres_magic(good,key)=="AUTHENTICATED_PGDMP_HEADER_ONLY"
    assert inv._single_chunk_postgres_magic(other,key)=="NOT_POSTGRES_CUSTOM"
    assert inv._single_chunk_postgres_magic(good,p.AESGCM.generate_key(256))=="NOT_CONFIRMED"
    assert good.exists() and other.exists()


@pytest.mark.parametrize("v",[
    b"PGDMP",b"PGDMP\x02\x0fmore",b"PGDMP\x01",b"PGDMP\x00\x0e",
])
def test_reject_forged_or_incomplete_pg_magic(tmp_path,v):
    key=p.AESGCM.generate_key(256)
    path=mk_candidate(tmp_path,"bad",key,v)
    assert inv._single_chunk_postgres_magic(path,key)=="NOT_POSTGRES_CUSTOM"


def test_end_to_end_11_encrypted_archives_all_pg_headers(tmp_path,monkeypatch):
    root, backup, child=mk_owner_root(tmp_path,monkeypatch)
    key=p.AESGCM.generate_key(256)
    for i in range(11):
        src=mk_candidate(tmp_path,str(i),key)
        target=child / (str(i)+".jwpgbk")
        target.write_bytes(src.read_bytes())
        target.chmod(0o600)
    monkeypatch.setenv("JW_PG_BACKUP_KEY",base64.urlsafe_b64encode(key).decode())
    report=inv.generate_inventory()
    assert report["inventory_execution"]=="PASS"
    assert report["archive_discovery"]=="MULTIPLE_ARCHIVES"
    assert report["private_archive_count"]==11
    assert report["aes_gcm_full_archive_authenticated"]==11
    assert report["postgres_custom_header_authenticated"]==11
    assert report["independent_archive_receipt_verified"] is False
    assert report["actual_65_table_restore"]=="NOT_RUN"
    assert report["overall"]=="BLOCKED"


def test_mixed_authenticated_archives_classified_without_picking_one(tmp_path,monkeypatch):
    root, backup, child=mk_owner_root(tmp_path,monkeypatch)
    key=p.AESGCM.generate_key(256)
    for i,payload in enumerate((b"PGDMP\x01\x0fhi",b"not a pg dump")):
        src=mk_candidate(tmp_path,str(i),key,payload)
        dest=child/(str(i)+".jwpgbk")
        dest.write_bytes(src.read_bytes())
        dest.chmod(0o600)
    monkeypatch.setenv("JW_PG_BACKUP_KEY",base64.urlsafe_b64encode(key).decode())
    report=inv.generate_inventory()
    assert report["aes_gcm_full_archive_authenticated"]==2
    assert report["postgres_custom_header_authenticated"]==1
    assert report["not_postgres_custom_header_count"]==1
    assert report["overall"]=="BLOCKED"


def test_old_owner_report_blocked_never_promoted_to_pass(tmp_path,monkeypatch):
    root, backup, child=mk_owner_root(tmp_path,monkeypatch)
    receipt=root/"owner_b2b3_20261117_123.json"
    receipt.write_text(json.dumps({"verdict":"BLOCKED","stages":{"temporary_login":"PASS",
                              "real_encrypted_backup_independent_restore":"BLOCKED"}}))
    receipt.chmod(0o600)
    record=inv._owner_history_status()
    assert record["historical_owner_receipt"]=="REPORTED_BLOCKED_NOT_PROOF"
    assert record["historical_owner_b2b3_stage"]=="REPORTED_NOT_PASS"


def test_forged_owner_pass_is_always_claim_only(tmp_path,monkeypatch):
    root, backup, child=mk_owner_root(tmp_path,monkeypatch)
    receipt=root/"owner_b2b3_20261117_123.json"
    receipt.write_text(json.dumps({"verdict":"PASS","stages":{
                              "real_encrypted_backup_independent_restore":"PASS"}}))
    receipt.chmod(0o600)
    record=inv._owner_history_status()
    assert record["historical_owner_receipt"]=="REPORTED_PASS_NOT_PROOF"
    assert record["historical_owner_b2b3_stage"]=="REPORTED_PASS_NOT_PROOF"


def test_prev_error_log_only_finite_labels_and_no_leak(tmp_path,monkeypatch,capsys):
    root, backup, child=mk_owner_root(tmp_path,monkeypatch)
    log=root/"last_backup_error.log"
    secret="postgresql://admin:private_password@db.example.com/private"
    log.write_text("exit_code=1\n--- stdout (tail) ---\n"+secret+
      '\n"signature_mismatches": ["acl:tenant-name"],"tables": 65\n--- stderr (tail) ---\n')
    log.chmod(0o600)
    report=inv.generate_inventory()
    assert report["historical_error_log"]=="PRESENT_UNTRUSTED_PRIOR_RUN"
    assert report["historical_reported_signature_mismatch"]=="LIST_PRESENT_NOT_INDEPENDENTLY_VERIFIED"
    assert report["historical_reported_tables_65"]=="REPORTED_65_NOT_INDEPENDENTLY_VERIFIED"
    assert secret not in json.dumps(report)
    assert "tenant-name" not in json.dumps(report)
    assert inv.main(["inventory"])==0
    assert secret not in capsys.readouterr().out


def test_owner_record_symlink_or_wrong_mode_ignored(tmp_path,monkeypatch):
    root,backup,child=mk_owner_root(tmp_path,monkeypatch)
    receipt=root/"owner_b2b3_20261117_123.json"
    receipt.write_text('{"verdict":"PASS"}')
    receipt.chmod(0o644)
    report=inv._owner_history_status()
    assert report["historical_owner_receipt"]=="UNAVAILABLE"
    receipt.chmod(0o600)
    link=root/"last_backup_error.log"
    link.symlink_to(receipt)
    assert inv._owner_history_status()["historical_error_log"]=="UNAVAILABLE"


def test_inventory_missing_key_and_old_archive_discovery(tmp_path,monkeypatch):
    root,backup,child=mk_owner_root(tmp_path,monkeypatch)
    key=p.AESGCM.generate_key(256)
    source=mk_candidate(tmp_path,"single",key)
    target=child/"single.jwpgbk"
    target.write_bytes(source.read_bytes())
    target.chmod(0o600)
    monkeypatch.delenv("JW_PG_BACKUP_KEY",raising=False)
    r=inv.generate_inventory()
    assert r["private_archive_count"]==1
    assert r["crypto_probe"]=="NO_ARCHIVES_OR_KEY"
    assert r["postgres_custom_header_authenticated"]==0
    assert r["overall"]=="BLOCKED"


def test_no_plaintext_file_or_private_secrets_from_inventory(tmp_path,monkeypatch,capsys):
    root,backup,child=mk_owner_root(tmp_path,monkeypatch)
    key=p.AESGCM.generate_key(256)
    src=mk_candidate(tmp_path,"secret",key)
    encrypted=child/"account-99999.jwpgbk"
    encrypted.write_bytes(src.read_bytes())
    encrypted.chmod(0o600)
    monkeypatch.setenv("JW_PG_BACKUP_KEY",base64.urlsafe_b64encode(key).decode())
    before=sorted(str(x) for x in root.rglob("*"))
    assert inv.main(["inventory"])==0
    printed=capsys.readouterr().out
    assert "account-99999" not in printed
    assert "private_password" not in printed
    assert "PGDMP" not in printed
    assert base64.urlsafe_b64encode(key).decode() not in printed
    assert sorted(str(x) for x in root.rglob("*"))==before


def test_bad_command_fail_closed(capsys):
    assert inv.main(["execute_backup"])==2
    assert "USAGE" in capsys.readouterr().err


def test_header_probe_rejects_symlink_and_world_readable(tmp_path):
    key=p.AESGCM.generate_key(256)
    good=mk_candidate(tmp_path,"good_privacy",key)
    good.chmod(0o644)
    assert inv._single_chunk_postgres_magic(good,key)=="NOT_CONFIRMED"
    good.chmod(0o600)
    alias=tmp_path/"alias.jwpgbk"
    alias.symlink_to(good)
    assert inv._single_chunk_postgres_magic(alias,key)=="NOT_CONFIRMED"
