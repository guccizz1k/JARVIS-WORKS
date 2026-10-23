"""Encrypted backup content, tamper rejection, safe restore, no plaintext artifacts."""
import os
import sqlite3
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from scripts.secure_backup import make_backup,verify_backup,restore_backup,HEADER


def fixture_db(path):
    with sqlite3.connect(path) as c:
        c.execute('CREATE TABLE customers(id integer primary key, secret text)')
        c.execute('INSERT INTO customers(secret) VALUES (?)',('수취계좌 123-456-789',))


def test_backup_encrypted_restorable_and_no_plaintext(tmp_path,monkeypatch):
    key=Fernet.generate_key().decode(); monkeypatch.setenv('JW_BACKUP_KEY',key)
    db=tmp_path/'original.db';fixture_db(db)
    b=make_backup(db,tmp_path/'private')
    assert b.suffix=='.jwbackup' and b.is_file()
    assert b.read_bytes().startswith(HEADER)
    assert '수취계좌'.encode() not in b.read_bytes()
    assert len(list((tmp_path/'private').iterdir()))==1
    assert (b.stat().st_mode & 0o077)==0
    restored=restore_backup(b,tmp_path/'restored'/'restored.db')
    with sqlite3.connect(restored) as conn:
        assert conn.execute('SELECT secret FROM customers').fetchone()[0]=='수취계좌 123-456-789'
    with pytest.raises(ValueError,match='already exists'):
        restore_backup(b,restored)


def test_backup_wrong_key_and_tamper_fail_closed(tmp_path,monkeypatch):
    monkeypatch.setenv('JW_BACKUP_KEY',Fernet.generate_key().decode())
    src=tmp_path/'source.db';fixture_db(src)
    backup=make_backup(src,tmp_path/'backups')
    monkeypatch.setenv('JW_BACKUP_KEY',Fernet.generate_key().decode())
    with pytest.raises(ValueError,match='authentication failed'):
        restore_backup(backup,tmp_path/'restored.db')
    assert not (tmp_path/'restored.db').exists()
    data=bytearray(backup.read_bytes());data[-7]^=8;backup.write_bytes(data)
    with pytest.raises(ValueError,match='authentication failed'):
        verify_backup(backup)


def test_backup_missing_key_symlink_source_and_target(tmp_path,monkeypatch):
    monkeypatch.delenv('JW_BACKUP_KEY',raising=False)
    src=tmp_path/'source.db';fixture_db(src)
    with pytest.raises(RuntimeError,match='JW_BACKUP_KEY'):
        make_backup(src,tmp_path/'backups')
    monkeypatch.setenv('JW_BACKUP_KEY',Fernet.generate_key().decode())
    symlink=tmp_path/'source-link.db';symlink.symlink_to(src)
    with pytest.raises(ValueError,match='symlink'):
        make_backup(symlink,tmp_path/'backups')
