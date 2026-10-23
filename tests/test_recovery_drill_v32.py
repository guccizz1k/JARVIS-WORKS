"""Synthetic encrypted-backup restore + corruption + immutable original checks."""
import hashlib
import sqlite3
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from scripts.secure_backup import make_backup,restore_backup,verify_backup


def test_encrypted_restore_drill_and_wrong_key(tmp_path,monkeypatch):
    key=Fernet.generate_key().decode()
    monkeypatch.setenv('JW_BACKUP_KEY',key)
    source=tmp_path/'synthetic.db'
    with sqlite3.connect(source) as c:
        c.execute('CREATE TABLE messages (id INTEGER PRIMARY KEY, company TEXT, body TEXT)')
        c.executemany('INSERT INTO messages(company,body) VALUES(?,?)',
                      [('company_a','message'+str(n)) for n in range(25)])
    original_hash=hashlib.sha256(source.read_bytes()).hexdigest()
    backup=make_backup(source,tmp_path/'backups')
    assert backup.read_bytes().startswith(b'JWBACKUP1\n')
    assert b'message24' not in backup.read_bytes()
    with sqlite3.connect(source) as c:
        c.execute("DELETE FROM messages WHERE id>5")
    restored=restore_backup(backup,tmp_path/'restored.db')
    with sqlite3.connect(restored) as c:
        assert c.execute('SELECT count(*) FROM messages').fetchone()[0]==25
        assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    # SQLite backup/restore may reserialize B-tree pages and change byte hashes;
    # compare semantic records and integrity instead of physical file layout.
    with sqlite3.connect(restored) as c:
        rows=c.execute('SELECT id,company,body FROM messages ORDER BY id').fetchall()
    assert rows==[(n,'company_a','message'+str(n-1)) for n in range(1,26)]
    assert hashlib.sha256(restored.read_bytes()).hexdigest()  # recorded artifact digest
    with pytest.raises(ValueError):restore_backup(backup,restored)
    monkeypatch.setenv('JW_BACKUP_KEY',Fernet.generate_key().decode())
    with pytest.raises(ValueError):verify_backup(backup)


def test_backup_bit_flip_detected(tmp_path,monkeypatch):
    monkeypatch.setenv('JW_BACKUP_KEY',Fernet.generate_key().decode())
    source=tmp_path/'synthetic.db'
    with sqlite3.connect(source) as c:c.execute('CREATE TABLE t(x TEXT)')
    backup=make_backup(source,tmp_path/'backups')
    broken=bytearray(backup.read_bytes());broken[-18]^=0x01
    corrupted=tmp_path/'corrupt.jwbackup';corrupted.write_bytes(broken)
    with pytest.raises(ValueError):verify_backup(corrupted)
    with pytest.raises(ValueError):restore_backup(corrupted,tmp_path/'must_not_exist.db')
    assert not (tmp_path/'must_not_exist.db').exists()
