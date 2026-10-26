"""Offline one-time evidence encryption migration: makes a verified backup first.

Run with JW_DATA_KEY configured, app stopped, and JARVIS_DB_PATH set.
This tool does not encrypt general customer/payment rows and is not a production
launch authorization.
"""
from __future__ import annotations
import os
import sqlite3
from pathlib import Path
from app.security_hardening import data_cipher, migrate_evidence_encryption


def migrate(path:Path, backup:Path):
    data_cipher()
    if not path.exists():raise RuntimeError('Source database does not exist')
    if backup.exists():raise RuntimeError('Backup already exists: refusing overwrite')
    backup.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(path) as db, sqlite3.connect(backup) as dest:
        db.row_factory=sqlite3.Row
        db.backup(dest)
        if dest.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
            backup.unlink(missing_ok=True)
            raise RuntimeError('Database backup integrity check failed')
        db.execute('BEGIN IMMEDIATE')
        try:
            count=migrate_evidence_encryption(db)
            db.commit()
        except BaseException:
            db.rollback()
            raise
        if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
            raise RuntimeError('Migrated DB integrity check failed; restore verified backup')
        return count

if __name__=='__main__':
    src=Path(os.environ['JARVIS_DB_PATH']).expanduser().resolve()
    out=src.with_suffix(src.suffix+'.pre-encryption.bak')
    print(f'Encrypted {migrate(src,out)} evidence records; backup created at {out}')
