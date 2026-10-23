"""V1.8 encrypted offline SQLite backups, with no intermediate plaintext backup file.

This protects backup artifacts only. The live SQLite database is NOT encrypted, and
this does NOT implement PostgreSQL RLS, online replication, or scheduled recovery.
"""
from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet, InvalidToken

ROOT=Path(__file__).resolve().parents[1]
HEADER=b'JWBACKUP1\n'
MAX_DB_BYTES=48*1024*1024  # Fernet encrypts entirely in memory. Fail closed above this.


def cipher():
    value=os.environ.get('JW_BACKUP_KEY','')
    if not value:
        raise RuntimeError('JW_BACKUP_KEY is required; a separate backup encryption key is mandatory')
    try:
        return Fernet(value.encode('ascii'))
    except (ValueError,TypeError) as exc:
        raise RuntimeError('JW_BACKUP_KEY must be a valid Fernet key') from exc


def safe_folder(folder:Path):
    if folder.is_symlink():
        raise ValueError('Symlink backup directories are forbidden')
    folder.mkdir(parents=True,exist_ok=True,mode=0o700)
    if os.name=='posix':
        os.chmod(folder,0o700)


def integrity(connection):
    if connection.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
        raise ValueError('SQLite integrity_check failed')


def make_backup(source:Path|None=None,target_dir:Path|None=None):
    source=Path(source or os.environ.get('JARVIS_DB_PATH',ROOT/'data'/'works.db'))
    target_dir=Path(target_dir or os.environ.get('JARVIS_BACKUP_DIR',ROOT/'backups'))
    if source.is_symlink() or not source.is_file():
        raise ValueError('Source must be a real SQLite database file (not a symlink)')
    if source.stat().st_size>MAX_DB_BYTES:
        raise ValueError('Database exceeds in-memory encrypted-backup limit')
    key=cipher()
    safe_folder(target_dir)
    # Online SQLite backup API gives a consistent snapshot into RAM only.
    with sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True) as src,sqlite3.connect(':memory:') as snapshot:
        src.backup(snapshot)
        integrity(snapshot)
        raw=snapshot.serialize()
        if len(raw)>MAX_DB_BYTES:
            raise ValueError('Snapshot exceeds in-memory encrypted-backup limit')
        payload=HEADER+key.encrypt(raw)
    time=datetime.now(ZoneInfo('Asia/Seoul')).strftime('%Y%m%d_%H%M%S_%f')
    dest=target_dir/f'works_{time}.jwbackup'
    flags=os.O_CREAT|os.O_EXCL|os.O_WRONLY
    if hasattr(os,'O_NOFOLLOW'):flags|=os.O_NOFOLLOW
    fd=os.open(dest,flags,0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        # Verify the just-written encrypted file before reporting success.
        verify_backup(dest,key)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return dest


def verify_backup(path:Path,key:Fernet|None=None):
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise ValueError('Backup file must not be a symlink')
    raw=path.read_bytes()
    if not raw.startswith(HEADER):raise ValueError('Invalid backup header')
    if len(raw)>2*MAX_DB_BYTES+512:
        raise ValueError('Encrypted backup exceeds allowed size')
    try:
        plain=(key or cipher()).decrypt(raw[len(HEADER):])
    except InvalidToken as exc:
        raise ValueError('Encrypted backup authentication failed; wrong key or tampering') from exc
    if len(plain)>MAX_DB_BYTES:raise ValueError('Backup payload too large')
    with sqlite3.connect(':memory:') as snapshot:
        snapshot.deserialize(plain)
        integrity(snapshot)
    return plain


def restore_backup(src:Path,dest:Path):
    dest=Path(dest)
    if dest.is_symlink() or dest.exists():raise ValueError('Restore target already exists or is a symlink')
    plain=verify_backup(Path(src))
    safe_folder(dest.parent)
    with sqlite3.connect(':memory:') as snapshot:
        snapshot.deserialize(plain)
        integrity(snapshot)
        # Exclusive creation means even an existing empty file is not overwritten.
        flags=os.O_CREAT|os.O_EXCL|os.O_WRONLY
        if hasattr(os,'O_NOFOLLOW'):flags|=os.O_NOFOLLOW
        fd=os.open(dest,flags,0o600)
        os.close(fd)
        try:
            with sqlite3.connect(dest) as target:
                snapshot.backup(target)
                integrity(target)
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
    return dest


if __name__=='__main__':
    try:
        if len(sys.argv)==1:
            print(make_backup())
        elif len(sys.argv)==4 and sys.argv[1]=='restore':
            print(restore_backup(Path(sys.argv[2]),Path(sys.argv[3])))
        else:
            raise ValueError('Usage: python scripts/secure_backup.py [restore ENCRYPTED_BACKUP NEW_DB_PATH]')
    except Exception as exc:
        print(f'Encrypted backup failed: {exc}',file=sys.stderr)
        raise SystemExit(1)
