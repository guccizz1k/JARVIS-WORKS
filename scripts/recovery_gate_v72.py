"""Isolated failure-injection + encrypted SQLite restore gate.

Tests a synthetic database ONLY. It never inspects or alters customer data,
does not schedule backups, and does not certify production recovery targets.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from cryptography.fernet import Fernet
from scripts.secure_backup import make_backup, restore_backup, verify_backup


def semantic_digest(db: Path):
    with sqlite3.connect(db) as c:
        assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        rows=c.execute('SELECT id,org_id,amount FROM synthetic_payments ORDER BY id').fetchall()
    return hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()


def run():
    if os.environ.get('JW_ENV','').lower() in ('production','prod'):
        raise RuntimeError('Isolated test only; production is forbidden')
    started=time.monotonic()
    result={'dataset':'synthetic only', 'tests':{}, 'production_recovery_certified':False}
    with tempfile.TemporaryDirectory(prefix='jw-v72-synthetic-') as name:
        root=Path(name);source=root/'source.db';restored=root/'restored.db'
        with sqlite3.connect(source) as c:
            c.execute('CREATE TABLE synthetic_payments(id INTEGER PRIMARY KEY,org_id TEXT NOT NULL,amount INTEGER NOT NULL)')
            c.executemany('INSERT INTO synthetic_payments(org_id,amount) VALUES(?,?)',
                          [(f'fake_org_{i%3}',(i+1)*101) for i in range(500)])
            c.commit()  # fixture setup is durable before injecting a new transaction fault
            # Deliberate mid-transaction exception must not leave a partial transfer.
            before=c.execute('SELECT COUNT(*) FROM synthetic_payments').fetchone()[0]
            try:
                with c:
                    c.execute('INSERT INTO synthetic_payments(org_id,amount) VALUES(?,?)',('fake_org_1',1000))
                    raise RuntimeError('synthetic_crash')
            except RuntimeError:
                pass
            after=c.execute('SELECT COUNT(*) FROM synthetic_payments').fetchone()[0]
            assert before==after==500
            result['tests']['atomic_rollback']='PASS'
        original=semantic_digest(source)
        original_key=os.environ.get('JW_BACKUP_KEY')
        try:
            os.environ['JW_BACKUP_KEY']=Fernet.generate_key().decode()
            backup=make_backup(source,root/'backups')
            encrypted=backup.read_bytes()
            assert b'fake_org_' not in encrypted
            result['tests']['encrypted_backup']='PASS'
            broken=bytearray(encrypted);broken[-20]^=0x01
            tampered=root/'tampered.jwbackup';tampered.write_bytes(broken)
            try:
                verify_backup(tampered)
                raise AssertionError('Corruption was accepted')
            except ValueError:
                result['tests']['tamper_rejected']='PASS'
            recover_start=time.monotonic()
            restore_backup(backup,restored)
            result['restore_elapsed_seconds']=round(time.monotonic()-recover_start,4)
            assert semantic_digest(restored)==original
            assert semantic_digest(source)==original
            result['tests']['semantic_restore']='PASS'
            result['tests']['source_unchanged']='PASS'
            os.environ['JW_BACKUP_KEY']=Fernet.generate_key().decode()
            try:
                verify_backup(backup)
                raise AssertionError('Wrong key accepted')
            except ValueError:
                result['tests']['wrong_key_rejected']='PASS'
        finally:
            if original_key is None:os.environ.pop('JW_BACKUP_KEY',None)
            else:os.environ['JW_BACKUP_KEY']=original_key
    result['total_elapsed_seconds']=round(time.monotonic()-started,4)
    result['local_result']='PASS' if all(x=='PASS' for x in result['tests'].values()) else 'FAIL'
    result['limits']=['Local synthetic SQLite only','Not a production restore/RPO/RTO guarantee',
                      'PostgreSQL RLS and production failover NOT RUN']
    return result


if __name__=='__main__':
    print(json.dumps(run(),ensure_ascii=False,indent=2))
