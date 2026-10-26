"""V7.6 synthetic full-schema source snapshot regression tests."""
from dataclasses import replace
from hashlib import sha256
import sqlite3
import pytest
from app import main
from app.pg_full_shadow_v76 import ShadowBlocked,capture,compare,summary,EXPECTED_TABLES


def test_captures_every_app_table_and_never_claims_cutover(api):
    with main.conn() as c:
        data=capture(c)
    result=summary(data)
    assert result['tables']==35
    assert set(result['per_table'])==EXPECTED_TABLES
    assert result['per_table']['quotes']>=2
    assert len(result['schema_sha256'])==64
    assert result['operational_cutover_permitted'] is False
    assert compare(data,data)['seal_sha256']==data.seal


def test_original_snapshot_unchanged_after_later_commit(api):
    with main.conn() as c:
        first=capture(c)
        c.execute("UPDATE customers SET name='AFTER SNAPSHOT' WHERE id=(SELECT id FROM customers LIMIT 1)")
        second=capture(c)
    assert first!=second
    assert compare(first,first)['seal_sha256']==first.seal
    with pytest.raises(ShadowBlocked):compare(first,second)


def test_source_column_and_content_tamper_rejected(api):
    with main.conn() as c:
        initial=capture(c)
    modified=list(initial.records)
    modified[0]=replace(modified[0],payload=modified[0].payload+b'!')
    with pytest.raises(ShadowBlocked,match='Corrupted'):
        summary(replace(initial,records=tuple(modified)))
    with pytest.raises(ShadowBlocked,match='seal mismatch'):
        summary(replace(initial,schema_bytes=initial.schema_bytes+b' '))
    with pytest.raises(ShadowBlocked,match='Duplicate row key'):
        summary(replace(initial,records=initial.records+(initial.records[-1],)))


def test_unknown_schema_table_must_block(api):
    with main.conn() as c:
        c.execute('CREATE TABLE unexpected_new_finance_table(id TEXT PRIMARY KEY)')
        with pytest.raises(ShadowBlocked,match='table set mismatch'):
            capture(c)


def test_fk_corruption_must_block(api):
    with main.conn() as c:
        c.execute('PRAGMA foreign_keys=OFF')
        c.execute("INSERT INTO customers(id,org_id,name,created_at) VALUES('rogue','missing','rogue','2026')")
        with pytest.raises(ShadowBlocked,match='foreign_key_check'):
            capture(c)


def test_synthetic_binary_float_unicode_and_composite_pk(monkeypatch):
    import app.pg_full_shadow_v76 as subject
    monkeypatch.setattr(subject,'EXPECTED_TABLES',frozenset({'lines'}))
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE lines(a TEXT NOT NULL,b INTEGER NOT NULL, note BLOB, amount REAL, PRIMARY KEY(a,b))')
        db.execute('INSERT INTO lines VALUES(?,?,?,?)',('한글',1,b'\x00\xff',-0.0))
        db.commit()
        result=subject.capture(db)
        assert result.records[0].key.find('한글')>=0
        assert b'AP8=' in result.records[0].payload
        assert b'0x0.0p+0' in result.records[0].payload


def test_synthetic_without_explicit_pk_rejected(monkeypatch):
    import app.pg_full_shadow_v76 as subject
    monkeypatch.setattr(subject,'EXPECTED_TABLES',frozenset({'orphans'}))
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE orphans(name TEXT)')
        with pytest.raises(ShadowBlocked,match='explicit PK'):
            subject.capture(db)


def test_source_size_limit(monkeypatch):
    import app.pg_full_shadow_v76 as subject
    monkeypatch.setattr(subject,'EXPECTED_TABLES',frozenset({'lines'}))
    monkeypatch.setattr(subject,'MAX_BYTES',30)
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE lines(id TEXT PRIMARY KEY, data BLOB)')
        db.execute('INSERT INTO lines VALUES(?,?)',('1',b'a'*100))
        db.commit()
        with pytest.raises(ShadowBlocked,match='safety cap'):
            subject.capture(db)


def test_pg_write_guard_rejects_non_ephemeral(monkeypatch):
    from app.pg_full_shadow_v76 import _guard
    class Cur:
        def __init__(self):self.calls=0
        def execute(self,sql,params=None):self.calls+=1
        def fetchone(self):return ('production','postgres','170000')
    c=Cur()
    with pytest.raises(ShadowBlocked,match='temporary isolated'):_guard(c)
    assert c.calls==1


def test_open_transaction_fails_without_hanging():
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE lines(id TEXT PRIMARY KEY)')
        db.execute("INSERT INTO lines VALUES ('x')")
        with pytest.raises(ShadowBlocked,match='open transaction'):
            capture(db)


def test_full_schema_synthetic_cli_is_read_only_and_redacted(monkeypatch):
    from scripts.inspect_full_shadow_v76 import run
    result=run()
    assert result['tables']==35 and result['data_source']=='synthetic_demo_only'
    assert result['operational_cutover_permitted'] is False
    assert 'demo@hanbit' not in str(result)
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(RuntimeError,match='forbidden'):
        run()


def test_autoincrement_sequence_retained_after_deleted_high_watermark(monkeypatch):
    import app.pg_full_shadow_v76 as subject
    import json
    monkeypatch.setattr(subject,'EXPECTED_TABLES',frozenset({'seq'}))
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE seq (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)')
        db.execute("INSERT INTO seq(name) VALUES('first'),('second')")
        db.execute('DELETE FROM seq WHERE id=2')
        db.commit()
        bundle=subject.capture(db)
    metadata=json.loads(bundle.schema_bytes)
    assert metadata['sqlite_sequence']==[['seq',2]]
    assert len(bundle.records)==1


def test_source_production_guard(monkeypatch):
    monkeypatch.setenv('JW_ENV','production')
    with sqlite3.connect(':memory:') as c:
        with pytest.raises(ShadowBlocked,match='forbidden'):
            capture(c)
