"""CINEMA evidence source size is integrity-bound without schema changes.

Tests synthetic metadata only. A legacy preview remains unchanged.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

from app.evidence_v64 import install_schema, digest_doc


@contextmanager
def open_db(db_path):
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def test_fresh_evidence_schema_has_no_unreviewed_column(tmp_path):
    db = tmp_path / 'evidence-new.db'
    install_schema(lambda: open_db(db))
    with open_db(db) as con:
        cols = {r['name'] for r in con.execute('PRAGMA table_info(evidence_previews_v64)')}
        assert cols == {
            'id', 'org_id', 'uploaded_by', 'file_sha256', 'filename', 'proposed_json',
            'digest', 'status', 'created_at', 'confirmed_at', 'record_id'
        }


def test_legacy_evidence_rows_unchanged_across_reinstalls(tmp_path):
    db = tmp_path / 'evidence-old.db'
    with open_db(db) as con:
        con.execute('''CREATE TABLE evidence_previews_v64 (
            id TEXT PRIMARY KEY, org_id TEXT NOT NULL, uploaded_by TEXT NOT NULL,
            file_sha256 TEXT NOT NULL, filename TEXT NOT NULL,
            proposed_json TEXT NOT NULL, digest TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('pending','confirmed')),
            created_at TEXT NOT NULL, confirmed_at TEXT, record_id TEXT UNIQUE
        )''')
        con.execute('''INSERT INTO evidence_previews_v64
            (id,org_id,uploaded_by,file_sha256,filename,proposed_json,digest,status,created_at)
            VALUES (?,?,?,?,?,?,?,?,?)''',
            ('legacy','org','user','a'*64,'archived.xlsx',
             '{"document_kind":null}','b'*64,'pending','2026-11-04T00:00:00'))
    install_schema(lambda: open_db(db))
    install_schema(lambda: open_db(db))
    with open_db(db) as con:
        row = con.execute(
            'SELECT filename, proposed_json FROM evidence_previews_v64 WHERE id=?',
            ('legacy',)
        ).fetchone()
        assert row['filename'] == 'archived.xlsx'
        assert row['proposed_json'] == '{"document_kind":null}'
        cols = {r['name'] for r in con.execute('PRAGMA table_info(evidence_previews_v64)')}
        assert 'source_size_bytes' not in cols


def test_source_byte_count_is_integrity_bound_to_document():
    before = {'document_kind':None,'fields':{}}
    sized = {**before,'source_size_bytes':527}
    assert digest_doc(before) != digest_doc(sized)
    assert digest_doc(sized) != digest_doc({**before,'source_size_bytes':528})
