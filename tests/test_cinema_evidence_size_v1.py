"""CINEMA OCR queue source-byte provenance and additive SQLite migration.

Synthetic data only. Old rows must not have an invented upload size.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

import pytest

from app.evidence_v64 import install_schema


@contextmanager
def open_db(db_path):
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def test_new_evidence_schema_tracks_bytes_with_valid_range(tmp_path):
    db = tmp_path / 'evidence-new.db'
    install_schema(lambda: open_db(db))
    with open_db(db) as con:
        cols = {r['name'] for r in con.execute('PRAGMA table_info(evidence_previews_v64)')}
        assert 'source_size_bytes' in cols
        definition = con.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='evidence_previews_v64'"
        ).fetchone()['sql']
        assert 'source_size_bytes INTEGER CHECK' in definition
        assert 'source_size_bytes BETWEEN 1 AND 5242880' in definition


def test_legacy_evidence_rows_preserve_unknown_size_and_upgrade_twice(tmp_path):
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
            'SELECT filename, source_size_bytes FROM evidence_previews_v64 WHERE id=?',
            ('legacy',)
        ).fetchone()
        assert row['filename'] == 'archived.xlsx'
        assert row['source_size_bytes'] is None
        cols = [r['name'] for r in con.execute('PRAGMA table_info(evidence_previews_v64)')]
        assert cols.count('source_size_bytes') == 1
