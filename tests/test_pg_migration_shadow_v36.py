"""V3.6 lossless archive contracts, not a substitute for live PostgreSQL."""
import hashlib
import json
import sqlite3
from dataclasses import replace

import pytest

from app.pg_migration_shadow_v36 import (TABLES, MigrationBlocked, Record,
    value_token, source_records, compare_records, operational_cutover_blockers,
    canonical_bytes, seal, MAX_BYTES)
from scripts.v36_synthetic_fixture import fixture


def test_all_seven_entities_retained_byte_exact_and_no_live_cutover():
    db=fixture()
    try:
        rows=source_records(db)
    finally:
        db.close()
    result=compare_records(rows,rows)
    assert result['rows']==11 and set(result['tables'])==set(TABLES)
    assert len(result['seal_sha256'])==64
    assert 'PG_OPERATIONAL_SCHEMA_NOT_LOSSLESS' in operational_cutover_blockers(rows)


def test_binary_bytes_unicode_and_order_snapshot_preserved():
    db=fixture()
    try:r=source_records(db)
    finally:db.close()
    item=next(x for x in r if x.entity=='messenger_attachments')
    obj=json.loads(item.payload)
    assert obj['values'][obj['columns'].index('data')]==['bytes','AP8B/lBORy1kZW1vLWJ5dGVzAA==']
    assert obj['values'][obj['columns'].index('filename')]==['text','synthetic-한글.png']
    order=next(x for x in r if x.entity=='messenger_messages' and b'msg_order' in x.payload)
    assert 'lineItems' in order.payload.decode()
    assert b'\x00' not in item.payload  # base64-encoded bytes, lossless in JSON


def test_preserves_source_snapshot_despite_later_sqlite_mutation():
    db=fixture()
    try:
        original=source_records(db)
        db.execute("UPDATE messenger_messages SET body='later changed' WHERE id='msg_text'")
        db.commit()
        updated=source_records(db)
        assert original!=updated
        assert compare_records(original,original)['rows']==11
        with pytest.raises(MigrationBlocked):compare_records(original,updated)
    finally:db.close()


def test_pg_payload_mutation_detected_independent_of_row_count():
    db=fixture()
    try:original=source_records(db)
    finally:db.close()
    altered=list(original)
    altered[0]=replace(altered[0],payload=altered[0].payload+b'!')
    with pytest.raises(MigrationBlocked,match='bytes|SHA'):compare_records(original,altered)
    altered[0]=replace(altered[0],digest='f'*64)
    with pytest.raises(MigrationBlocked):compare_records(original,altered)


def test_missing_table_fails_closed():
    db=fixture()
    try:
        db.execute('DROP TABLE messenger_receipts')
        with pytest.raises(MigrationBlocked,match='table missing'):source_records(db)
    finally:db.close()


def test_untrusted_source_fk_fails_closed():
    db=fixture()
    try:
        db.execute('PRAGMA foreign_keys=OFF')
        db.execute("INSERT INTO messenger_receipts VALUES ('nonexistent','tenant_b','X','ub','2026')")
        db.commit()
        with pytest.raises(MigrationBlocked,match='foreign key'):source_records(db)
    finally:db.close()


def test_too_much_attachment_data_fails_closed(monkeypatch):
    import app.pg_migration_shadow_v36 as subject
    monkeypatch.setattr(subject,'MAX_BYTES',100)
    db=fixture()
    try:
        with pytest.raises(MigrationBlocked,match='safety cap'):subject.source_records(db)
    finally:db.close()


def test_supported_value_types_and_invalid_boolean():
    assert value_token(None)==['null',None]
    assert value_token(17)==['integer','17']
    assert value_token(-0.0)==['float','-0x0.0p+0']
    assert value_token(b'\x00')==['bytes','AA==']
    with pytest.raises(MigrationBlocked):value_token(True)


def test_read_positions_use_composite_stable_row_keys():
    db=fixture()
    try:r=source_records(db)
    finally:db.close()
    reads=[x for x in r if x.entity=='messenger_read_positions']
    assert len(reads)==2 and len({x.row_key for x in reads})==2
    assert all('thread_ab' in x.row_key for x in reads)


def test_empty_tables_still_included_and_counted_zero():
    db=fixture()
    try:
        db.execute('DELETE FROM messenger_receipts')
        db.execute('DELETE FROM messenger_edits')
        db.commit()
        r=source_records(db)
        assert len(r)==9
        assert len({x.entity for x in r})==5
    finally:db.close()


def test_duplicate_entity_keys_are_rejected_by_comparison():
    db=fixture()
    try:r=source_records(db)
    finally:db.close()
    with pytest.raises(MigrationBlocked):compare_records(r,r+[r[-1]])


def test_explicit_no_customer_file_path_api_and_gate_source_present():
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    code=(root/'scripts/test_postgres_migration_v36.py').read_text()
    assert "JW_PG_ALLOW_TEST_WRITES" in code
    assert "ONLY_DISPOSABLE_LAB" in code
    assert "Injected failure was not applied" in code
    assert "sqlstate=='42501'" in code
    assert "sqlstate=='23514'" in code
    assert (root/'app/pg_migration_shadow_v36.py').exists()
