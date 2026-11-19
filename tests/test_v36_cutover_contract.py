"""V3.6 synthetic-only migration compatibility regression."""
import json
from dataclasses import replace

import pytest

from scripts.v36_synthetic_fixture import fixture
from app.pg_migration_shadow_v36 import (
    MigrationBlocked,
    TABLES,
    compare_records,
    operational_cutover_blockers,
    source_records,
)


@pytest.fixture
def records():
    db = fixture()
    try:
        return source_records(db)
    finally:
        db.close()


def test_all_seven_legacy_entities_preserved(records):
    assert {r.entity for r in records} == set(TABLES)
    assert compare_records(records, list(reversed(records)))["rows"] == len(records)


def test_order_snapshot_preserved(records):
    orders = [
        json.loads(r.payload)
        for r in records
        if r.entity == "messenger_messages"
        and '"order"' in r.payload.decode("utf-8")
    ]
    assert orders
    assert any("immutable_order_snapshot" in r["columns"] for r in orders)


def test_attachment_binary_and_receipt_preserved(records):
    attachments = [r for r in records if r.entity == "messenger_attachments"]
    receipts = [r for r in records if r.entity == "messenger_receipts"]
    assert attachments and receipts
    assert any('"bytes"' in r.payload.decode("utf-8") for r in attachments)


def test_mutated_payload_rejected(records):
    altered = list(records)
    altered[0] = replace(altered[0], payload=altered[0].payload + b"tamper")
    with pytest.raises(MigrationBlocked):
        compare_records(records, altered)


def test_operational_cutover_remains_blocked(records):
    blockers = set(operational_cutover_blockers(records))
    required = {
        "PG_OPERATIONAL_SCHEMA_NOT_LOSSLESS",
        "REAL_EMPLOYEE_IDENTITY_NOT_VERIFIED",
        "LIVE_API_STORAGE_NOT_MIGRATED",
        "PRODUCTION_CUTOVER_NOT_AUTHORIZED",
        "ORDER_SNAPSHOT_FIELDS_MISSING_IN_PG_SCHEMA",
        "LEGACY_ATTACHMENT_MESSAGE_KIND_INCOMPATIBLE",
        "RECEIPT_EVIDENCE_FIELDS_DIFFER",
    }
    assert required <= blockers
