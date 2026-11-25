"""V3.6 lossless migration contract; synthetic data only."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from scripts.v36_synthetic_fixture import fixture
from app.pg_migration_shadow_v36 import (
    TABLES, MigrationBlocked, source_records, compare_records,
    operational_cutover_blockers,
)


@pytest.fixture
def records():
    db = fixture()
    try:
        return source_records(db)
    finally:
        db.close()


def decoded(record):
    obj = json.loads(record.payload)
    return dict(zip(obj["columns"], obj["values"]))


def test_all_seven_legacy_tables_preserved(records):
    assert {r.entity for r in records} == set(TABLES)
    assert compare_records(records, list(reversed(records)))["rows"] == len(records)


def test_order_snapshot_preserved(records):
    messages = [decoded(r) for r in records if r.entity == "messenger_messages"]
    orders = [m for m in messages if m["kind"][1] == "order"]
    assert orders
    for order in orders:
        assert order["order_id"][1]
        assert order["immutable_order_snapshot"][1]
        assert "lineItems" in json.loads(order["immutable_order_snapshot"][1])


def test_attachment_binary_and_digest_preserved(records):
    attachments = [decoded(r) for r in records if r.entity == "messenger_attachments"]
    assert attachments
    for attachment in attachments:
        import base64
        blob = base64.b64decode(attachment["data"][1], validate=True)
        assert attachment["data"][0] == "bytes"
        assert len(blob) == int(attachment["size_bytes"][1])
        assert sha256(blob).hexdigest() == attachment["content_hash"][1]


def test_receipt_evidence_preserved(records):
    receipts = [decoded(r) for r in records if r.entity == "messenger_receipts"]
    assert receipts
    for receipt in receipts:
        for field in ("message_id", "receiver_org", "receiver_user", "received_at"):
            assert receipt[field][1]


def test_tampered_payload_rejected(records):
    altered = list(records)
    altered[0] = replace(altered[0], payload=altered[0].payload + b"tamper")
    with pytest.raises(MigrationBlocked):
        compare_records(records, altered)


def test_missing_record_rejected(records):
    with pytest.raises(MigrationBlocked):
        compare_records(records, records[:-1])


def test_operational_cutover_remains_blocked(records):
    blockers = set(operational_cutover_blockers(records))
    assert {
        "PG_OPERATIONAL_SCHEMA_NOT_LOSSLESS",
        "REAL_EMPLOYEE_IDENTITY_NOT_VERIFIED",
        "LIVE_API_STORAGE_NOT_MIGRATED",
        "PRODUCTION_CUTOVER_NOT_AUTHORIZED",
        "ORDER_SNAPSHOT_FIELDS_MISSING_IN_PG_SCHEMA",
        "LEGACY_ATTACHMENT_MESSAGE_KIND_INCOMPATIBLE",
        "RECEIPT_EVIDENCE_FIELDS_DIFFER",
    } <= blockers
