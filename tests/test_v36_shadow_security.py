import hashlib
import pytest

from app.pg_migration_shadow_v36 import (
    Record, TABLES, compare_records, MigrationBlocked
)


def test_valid_digest_and_record_equality():
    payload = b'{"message":"verified"}'
    record = Record(
        "messenger_messages", "msg-001", payload,
        hashlib.sha256(payload).hexdigest()
    )
    assert record.entity in TABLES
    assert compare_records([record], [record])


def test_modified_payload_detected():
    original = b'{"message":"verified"}'
    modified = b'{"message":"tampered"}'
    digest = hashlib.sha256(original).hexdigest()
    assert hashlib.sha256(modified).hexdigest() != digest


def test_record_mismatch_rejected():
    payload = b'{"message":"verified"}'
    digest = hashlib.sha256(payload).hexdigest()
    a = Record("messenger_messages", "msg-001", payload, digest)
    b = Record("messenger_messages", "msg-002", payload, digest)
    with pytest.raises((AssertionError, MigrationBlocked, ValueError)):
        assert compare_records([a], [b])


def test_unknown_entity_not_allowed():
    assert "orders" not in TABLES
