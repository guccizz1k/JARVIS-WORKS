"""J6 negative safety gates for ephemeral PostgreSQL restore rehearsal."""
import pytest
from scripts.ci_j6_postgres_restore import allowed_connection, validate_container_id, RESTORE_NAME, IMAGE


def test_only_local_approved_pg17_cluster_can_be_rehearsed():
    approved = "postgresql://postgres:ci-test-only@127.0.0.1:5432/postgres"
    assert allowed_connection("ONLY_EPHEMERAL_LOCAL_DATABASE", approved)


@pytest.mark.parametrize("guard,dsn", [
    ("", "postgresql://postgres:secret@127.0.0.1:5432/postgres"),
    ("dev", "postgresql://postgres:secret@127.0.0.1:5432/postgres"),
    ("ONLY_EPHEMERAL_LOCAL_DATABASE", "postgresql://postgres:secret@db.example.com/postgres"),
    ("ONLY_EPHEMERAL_LOCAL_DATABASE", "postgresql://postgres:secret@127.0.0.1:5432/prod"),
    ("ONLY_EPHEMERAL_LOCAL_DATABASE", "postgresql://app:secret@127.0.0.1:5432/postgres"),
    ("ONLY_EPHEMERAL_LOCAL_DATABASE", "postgresql://postgres@127.0.0.1:5432/postgres"),
    ("ONLY_EPHEMERAL_LOCAL_DATABASE", ""),
])
def test_block_unapproved_database(guard, dsn):
    assert not allowed_connection(guard, dsn)


def test_container_id_requires_exactly_one():
    assert validate_container_id("abcdef012345") == "abcdef012345"


@pytest.mark.parametrize("data", ["", "not-an-id", "abcdef012345\n123456789abc", "A" * 12])
def test_refuse_ambiguous_container_ids(data):
    with pytest.raises(RuntimeError):
        validate_container_id(data)


def test_restored_name_must_be_random_and_namespaced():
    assert RESTORE_NAME.fullmatch("jw_j6_restore_0123456789")
    assert not RESTORE_NAME.fullmatch("postgres")
    assert not RESTORE_NAME.fullmatch("jw_j6_restore_../../prod")


def test_immutable_pg17_image_pin():
    assert IMAGE == "postgres:17"
