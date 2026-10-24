"""Negative guards for real local postgres verify-full TLS integration."""
from scripts.ci_pg_v91_tls_gateway import safe_environment, PG_IMAGE, PORT


def test_only_ephemeral_review_guard_is_accepted():
    assert safe_environment("ONLY_EPHEMERAL_LOCAL_DATABASE","review")


def test_missing_guard_is_denied():
    assert not safe_environment("","review")


def test_nonreview_environment_denied():
    for state in ("dev","production","prod","local","test",""):
        assert not safe_environment("ONLY_EPHEMERAL_LOCAL_DATABASE",state)


def test_postgres_fixture_cannot_point_at_external_host_or_other_port():
    assert PG_IMAGE=="postgres:17"
    assert PORT=="55432"


def test_runner_unprivileged_key_owner_recovery_is_explicit():
    from pathlib import Path
    import inspect
    from scripts import ci_pg_v91_tls_gateway as module
    body=inspect.getsource(module.build_local_certificates)
    assert 'except PermissionError:' in body
    assert '"sudo","chown","999:999"' in body
    assert 'key.chmod(0o600)' in body
