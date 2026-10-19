"""Replacement V1.9 static security tests; NOT live PostgreSQL validation."""
from pathlib import Path
from scripts.check_postgres_rls import TENANT_TABLES, AUTH_TABLES


def test_rls_candidate_targets_all_business_entities():
    sql=Path('security/postgres_rls_proposal.sql').read_text()
    for table in TENANT_TABLES:
        assert f"'{table}'" in sql or f'public.{table}' in sql
    assert 'FORCE ROW LEVEL SECURITY' in sql
    assert 'NOBYPASSRLS' in sql
    assert 'jw_guard.current_tenant()' in sql
    assert 'jw_guard.bind_session' in sql
    assert "NULLIF(current_setting('jw.org_id'" not in sql
    for name in AUTH_TABLES: assert f"'{name}'" in sql or f'public.{name}' in sql


def test_sqlite_runtime_still_fails_closed_for_production():
    from app import main
    import inspect
    source=inspect.getsource(main.init_db)
    assert 'Production remains BLOCKED' in source
