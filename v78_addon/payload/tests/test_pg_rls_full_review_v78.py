"""Auditable V7.8 offline policy coverage and fail-closed startup tests."""
from __future__ import annotations

from pathlib import Path
import json
import os
import sqlite3

from fastapi.testclient import TestClient
import pytest

from app import main
from app.deployment_safety_v78 import DeploymentBlocked, require_safe_runtime
from app.pg_full_shadow_v76 import EXPECTED_TABLES
from app.pg_rls_full_review_v78 import (
    DIRECT, DERIVED, PRIVATE, SPECIAL, REVIEW_TABLES, ReviewBlocked,
    generate_lab_sql, schema_contract,
)


def test_full_table_coverage_drift_is_not_allowed(client):
    assert REVIEW_TABLES == EXPECTED_TABLES
    with main.conn() as c:
        summary=schema_contract(c)
    assert summary['tables']==35 and len(summary['source_schema_sha256'])==64
    assert sum(summary[key] for key in ('private','direct','derived','special'))==35
    assert summary['all_tables_accounted_for'] and not summary['postgres_executed']


def test_review_sql_only_select_and_compartmentalized(client):
    with main.conn() as c:
        sql=generate_lab_sql(c)
    assert 'jw_v20_test_' in sql
    assert sql.count('ENABLE ROW LEVEL SECURITY;')==35
    assert sql.count('FORCE ROW LEVEL SECURITY;')==35
    assert sql.count('REVOKE ALL ON TABLE public.')==35
    assert sql.count('GRANT SELECT ON TABLE public.')==35-len(PRIVATE)
    assert sql.count('CREATE POLICY jw_v78_review_select')==35-len(PRIVATE)
    assert 'GRANT INSERT' not in sql and 'GRANT UPDATE' not in sql and 'GRANT DELETE' not in sql
    assert 'CREATE TABLE' not in sql and 'DROP TABLE' not in sql
    for name in PRIVATE:
        assert f'GRANT SELECT ON TABLE public."{name}"' not in sql
        assert f'CREATE POLICY jw_v78_review_select ON public."{name}"' not in sql
    assert 'Existing policies require manual review' in sql
    assert sql.count('Column drift: ')==35


def test_messenger_visibility_uses_connection_parties(client):
    with main.conn() as c:
        sql=generate_lab_sql(c)
    for table in ('messenger_messages','messenger_attachments','messenger_edits','messenger_receipts','messenger_connections'):
        policy=next(line for line in sql.splitlines() if f'CREATE POLICY jw_v78_review_select ON public."{table}" ' in line)
        assert 'jw_guard.current_tenant()' in policy
        assert 'org_a=' in policy and 'org_b=' in policy
    assert 'set_config(' not in sql
    assert 'current_setting(\'jw.ctx_org\'' not in sql


def test_source_metadata_changed_fail_closed(client):
    with main.conn() as c:
        c.execute('CREATE TABLE new_finance_records (id TEXT PRIMARY KEY)')
        with pytest.raises(ReviewBlocked,match='Unreviewed or missing'):
            generate_lab_sql(c)


def test_added_column_fails_closed(client):
    with main.conn() as c:
        c.execute('ALTER TABLE customers ADD COLUMN private_bank_account TEXT')
        with pytest.raises(ReviewBlocked,match='fingerprint changed'):
            generate_lab_sql(c)


def test_wrong_column_fails_closed(client):
    with main.conn() as c:
        c.execute('ALTER TABLE customers RENAME COLUMN org_id TO company_id')
        with pytest.raises(ReviewBlocked,match='org_id key missing'):
            generate_lab_sql(c)


def test_prod_blocks_review_even_without_db_access(monkeypatch):
    monkeypatch.setenv('JW_ENV','production')
    with sqlite3.connect(':memory:') as c:
        with pytest.raises(ReviewBlocked,match='Production'):
            generate_lab_sql(c)


@pytest.mark.parametrize('env',['production','prod',' Production '])
def test_production_api_startup_prevented_before_sqlite_write(tmp_path,monkeypatch,env):
    monkeypatch.setenv('JW_ENV',env)
    db=tmp_path/'must_not_exist.db'
    monkeypatch.setattr(main,'DB_PATH',db)
    with pytest.raises(DeploymentBlocked,match='PRODUCTION_BLOCKED'):
        with TestClient(main.app):
            pass
    assert not db.exists()


def test_local_app_still_runs(client):
    assert client.get('/health').status_code in (200,404)


def test_direct_derived_and_private_scopes_are_disjoint():
    groups=[PRIVATE,DIRECT,frozenset(DERIVED),frozenset(SPECIAL)]
    for i,group in enumerate(groups):
        for other in groups[i+1:]:
            assert not group & other


def test_review_generator_uses_disposable_empty_db(monkeypatch,tmp_path):
    from scripts.generate_pg_rls_review_v78 import run
    source=main.DB_PATH
    ddl,stats=run()
    assert stats['tables']==35 and main.DB_PATH==source
    assert len(ddl)>25000 and 'COMMIT;' in ddl
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(RuntimeError,match='prohibited'):
        run()
