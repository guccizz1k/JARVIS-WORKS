"""V2.0 NON-SQL-ENGINE test. Live policy requires the isolated PostgreSQL gate.

These tests only prove the expected source constraints and fail-closed triggers
are present in candidate artifacts. They do not demonstrate actual PG safety.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
SQL=(ROOT/'security/postgres_rls_proposal.sql').read_text()
FIXTURE=(ROOT/'security/pg_rls_test_fixture.sql').read_text()
RUNTIME=(ROOT/'scripts/test_postgres_rls_runtime.py').read_text()
AUDIT=(ROOT/'scripts/check_postgres_rls.py').read_text()
CI=(ROOT/'.github/workflows/pg-rls-attack-gate.yml').read_text()


def test_rls_tenant_foreign_key_preflight_is_explicit():
    assert 'DO $tenant_fk_preflight$' in SQL
    assert 'c.contype=\'f\' AND c.convalidated' in SQL
    assert 'c.conkey=' in SQL and 'c.confkey=' in SQL
    for c,p in [('quotes','customers'),('quote_items','quotes'),('orders','quotes'),
                ('order_items','orders'),('order_items','quote_items'),
                ('invoices','orders'),('invoice_items','invoices'),('payments','invoices')]:
        assert f"('{c}','{p}'" in SQL


def test_fixture_models_tenant_safe_references():
    assert 'jw_fk_quotes_customer_tenant' in FIXTURE
    assert 'jw_fk_order_items_source_quote_tenant' in FIXTURE
    assert 'FOREIGN KEY(customer_id,org_id) REFERENCES public.customers(id,org_id)' in FIXTURE
    assert "public.quote_items(id text PRIMARY KEY,org_id text NOT NULL" in FIXTURE
    assert "public.invoice_items(id text PRIMARY KEY,org_id text NOT NULL" in FIXTURE


def test_no_audit_log_mutation_by_tenant_role():
    assert 'public.audit_logs, public.security_events FROM jw_app' in SQL
    assert 'GRANT SELECT ON public.audit_logs TO jw_app;' in SQL
    assert 'public.security_events, public.import_previews TO jw_app' not in SQL
    assert "('audit_logs', 'UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')" in AUDIT
    assert 'TRUNCATE, REFERENCES, TRIGGER' in SQL
    assert 'Dangerous privilege bypassing RLS' in AUDIT


def test_session_bind_cannot_switch_tenant_within_transaction():
    assert 'Tenant context already bound for this transaction' in SQL
    assert 'SAVEPOINT rebind' in RUNTIME
    assert 'tok_b' in RUNTIME


def test_runtime_has_fk_attack_vectors():
    for target in ('evilquote','evilorder','evilinvoice','evilpayment','evilqi','eviloi','evilii'):
        assert target in RUNTIME
    assert "UPDATE public.quotes SET customer_id='cb'" in RUNTIME
    assert 'protected_log' in RUNTIME
    assert 'TRUNCATE public.customers' in RUNTIME
    assert 'SET ROLE postgres' in RUNTIME


def test_catalog_audit_validates_composite_column_lists():
    assert 'COMPOSITE_FOREIGN_KEYS' in AUDIT
    assert 'c.convalidated' in AUDIT
    assert 'WITH ORDINALITY' in AUDIT
    assert 'Missing validated tenant composite FK' in AUDIT


def test_pg_ci_is_manual_and_read_only_for_repository():
    assert 'workflow_dispatch:' in CI
    assert 'contents: read' in CI
    assert 'timeout-minutes: 8' in CI
    assert 'postgres:17' in CI
    assert 'run_postgres_isolation_ci' in CI
    assert 'schedule:' not in CI


def test_ci_runner_refuses_without_local_ephemeral_context():
    env=os.environ.copy()
    env.pop('JW_PG_CI_ROOT_DSN',None)
    env.pop('JW_PG_CI_ALLOW',None)
    p=subprocess.run([sys.executable,'-m','scripts.run_postgres_isolation_ci'],
                     cwd=ROOT,env=env,capture_output=True,text=True,timeout=10)
    assert p.returncode==2
    assert 'NOT RUN' in p.stdout


def test_fixture_scope_guards_only_throwaway_db():
    assert "current_database() !~ '^jw_v(19|20)_test_'" in FIXTURE
    assert "name = 'jw_v20_test_' + secrets.token_hex(6)" in (ROOT/'scripts/run_postgres_isolation_ci.py').read_text()


def test_signed_tenant_claim_tied_to_session_and_revalidated():
    assert "v_org || '|' || v_xid || '|' || v_session_digest" in SQL
    assert "pg_catalog.set_config('jw.ctx_session_digest',v_session_digest,true)" in SQL
    assert "s.token_digest=pg_catalog.decode(v_session_digest,'hex')" in SQL
    assert 's.revoked_at IS NULL' in SQL
    assert 'Revoked bound session retained row access' in RUNTIME
    assert 'jw.ctx_session_digest' in RUNTIME

def test_ci_refuses_shared_postgres_cluster():
    source=(ROOT/'scripts/run_postgres_isolation_ci.py').read_text()
    assert 'non-template databases exist; refused shared server' in source
    assert 'nonstandard roles exist; refused shared server' in source
    assert 'public objects exist in postgres DB; refused shared server' in source


def test_definer_functions_use_explicit_pg_temp_last():
    assert SQL.count('SET search_path = pg_catalog, jw_guard, pg_temp') == 2
    assert "'search_path=pg_catalog,jw_guard,pg_temp'" in AUDIT
