"""V1.9 OFFLINE regression checks. Only live PG script proves DB behavior."""
import hashlib
import hmac
import os
from pathlib import Path
import subprocess
import sys

POLICY = Path('security/postgres_rls_proposal.sql').read_text()
SCRIPT = Path('scripts/test_postgres_rls_runtime.py').read_text()
FIXTURE = Path('security/pg_rls_test_fixture.sql').read_text()


def test_policy_has_signed_transaction_bound_context():
    assert 'public.hmac(' in POLICY
    assert 'jw_guard.signing_key' in POLICY
    assert 'pg_catalog.txid_current()' in POLICY
    assert 'pg_catalog.txid_current_if_assigned()' in POLICY
    assert "pg_catalog.set_config('jw.ctx_proof',v_proof,true)" in POLICY


def test_policy_cannot_trust_raw_tenant_setting():
    assert "current_setting('jw.org_id'" not in POLICY
    assert 'USING (org_id=jw_guard.current_tenant())' in POLICY
    assert 'WITH CHECK (org_id=jw_guard.current_tenant())' in POLICY
    assert 'USING (id=jw_guard.current_tenant())' in POLICY
    assert 'FORCE ROW LEVEL SECURITY' in POLICY


def test_verified_session_required_for_binding():
    assert 's.mfa_verified' in POLICY
    assert 's.revoked_at IS NULL' in POLICY
    assert 's.expires_at > pg_catalog.clock_timestamp()' in POLICY
    assert 'token_digest=public.digest' in POLICY
    assert "raw_session_token) < 32" in POLICY


def test_private_key_and_session_registry_never_directly_exposed():
    assert 'REVOKE ALL ON ALL TABLES IN SCHEMA jw_guard FROM PUBLIC, jw_app' in POLICY
    assert 'REVOKE ALL ON FUNCTION jw_guard.bind_session(text) FROM PUBLIC' in POLICY
    assert 'GRANT EXECUTE ON FUNCTION jw_guard.bind_session(text) TO jw_app' in POLICY
    assert 'REVOKE CREATE ON SCHEMA public FROM PUBLIC' in POLICY
    assert 'jw_app must not own or inherit table owner privileges' in POLICY


def test_indirect_child_policies_restrict_parent_tenant():
    for child, parent, parent_column in [
        ('quote_items', 'quotes', 'quote_id'),
        ('order_items', 'orders', 'order_id'),
        ('invoice_items', 'invoices', 'invoice_id')]:
        assert f'CREATE POLICY jw_rls_guard ON public.{child}' in POLICY
        assert f'FROM public.{parent} ' in POLICY
        assert f'.id={parent_column}' in POLICY
        assert 'org_id=jw_guard.current_tenant() AND EXISTS' in POLICY


def test_fails_unexpected_additional_permissive_policies():
    assert "policyname NOT IN ('jw_org_scope','jw_tenant_scope','jw_child_scope','jw_rls_guard')" in POLICY
    assert 'Unexpected RLS policy' in POLICY
    audit = Path('scripts/check_postgres_rls.py').read_text()
    assert 'Exactly one policy required' in audit
    assert 'Public can execute guarded function' in audit


def test_fixture_rejects_any_non_test_database():
    assert "current_database() !~ '^jw_v(19|20)_test_'" in FIXTURE
    assert "Fixture requires an empty throwaway test database" in FIXTURE
    assert "jw_v19_test_" in SCRIPT
    assert "ONLY_EPHEMERAL_DATABASE" in SCRIPT


def test_runtime_adversarial_suite_has_required_attack_vectors():
    for marker in ['Plain org GUC spoof', 'Cross-tenant UPDATE', 'Cross-tenant DELETE',
                   'foreign_child', 'no_signing_key', 'Old transaction claim replayed',
                   'Tenant B visibility incorrect', 'tok_expired', 'tok_not_mfa', 'revoked_at']:
        assert marker in SCRIPT


def test_runtime_runner_refuses_without_explicit_dsn():
    env = dict(os.environ)
    env.pop('JW_PG_TEST_ADMIN_DSN', None)
    env.pop('JW_PG_TEST_APP_DSN', None)
    p=subprocess.run([sys.executable,'-m','scripts.test_postgres_rls_runtime'],
                     capture_output=True,text=True,env=env,timeout=5)
    assert p.returncode==2
    assert 'NOT RUN' in p.stderr


def test_catalog_audit_refuses_without_postgresql_dsn():
    env=dict(os.environ)
    env.pop('JW_PG_CHECK_DSN',None)
    p=subprocess.run([sys.executable,'-m','scripts.check_postgres_rls'],
                     capture_output=True,text=True,env=env,timeout=5)
    assert p.returncode==2
    assert 'NOT RUN' in p.stderr


def test_illustrative_signature_rejects_forged_tenant_and_replay():
    # Python MODEL test only, explicitly not SQL engine behavior verification.
    secret=b'k'*32
    def proof(org,tx):
        return hmac.new(secret, f'{org}|{tx}'.encode(),hashlib.sha256).hexdigest()
    a=proof('tenant_a',12)
    assert hmac.compare_digest(a,proof('tenant_a',12))
    assert not hmac.compare_digest(a,proof('tenant_b',12))
    assert not hmac.compare_digest(a,proof('tenant_a',13))


def test_existing_sqlite_production_is_still_blocked():
    from app import main
    import inspect
    assert 'Production remains BLOCKED' in inspect.getsource(main.init_db)
