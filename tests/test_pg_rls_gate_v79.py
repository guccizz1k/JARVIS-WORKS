"""V7.9 offline adversarial catalog fixtures: not a real PostgreSQL test."""
import dataclasses
from copy import deepcopy

import pytest

from app.pg_full_shadow_v76 import EXPECTED_TABLES
from app.pg_rls_full_review_v78 import PRIVATE,DIRECT,DERIVED,SPECIAL
from app.pg_rls_gate_v79 import audit_catalog, require_catalog_pass, CatalogBlocked, DANGEROUS_GRANTS
from scripts.check_pg_rls_v79 import preflight, run


def good_catalog():
    policies={}; tables={}
    for t in EXPECTED_TABLES:
        tables[t]={'rls_enabled':True,'force_rls':True,'owner':'postgres',
                   'grants':{'SELECT':t not in PRIVATE,**{g:False for g in DANGEROUS_GRANTS}}}
        if t in PRIVATE: policies[t]=[]
        else:
            predicate=('EXISTS(SELECT 1 FROM public.parents WHERE org_id=jw_guard.current_tenant())' if t in DERIVED
                      else '(org_a=jw_guard.current_tenant() OR org_b=jw_guard.current_tenant())' if t=='messenger_connections'
                      else 'id=jw_guard.current_tenant()' if t=='organizations'
                      else 'org_id=jw_guard.current_tenant()')
            policies[t]=[dict(name='jw_v78_review_select',command='SELECT',roles=['jw_app'],permissive=True,using=predicate)]
    return {'app_role':dict(name='jw_app',superuser=False,bypassrls=False,createrole=False,createdb=False,replication=False,member_of=[]),
            'tables':tables,'policies':policies,
            'tenant_guard':dict(schema='jw_guard',name='current_tenant',definer=True,owner='postgres',app_can_execute=True,signature='current_tenant()',settings=['search_path=pg_catalog, jw_guard, pg_temp'],public_can_execute=False)}


def assert_blocked(value,phrase):
    result=audit_catalog(value)
    assert result.decision=='BLOCKED'
    assert phrase in '\n'.join(result.findings)
    with pytest.raises(CatalogBlocked): require_catalog_pass(result)


def test_good_fixture_catalog_only_not_runtime_success():
    x=audit_catalog(good_catalog())
    assert x.decision=='CATALOG_ONLY_PASS' and x.tables==35 and not x.postgres_executed
    assert not x.tenant_attack_executed and not x.cutover_approved
    require_catalog_pass(x)

@pytest.mark.parametrize('field', ['superuser','bypassrls','createrole','createdb','replication'])
def test_privileged_app_role_denied(field):
    x=good_catalog();x['app_role'][field]=True
    assert_blocked(x,field)


def test_inherited_role_denied():
    x=good_catalog();x['app_role']['member_of']=['pg_read_all_data'];assert_blocked(x,'inherited')

@pytest.mark.parametrize('field', ['rls_enabled','force_rls'])
def test_missing_rls_denied(field):
    x=good_catalog();x['tables']['customers'][field]=False;assert_blocked(x,'customers: RLS')


def test_missing_private_restriction_denied():
    x=good_catalog();x['tables']['sessions']['grants']['SELECT']=True;assert_blocked(x,'sessions: incorrect SELECT')

@pytest.mark.parametrize('grant', DANGEROUS_GRANTS)
def test_write_privilege_denied(grant):
    x=good_catalog();x['tables']['quotes']['grants'][grant]=True;assert_blocked(x,'quotes: '+grant)


def test_permissive_policy_accumulation_denied():
    x=good_catalog();x['policies']['customers'].append(x['policies']['customers'][0].copy());assert_blocked(x,'expected 1 policy')


def test_parent_scope_is_required():
    x=good_catalog();x['policies']['quote_items'][0]['using']='org_id=jw_guard.current_tenant()';assert_blocked(x,'parent relationship missing')


def test_function_definer_required():
    x=good_catalog();x['tenant_guard']['definer']=False;assert_blocked(x,'Signed tenant context function')


def test_new_table_blocks():
    x=good_catalog();x['tables']['secret_export']={'rls_enabled':True};assert_blocked(x,'35-table set mismatch')


def test_offline_gate_does_not_contact_pg(monkeypatch):
    for name in ('JW_PG_V79_ADMIN_DSN','JW_PG_V79_APP_DSN','JW_PG_V79_CONSENT'):
        monkeypatch.delenv(name,raising=False)
    assert preflight({}) is not None
    assert run()==2


def test_prod_never_runs_gate():
    assert preflight({'JW_ENV':'production','JW_PG_V79_CONSENT':'ONLY_DISPOSABLE_LAB',
        'JW_PG_V79_ADMIN_DSN':'password', 'JW_PG_V79_APP_DSN':'password'}) is not None


def test_signed_guard_search_path_required():
    x=good_catalog();x['tenant_guard']['settings']=[];assert_blocked(x,'search_path')


def test_signed_guard_public_execution_denied():
    x=good_catalog();x['tenant_guard']['public_can_execute']=True;assert_blocked(x,'publicly executable')
