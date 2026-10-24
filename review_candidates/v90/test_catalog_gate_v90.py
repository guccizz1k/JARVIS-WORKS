"""Synthetic unit fixtures only; these tests never connect to a database."""
from catalog_gate_v90 import assess


def valid_metadata():
    return {
        'postgresql_17': True, 'force_rls_tables': 35,
        'app_role_nologin': True, 'safe_gateway_logins': 1,
        'functions': {name: {'tx_lock': True, 'anon_execute': False,
                             'authenticated_execute': False, 'app_execute': True}
                      for name in ('v90_send_text', 'v90_edit_text')},
    }


def test_missing_gateway_login_blocks():
    m = valid_metadata(); m['safe_gateway_logins'] = 0
    assert 'safe_nonprivileged_gateway_login_exists' in assess(m)['blocking_checks']


def test_missing_cursor_lock_blocks():
    m = valid_metadata(); m['functions']['v90_send_text']['tx_lock'] = False
    assert 'send_function_has_tx_lock' in assess(m)['blocking_checks']


def test_function_exposed_to_anon_blocks():
    m = valid_metadata(); m['functions']['v90_edit_text']['anon_execute'] = True
    assert 'function_execution_least_privilege' in assess(m)['blocking_checks']


def test_fake_catalog_without_real_e2e_remains_blocked():
    assert assess(valid_metadata())['verdict'] == 'BLOCKED'
    assert 'two_independent_pg_sessions_e2e' in assess(valid_metadata())['blocking_checks']


def test_explicit_real_e2e_evidence_required_to_pass():
    assert assess(valid_metadata(), independent_pg_e2e=True)['verdict'] == 'PASS'


def test_missing_fields_fails_closed():
    r = assess({})
    assert r['verdict'] == 'BLOCKED'
    assert len(r['blocking_checks']) >= 5
