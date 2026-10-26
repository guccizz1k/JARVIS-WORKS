"""V2.1 runner integrity checks; no database engine used by these tests."""
import ast
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PATH = ROOT / 'scripts' / 'test_postgres_rls_runtime.py'
RUNNER_PATH = ROOT / 'scripts' / 'run_postgres_isolation_ci.py'
WORKFLOW = ROOT / '.github' / 'workflows' / 'pg-rls-attack-gate.yml'


def _module():
    spec = importlib.util.spec_from_file_location('pg_runtime_v21', RUNTIME_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakePsycopg:
    class Error(Exception):
        def __init__(self, sqlstate):
            self.sqlstate = sqlstate


def _raise_sqlstate(sqlstate):
    raise FakePsycopg.Error(sqlstate)


@pytest.mark.parametrize('sqlstate', ['42501', 'P0001', '23503'])
def test_expected_denial_is_accepted_only_for_expected_sqlstate(sqlstate):
    x = _module()
    x._is_expected_error(lambda: _raise_sqlstate(sqlstate), FakePsycopg, {sqlstate})
    with pytest.raises(AssertionError, match='Unexpected SQLSTATE'):
        x._is_expected_error(lambda: _raise_sqlstate(sqlstate), FakePsycopg, {'23505'})


@pytest.mark.parametrize('bad_sqlstate', ['08006', '42703', '42P01', '42601', 'XX000', None])
def test_transport_syntax_missing_object_and_internal_failures_do_not_count_as_denials(bad_sqlstate):
    x = _module()
    with pytest.raises(AssertionError, match='Unexpected SQLSTATE'):
        x._is_expected_error(lambda: _raise_sqlstate(bad_sqlstate), FakePsycopg, x.PRIVILEGE_DENIED)


def test_negative_attack_requires_actual_denial():
    x = _module()
    with pytest.raises(AssertionError, match='Expected security denial'):
        x._is_expected_error(lambda: None, FakePsycopg, x.TENANT_FK_DENIED)
    with pytest.raises(ValueError):
        x._is_expected_error(lambda: None, FakePsycopg, frozenset())


def test_every_negative_attack_declares_expected_sqlstate():
    module = ast.parse(RUNTIME_PATH.read_text())
    calls = [node for node in ast.walk(module) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == '_is_expected_error']
    assert len(calls) >= 12
    assert all(len(call.args) == 3 for call in calls), 'A denial test failed to classify SQLSTATE'


def test_pg_gate_is_explicitly_manual_to_protect_budget():
    source = WORKFLOW.read_text()
    assert 'workflow_dispatch:' in source
    assert '  push:' not in source
    assert '  schedule:' not in source
    assert 'contents: read' in source
    assert 'timeout-minutes: 8' in source


def test_ci_gate_fails_closed_without_explicit_ephemeral_db():
    env = os.environ.copy()
    env.pop('JW_PG_CI_ALLOW', None)
    env.pop('JW_PG_CI_ROOT_DSN', None)
    result = subprocess.run([sys.executable, '-m', 'scripts.run_postgres_isolation_ci'],
                            cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'NOT RUN' in result.stdout


def test_ephemeral_cleanup_failure_is_hard_failure():
    code = RUNNER_PATH.read_text()
    assert 'cleanup_failed = True' in code
    assert 'if cleanup_failed:' in code
    assert "print('FAIL: ephemeral cleanup failed:" in code
    assert 'return 1' in code


def test_live_gate_requires_exact_pg17_and_proof_after_teardown():
    runner = RUNNER_PATH.read_text()
    assert 'SHOW server_version_num' in runner
    assert 'version // 10000 != 17' in runner
    assert 'if cleanup_failed:' in runner
    assert 'if success_marker:' in runner
    assert 'cleanup confirmed' in runner
    assert runner.index('if cleanup_failed:') < runner.index('if success_marker:')


def test_attack_suite_checks_retenant_on_row_without_fk_false_positive():
    source = RUNTIME_PATH.read_text()
    assert 'tenant_rekey_canary' in source
    assert "SET org_id='tenant_b' WHERE id='tenant_rekey_canary'" in source
    assert 'SAVEPOINT retenant_own_row' in source
    assert 'PRIVILEGE_DENIED)' in source
