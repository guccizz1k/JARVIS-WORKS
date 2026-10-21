"""Historical PG17 chain, fail-closed wrapper and operational protections."""
from pathlib import Path
import importlib
import os
import sys
import types

import pytest


def test_entrypoint_reuses_full_v50_without_direct_prod_connection():
    src=Path('scripts/run_postgres_isolation_ci_v52.py').read_text()
    assert 'from scripts import run_postgres_isolation_ci_v50 as supervisor' in src
    assert 'return supervisor.main()' in src
    assert 'return rc if rc != 0 else current.run()' in src
    assert 'finally:' in src and 'previous.run=original' in src


def test_review_scripts_preserve_history_and_jw_mobile_name():
    shell=Path('scripts/run_pg17_codespaces_v52.sh').read_text()
    check=Path('scripts/check_v52_review.sh').read_text()
    assert 'V5_0 V5_1 V5_2;' in shell
    assert 'scripts.run_postgres_isolation_ci_v52' in shell
    assert '47 48 50 52; do' in shell
    assert 'JW_PG_RELAY_V52=ONLY_DISPOSABLE_LAB' in shell
    assert 'JW_PG_OUTBOX_V51=ONLY_DISPOSABLE_LAB' in shell
    assert "bash scripts/check_v51_review.sh" in check
    assert 'sha256sum --check --status V5_2_PG_GATE_SHA256.txt' in check
    assert '--rm -d' in shell and '127.0.0.1::5432 postgres:17' in shell


def test_fail_closed_wrapper_when_not_authorized(monkeypatch):
    from scripts.run_postgres_isolation_ci_v52 import main
    monkeypatch.setenv('JW_PG_RELAY_V52','')
    assert main() == 2


def test_previous_failure_does_not_invoke_new_stage(monkeypatch):
    from scripts.run_postgres_isolation_ci_v52 import main
    from scripts import test_postgres_identity_audit_v50 as prev
    from scripts import run_postgres_isolation_ci_v50 as supervisor
    from scripts import test_postgres_outbox_relay_v52 as current
    for name,value in [('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE'),
                       ('JW_PG_LAB_V52','ONLY_DISPOSABLE_LAB'),
                       ('JW_PG_RELAY_V52','ONLY_DISPOSABLE_LAB'),
                       ('JW_PG_OUTBOX_V51','ONLY_DISPOSABLE_LAB'),
                       ('JW_PG_LAB_V50','ONLY_DISPOSABLE_LAB')]:
        monkeypatch.setenv(name,value)
    monkeypatch.delenv('JW_ENV',raising=False)
    invoked=[]
    def old(): invoked.append('old'); return 1
    def new(): invoked.append('new'); return 0
    monkeypatch.setattr(prev,'run',old)
    monkeypatch.setattr(current,'run',new)
    def fake_supervisor():return prev.run()
    monkeypatch.setattr(supervisor,'main',fake_supervisor)
    assert main()==1
    assert invoked==['old']
    assert prev.run is old


def test_previous_success_invokes_new_and_restores(monkeypatch):
    from scripts.run_postgres_isolation_ci_v52 import main
    from scripts import test_postgres_identity_audit_v50 as prev
    from scripts import run_postgres_isolation_ci_v50 as supervisor
    from scripts import test_postgres_outbox_relay_v52 as current
    for name,value in [('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE'),
                       ('JW_PG_LAB_V52','ONLY_DISPOSABLE_LAB'),
                       ('JW_PG_RELAY_V52','ONLY_DISPOSABLE_LAB'),
                       ('JW_PG_OUTBOX_V51','ONLY_DISPOSABLE_LAB'),
                       ('JW_PG_LAB_V50','ONLY_DISPOSABLE_LAB')]:
        monkeypatch.setenv(name,value)
    monkeypatch.delenv('JW_ENV',raising=False)
    invoked=[]
    def old(): invoked.append('old'); return 0
    def new(): invoked.append('new'); return 1
    monkeypatch.setattr(prev,'run',old)
    monkeypatch.setattr(current,'run',new)
    monkeypatch.setattr(supervisor,'main',lambda:prev.run())
    assert main()==1
    assert invoked==['old','new'] and prev.run is old


def test_new_stage_exception_restores_original(monkeypatch):
    from scripts.run_postgres_isolation_ci_v52 import main
    from scripts import test_postgres_identity_audit_v50 as prev
    from scripts import run_postgres_isolation_ci_v50 as supervisor
    from scripts import test_postgres_outbox_relay_v52 as current
    for name,value in [('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE'),
                       ('JW_PG_LAB_V52','ONLY_DISPOSABLE_LAB'),
                       ('JW_PG_RELAY_V52','ONLY_DISPOSABLE_LAB'),
                       ('JW_PG_OUTBOX_V51','ONLY_DISPOSABLE_LAB'),
                       ('JW_PG_LAB_V50','ONLY_DISPOSABLE_LAB')]:monkeypatch.setenv(name,value)
    monkeypatch.delenv('JW_ENV',raising=False)
    def old():return 0
    monkeypatch.setattr(prev,'run',old)
    monkeypatch.setattr(current,'run',lambda: 1/0)
    monkeypatch.setattr(supervisor,'main',lambda:prev.run())
    with pytest.raises(ZeroDivisionError):main()
    assert prev.run is old


def test_v52_pg17_environment_guard_unset_and_production():
    """A missing JW_ENV must not fail under nounset; all production case variants deny."""
    import subprocess
    script = Path('scripts/run_pg17_codespaces_v52.sh').read_text()
    assert '[[ "${JW_ENV,,}"' not in script
    begin = script.index('JW_ENV_SAFE="${JW_ENV:-}"')
    end = script.index('for version in 35', begin)
    guard = script[begin:end]
    for value, expected in (
        (None, 0), ('', 0), ('development', 0), ('staging', 0),
        ('production', 2), ('PRODUCTION', 2), ('PrOdUcTiOn', 2),
    ):
        env = os.environ.copy()
        env.pop('JW_ENV', None)
        if value is not None:
            env['JW_ENV'] = value
        result = subprocess.run(
            ['bash', '-c', 'set -Eeuo pipefail\n' + guard + '\nprintf "GUARD_REACHED\\n"'],
            env=env, capture_output=True, text=True, timeout=5,
        )
        assert result.returncode == expected, (value, result.stderr)
        assert ('GUARD_REACHED' in result.stdout) == (expected == 0)
