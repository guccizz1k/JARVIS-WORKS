"""V2.8 offline structural and fail-closed checks. These are NOT PG live tests."""
from hashlib import sha256
from pathlib import Path
import os
import subprocess
import sys
import pytest

from scripts.test_postgres_messenger_v28 import denied

ROOT=Path(__file__).resolve().parents[1]
SQL=(ROOT/'security/postgres_messenger_rls_v28_hardening.sql').read_text()
RUN=(ROOT/'scripts/run_postgres_isolation_ci_v28.py').read_text()
ATTACK=(ROOT/'scripts/test_postgres_messenger_v28.py').read_text()
LAUNCH=(ROOT/'scripts/run_pg17_codespaces_v28.sh').read_text()
WORKFLOW=(ROOT/'.github/workflows/pg-rls-v28-gate.yml').read_text()


def test_new_sql_only_runs_in_disposable_guarded_database():
    assert "current_database() !~ '^jw_v20_test_[0-9a-f]{12}$'" in SQL
    assert 'NEVER APPLY TO PRODUCTION' in SQL
    assert "m.kind <> 'attachment'" in SQL
    assert "content_hash IS DISTINCT FROM pg_catalog.encode(public.digest(a.data,'sha256'),'hex')" in SQL
    assert 'RAISE EXCEPTION' in SQL
    assert 'BEGIN;' in SQL and 'COMMIT;' in SQL


def test_sha256_server_enforced_check_constraint():
    assert 'ADD CONSTRAINT jw_v28_attachment_sha256' in SQL
    assert "content_hash ~ '^[0-9a-f]{64}$'" in SQL
    assert "content_hash = pg_catalog.encode(public.digest(data, 'sha256'), 'hex')" in SQL
    assert "{'23514'}" in ATTACK  # actual DB check violation, not any exception


def test_attachment_is_bound_to_original_sender_and_kind():
    assert 'CREATE FUNCTION jw_guard.validate_attachment_sender_v28()' in SQL
    assert 'SECURITY DEFINER' in SQL
    assert 'SET search_path=pg_catalog,jw_guard,pg_temp' in SQL
    for required in (
      'NEW.message_id',
      'm.sender_org=jw_guard.current_tenant()',
      'm.sender_user=jw_guard.current_actor()',
      "m.kind='attachment'",
      'BEFORE INSERT ON public.messenger_attachments',
      'REVOKE ALL ON FUNCTION jw_guard.validate_attachment_sender_v28() FROM PUBLIC,jw_app',
    ):
        assert required in SQL
    assert 'ub_v28_other' in ATTACK
    assert 'denied_in_session(token_other' in ATTACK


def test_read_time_server_only_and_cursor_guard_preserved():
    assert 'REVOKE UPDATE(updated_at) ON TABLE public.messenger_read_positions FROM jw_app' in SQL
    assert 'NEW.updated_at:=pg_catalog.clock_timestamp()' in SQL
    assert 'NEW.last_read_seq<OLD.last_read_seq' in SQL
    assert 'NEW.last_read_seq>v_last' in SQL
    assert "'2099-01-01'" in ATTACK


def test_existing_sqlite_app_unmodified_by_addon():
    main=(ROOT/'app/main.py').read_text()
    messenger=(ROOT/'app/messenger.py').read_text()
    assert 'sqlite3' in main and 'sqlite3' in messenger
    assert 'postgres_messenger_rls_v28' not in main+messenger


def test_runner_orders_old_attack_then_sql_upgrade_then_new_attack():
    a=RUN.index('if attack_run() != 0:')
    b=RUN.index('if messenger_attack_run() != 0:')
    c=RUN.index('postgres_messenger_rls_v28_hardening.sql')
    d=RUN.index('if v28_attack_run() != 0:')
    assert a<b<c<d<RUN.index('success_marker = True')
    assert "WHERE message_id='ab_two' AND content_hash='sha256-demo'" in RUN
    assert 'Synthetic legacy V2.7 hash fixture mismatch' in RUN
    assert 'created_db' in RUN and 'DROP DATABASE IF EXISTS' in RUN
    assert 'JW_PG_CI_ALLOW' in RUN and 'ONLY_EPHEMERAL_LOCAL_DATABASE' in RUN
    assert 'cleanup_failed' in RUN


def test_manual_only_new_gate_and_no_autopublish():
    assert 'workflow_dispatch:' in WORKFLOW
    assert '  push:' not in WORKFLOW and '  schedule:' not in WORKFLOW
    assert 'scripts.run_postgres_isolation_ci_v28' in WORKFLOW
    assert 'scripts.run_postgres_isolation_ci_v28' in LAUNCH
    assert 'V2_8_PG_GATE_SHA256.txt' in LAUNCH
    assert 'sha256sum --check --status' in LAUNCH


def test_live_attack_driver_explicitly_not_run_without_consent():
    env=os.environ.copy()
    for key in ('JW_PG_TEST_ADMIN_DSN','JW_PG_TEST_APP_DSN','JW_PG_ALLOW_TEST_WRITES',
                'JW_PG_CI_ROOT_DSN','JW_PG_CI_ALLOW'):
        env.pop(key,None)
    for module in ('scripts.test_postgres_messenger_v28','scripts.run_postgres_isolation_ci_v28'):
        proc=subprocess.run([sys.executable,'-m',module],cwd=ROOT,env=env,
            capture_output=True,text=True,timeout=10)
        assert proc.returncode == 2 and 'NOT RUN' in proc.stdout, module


class DummyPG:
    class Error(Exception):
        def __init__(self,state):
            self.sqlstate=state


def test_denied_only_whitelisted_postgresql_sqlstates():
    denied(lambda: (_ for _ in ()).throw(DummyPG.Error('23514')),DummyPG,{'23514'})
    with pytest.raises(AssertionError,match='Unexpected SQLSTATE'):
        denied(lambda: (_ for _ in ()).throw(DummyPG.Error('42P01')),DummyPG,{'23514'})
    with pytest.raises(AssertionError,match='Unexpectedly permitted'):
        denied(lambda: None,DummyPG,{'23514'})


def test_v28_integrity_manifest_matches_run_surface():
    records=(ROOT/'V2_8_PG_GATE_SHA256.txt').read_text().splitlines()
    assert len(records)>=11
    tracked=set()
    for line in records:
        expected,name=line.split('  ',1)
        assert len(expected)==64 and name not in tracked
        actual=sha256((ROOT/name).read_bytes()).hexdigest()
        assert expected==actual, name
        tracked.add(name)
    for mandatory in ('security/postgres_messenger_rls_v28_hardening.sql',
        'scripts/test_postgres_messenger_v28.py','scripts/run_postgres_isolation_ci_v28.py',
        'scripts/run_pg17_codespaces_v28.sh'):
        assert mandatory in tracked
