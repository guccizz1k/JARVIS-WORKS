"""V2.7 static fail-closed contracts. These tests are NOT live PostgreSQL RLS proof."""
from pathlib import Path
from hashlib import sha256
from unittest.mock import Mock
import os
import subprocess
import sys
import pytest

from scripts.test_postgres_messenger_v27 import REQUIRED_TABLES, denied

ROOT=Path(__file__).resolve().parents[1]
SQL=(ROOT/'security/postgres_messenger_rls_v27.sql').read_text()
RUNNER=(ROOT/'scripts/run_postgres_isolation_ci.py').read_text()
GATE=(ROOT/'.github/workflows/pg-rls-attack-gate.yml').read_text()


def test_all_evidence_tables_have_explicit_force_rls_and_policies():
    assert len(REQUIRED_TABLES)==7
    for table,names in REQUIRED_TABLES.items():
        assert f'CREATE TABLE public.{table} (' in SQL
        assert f'ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY' in SQL
        assert f'ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY' in SQL
        for policy in names: assert f'CREATE POLICY {policy} ON public.{table}' in SQL
    assert "current_database() !~ '^jw_v20_test_[0-9a-f]{12}$'" in SQL
    assert 'NOT CONNECTED TO FASTAPI/SQLITE' in SQL


def test_shared_thread_read_and_sender_write_require_verified_actor():
    assert SQL.count('jw_guard.current_tenant()')>=15
    assert SQL.count('jw_guard.current_actor()')>=4
    assert 'sender_user=jw_guard.current_actor()' in SQL
    assert 'sender_org=jw_guard.current_tenant()' in SQL
    assert 'WITH CHECK (receiver_org=jw_guard.current_tenant()' in SQL
    assert "org_a < org_b" in SQL
    assert 'status=\'active\'' in SQL
    assert 'FOREIGN KEY(sender_user,sender_org) REFERENCES public.users(id,org_id)' in SQL


def test_receipt_read_requires_direct_verified_tenant_and_message_visibility():
    read_policy = SQL.split('CREATE POLICY jw_v27_receipt_read ', 1)[1].split(';', 1)[0]
    assert 'jw_guard.current_tenant() IS NOT NULL' in read_policy
    assert 'SELECT 1 FROM public.messenger_messages m WHERE m.id=message_id' in read_policy
    write_policy = SQL.split('CREATE POLICY jw_v27_receipt_write ', 1)[1].split(';', 1)[0]
    assert 'receiver_org=jw_guard.current_tenant()' in write_policy
    assert 'receiver_user=jw_guard.current_actor()' in write_policy


def test_sequence_allocation_requires_serial_transaction_counter():
    assert 'CREATE TABLE jw_guard.messenger_counters' in SQL
    assert 'BEFORE INSERT ON public.messenger_messages' in SQL
    assert 'ON CONFLICT(connection_id) DO UPDATE SET last_seq=counter.last_seq+1' in SQL
    assert 'RETURNING last_seq INTO NEW.message_seq' in SQL
    assert 'REVOKE ALL ON jw_guard.messenger_counters FROM PUBLIC,jw_app' in SQL
    assert 'NEW.last_read_seq<OLD.last_read_seq' in SQL
    assert 'NEW.last_read_seq>v_last' in SQL
    assert 'GRANT INSERT(id,connection_id,sender_org,sender_user,kind,body,request_id)' in SQL
    assert 'GRANT INSERT(id,connection_id,sender_org,sender_user,kind,body,request_id,message_seq)' not in SQL


def test_privileges_forbid_message_mutation_or_raw_company_certification():
    assert 'GRANT SELECT(org_id,company_name) ON public.messenger_companies TO jw_app' in SQL
    assert 'GRANT INSERT(message_id,filename,data,content_hash)' in SQL
    assert 'GRANT SELECT ON public.messenger_connections,public.messenger_messages' in SQL
    assert 'GRANT UPDATE ON public.messenger_messages TO jw_app' not in SQL
    assert 'GRANT DELETE ON public.messenger_messages TO jw_app' not in SQL
    assert 'REVOKE ALL ON public.messenger_companies,public.messenger_connections' in SQL


def test_runner_and_manual_workflow_are_fail_closed():
    assert 'postgres_messenger_rls_v27.sql' in RUNNER
    assert 'test_postgres_messenger_v27' in RUNNER
    assert RUNNER.index('if attack_run() != 0:') < RUNNER.index('messenger_attack_run()') < RUNNER.index('success_marker = True')
    assert 'workflow_dispatch:' in GATE and '  push:' not in GATE and '  schedule:' not in GATE
    env=os.environ.copy()
    for k in ('JW_PG_TEST_ADMIN_DSN','JW_PG_TEST_APP_DSN','JW_PG_ALLOW_TEST_WRITES'):
        env.pop(k,None)
    r=subprocess.run([sys.executable,'-m','scripts.test_postgres_messenger_v27'],cwd=ROOT,env=env,capture_output=True,text=True,timeout=8)
    assert r.returncode==2 and 'NOT RUN' in r.stdout


class FakePG:
    class Error(Exception):
        def __init__(self,state): self.sqlstate=state


def test_attack_denial_only_matching_sqlstate_counts():
    denied(lambda: (_ for _ in ()).throw(FakePG.Error('42501')),FakePG,{'42501'})
    with pytest.raises(AssertionError,match='Unexpected SQLSTATE'):
        denied(lambda: (_ for _ in ()).throw(FakePG.Error('42703')),FakePG,{'42501'})
    with pytest.raises(AssertionError,match='unexpectedly succeeded'):
        denied(lambda: None,FakePG,{'42501'})
    with pytest.raises(AssertionError,match='explicit SQLSTATE'):
        denied(lambda: None,FakePG,set())


def test_v26_sqlite_production_path_unchanged():
    # No unverified PG adapter is enabled in the live FastAPI application.
    main=(ROOT/'app/main.py').read_text()
    messenger=(ROOT/'app/messenger.py').read_text()
    assert "sqlite3" in main and "sqlite3" in messenger
    assert "postgres_messenger_rls_v27" not in main + messenger
    assert "Production remains BLOCKED" in main


def test_current_pg17_gate_integrity_manifest_matches_live_files():
    manifest=(ROOT/'V2_7_PG_GATE_SHA256.txt').read_text().splitlines()
    assert len(manifest)>=10
    checked=[]
    for record in manifest:
        expected,relpath=record.split('  ',1)
        assert len(expected)==64
        path=ROOT/relpath
        assert path.exists() and sha256(path.read_bytes()).hexdigest()==expected,relpath
        checked.append(relpath)
    assert 'scripts/run_pg17_codespaces.sh' in checked
    assert 'security/postgres_messenger_rls_v27.sql' in checked
