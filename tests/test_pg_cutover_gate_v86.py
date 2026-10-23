"""V8.6 cutover gate: synthetic snapshots only; no network/production."""
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from app.pg_cutover_gate_v86 import (
    audit_sqlite_auth_snapshot, role_boundary_evidence,
    preflight_live_connections, ROLE_QUERY,
)


def fake_snapshot(path):
    conn=sqlite3.connect(path)
    conn.execute('PRAGMA foreign_keys=ON')
    conn.executescript('''
CREATE TABLE organizations(id text primary key, name text);
CREATE TABLE users(id text primary key,org_id text references organizations(id),email text unique,password_hash text,role text);
CREATE TABLE sessions(token_hash text primary key,user_id text references users(id),expires_at text,csrf_token text);
CREATE TABLE staff_disabled(user_id text primary key references users(id),org_id text references organizations(id));
CREATE TABLE mfa_credentials(user_id text primary key references users(id),secret_encrypted text,last_counter integer);
CREATE TABLE mfa_recovery_codes(user_id text references users(id),code_hash text,consumed_at text);
CREATE TABLE login_failures(email text,attempts integer,first_failed_at text);
''')
    h=hashlib.pbkdf2_hmac('sha256',b'testpass',bytes.fromhex('aa'*16),260_000)
    pw=f'pbkdf2_sha256$260000${"aa"*16}${h.hex()}'
    conn.execute('INSERT INTO organizations VALUES (?,?)',('org1','TEST'))
    conn.execute('INSERT INTO users VALUES (?,?,?,?,?)',('user1','org1','a@example.invalid',pw,'member'))
    conn.execute('INSERT INTO sessions VALUES (?,?,?,?)',('b'*64,'user1','2026-10-23','csrf-token'))
    conn.commit()
    conn.close()


def statuses(a):
    return {c.code:c.status for c in a.checks}


def test_read_only_auth_snapshot_never_changes_bytes(tmp_path):
    p=tmp_path/'migration.sqlite'; fake_snapshot(p)
    before=p.read_bytes()
    r=audit_sqlite_auth_snapshot(p)
    assert p.read_bytes()==before
    assert r.counts['users']==1 and r.counts['sessions']==1
    assert r.pass_preflight is False  # never auto-migrate sessions
    assert statuses(r)['password_compatibility']=='PASS'
    assert statuses(r)['session_cutover']=='BLOCKED'
    assert 'a@example.invalid' not in json.dumps(r.public_report())
    assert 'testpass' not in json.dumps(r.public_report())
    assert 'b'*64 not in json.dumps(r.public_report())


def test_missing_schema_is_fail_closed(tmp_path):
    p=tmp_path/'missing.db'
    sqlite3.connect(p).close()
    r=audit_sqlite_auth_snapshot(p)
    assert statuses(r)['schema']=='FAIL'


def test_column_mismatch_is_fail_closed(tmp_path):
    p=tmp_path/'bad.sqlite'; fake_snapshot(p)
    c=sqlite3.connect(p);c.execute('ALTER TABLE users DROP COLUMN password_hash');c.commit();c.close()
    r=audit_sqlite_auth_snapshot(p)
    assert statuses(r)['columns']=='FAIL'


def test_duplicate_normalized_email_detected(tmp_path):
    p=tmp_path/'dupe.sqlite';fake_snapshot(p)
    c=sqlite3.connect(p)
    c.execute('INSERT INTO users VALUES (?,?,?,?,?)',('user2','org1','A@EXAMPLE.INVALID','pbkdf2_sha256$260000$'+'aa'*16+'$'+'ab'*32,'member'))
    c.commit();c.close()
    assert statuses(audit_sqlite_auth_snapshot(p))['normalized_emails']=='FAIL'


def test_unsupported_password_hash_detected(tmp_path):
    p=tmp_path/'legacy.sqlite';fake_snapshot(p)
    c=sqlite3.connect(p);c.execute("UPDATE users SET password_hash='sha1$legacy'");c.commit();c.close()
    assert statuses(audit_sqlite_auth_snapshot(p))['password_compatibility']=='FAIL'


def test_foreign_key_inconsistency_detected(tmp_path):
    p=tmp_path/'orphan.sqlite';fake_snapshot(p)
    c=sqlite3.connect(p);c.execute("UPDATE users SET org_id='missing_org'");c.commit();c.close()
    a=statuses(audit_sqlite_auth_snapshot(p))
    assert a['foreign_keys']=='FAIL' and a['tenant_relations']=='FAIL'


def test_invalid_session_is_caught(tmp_path):
    p=tmp_path/'session.sqlite';fake_snapshot(p)
    c=sqlite3.connect(p);c.execute("UPDATE sessions SET token_hash='weak'");c.commit();c.close()
    assert statuses(audit_sqlite_auth_snapshot(p))['session_format']=='FAIL'


def test_role_evidence_all_checks_positive():
    checks=role_boundary_evidence((False,True,False,False,True,17),auth=True)
    assert len(checks)==6 and all(x.status=='PASS' for x in checks)
    checks=role_boundary_evidence((False,False,True,False,True,17),auth=False)
    assert all(x.status=='PASS' for x in checks)


@pytest.mark.parametrize('row',[(True,True,False,False,True,17),
                                 (False,True,True,False,True,17),
                                 (False,False,False,False,True,17),
                                 (False,True,False,True,True,17),
                                 (False,True,False,False,False,17),
                                 (False,True,False,False,True,16)])
def test_role_evidence_rejects_any_failed_guard(row):
    assert any(x.status=='FAIL' for x in role_boundary_evidence(row,auth=True))


def test_preflight_refuses_missing_or_equal_dsn():
    assert preflight_live_connections(env={})['result']=='BLOCKED'
    assert preflight_live_connections(env={'JW_ENV':'production','JW_PG_AUTH_STAGE_DSN':'a','JW_PG_STAGE_DSN':'b'})['result']=='BLOCKED'
    assert preflight_live_connections(env={'JW_PG_AUTH_STAGE_DSN':'same','JW_PG_STAGE_DSN':'same'})['result']=='BLOCKED'


class FakeCursor:
    def __init__(self,row):self.row=row;self.queries=[]
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def execute(self,query):self.queries.append(query)
    def fetchone(self):return self.row

class FakeDb:
    def __init__(self,row):self.cursor_obj=FakeCursor(row)
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def cursor(self):return self.cursor_obj


def test_two_distinct_connections_use_tls_and_partitioned_roles():
    seen=[]
    def connect(dsn,**opts):
        seen.append((dsn,opts))
        return FakeDb((False,True,False,False,True,17) if dsn=='AUTH' else (False,False,True,False,True,17))
    r=preflight_live_connections(connector=connect,env={'JW_PG_AUTH_STAGE_DSN':'AUTH','JW_PG_STAGE_DSN':'TRADE'})
    assert r['result']=='PASS' and r['production_cutover'] is False
    assert [x[1]['sslmode'] for x in seen]==['verify-full','verify-full']
    assert not any('AUTH' in str(c) or 'TRADE' in str(c) for c in r['auth']+r['trading'])


def test_network_error_is_masked():
    def connect(dsn,**kwargs):raise OSError('password=highly_sensitive')
    r=preflight_live_connections(connector=connect,env={'JW_PG_AUTH_STAGE_DSN':'AUTH','JW_PG_STAGE_DSN':'TRADE'})
    assert r['result']=='BLOCKED' and 'highly_sensitive' not in str(r)


def test_role_query_is_read_only():
    assert 'pg_has_role' in ROLE_QUERY
    assert 'UPDATE ' not in ROLE_QUERY and 'INSERT ' not in ROLE_QUERY
