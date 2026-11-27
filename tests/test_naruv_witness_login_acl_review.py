"""Actual password-authenticated PG17 service logins, isolated CI only."""
import os
import secrets
from contextlib import contextmanager
import pytest
import psycopg
from psycopg import sql
from scripts import naruv_witness_login_acl_review as acl
from scripts import naruv_pg_witness_ledger_review as ledger
from scripts import naruv_receipt_witness_bridge_review as bridge
from tests.test_naruv_pg_signed_receipt_review import witness_fixture

def assert_ci():
    assert os.environ.get('GITHUB_ACTIONS')=='true'
    assert os.environ.get('GITHUB_REPOSITORY')=='guccizz1k/JARVIS-WORKS'
    assert os.environ.get('NARUV_WITNESS_DIRECT_LOGIN_CI')=='1'

@contextmanager
def admin():
    assert_ci()
    with psycopg.connect(host='127.0.0.1',port=55439,dbname='postgres',user='postgres',
                         password='synthetic_review_only',connect_timeout=4,autocommit=True) as c:
        assert c.info.server_version//10000==17
        c.execute("SET statement_timeout='15s'")
        yield c

@contextmanager
def login(role,passwords):
    assert_ci()
    assert role in acl.LOGINS
    with psycopg.connect(host='127.0.0.1',port=55439,dbname='postgres',user=role,
                         password=passwords[role],connect_timeout=4,autocommit=True) as c:
        c.execute("SET statement_timeout='15s'")
        assert c.execute('SELECT session_user,current_user').fetchone()==(role,role)
        yield c

@pytest.fixture(scope='module')
def passwords():
    values={r:secrets.token_urlsafe(32) for r in acl.LOGINS}
    with admin() as c:
        assert c.execute("SELECT to_regnamespace(%s)",(acl.SCHEMA,)).fetchone()==(None,)
        with c.transaction():
            c.execute(ledger.DDL)
            c.execute(acl.DDL)
            for role,pw in values.items():
                c.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(role),sql.Literal(pw)))
        try:
            assert acl.audit(c)=='PASS_PROSPECTIVE_WITNESS_ACL_ONLY'
            yield values
        finally:
            with c.transaction():
                c.execute('DROP SCHEMA naruv_witness_ledger_ci CASCADE')
                c.execute('DROP ROLE naruv_witness_registrar_ci,naruv_witness_verifier_ci,naruv_witness_reader_ci,naruv_witness_owner_ci')

@pytest.fixture(autouse=True)
def reset(passwords):
    with admin() as c:
        c.execute('TRUNCATE naruv_witness_ledger_ci.evidence,naruv_witness_ledger_ci.run,naruv_witness_ledger_ci.approval')

def populate(monkeypatch,passwords):
    raw,policy,obs,wit,signer,_=witness_fixture(monkeypatch)
    receipts,_=bridge.build_pair(raw,policy,obs,wit,signer)
    with login(acl.REGISTRAR,passwords) as c:pin=ledger.register(c,raw,policy)
    with login(acl.VERIFIER,passwords) as c:
        assert ledger.consume(c,pin,obs,wit,receipts)['receipt_consumption']=='PASS_WITNESS_LEDGER_REVIEW'
    return pin

def test_actual_login_full_flow(monkeypatch,passwords):
    pin=populate(monkeypatch,passwords)
    with login(acl.READER,passwords) as c:
        r=ledger.inspect_status(c,pin)
        assert r['state']=='CONSUMED' and r['gate5']=='BLOCKED'
        assert r['actual_host_isolation']=='NOT_ATTESTED'
    with admin() as c:assert acl.audit(c)=='PASS_PROSPECTIVE_WITNESS_ACL_ONLY'

@pytest.mark.parametrize('role',acl.LOGINS)
def test_real_login_cannot_escalate_or_mutate(monkeypatch,passwords,role):
    populate(monkeypatch,passwords)
    with login(role,passwords) as c:
        for other in (acl.OWNER,*(r for r in acl.LOGINS if r!=role)):
            with pytest.raises(psycopg.errors.InsufficientPrivilege) as ex:
                c.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(other)))
            assert ex.value.sqlstate=='42501'
        for table in acl.TABLES:
            target=sql.Identifier(acl.SCHEMA,table)
            assert c.execute(sql.SQL('SELECT count(*) FROM {}').format(target)).fetchone()[0]>=1
            for q in (sql.SQL('UPDATE {} SET pin=pin').format(target),
                      sql.SQL('DELETE FROM {}').format(target),
                      sql.SQL('TRUNCATE {}').format(target),
                      sql.SQL('ALTER TABLE {} DISABLE ROW LEVEL SECURITY').format(target)):
                with pytest.raises(psycopg.errors.InsufficientPrivilege) as ex:c.execute(q)
                assert ex.value.sqlstate=='42501'
            if acl.INSERT[table]!=role:
                with pytest.raises(psycopg.errors.InsufficientPrivilege) as ex:
                    c.execute(sql.SQL('INSERT INTO {} SELECT * FROM {}').format(target,target))
                assert ex.value.sqlstate=='42501'
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute('CREATE TABLE naruv_witness_ledger_ci.forbidden(id int)')
        c.execute('SET row_security=off')
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as ex:
            c.execute('SELECT * FROM naruv_witness_ledger_ci.evidence')
        assert ex.value.sqlstate=='42501'
        c.execute('RESET row_security')

def test_force_rls_owner_has_no_runtime_policy(monkeypatch,passwords):
    pin=populate(monkeypatch,passwords)
    with admin() as c:
        c.execute('SET ROLE naruv_witness_owner_ci')
        try:
            for table in acl.TABLES:
                assert c.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier(acl.SCHEMA,table))).fetchone()==(0,)
            with pytest.raises(psycopg.errors.InsufficientPrivilege) as ex:
                c.execute('INSERT INTO naruv_witness_ledger_ci.approval VALUES(%s,%s,%s,%s)',('f'*64,b'a',b'b','f'*64))
            assert ex.value.sqlstate=='42501'
        finally:c.execute('RESET ROLE')
    with login(acl.READER,passwords) as c:assert ledger.inspect_status(c,pin)['state']=='CONSUMED'

@pytest.mark.parametrize('mutation,code',[
 ('GRANT UPDATE ON naruv_witness_ledger_ci.evidence TO naruv_witness_verifier_ci','ACL_TABLE_GRANTS'),
 ('GRANT USAGE ON SCHEMA naruv_witness_ledger_ci TO PUBLIC','ACL_SCHEMA_GRANTS'),
 ('ALTER TABLE naruv_witness_ledger_ci.evidence NO FORCE ROW LEVEL SECURITY','ACL_OBJECT_OR_RLS'),
 ('GRANT naruv_witness_verifier_ci TO naruv_witness_reader_ci','ACL_ROLE_MEMBERSHIP'),
 ('ALTER POLICY read_evidence ON naruv_witness_ledger_ci.evidence USING (false)','ACL_POLICY_DRIFT'),
 ('GRANT UPDATE(pin) ON naruv_witness_ledger_ci.evidence TO naruv_witness_reader_ci','ACL_COLUMN_GRANTS'),
 ('ALTER DEFAULT PRIVILEGES FOR ROLE naruv_witness_owner_ci GRANT SELECT ON TABLES TO PUBLIC','ACL_DEFAULT_GRANTS'),
 ('ALTER ROLE naruv_witness_reader_ci BYPASSRLS','ACL_ROLE_FLAGS')])
def test_catalog_drift_detected_and_rollback(passwords,mutation,code):
    with admin() as c:
        with c.transaction(force_rollback=True):
            c.execute(mutation)
            with pytest.raises(ValueError,match=code):acl.audit(c)
        assert acl.audit(c)=='PASS_PROSPECTIVE_WITNESS_ACL_ONLY'

def test_live_role_guard_detects_membership_drift(passwords):
    with admin() as c:c.execute('GRANT naruv_witness_verifier_ci TO naruv_witness_reader_ci')
    try:
        with login(acl.READER,passwords) as c:
            with pytest.raises(ValueError,match='DIRECT_LOGIN_MEMBERSHIP_DRIFT'):
                ledger.inspect_status(c,'f'*64)
    finally:
        with admin() as c:
            c.execute('REVOKE naruv_witness_verifier_ci FROM naruv_witness_reader_ci')
            assert acl.audit(c)=='PASS_PROSPECTIVE_WITNESS_ACL_ONLY'
