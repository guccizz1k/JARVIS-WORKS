"""V5.0 synthetic identity gate fail-shut/side effects regression."""
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import replace
import pytest
from app.pg_identity_audit_v50 import ActorLink, IdentityAuditBlocked, audit_roster

LINKS = (ActorLink('wa','ua','pa','pua'), ActorLink('wb','ub','pb','pub'))
TOKENS = ('a' * 55, 'b' * 55)


class Cursor:
    def __init__(self, pg): self.pg = pg
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def execute(self, statement, params=None):
        self.pg.calls.append((statement, params))
        if statement.startswith('SELECT id,org_id'): self.result = self.pg.rows
        else: self.result = [self.pg.identity]
    def fetchone(self): return self.result[0]
    def fetchall(self): return self.result


class Admin:
    def __init__(self):
        self.identity = ('jw_v20_test_012345abcdef','postgres','170004')
        self.rows = [('pua','pa'),('pub','pb')]
        self.calls = []
    def cursor(self): return Cursor(self)


class Adapter:
    def __init__(self): self.revoked = set(); self.calls = []
    @contextmanager
    def verified_transaction(self, token, readonly=False):
        self.calls.append((token, readonly))
        if token in self.revoked: raise ValueError('rejected')
        yield (object(),) + (('pa','pua') if token == TOKENS[0] else ('pb','pub'))


@pytest.fixture
def audit_env(monkeypatch):
    monkeypatch.delenv('JW_ENV', raising=False)
    monkeypatch.setenv('JW_PG_CI_ALLOW', 'ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.setenv('JW_PG_LAB_V50', 'ONLY_DISPOSABLE_LAB')
    db=sqlite3.connect(':memory:')
    db.executescript('''CREATE TABLE users(id text primary key, org_id text not null);
       CREATE TABLE staff_disabled(user_id text primary key);
       INSERT INTO users VALUES('ua','wa'),('ub','wb');''')
    pg=Admin(); adapter=Adapter()
    yield db,pg,adapter
    db.close()


def run(a,links=LINKS,tokens=TOKENS):return audit_roster(a[0],a[1],a[2],links,tokens)


def test_two_tenant_verified_identity_never_grants_cutover(audit_env):
    result=run(audit_env)
    assert result['decision']=='BLOCKED' and result['cutover_approved'] is False
    assert result['verified_fixture_links']==2 and result['verified_fixture_tenants']==2
    assert not any('aaa' in str(v) for v in result.values())
    assert all(ro for _,ro in audit_env[2].calls)
    assert len(audit_env[1].calls)==2
    assert audit_env[0].execute('select count(*) from users').fetchone()[0]==2

@pytest.mark.parametrize('links',(
    (), (LINKS[0],), (LINKS[0],LINKS[0]),
    (LINKS[0],replace(LINKS[1],pg_user='pua')),
    (LINKS[0],replace(LINKS[1],pg_org='pa')),
    (LINKS[0],replace(LINKS[1],source_org='wa')),
    (LINKS[0], replace(LINKS[1],pg_org='pa',pg_user='pub')),
    (LINKS[0],replace(LINKS[1],source_user='u\n')), 
))
def test_invalid_roster_rejected_without_db_reads(audit_env,links):
    with pytest.raises(IdentityAuditBlocked):run(audit_env,links=links)
    assert audit_env[1].calls==[] and audit_env[2].calls==[]

@pytest.mark.parametrize('tokens', ((),('a'*55,),('a'*55,)*2,('x','b'*55),('a'*55,123)))
def test_invalid_tokens_are_rejected_before_db(audit_env,tokens):
    with pytest.raises(IdentityAuditBlocked):run(audit_env,tokens=tokens)
    assert audit_env[1].calls == []

@pytest.mark.parametrize('environment', ('production','PRODUCTION','Production'))
def test_production_always_refused(audit_env,monkeypatch,environment):
    monkeypatch.setenv('JW_ENV',environment)
    with pytest.raises(IdentityAuditBlocked):run(audit_env)
    assert not audit_env[1].calls

@pytest.mark.parametrize('missing', ('JW_PG_LAB_V50','JW_PG_CI_ALLOW'))
def test_missing_isolation_flag_refused(audit_env,monkeypatch,missing):
    monkeypatch.delenv(missing)
    with pytest.raises(IdentityAuditBlocked):run(audit_env)

@pytest.mark.parametrize('identity', (
    ('prod','postgres','170004'),('jw_v20_test_012345abcdef','jw_app','170004'),
    ('jw_v20_test_012345abcdef','postgres','160008'),
    ('jw_v20_test_012345abcdeg','postgres','170004')))
def test_wrong_pg_instance_no_actor_read(audit_env,identity):
    audit_env[1].identity=identity
    with pytest.raises(IdentityAuditBlocked):run(audit_env)
    assert len(audit_env[1].calls)==1

@pytest.mark.parametrize('rows', ([], [('pua','pa')], [('pua','pa'),('pua','pa')], [('pua','pa'),('pub','pa')]))
def test_missing_colliding_or_cross_org_pg_actor(audit_env,rows):
    audit_env[1].rows=rows
    with pytest.raises(IdentityAuditBlocked):run(audit_env)

@pytest.mark.parametrize('sql',(
    "INSERT INTO staff_disabled VALUES('ua')",
    "UPDATE users SET org_id='wb' WHERE id='ua'",
    "DELETE FROM users WHERE id='ub'",
))
def test_disabled_cross_tenant_or_missing_sqlite_identity(audit_env,sql):
    audit_env[0].execute(sql)
    with pytest.raises(IdentityAuditBlocked):run(audit_env)

@pytest.mark.parametrize('index',(0,1))
def test_revoked_pg_actor_denied(audit_env,index):
    audit_env[2].revoked.add(TOKENS[index])
    with pytest.raises(IdentityAuditBlocked):run(audit_env)


def test_immutable_link_object_and_read_only_sql(audit_env):
    from dataclasses import FrozenInstanceError
    with pytest.raises(FrozenInstanceError):LINKS[0].pg_org='changed'
    run(audit_env)
    assert all(sql.startswith('SELECT') for sql,_ in audit_env[1].calls)
    assert all(readonly is True for _,readonly in audit_env[2].calls)


def test_swapped_signed_sessions_are_denied(audit_env):
    with pytest.raises(IdentityAuditBlocked):
        run(audit_env, tokens=TOKENS[::-1])
