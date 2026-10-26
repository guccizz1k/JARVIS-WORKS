"""V8.8 preflight mocks. These DO NOT represent live network tests."""
import json
import pytest
from app import pg_live_dryrun_v88 as stage


def environment(**overrides):
    env = dict(JW_PG_V88_LIVE_GATE='ISOLATED_DEV_ONLY', JW_ENV='dev',
               JW_PG_AUTH_STAGE_DSN='private_auth', JW_PG_STAGE_DSN='private_trade')
    env.update(overrides)
    return env


class FakeCursor:
    def __init__(self, db):
        self.db = db
        self.last = None
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def execute(self, sql, args=None):
        self.db.sql.append(sql)
        if 'pg_backend_pid()' in sql:
            self.last = (self.db.pid, 'jw_app_dev', 'jw_trade_login_v86')
        elif 'pg_try_advisory_xact_lock' in sql:
            if args != (872688, 20261023):
                raise AssertionError('Non-namespaced advisory lock')
            if self.db.pool.held and self.db.pid not in self.db.pool.held:
                self.last = (False,)
            else:
                self.db.pool.held.add(self.db.pid)
                self.last = (True,)
        else:
            self.last = None
    def fetchone(self): return self.last


class FakeDb:
    def __init__(self, pool, pid):
        self.pool, self.pid = pool, pid
        self.sql = []
        self.closed = False
        self.rollbacks = 0
    def cursor(self): return FakeCursor(self)
    def rollback(self):
        self.pool.held.discard(self.pid)
        self.rollbacks += 1
    def close(self): self.closed = True


class Pool:
    def __init__(self, reuse_pid=False):
        self.held = set()
        self.items = []
        self.reuse_pid = reuse_pid
    def connector(self, dsn, **kwargs):
        assert dsn == 'private_trade'
        assert kwargs == {'sslmode': 'verify-full', 'connect_timeout': 5}
        item = FakeDb(self, 50 if self.reuse_pid else 50+len(self.items))
        self.items.append(item)
        return item


@pytest.mark.parametrize('changes', [
    {}, {'JW_ENV': 'production'}, {'JW_ENV': 'preview'},
    {'JW_PG_V88_LIVE_GATE': 'YES'}, {'JW_INSECURE_LOCAL_DEV': '1'},
    {'JW_PG_AUTH_STAGE_DSN': ''},
    {'JW_PG_STAGE_DSN': 'private_auth'},
])
def test_disabled_or_missing_credentials_fails_without_connections(monkeypatch, changes):
    if changes:
        e = environment(**changes)
    else:
        e = {}
    def unexpected(**_):
        raise AssertionError('Connection check should not run')
    monkeypatch.setattr(stage, 'check_two_connections', unexpected)
    result = stage.live_gate_v88(env=e)
    assert result['result'] == 'BLOCKED'
    assert result['payment_race_e2e'] == 'NOT_RUN'


def test_prior_security_gate_failure_blocks(monkeypatch):
    monkeypatch.setattr(stage, 'check_two_connections',
                        lambda **_: {'result':'BLOCKED'})
    def fail(*_, **__): raise AssertionError('Should never connect')
    assert stage.live_gate_v88(connector=fail, env=environment())['result'] == 'BLOCKED'


def test_independent_lock_contention_and_rollback(monkeypatch):
    monkeypatch.setattr(stage, 'check_two_connections',
                        lambda **_: {'result':'PASS'})
    pool = Pool()
    out = stage.live_gate_v88(connector=pool.connector, env=environment())
    assert out['result'] == 'PASS' and out['production_cutover'] is False
    assert out['scope'] == 'INDEPENDENT_TLS_ROLES_AND_ADVISORY_LOCK_ONLY'
    assert out['login_mfa_e2e'] == 'NOT_RUN'
    assert out['payment_race_e2e'] == 'NOT_RUN'
    assert len(pool.items) == 2 and all(db.closed and db.rollbacks >= 1 for db in pool.items)
    assert not pool.held
    assert 'private_' not in json.dumps(out)
    assert all('SET TRANSACTION READ ONLY' in db.sql for db in pool.items)
    assert all('SET LOCAL ROLE jw_app_dev' in db.sql for db in pool.items)


def test_same_backend_rejected(monkeypatch):
    monkeypatch.setattr(stage, 'check_two_connections', lambda **_: {'result':'PASS'})
    pool = Pool(reuse_pid=True)
    result = stage.live_gate_v88(connector=pool.connector, env=environment())
    assert result['result'] == 'BLOCKED'
    assert all(db.closed for db in pool.items)


def test_db_exception_redacted_and_connections_closed(monkeypatch):
    monkeypatch.setattr(stage, 'check_two_connections', lambda **_: {'result':'PASS'})
    pool = Pool()
    def bad_connector(*args, **kwargs):
        db = pool.connector(*args, **kwargs)
        if len(pool.items) == 2:
            def broken(): raise RuntimeError('DSN=private_trade password=secret')
            db.cursor = broken
        return db
    result = stage.live_gate_v88(connector=bad_connector, env=environment())
    assert result['result'] == 'BLOCKED'
    assert 'private_trade' not in str(result) and 'secret' not in str(result)
    assert all(db.closed and db.rollbacks >= 1 for db in pool.items)
