"""Isolated Psycopg3 lifecycle contract, using a fake network-free driver."""
import sys
from types import SimpleNamespace
from unittest.mock import patch
import pytest

from app.pg_driver_v39 import verified_read_cursor, LabRefused

DSN='host=127.0.0.1 dbname=jw_v20_test_abcdef123456 user=jw_app password=test'


class FakeCursor:
    def __init__(self, *, privileged=False, deny=False, version='170008'):
        self.commands=[]
        self.privileged=privileged
        self.deny=deny
        self.version=version
        self.response=None
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def execute(self, sql, params=None):
        self.commands.append((sql, params))
        if 'SELECT current_database()' in sql:
            self.response=('jw_v20_test_abcdef123456','jw_app',self.version,self.privileged)
        elif 'SELECT jw_guard.current_tenant()' in sql:
            self.response=(None,None) if self.deny else ('tenant_a','ua')
        elif 'SELECT jw_guard.bind_session' in sql:
            assert params==('t'*48,)
            self.response=(None,)
        else: self.response=(1,)
    def fetchone(self): return self.response


class FakeConn:
    def __init__(self, **kwargs):
        self.cur=FakeCursor(**kwargs)
        self.rolled_back=0
        self.closed=0
    def cursor(self): return self.cur
    def rollback(self): self.rolled_back+=1
    def close(self): self.closed+=1


@pytest.fixture
def allow(monkeypatch):
    monkeypatch.setenv('JW_PG_LAB_V38','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_ALLOW_TEST_WRITES','ONLY_EPHEMERAL_DATABASE')


def test_refuses_real_host_and_missing_flag_without_driver(monkeypatch):
    with pytest.raises(LabRefused):
        with verified_read_cursor(DSN,'t'*48): pass
    monkeypatch.setenv('JW_PG_LAB_V38','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_ALLOW_TEST_WRITES','ONLY_EPHEMERAL_DATABASE')
    with pytest.raises(LabRefused):
        with verified_read_cursor(DSN.replace('127.0.0.1','example.com'),'t'*48): pass
    with pytest.raises(LabRefused):
        with verified_read_cursor(DSN.replace('jw_app','postgres'),'t'*48): pass
    with pytest.raises(LabRefused):
        with verified_read_cursor(DSN,'short'): pass


def test_connection_is_always_rolled_back_even_on_success(allow,monkeypatch):
    opened=[]
    def connect(dsn,connect_timeout):
        assert dsn==DSN and connect_timeout==5
        conn=FakeConn();opened.append(conn);return conn
    monkeypatch.setitem(sys.modules,'psycopg',SimpleNamespace(connect=connect))
    with verified_read_cursor(DSN,'t'*48) as cur:
        cur.execute('SELECT 1')
    assert opened[0].rolled_back==1 and opened[0].closed==1
    cmds=[sql for sql,_ in opened[0].cur.commands]
    assert cmds.index('SELECT jw_guard.bind_session(%s)') > next(i for i,s in enumerate(cmds) if 'SELECT current_database()' in s)
    assert all('SET LOCAL' in x for x in cmds[:3])
    assert any('jw_guard.current_actor()' in x for x in cmds)


def test_cursor_exception_rolls_back_and_does_not_reveal_credentials(allow,monkeypatch):
    con=FakeConn()
    monkeypatch.setitem(sys.modules,'psycopg',SimpleNamespace(connect=lambda *a,**kw: con))
    with pytest.raises(RuntimeError):
        with verified_read_cursor(DSN,'t'*48): raise RuntimeError('synthetic operation error')
    assert con.rolled_back==con.closed==1


@pytest.mark.parametrize('kwargs', [{'privileged':True},{'deny':True},{'version':'160001'}])
def test_rejects_superuser_unverified_actor_or_wrong_pg_version(allow,monkeypatch,kwargs):
    conn=FakeConn(**kwargs)
    monkeypatch.setitem(sys.modules,'psycopg',SimpleNamespace(connect=lambda *a,**kw:conn))
    with pytest.raises(LabRefused):
        with verified_read_cursor(DSN,'t'*48): pass
    assert conn.closed==1 and conn.rolled_back==1


def test_requires_no_production_pool_and_remains_isolated():
    from pathlib import Path
    src=Path('app/pg_driver_v39.py').read_text()
    assert 'psycopg_pool' not in src and 'pg.rollback()' in src and 'pg.close()' in src
    assert 'pg_driver_v39' not in Path('app/main.py').read_text()
    src38=Path('app/pg_compat_read_api_v38.py').read_text()
    assert 'with verified_read_cursor(dsn, token) as cur' in src38
