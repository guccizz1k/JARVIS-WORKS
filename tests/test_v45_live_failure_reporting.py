"""Regression: live synthetic evidence failures must not be blamed on cleanup.

Use in-memory SQLite, fake psycopg connections and HTTP responses. No Docker,
network, production DSN or real DB access is made.
"""
from __future__ import annotations
import sqlite3
import sys
from types import ModuleType, SimpleNamespace

import pytest
from scripts import test_postgres_evidence_shadow_v45 as runner


class FakeCursor:
    def __init__(self):
        self.values = [(None,)]
        self.rowcount = 1
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def execute(self, sql, *args):
        if 'to_regnamespace' in sql:
            self.values = [(None,)]
    def fetchone(self): return self.values.pop(0)

class FakePG:
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def cursor(self): return FakeCursor()

class FakeCookies:
    def set(self, *a): pass

class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code=status
        self._payload=payload or {}
        self.text='REDACTED RESPONSE' if status >= 400 else 'safe synthetic summary'
    def json(self): return self._payload

class FakeClient:
    def __init__(self, app, **kwargs):
        self.cookies=FakeCookies()
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def get(self, endpoint, headers=None):
        if headers:
            return FakeResponse(401)
        self.count=getattr(self, 'count', 0)+1
        # before the valid cookie injection, the initial request is rejected
        if self.count==1:
            return FakeResponse(401)
        return FakeResponse(503, {'code': 'PG_UNAVAILABLE'})
    def post(self, *a, **kw): return FakeResponse(405)

@pytest.fixture
def synthetic(monkeypatch):
    for n in range(35,46):
        monkeypatch.setenv('JW_PG_LAB_V'+str(n), 'ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_CI_ALLOW', 'ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.setenv('JW_PG_ALLOW_TEST_WRITES', 'ONLY_EPHEMERAL_DATABASE')
    monkeypatch.setenv('JW_PG_TEST_ADMIN_DSN', 'synthetic-admin')
    monkeypatch.setenv('JW_PG_TEST_APP_DSN', 'synthetic-app')
    monkeypatch.delenv('JW_ENV', raising=False)

    conninfo=ModuleType('psycopg.conninfo')
    conninfo.conninfo_to_dict=lambda uri: {'dbname':'jw_v20_test_aaaaaaaaaaaa',
                                           'user': 'postgres' if uri=='synthetic-admin' else 'jw_app'}
    pg=ModuleType('psycopg');pg.__path__=[]
    pg.connect=lambda *_args,**_kwargs:FakePG()
    pg.conninfo=conninfo
    monkeypatch.setitem(sys.modules,'psycopg',pg)
    monkeypatch.setitem(sys.modules,'psycopg.conninfo',conninfo)
    import fastapi.testclient
    monkeypatch.setattr(fastapi.testclient, 'TestClient', FakeClient)
    from app import pg_evidence_shadow_v45, pg_migration_shadow_v36, pg_migration_compat_v37
    monkeypatch.setattr(pg_evidence_shadow_v45, 'create_review_app',lambda **kw:object())
    class Adapter:
        def __init__(self,*args):pass
        def _check_dsn(self):pass
    import app
    pg_adapter=ModuleType('app.pg_messenger_review')
    pg_adapter.MessengerReviewAdapter=Adapter
    monkeypatch.setitem(sys.modules,'app.pg_messenger_review',pg_adapter)
    monkeypatch.setattr(app,'pg_messenger_review',pg_adapter,raising=False)
    monkeypatch.setattr(pg_migration_shadow_v36, 'source_records', lambda db:['row'],raising=False)
    monkeypatch.setattr(pg_migration_compat_v37,'stage_compat',lambda pg,records:None,raising=False)
    monkeypatch.setattr(pg_migration_compat_v37,'verify_compat',lambda pg,records:{'rows':len(records)},raising=False)
    monkeypatch.setattr(pg_migration_compat_v37,'drop_compat',lambda pg:None,raising=False)
    writer=ModuleType('scripts.test_postgres_writer_v40')
    writer._verified_lab_uri=lambda *args:'postgresql://jw_app:fake@localhost/jw_v20_test_aaaaaaaaaaaa'
    def fixture():
        db=sqlite3.connect(':memory:')
        db.executescript('''CREATE TABLE messenger_connections(id TEXT);
            CREATE TABLE messenger_messages(connection_id TEXT);
            CREATE TABLE messenger_read_positions(connection_id TEXT);
            INSERT INTO messenger_connections VALUES('thread_ab');
            INSERT INTO messenger_messages VALUES('thread_ab');
            INSERT INTO messenger_read_positions VALUES('thread_ab');''')
        return db
    synthetic_fixture=ModuleType('scripts.v36_synthetic_fixture')
    synthetic_fixture.fixture=fixture
    import scripts
    monkeypatch.setitem(sys.modules,'scripts.test_postgres_writer_v40',writer)
    monkeypatch.setattr(scripts,'test_postgres_writer_v40',writer,raising=False)
    monkeypatch.setitem(sys.modules,'scripts.v36_synthetic_fixture',synthetic_fixture)
    monkeypatch.setattr(scripts,'v36_synthetic_fixture',synthetic_fixture,raising=False)
    return pg_migration_compat_v37


def test_primary_http_failure_is_not_reported_as_cleanup(synthetic,capsys):
    assert runner.run()==1
    err=capsys.readouterr().err
    assert 'stage=RLS-full-evidence-HTTP-parity code=BASELINE_HTTP_503_PG_UNAVAILABLE' in err
    assert 'cleanup-compatibility-schema' not in err
    assert 'postgresql://' not in err and 'synthetic-app' not in err


def test_concurrent_cleanup_failure_reported_separately(synthetic,monkeypatch,capsys):
    def fail_cleanup(pg):
        raise RuntimeError('secret token, never print me')
    monkeypatch.setattr(synthetic,'drop_compat',fail_cleanup)
    assert runner.run()==1
    err=capsys.readouterr().err
    assert 'stage=RLS-full-evidence-HTTP-parity code=BASELINE_HTTP_503_PG_UNAVAILABLE' in err
    assert 'cleanup code=RuntimeError' in err
    assert 'secret token' not in err
