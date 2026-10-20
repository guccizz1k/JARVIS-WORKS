import os
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.pg_compat_read_api_v38 import create_lab_app, check_dsn, LabRefused

GOOD='host=127.0.0.1 dbname=jw_v20_test_abcdef123456 user=jw_app password=fake'


def test_rejects_production_and_absent_flags(monkeypatch):
    with pytest.raises(LabRefused): check_dsn(GOOD)
    monkeypatch.setenv('JW_PG_ALLOW_TEST_WRITES','ONLY_EPHEMERAL_DATABASE')
    monkeypatch.setenv('JW_PG_LAB_V38','ONLY_DISPOSABLE_LAB')
    for dsn in ('host=localhost dbname=production user=jw_app password=fake',
                'host=example.com dbname=jw_v20_test_abcdef123456 user=jw_app password=fake',
                'host=localhost dbname=jw_v20_test_abcdef123456 user=postgres password=fake',
                'host=localhost dbname=jw_v20_test_abcdef123456 user=jw_app'):
        with pytest.raises(LabRefused):check_dsn(dsn)
    assert check_dsn(GOOD)['user']=='jw_app'


def test_lab_is_not_mounted_into_main():
    s=Path('app/main.py').read_text()
    assert 'pg_compat_read_api_v38' not in s
    assert 'include_router' not in Path('app/pg_compat_read_api_v38.py').read_text()


def test_public_payload_never_accepts_tenant_from_client(monkeypatch):
    monkeypatch.setenv('JW_PG_ALLOW_TEST_WRITES','ONLY_EPHEMERAL_DATABASE')
    monkeypatch.setenv('JW_PG_LAB_V38','ONLY_DISPOSABLE_LAB')
    app=create_lab_app(GOOD)
    with TestClient(app) as c:
        assert c.get('/lab38/threads/a/messages').status_code==401
        assert c.get('/lab38/threads/!bad/messages',headers={'X-JW-Lab-Session':'x'*48}).status_code==422
        assert c.get('/lab38/threads/a/messages?after=-1',headers={'X-JW-Lab-Session':'x'*48}).status_code==422
        assert c.get('/lab38/threads/a/messages?limit=1000',headers={'X-JW-Lab-Session':'x'*48}).status_code==422
        assert c.get('/lab38/threads/a/attachments/..',headers={'X-JW-Lab-Session':'x'*48}).status_code in (404,422)
    routes=[r for r in app.routes if getattr(r,'path','').startswith('/lab38/')]
    assert routes and all('POST' not in r.methods and 'PUT' not in r.methods and 'DELETE' not in r.methods for r in routes)


def test_no_unsafe_sql_interpolation():
    s=Path('app/pg_compat_read_api_v38.py').read_text()
    assert 'with verified_read_cursor(dsn, token) as cur' in s
    assert 'jw_guard.bind_session(%s)' in Path('app/pg_driver_v39.py').read_text()
    assert 'jw_guard.current_tenant()' in s
    assert 'application/octet-stream' in s and 'nosniff' in s
    assert 'UPDATE jw_migration' not in s and 'INSERT INTO jw_migration' not in s
    assert 'password' not in s.split('raise HTTPException(403,')[1]  # no cred in denial
