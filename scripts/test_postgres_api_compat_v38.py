"""TestClient against disposable PG17 typed compatibility records, no public route."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
import re
import secrets

from app.pg_migration_shadow_v36 import source_records
from app.pg_migration_compat_v37 import stage_compat, verify_compat, drop_compat
from scripts.v36_synthetic_fixture import fixture


def run() -> int:
    if (os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'
            or os.getenv('JW_PG_LAB_V38') != 'ONLY_DISPOSABLE_LAB'):
        print('NOT RUN: no disposable V3.8 authorization')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from fastapi.testclient import TestClient
        from app.pg_compat_read_api_v38 import create_lab_app, check_dsn
        admin = os.getenv('JW_PG_TEST_ADMIN_DSN','')
        app_dsn = os.getenv('JW_PG_TEST_APP_DSN','')
        a,b = conninfo_to_dict(admin),check_dsn(app_dsn)
        if (not re.fullmatch(r'jw_v20_test_[a-f0-9]{12}',a.get('dbname',''))
                or a.get('dbname') != b.get('dbname') or a.get('user')!='postgres'
                or a.get('host') not in ('127.0.0.1','localhost','::1')
                or not a.get('password')):
            print('NOT RUN: V3.8 unsafe PG17 admin connection')
            return 2
    except (ImportError,ValueError,TypeError,RuntimeError):
        print('NOT RUN: V3.8 PG17 driver or synthetic DB connection missing')
        return 2
    fixture_db=fixture()
    staged=False
    try:
        records=source_records(fixture_db)
        with psycopg.connect(admin,autocommit=True,connect_timeout=5) as pg:
            stage_compat(pg,records)
            staged=True
            verify_compat(pg,records)
            tokens={name:secrets.token_urlsafe(40) for name in ('tenant_a','tenant_b','tenant_c')}
            with pg.cursor() as c:
                for org,user in [('tenant_a','ua'),('tenant_b','ub'),('tenant_c','uc')]:
                    c.execute('''INSERT INTO jw_guard.authenticated_sessions
                      (token_digest,org_id,user_id,mfa_verified,expires_at)
                      VALUES(%s,%s,%s,true,%s)''',
                      (sha256(tokens[org].encode()).digest(),org,user,
                       datetime.now(timezone.utc)+timedelta(minutes=15)))
            api=create_lab_app(app_dsn)
            h=lambda org:{'X-JW-Lab-Session':tokens[org]}
            with TestClient(api) as client:
                path='/lab38/threads/thread_ab/messages'
                for org in ('tenant_a','tenant_b'):
                    response=client.get(path,headers=h(org))
                    assert response.status_code==200, 'Legitimate company not authorized'
                    messages=response.json()['messages']
                    assert len(messages)==3, 'Legacy order/text/attachment context missing'
                    order=next(m for m in messages if m['kind']=='order')
                    assert order['order_id']=='order_fake_001'
                    assert 'order_fake_001' in order['immutable_order_snapshot']
                    assert next(m for m in messages if m['id']=='msg_text')['version']==2
                    attachment=client.get('/lab38/threads/thread_ab/attachments/msg_file',headers=h(org))
                    assert attachment.status_code==200 and attachment.content==b'\x00\xff\x01\xfePNG-demo-bytes\x00'
                    assert attachment.headers.get('x-content-sha256')==sha256(attachment.content).hexdigest()
                    assert attachment.headers.get('x-content-type-options')=='nosniff'
                assert client.get(path,headers=h('tenant_c')).status_code==404
                assert client.get('/lab38/threads/thread_ab/attachments/msg_file',headers=h('tenant_c')).status_code==404
                assert client.get(path).status_code==401
                assert client.get('/lab38/threads/thread_ab/my-read-position',headers=h('tenant_a')).json()=={'last_read_seq':1}
                assert client.get('/lab38/threads/thread_ab/my-read-position',headers=h('tenant_b')).json()=={'last_read_seq':2}
                assert client.get('/lab38/threads/thread_ab/my-read-position',headers=h('tenant_c')).status_code==404
                assert client.get(path+'?after=1&limit=1',headers=h('tenant_a')).json()['messages'][0]['id']=='msg_file'
                assert client.post(path,headers=h('tenant_a'),json={'body':'forged'}).status_code==405
                # Use the same HTTP session token after DB-side revocation:
                # every new request must re-bind rather than reusing tenant GUC.
                with pg.cursor() as c:
                    c.execute('''UPDATE jw_guard.authenticated_sessions
                      SET revoked_at=clock_timestamp() WHERE token_digest=%s''',
                      (sha256(tokens['tenant_a'].encode()).digest(),))
                    assert c.rowcount==1
                revoked=client.get(path,headers=h('tenant_a'))
                assert revoked.status_code==403 and tokens['tenant_a'] not in revoked.text
                assert client.get(path,headers=h('tenant_b')).status_code==200
            verify_compat(pg,records)
            drop_compat(pg)
            staged=False
            with pg.cursor() as c:
                c.execute("SELECT to_regnamespace('jw_migration_v37')")
                assert c.fetchone()==(None,), 'Compatibility test schema not removed'
        print('PASS: V3.8 isolated FastAPI TestClient PG17 typed reads, attachment SHA256, bilateral RLS, revoke, cleanup')
        print('BLOCKED: real public FastAPI PG17 adapter, live migration and production deployment NOT RUN')
        return 0
    except Exception as ex:
        print('FAIL: V3.8 isolated API gate '+type(ex).__name__+' (details redacted)')
        return 1
    finally:
        fixture_db.close()
        # Outer disposable DB runner destroys the entire test DB even on error.
        # Best effort here ensures V3.8 cannot mask test failure with a stale schema.
        if staged:
            try:
                with psycopg.connect(admin,autocommit=True,connect_timeout=5) as pg:
                    drop_compat(pg)
            except Exception:
                pass


if __name__=='__main__':
    raise SystemExit(run())
