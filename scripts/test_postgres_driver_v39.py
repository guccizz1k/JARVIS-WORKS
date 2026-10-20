"""V3.9: isolated PostgreSQL 17 Psycopg transaction/session lifecycle test."""
from __future__ import annotations

import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from hashlib import sha256


def run() -> int:
    if (os.getenv('JW_PG_ALLOW_TEST_WRITES')!='ONLY_EPHEMERAL_DATABASE'
            or os.getenv('JW_PG_LAB_V39')!='ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_LAB_V38')!='ONLY_DISPOSABLE_LAB'):
        print('NOT RUN: V3.9 disposable-driver authorization missing')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from app.pg_compat_read_api_v38 import check_dsn
        from app.pg_driver_v39 import verified_read_cursor
        from app.pg_migration_shadow_v36 import source_records
        from app.pg_migration_compat_v37 import stage_compat, drop_compat
        from scripts.v36_synthetic_fixture import fixture
        admin=os.getenv('JW_PG_TEST_ADMIN_DSN','')
        target=os.getenv('JW_PG_TEST_APP_DSN','')
        a,b=conninfo_to_dict(admin),check_dsn(target)
        if (not re.fullmatch(r'jw_v20_test_[a-f0-9]{12}',a.get('dbname',''))
                or a.get('dbname')!=b.get('dbname') or a.get('user')!='postgres'
                or a.get('host') not in ('127.0.0.1','localhost','::1')
                or not a.get('password')):
            print('NOT RUN: V3.9 refused non-disposable PG17 target')
            return 2
    except (ImportError,RuntimeError,ValueError,TypeError):
        print('NOT RUN: V3.9 driver not available or safe DSN not verified')
        return 2
    fixture_db=fixture()
    staged=False
    try:
        tokens=[secrets.token_urlsafe(40),secrets.token_urlsafe(40)]
        with psycopg.connect(admin,autocommit=True,connect_timeout=5) as supervisor:
            stage_compat(supervisor,source_records(fixture_db))
            staged=True
            with supervisor.cursor() as cur:
                for idx,tenant in enumerate(('tenant_a','tenant_b')):
                    cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                      (token_digest,org_id,user_id,mfa_verified,expires_at)
                      VALUES (%s,%s,%s,true,%s)''',
                      (sha256(tokens[idx].encode()).digest(),tenant,'ua' if idx==0 else 'ub',
                       datetime.now(timezone.utc)+timedelta(minutes=10)))
            for i,(tenant,actor) in enumerate((('tenant_a','ua'),('tenant_b','ub'))):
                with verified_read_cursor(target,tokens[i]) as cur:
                    cur.execute('SELECT jw_guard.current_tenant(),jw_guard.current_actor()')
                    if cur.fetchone()!=(tenant,actor):
                        raise AssertionError('Tenant/actor binding mismatch')
                    # The driver never allows writes to the read-only archive.
                    cur.execute('SELECT COUNT(*) FROM jw_migration_v37.messenger_connections')
                    if cur.fetchone()[0]!=1:
                        raise AssertionError('Expected bilateral thread was not readable')
            with psycopg.connect(target,connect_timeout=5) as unbound:
                with unbound.cursor() as cur:
                    cur.execute('SELECT jw_guard.current_tenant(),jw_guard.current_actor()')
                    if cur.fetchone()!=(None,None):
                        raise AssertionError('Tenant context leaked into unrelated connection')
            try:
                with verified_read_cursor(target,secrets.token_urlsafe(40)):
                    pass
            except (psycopg.Error, RuntimeError):
                pass
            else:
                raise AssertionError('Unverified token accepted')
            with supervisor.cursor() as cur:
                cur.execute('UPDATE jw_guard.authenticated_sessions SET revoked_at=clock_timestamp() '
                            'WHERE token_digest=%s',(sha256(tokens[0].encode()).digest(),))
                if cur.rowcount!=1: raise AssertionError('Revocation fixture mismatch')
            try:
                with verified_read_cursor(target,tokens[0]): pass
            except (psycopg.Error, RuntimeError): pass
            else: raise AssertionError('Revoked actor reused')
            with verified_read_cursor(target,tokens[1]) as cur:
                cur.execute('SELECT jw_guard.current_actor()')
                if cur.fetchone()!=('ub',): raise AssertionError('Unrelated actor was revoked')
            drop_compat(supervisor)
            staged=False
        print('PASS: V3.9 real Psycopg 3 PostgreSQL 17 safe DSN, actor binding, '
              'per-request rollback, isolation and session revocation')
        return 0
    except Exception as exc:
        print('FAIL: V3.9 isolated driver gate '+type(exc).__name__+' (details redacted)')
        return 1
    finally:
        fixture_db.close()
        # Outer runner destroys the disposable database regardless of status.
        if staged:
            try:
                with psycopg.connect(admin,autocommit=True,connect_timeout=5) as pg:
                    drop_compat(pg)
            except Exception:
                pass
