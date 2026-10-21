"""Real disposable PostgreSQL 17 roster/tenant/RLS identity audit, V5.0.

All accounts and tokens are synthetic; independent of the user's B2B service.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
import secrets
import sqlite3
import sys


def run() -> int:
    if (os.getenv('JW_ENV','').casefold()=='production'
        or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
        or os.getenv('JW_PG_ALLOW_TEST_WRITES')!='ONLY_EPHEMERAL_DATABASE'
        or any(os.getenv(f'JW_PG_LAB_V{v}')!='ONLY_DISPOSABLE_LAB' for v in range(35,49))
        or os.getenv('JW_PG_LAB_V50')!='ONLY_DISPOSABLE_LAB'):
        print('NOT RUN: V5.0 disposable PG17 flags not authorized')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from scripts.test_postgres_writer_v40 import _verified_lab_uri
        from app.pg_messenger_review import MessengerReviewAdapter
        from app.pg_identity_audit_v50 import ActorLink, IdentityAuditBlocked, audit_roster
        admin_dsn=os.environ['JW_PG_TEST_ADMIN_DSN']
        app_dsn=os.environ['JW_PG_TEST_APP_DSN']
        lab_uri=_verified_lab_uri(conninfo_to_dict(admin_dsn),conninfo_to_dict(app_dsn))
        adapter=MessengerReviewAdapter(lab_uri)
        adapter._check_dsn()
    except (ImportError,ValueError,KeyError,RuntimeError,TypeError):
        print('NOT RUN: disposable PG17 connection or dependencies absent')
        return 2
    stage='seed-synthetic-actors'
    sqlite_db=sqlite3.connect(':memory:')
    tokens=(secrets.token_urlsafe(48),secrets.token_urlsafe(48))
    links=(ActorLink('v50_wa','v50_wua','v50_pa','v50_pua'),
           ActorLink('v50_wb','v50_wub','v50_pb','v50_pub'))
    try:
        sqlite_db.executescript('''CREATE TABLE users(id text PRIMARY KEY,org_id text NOT NULL);
           CREATE TABLE staff_disabled(user_id text PRIMARY KEY);
           INSERT INTO users VALUES('v50_wua','v50_wa'),('v50_wub','v50_wb');''')
        with psycopg.connect(admin_dsn,connect_timeout=5) as pg:
            with pg.cursor() as cur:
                cur.execute("INSERT INTO public.organizations(id,name) VALUES ('v50_pa','V50 A'),('v50_pb','V50 B')")
                cur.execute("INSERT INTO public.users(id,org_id,password_hash) VALUES ('v50_pua','v50_pa','synthetic'),('v50_pub','v50_pb','synthetic')")
                for index,link in enumerate(links):
                    cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                       (token_digest,org_id,user_id,mfa_verified,expires_at)
                       VALUES (%s,%s,%s,true,%s)''',
                       (sha256(tokens[index].encode()).digest(),link.pg_org,link.pg_user,
                        datetime.now(timezone.utc)+timedelta(minutes=10)))
        stage='signed-actor-two-tenant-parity'
        with psycopg.connect(admin_dsn,connect_timeout=5) as pg:
            evidence=audit_roster(sqlite_db,pg,adapter,links,tokens)
            assert (evidence['decision']=='BLOCKED' and evidence['synthetic_only']
                and evidence['cutover_approved'] is False
                and evidence['verified_fixture_tenants']==2
                and evidence['verified_fixture_links']==2)
            stage='wrong-tenant-identity-collision'
            try:
                audit_roster(sqlite_db,pg,adapter,
                             (links[0],replace(links[1],pg_org=links[0].pg_org)),tokens)
            except IdentityAuditBlocked:
                pass
            else:
                raise AssertionError('Unexpected cross-tenant authorization')
            stage='website-employee-deactivation'
            sqlite_db.execute("INSERT INTO staff_disabled VALUES('v50_wua')")
            try:
                audit_roster(sqlite_db,pg,adapter,links,tokens)
            except IdentityAuditBlocked:
                pass
            else:
                raise AssertionError('Disabled synthetic employee not denied')
            sqlite_db.execute('DELETE FROM staff_disabled')
        stage='pg-verified-token-revocation'
        with psycopg.connect(admin_dsn,connect_timeout=5) as pg:
            with pg.cursor() as cur:
                cur.execute('''UPDATE jw_guard.authenticated_sessions
                   SET revoked_at=clock_timestamp() WHERE token_digest=%s''',
                   (sha256(tokens[0].encode()).digest(),))
                assert cur.rowcount==1
        with psycopg.connect(admin_dsn,connect_timeout=5) as pg:
            try:
                audit_roster(sqlite_db,pg,adapter,links,tokens)
            except IdentityAuditBlocked:
                pass
            else:
                raise AssertionError('Revoked synthetic token still accepted')
        print('PASS: V5.0 disposable PG17 two-sided synthetic employee binding, RLS signature, disablement and revocation')
        print('BLOCKED: operational identity mapping, dual-write and production cutover remain unverified')
        return 0
    except Exception as exc:
        print('FAIL: V5.0 stage='+stage+' type='+type(exc).__name__+' (credentials and identity values redacted)',file=sys.stderr)
        return 1
    finally:
        sqlite_db.close()
        # Parent V2.8 supervisor exclusively owns and drops the whole ephemeral
        # PostgreSQL database; no privileged cleanup touches operational DBs.

if __name__=='__main__':
    raise SystemExit(run())
