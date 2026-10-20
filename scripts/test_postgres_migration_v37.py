"""V3.7 real PG17 *synthetic-only* compatibility schema, RLS and rollback gate."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
import re
import secrets
import sys

from app.pg_migration_shadow_v36 import MigrationBlocked, source_records
from app.pg_migration_compat_v37 import (
    SCHEMA, TABLES, build_contract, stage_compat, verify_compat, drop_compat,
)
from scripts.v36_synthetic_fixture import fixture


def run():
    if os.getenv('JW_PG_ALLOW_TEST_WRITES')!='ONLY_EPHEMERAL_DATABASE' or os.getenv('JW_PG_LAB_V37')!='ONLY_DISPOSABLE_LAB':
        print('NOT RUN: V3.7 isolated test authorization absent');return 2
    admin_dsn=os.getenv('JW_PG_TEST_ADMIN_DSN','')
    app_dsn=os.getenv('JW_PG_TEST_APP_DSN','')
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        a,b=conninfo_to_dict(admin_dsn),conninfo_to_dict(app_dsn)
        if not (re.fullmatch(r'jw_v20_test_[a-f0-9]{12}',a.get('dbname',''))
                and a.get('dbname')==b.get('dbname')
                and a.get('user')=='postgres' and b.get('user')=='jw_app'
                and a.get('host') in ('127.0.0.1','::1','localhost')
                and b.get('host') in ('127.0.0.1','::1','localhost')
                and a.get('password') and b.get('password')):
            print('NOT RUN: V3.7 unsafe database connection refused');return 2
    except (ImportError,ValueError,TypeError):
        print('NOT RUN: psycopg3 or isolated DB connection missing');return 2
    db=fixture()
    try:
        records=source_records(db)
        build_contract(records)
        with psycopg.connect(admin_dsn,autocommit=True,connect_timeout=5) as pg:
            try:
                stage_compat(pg,records,inject_failure_after=2)
                raise AssertionError('Required forced failure not fired')
            except MigrationBlocked as ex:
                assert str(ex)=='Injected V3.7 rollback'
            with pg.cursor() as c:
                c.execute('SELECT to_regnamespace(%s)',(SCHEMA,))
                assert c.fetchone()==(None,), 'Rollback left partial operational schema'
            stage_compat(pg,records)
            verification=verify_compat(pg,records)
            assert verification['rows']==len(records) and len(verification['tables'])==7
            with pg.cursor() as c:
                c.execute('''SELECT relname, relrowsecurity, relforcerowsecurity
                       FROM pg_class JOIN pg_namespace ON pg_namespace.oid=relnamespace
                       WHERE nspname=%s AND relkind='r' ''',(SCHEMA,))
                state={name:(e,f) for name,e,f in c.fetchall()}
                assert set(state)==set(TABLES) and all(flags==(True,True) for flags in state.values())
                c.execute('''SELECT tablename,cmd,roles FROM pg_policies
                             WHERE schemaname=%s''',(SCHEMA,))
                policies={name:(cmd,roles) for name,cmd,roles in c.fetchall()}
                assert set(policies)==set(TABLES) and all(roles==['jw_app'] for _,roles in policies.values())
                for entity in TABLES:
                    c.execute('SELECT has_table_privilege(%s,%s,%s)',('jw_app',SCHEMA+'.'+entity,'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'))
                    assert c.fetchone()==(False,), 'App has mutation privilege'
            tokens={k:secrets.token_urlsafe(40) for k in ('tenant_a','tenant_b','tenant_c')}
            with pg.cursor() as c:
                for org,token in tokens.items():
                    c.execute('''INSERT INTO jw_guard.authenticated_sessions
                      (token_digest,org_id,user_id,mfa_verified,expires_at)
                      VALUES (%s,%s,%s,true,%s)''',
                      (sha256(token.encode()).digest(),org,{'tenant_a':'ua','tenant_b':'ub','tenant_c':'uc'}[org],
                       datetime.now(timezone.utc)+timedelta(minutes=20)))
            def read(org,table,column='id'):
                with psycopg.connect(app_dsn) as con:
                    with con.cursor() as c:
                        if org:
                            c.execute('SELECT jw_guard.bind_session(%s)',(tokens[org],))
                        c.execute(f'SELECT {column} FROM jw_migration_v37.{table}')
                        return c.fetchall()
            for org in ('tenant_a','tenant_b'):
                assert len(read(org,'messenger_messages'))==3
                assert len(read(org,'messenger_attachments', 'message_id'))==1
                assert len(read(org,'messenger_receipts','message_id'))==1
            assert read('tenant_c','messenger_messages')==[]
            assert read('tenant_c','messenger_attachments','message_id')==[]
            assert read(None,'messenger_messages')==[]
            assert read('tenant_a','messenger_read_positions','org_id')==[('tenant_a',)]
            assert read('tenant_b','messenger_read_positions','org_id')==[('tenant_b',)]
            assert read('tenant_c','messenger_read_positions','org_id')==[]
            assert len(read('tenant_a','messenger_companies','org_id'))==1
            assert len(read('tenant_b','messenger_companies','org_id'))==1
            # Even a legitimate tenant cannot mutate migrated evidence or read the company identity proof.
            with psycopg.connect(app_dsn) as con:
                with con.cursor() as c:
                    c.execute('SELECT jw_guard.bind_session(%s)',(tokens['tenant_a'],))
                    for attack in (
                      "UPDATE jw_migration_v37.messenger_messages SET body='forged' WHERE id='msg_text'",
                      "DELETE FROM jw_migration_v37.messenger_attachments WHERE message_id='msg_file'",
                      "SELECT business_number FROM jw_migration_v37.messenger_companies",
                    ):
                        c.execute('SAVEPOINT attack')
                        try:
                            c.execute(attack)
                            raise AssertionError('Forbidden migrated evidence operation succeeded')
                        except psycopg.Error as exc:
                            assert exc.sqlstate=='42501', 'Unexpected denial SQLSTATE'
                        c.execute('ROLLBACK TO SAVEPOINT attack')
            # DB constraint must reject byte corruption, not just Python compare.
            try:
                with pg.transaction():
                    with pg.cursor() as c:
                        c.execute("UPDATE jw_migration_v37.messenger_attachments SET data=%s WHERE message_id='msg_file'",(b'tamper',))
                raise AssertionError('Corrupted attachment accepted')
            except psycopg.Error as exc:
                assert exc.sqlstate=='23514', 'Expected length/hash CHECK violation'
            assert verify_compat(pg,records)['seal_sha256']==verification['seal_sha256']
            drop_compat(pg)
            with pg.cursor() as c:
                c.execute('SELECT to_regnamespace(%s)',(SCHEMA,))
                assert c.fetchone()==(None,), 'Synthetic schema cleanup incomplete'
        print('PASS: V3.7 real PostgreSQL 17 typed legacy semantics, exact readback, tenant RLS, immutable bytes and rollback')
        print('BLOCKED: Production FastAPI PostgreSQL cutover remains not implemented or approved')
        return 0
    except Exception as ex:
        # Avoid leaking schema rows, DSNs, session tokens, or private fields.
        print('FAIL: V3.7 PG17 rehearsal: '+type(ex).__name__+' (details redacted)',file=sys.stderr)
        return 1
    finally:
        db.close()

if __name__=='__main__':
    raise SystemExit(run())
