"""V2.8: provision + attack + destroy a throwaway PostgreSQL *local* CI database.

Requires an EXPLICIT guard and LOCAL PG root DSN. Never accepts production data.
The runner creates a new PostgreSQL DB and role in the ephemeral service,
exercises the catalog audit and attack suite, and cleans up on every path.
Exit code 2 means NOT RUN, 1 FAIL, 0 PASS. No real credentials are printed.
"""
from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path


def main():
    root_dsn = os.getenv('JW_PG_CI_ROOT_DSN', '')
    if (os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'
            or not root_dsn):
        print('NOT RUN: CI-only local PostgreSQL consent/DSN missing')
        return 2
    try:
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
    except ImportError:
        print('NOT RUN: psycopg[binary] unavailable')
        return 2
    opts = conninfo_to_dict(root_dsn)
    if (opts.get('host', '') not in ('localhost', '127.0.0.1', '::1')
            or opts.get('dbname', '') not in ('postgres', 'template1')
            or opts.get('user') != 'postgres'
            or not opts.get('password')):
        print('NOT RUN: refused nonlocal, non-supervisor, or ambiguous DSN')
        return 2

    root = None
    db = None
    created_role = False
    created_db = False
    success_marker = False
    name = 'jw_v20_test_' + secrets.token_hex(6)
    password = secrets.token_urlsafe(32)
    try:
        root = psycopg.connect(root_dsn, autocommit=True, connect_timeout=5)
        with root.cursor() as cur:
            cur.execute('SELECT current_database(), current_user, rolsuper FROM pg_roles '
                        'JOIN (SELECT current_user AS name) me ON me.name=rolname '
                        'WHERE rolname=current_user')
            row = cur.fetchone()
            if row != (opts['dbname'], 'postgres', True):
                print('NOT RUN: refused non-ephemeral/non-admin server')
                return 2
            cur.execute('SHOW server_version_num')
            version = int(cur.fetchone()[0])
            if version // 10000 != 17:
                print('NOT RUN: isolated PostgreSQL 17 is required for this gate')
                return 2
            print('DB_ENGINE: PostgreSQL 17; test cluster only')
            # Never provision a global role on a shared developer/production PG
            # instance. The service must look like a freshly initialized CI DB.
            cur.execute("SELECT datname FROM pg_database WHERE NOT datistemplate AND datname <> 'postgres'")
            if cur.fetchone():
                print('NOT RUN: non-template databases exist; refused shared server')
                return 2
            cur.execute("SELECT rolname FROM pg_roles WHERE rolname <> 'postgres' AND rolname !~ '^pg_'")
            if cur.fetchone():
                print('NOT RUN: nonstandard roles exist; refused shared server')
                return 2
            cur.execute("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE n.nspname='public' AND c.relkind IN ('r','p','m','v')")
            if cur.fetchone():
                print('NOT RUN: public objects exist in postgres DB; refused shared server')
                return 2
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname='jw_app'")
            if cur.fetchone():
                print('NOT RUN: jw_app role preexists; refused shared server')
                return 2
            # Test-only credentials are randomly generated and kept in memory.
            cur.execute(sql.SQL('CREATE ROLE jw_app LOGIN PASSWORD {} NOSUPERUSER '
                                'NOBYPASSRLS NOCREATEROLE NOCREATEDB').format(sql.Literal(password)))
            created_role = True
            cur.execute(sql.SQL('CREATE DATABASE {} TEMPLATE template0').format(sql.Identifier(name)))
            created_db = True
        admin_dsn = make_conninfo(root_dsn, dbname=name)
        app_dsn = make_conninfo(root_dsn, dbname=name, user='jw_app', password=password)
        db = psycopg.connect(admin_dsn, autocommit=True)
        with db.cursor() as cur:
            # Only checked-in synthetic fixture. Every script aborts outside test DB.
            cur.execute(Path('security/pg_rls_test_fixture.sql').read_text())
            cur.execute(Path('security/postgres_rls_proposal.sql').read_text())
        from scripts.check_postgres_rls import audit
        issues = audit(db)
        if issues:
            raise AssertionError('Catalog RLS gate failed: ' + '; '.join(issues))
        from scripts.test_postgres_rls_runtime import run as attack_run
        os.environ['JW_PG_TEST_ADMIN_DSN'] = admin_dsn
        os.environ['JW_PG_TEST_APP_DSN'] = app_dsn
        os.environ['JW_PG_ALLOW_TEST_WRITES'] = 'ONLY_EPHEMERAL_DATABASE'
        if attack_run() != 0:
            raise AssertionError('Cross-tenant attack suite failed')
        # V2.7: review-only messenger RLS add-on, strictly AFTER legacy attacks.
        # This still does NOT connect the SQLite production-facing app to PG.
        with db.cursor() as cur:
            cur.execute(Path('security/postgres_messenger_rls_v27.sql').read_text())
        from scripts.test_postgres_messenger_v27 import run as messenger_attack_run
        if messenger_attack_run() != 0:
            raise AssertionError('V2.7 isolated messenger cross-tenant gate failed')
        # The historical V2.7 synthetic attack uses a placeholder digest and
        # attaches it to a text message. Normalize only this known disposable
        # fixture before testing the stricter V2.8 migration preflight.
        # Never perform evidence rewrites in an actual organization database.
        with db.cursor() as cur:
            cur.execute("UPDATE public.messenger_messages SET kind='attachment' "
                        "WHERE id='ab_two' AND kind='text'")
            if cur.rowcount != 1:
                raise AssertionError('Synthetic legacy V2.7 message fixture mismatch')
            cur.execute("UPDATE public.messenger_attachments "
                        "SET content_hash=encode(public.digest(data,'sha256'),'hex') "
                        "WHERE message_id='ab_two' AND content_hash='sha256-demo'")
            if cur.rowcount != 1:
                raise AssertionError('Synthetic legacy V2.7 hash fixture mismatch')
            cur.execute(Path('security/postgres_messenger_rls_v28_hardening.sql').read_text())
        from scripts.test_postgres_messenger_v28 import run as v28_attack_run
        if v28_attack_run() != 0:
            raise AssertionError('V2.8 isolated attachment/read integrity gate failed')
        success_marker = True
        return 0
    except Exception as exc:
        print('FAIL: PG live test did not complete: ' + type(exc).__name__
              + '; details suppressed to prevent credential disclosure', file=sys.stderr)
        return 1
    finally:
        if db:
            db.close()
        cleanup_failed = False
        if root:
            # No real company DB is ever dropped. Our only target is a randomly
            # minted jw_v20_test_* DB created by THIS invocation.
            try:
                with root.cursor() as cur:
                    if created_db:
                        cur.execute(sql.SQL('DROP DATABASE IF EXISTS {} WITH (FORCE)').format(sql.Identifier(name)))
                    if created_role:
                        cur.execute('DROP ROLE IF EXISTS jw_app')
            except Exception as exc:
                cleanup_failed = True
                print('FAIL: ephemeral cleanup failed: '+type(exc).__name__,file=sys.stderr)
            finally:
                root.close()
        os.environ.pop('JW_PG_TEST_ADMIN_DSN',None)
        os.environ.pop('JW_PG_TEST_APP_DSN',None)
        os.environ.pop('JW_PG_ALLOW_TEST_WRITES',None)
        # Clean teardown is a required part of a PASS; never report success
        # when a throwaway database/role could remain after the test.
        if cleanup_failed:
            return 1
        if success_marker:
            print('PASS: ephemeral PG legacy + V2.7 + V2.8 integrity attacks; cleanup confirmed')


if __name__ == '__main__':
    raise SystemExit(main())
