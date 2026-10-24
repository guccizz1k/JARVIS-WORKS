"""Real two-session V9 advisory semantics on disposable CI PG17 ONLY.

This does not install the V9 messenger RPC or claim live tenant E2E.
No production/shared DB connections, SQL migration, customer data or secrets.
"""
from __future__ import annotations

import json
import os
import secrets
import sys

from scripts.pg_advisory_probe_v90 import LOCK_SQL, assert_nonprivileged, probe, query_bool


def main() -> int:
    if os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE':
        print('BLOCKED: explicit disposable PostgreSQL 17 CI flag required')
        return 2
    try:
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
    except ImportError:
        print('BLOCKED: missing psycopg v3')
        return 2

    root_dsn = os.getenv('JW_PG_CI_ROOT_DSN', '')
    try:
        opts = conninfo_to_dict(root_dsn)
    except Exception:
        print('BLOCKED: invalid CI connection configuration')
        return 2
    if (opts.get('host') not in ('localhost', '127.0.0.1')
            or opts.get('dbname') != 'postgres'
            or opts.get('user') != 'postgres' or not opts.get('password')):
        print('BLOCKED: only local ephemeral postgres CI supervisor is allowed')
        return 2

    role = 'jw_v90_probe_' + secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    root = None
    created = False
    error = None
    outcome = None
    try:
        root = psycopg.connect(root_dsn, autocommit=True, connect_timeout=5)
        with root.cursor() as cur:
            cur.execute('SELECT current_user, current_database(), '
                        "current_setting('server_version_num')::integer / 10000")
            if cur.fetchone() != ('postgres', 'postgres', 17):
                raise PermissionError('Only fresh PostgreSQL 17 local runner supported')
            cur.execute("SELECT datname FROM pg_database WHERE NOT datistemplate AND datname <> 'postgres'")
            if cur.fetchone():
                raise PermissionError('Refusing DB server with other databases')
            cur.execute("SELECT rolname FROM pg_roles WHERE rolname <> 'postgres' AND rolname !~ '^pg_'")
            if cur.fetchone():
                raise PermissionError('Refusing DB server with existing nonstandard roles')
            cur.execute("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m')")
            if cur.fetchone():
                raise PermissionError('Refusing shared database with existing objects')
            cur.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB')
                        .format(sql.Identifier(role), sql.Literal(secret)))
            created = True

        dsn = make_conninfo(root_dsn, user=role, password=secret)
        factory = lambda: psycopg.connect(dsn, connect_timeout=5)
        # Reuse the previously reviewed V9 lock probe: it enforces autocommit
        # BEFORE privileged-role checks, ensuring the transaction closes cleanly.
        outcome = probe(factory)
        if not all(outcome.values()):
            raise AssertionError('Not all two-session advisory checks passed')

        a, b = factory(), factory()
        try:
            a.autocommit = b.autocommit = True
            assert_nonprivileged(a)
            assert_nonprivileged(b)
            with a.cursor() as cur:
                cur.execute('SELECT pg_backend_pid()')
                pid_a = cur.fetchone()[0]
            with b.cursor() as cur:
                cur.execute('SELECT pg_backend_pid()')
                pid_b = cur.fetchone()[0]
            if pid_a == pid_b:
                raise AssertionError('Connections not backed by distinct PG sessions')

            # Rollback must also free the lock. Never write to a business table.
            class DeliberateRollback(Exception):
                pass
            try:
                with a.transaction():
                    if not query_bool(a, LOCK_SQL, 'ci-rollback-' + role):
                        raise AssertionError('Could not claim uncontended lock')
                    raise DeliberateRollback()
            except DeliberateRollback:
                pass
            with b.transaction():
                if not query_bool(b, LOCK_SQL, 'ci-rollback-' + role):
                    raise AssertionError('Rollback did not release the advisory lock')
            outcome['rollback_releases_lock'] = True
            outcome['distinct_pg_backends'] = True
        finally:
            b.close()
            a.close()
    except Exception as exc:
        error = exc
    finally:
        if root is not None:
            try:
                if created:
                    with root.cursor() as cur:
                        cur.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))
            except Exception as exc:
                error = error or exc
            finally:
                root.close()
    if error is not None:
        print('FAIL: ephemeral PG probe or cleanup failed:', type(error).__name__)
        return 1
    print(json.dumps({'status':'PASS',
                      'scope':'EPHEMERAL_PG17_TWO_SESSIONS_ADVISORY_SEMANTICS_ONLY',
                      'checks':outcome,'v9_messenger_rpc_e2e':False}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
