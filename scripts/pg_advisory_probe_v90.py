"""Read-only two-connection Postgres advisory-lock probe for isolated V9.0 staging.

This tests transaction-scoped lock semantics, not full messenger RPC integration.
Never pass a production DSN, and never count fake/mock tests as live Postgres E2E.
Requires explicit JW_V90_ISOLATED_PG_DSN and JW_V90_ISOLATED_PG_APPROVED=yes.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

LOCK_SQL = "SELECT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('jw_dev.v90.messenger/' || %s, 0))"
ROLE_SQL = "SELECT rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user"


def query_bool(conn: Any, sql: str, arg: str | None = None) -> bool:
    with conn.cursor() as cur:
        cur.execute(sql, (arg,) if arg is not None else ())
        row = cur.fetchone()
        if row is None:
            raise RuntimeError('Database verification returned no rows')
        return bool(row[0])


def assert_nonprivileged(conn: Any) -> None:
    with conn.cursor() as cur:
        cur.execute(ROLE_SQL)
        row = cur.fetchone()
    if not row or bool(row[0]) or bool(row[1]):
        raise PermissionError('Superuser/BYPASSRLS/unknown roles are not permitted')


def probe(connect: Any) -> dict[str, bool]:
    """Independent connections; no table writes, role changes, or production commands."""
    a = connect()
    try:
        b = connect()
        try:
            # Psycopg starts an implicit transaction on the first SELECT by
            # default. Without autocommit, the subsequent transaction() blocks
            # are nested savepoints and DO NOT release advisory transaction
            # locks when they exit. Set this before any role/security query.
            a.autocommit = True
            b.autocommit = True
            assert_nonprivileged(a)
            assert_nonprivileged(b)
            with a.transaction():
                assert query_bool(a, LOCK_SQL, 'isolated-v90-conversation-A')
                with b.transaction():
                    # B cannot concurrently acquire A's conversation lock.
                    blocked = not query_bool(b, LOCK_SQL, 'isolated-v90-conversation-A')
                    unrelated = query_bool(b, LOCK_SQL, 'isolated-v90-conversation-B')
            with b.transaction():
                available_after_commit = query_bool(b, LOCK_SQL, 'isolated-v90-conversation-A')
            if not (blocked and unrelated and available_after_commit):
                raise AssertionError('Per-conversation transaction locking contract failed')
            return {'second_connection_blocked': blocked,
                    'other_chat_unblocked': unrelated,
                    'commit_releases_lock': available_after_commit}
        finally:
            b.close()
    finally:
        a.close()


def main() -> int:
    dsn = os.environ.get('JW_V90_ISOLATED_PG_DSN')
    approved = os.environ.get('JW_V90_ISOLATED_PG_APPROVED') == 'yes'
    if not dsn or not approved:
        print(json.dumps({'status':'BLOCKED','reason':'Approved isolated DB DSN is not available',
                          'live_postgres_test':'NOT RUN'}))
        return 2
    try:
        import psycopg
    except ImportError:
        print(json.dumps({'status':'BLOCKED','reason':'psycopg driver unavailable',
                          'live_postgres_test':'NOT RUN'}))
        return 2
    try:
        result = probe(lambda: psycopg.connect(dsn, connect_timeout=5))
        print(json.dumps({'status':'PASS','scope':'PG_ADVISORY_LOCK_SEMANTICS_ONLY',
                          'result':result}))
        return 0
    except Exception as exc:
        # No secret / DSN in diagnostics; no retry or fallback to privileged DB.
        print(json.dumps({'status':'FAIL','reason':type(exc).__name__,
                          'scope':'PG_ADVISORY_LOCK_SEMANTICS_ONLY'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
