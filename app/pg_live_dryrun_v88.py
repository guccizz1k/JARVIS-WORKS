"""V8.8 live connection and PostgreSQL lock-primitive drill (default OFF).

This does NOT execute payments, write business data, or certify a cutover.
It requires independent pre-provisioned TLS credentials for the authentication
and trading DB principals. Never send credentials to the chat or logs.
"""
from __future__ import annotations

import os
from typing import Callable

from .pg_connection_gate_v87 import check_two_connections

# Fixed, namespaced advisory lock keys; transaction-scoped and automatically
# released on rollback. This is a concurrency *primitive* drill, NOT an actual
# payment row-lock or double-spend test.
_LOCK_KEY = (872688, 20261023)


def live_gate_v88(*, connector: Callable | None = None, env: dict | None = None) -> dict:
    e = os.environ if env is None else env
    denied = {'result': 'BLOCKED', 'production_cutover': False,
              'payment_race_e2e': 'NOT_RUN', 'login_mfa_e2e': 'NOT_RUN'}
    if (e.get('JW_PG_V88_LIVE_GATE') != 'ISOLATED_DEV_ONLY'
            or e.get('JW_ENV', '').lower() not in {'dev', 'development', 'test'}
            or e.get('JW_INSECURE_LOCAL_DEV') == '1'):
        return {**denied, 'reason': 'Dev-only live gate not enabled'}
    auth_dsn = e.get('JW_PG_AUTH_STAGE_DSN')
    trade_dsn = e.get('JW_PG_STAGE_DSN')
    if not auth_dsn or not trade_dsn or auth_dsn == trade_dsn:
        return {**denied, 'reason': 'Distinct secret-managed database logins required'}
    if connector is None:
        try:
            import psycopg
        except ImportError:
            return {**denied, 'reason': 'PostgreSQL driver unavailable'}
        connector = psycopg.connect

    # Reuse and require the V8.7 proof of independent non-admin login,
    # TLS, force-RLS effective privileges, and role separation.
    safe_env = dict(e)
    safe_env['JW_PG_V87_CONNECT_GATE'] = 'ISOLATED_DEV_ONLY'
    proof = check_two_connections(connector=connector, env=safe_env)
    if proof.get('result') != 'PASS':
        return {**denied, 'reason': 'V8.7 connection boundary not verified'}

    first = second = None
    try:
        first = connector(trade_dsn, sslmode='verify-full', connect_timeout=5)
        second = connector(trade_dsn, sslmode='verify-full', connect_timeout=5)
        for conn in (first, second):
            with conn.cursor() as cur:
                cur.execute('SET TRANSACTION READ ONLY')
                cur.execute('SET LOCAL ROLE jw_app_dev')

        with first.cursor() as a, second.cursor() as b:
            a.execute('SELECT pg_backend_pid(),current_user,session_user')
            b.execute('SELECT pg_backend_pid(),current_user,session_user')
            left, right = a.fetchone(), b.fetchone()
            if (not left or not right or left[0] == right[0]
                    or left[1:] != ('jw_app_dev', 'jw_trade_login_v86')
                    or right[1:] != ('jw_app_dev', 'jw_trade_login_v86')):
                return {**denied, 'reason': 'Independent backend identities not verified'}
            a.execute('SELECT pg_try_advisory_xact_lock(%s,%s)', _LOCK_KEY)
            if a.fetchone() != (True,):
                return {**denied, 'reason': 'First transactional lock unavailable'}
            b.execute('SELECT pg_try_advisory_xact_lock(%s,%s)', _LOCK_KEY)
            if b.fetchone() != (False,):
                return {**denied, 'reason': 'Concurrent lock not isolated'}
            # The first rollback MUST free its transaction-scoped lock, while
            # the second connection remains in its separate transaction.
            first.rollback()
            b.execute('SELECT pg_try_advisory_xact_lock(%s,%s)', _LOCK_KEY)
            if b.fetchone() != (True,):
                return {**denied, 'reason': 'Transactional lock was not released'}
        return {'result': 'PASS', 'production_cutover': False,
                'scope': 'INDEPENDENT_TLS_ROLES_AND_ADVISORY_LOCK_ONLY',
                'separate_db_backends': True, 'lock_contention': 'PASS',
                'lock_release_on_rollback': 'PASS',
                'payment_race_e2e': 'NOT_RUN', 'login_mfa_e2e': 'NOT_RUN'}
    except Exception:
        # No traceback, SQL error or DSN in public output.
        return {**denied, 'reason': 'Live probe failed (details suppressed)'}
    finally:
        for conn in (first, second):
            if conn is not None:
                try:
                    conn.rollback()
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
