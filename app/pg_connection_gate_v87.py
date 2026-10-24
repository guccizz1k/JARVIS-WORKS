"""V8.7 independent credential / TLS / SET LOCAL ROLE integration gate.

Read-only, default-off. Requires two separate non-admin credential profiles
provisioned *outside* ChatGPT. Never displays DSNs, SQL errors, or user data.
No state change or operational cutover is performed.
"""
from __future__ import annotations

import os
from contextlib import closing
from typing import Callable

# Only role names from the reviewed V8.6 lineage and the verified V9.0
# least-privileged dev gateways are accepted. V8.6 roles are NOLOGIN in the
# actual dev database; rolcanlogin below rejects such accounts if supplied.
ALLOWED_GATEWAY_LOGINS = {
    'auth': frozenset(('jw_auth_login_v86', 'jw_auth_gateway_v90')),
    'trade': frozenset(('jw_trade_login_v86', 'jw_trade_gateway_v90')),
}

# The raw NOINHERIT login must not require jw_dev schema USAGE just to
# inspect direct grants. OID-based has_table_privilege() avoids regclass name
# resolution before SET LOCAL ROLE. No customer records or grants are read.
LOGIN_PROBE = """
SELECT session_user, current_user,
       (r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole) AS privileged,
       pg_has_role(session_user,'jw_auth_stage_v85','SET') AS can_auth,
       pg_has_role(session_user,'jw_app_dev','SET') AS can_trade,
       EXISTS (SELECT 1 FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p')
         AND (pg_catalog.has_table_privilege(session_user,c.oid,'SELECT')
         OR pg_catalog.has_table_privilege(session_user,c.oid,'INSERT')
         OR pg_catalog.has_table_privilege(session_user,c.oid,'UPDATE')
         OR pg_catalog.has_table_privilege(session_user,c.oid,'DELETE'))) AS direct_tables,
       (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AS ssl_active,
       current_setting('server_version_num')::integer / 10000 AS major,
       r.rolcanlogin AS can_login
FROM pg_roles r WHERE r.rolname=session_user
"""

ROLE_PROBE = """
SELECT current_user,
       has_table_privilege(current_user,'jw_dev.users','SELECT') AS users_read,
       has_table_privilege(current_user,'jw_dev.sessions','SELECT') AS sessions_read,
       has_table_privilege(current_user,'jw_dev.customers','SELECT') AS customers_read,
       has_table_privilege(current_user,'jw_dev.payments','INSERT') AS direct_payments_insert,
       has_function_privilege(current_user,'jw_dev.v85_auth_candidate(text)','EXECUTE') AS auth_candidate,
       has_function_privilege(current_user,'jw_dev.record_payment_v83(text,bigint,date,text,text)','EXECUTE') AS payment_rpc
"""


def _check_one(conn, *, kind: str) -> tuple[str | None, list[str]]:
    allowed_logins = ALLOWED_GATEWAY_LOGINS[kind]
    expected_stage = 'jw_auth_stage_v85' if kind == 'auth' else 'jw_app_dev'
    flags: list[str] = []
    # psycopg connection defaults to an implicit transaction; only SELECT and
    # transaction-scoped SET ROLE are used. Never commit or read table contents.
    with conn.cursor() as cur:
        cur.execute('SET TRANSACTION READ ONLY')
        cur.execute(LOGIN_PROBE)
        row = cur.fetchone()
        if not row or len(row) != 9:
            return None, ['login_metadata_missing']
        session_user, current_user, admin, can_auth, can_trade, direct, tls, major, can_login = row
        if (session_user not in allowed_logins or current_user != session_user
                or can_login is not True):
            flags.append('unexpected_login_identity')
        if admin or direct:
            flags.append('privilege_exposure')
        if bool(can_auth) != (kind == 'auth') or bool(can_trade) != (kind == 'trade'):
            flags.append('role_overlap_or_missing')
        if tls is not True or major != 17:
            flags.append('tls_or_postgres_mismatch')
        if flags:
            return None, flags
        # Literal, fixed role names only. No dynamic SQL from runtime inputs.
        cur.execute('SET LOCAL ROLE jw_auth_stage_v85' if kind == 'auth'
                    else 'SET LOCAL ROLE jw_app_dev')
        cur.execute(ROLE_PROBE)
        role = cur.fetchone()
        if not role or len(role) != 7 or role[0] != expected_stage:
            flags.append('set_local_role_failed')
        elif (role[1] or role[2] or role[4]
              or bool(role[3]) != (kind == 'trade')
              or bool(role[5]) != (kind == 'auth')
              or bool(role[6]) != (kind == 'trade')):
            flags.append('effective_role_permissions_wrong')
    return str(session_user), flags


def check_two_connections(*, connector: Callable | None = None, env: dict | None = None) -> dict:
    """Safe verdict only. Does not reveal connection secrets, role names or PII.

    Connection errors and database exceptions are intentionally redacted.
    This is strictly a preflight, never an authorization to enable production.
    """
    e = os.environ if env is None else env
    base = {'result': 'BLOCKED', 'production_cutover': False, 'checked': False}
    if (e.get('JW_PG_V87_CONNECT_GATE') != 'ISOLATED_DEV_ONLY'
        or e.get('JW_ENV', '').lower() not in ('development', 'dev', 'test')
        or e.get('JW_INSECURE_LOCAL_DEV') == '1'):
        return {**base, 'reason': 'Development-only connection gate not explicitly enabled'}
    auth = e.get('JW_PG_AUTH_STAGE_DSN')
    trade = e.get('JW_PG_STAGE_DSN')
    if not auth or not trade or auth == trade:
        return {**base, 'reason': 'Two distinct secret-managed DSNs required'}
    if connector is None:
        try:
            import psycopg
        except ImportError:
            return {**base, 'reason': 'PostgreSQL client unavailable'}
        connector = psycopg.connect
    flags = []
    identities = []
    for kind, dsn in [('auth', auth), ('trade', trade)]:
        try:
            with closing(connector(dsn, sslmode='verify-full', connect_timeout=5)) as db:
                identity, issues = _check_one(db, kind=kind)
                # Always roll back. SET LOCAL ROLE is automatically reset.
                db.rollback()
            flags.extend(issues)
            identities.append(identity)
        except Exception:
            flags.append('connection_or_tenant_role_failed')
            identities.append(None)
    if len(identities) == 2 and identities[0] == identities[1] and identities[0] is not None:
        flags.append('same_principal')
    if flags:
        return {**base, 'checked': True, 'failed_checks': sorted(set(flags))}
    return {'result': 'PASS', 'production_cutover': False, 'checked': True,
            'auth_boundary': 'PASS', 'trade_boundary': 'PASS', 'tls': 'PASS'}
