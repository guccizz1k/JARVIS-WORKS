"""Read-only real database-role readiness for isolated Render HTTPS review.

A green deployment alone cannot establish actual Supavisor TLS, authentication,
role confinement, or FORCE RLS. This check runs on the Render service itself
using its stored DSNs; it does not insert fixtures or certify tenant isolation.
All failure messages are deliberately credential-free and fail closed.
"""
from __future__ import annotations

from app import pg_api_v84 as trade
from app import pg_auth_v85 as auth

_EXPECTED = (
    ("TRADE", trade._connect, "jw_stage1_trade_20261030", "jw_app_dev", (True, False)),
    ("AUTH", auth._connect, "jw_stage1_auth_20261030", "jw_auth_stage_v85", (False, True)),
)


def verify() -> tuple[bool, str]:
    """Check real login and catalog without accessing customer records or writing."""
    for label, open_db, login_name, role_name, membership in _EXPECTED:
        try:
            with open_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SET TRANSACTION READ ONLY")
                    cur.execute("""SELECT session_user, current_database(),
                        current_setting('server_version_num')::integer,
                        r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb,
                        pg_has_role(session_user, 'jw_app_dev', 'MEMBER'),
                        pg_has_role(session_user, 'jw_auth_stage_v85', 'MEMBER')
                        FROM pg_catalog.pg_roles r WHERE r.rolname=session_user""")
                    row = cur.fetchone()
                    if (not row or len(row) != 9 or row[0] != login_name
                        or row[1] != "postgres" or row[2] < 170000
                        or any(row[3:7]) or tuple(row[7:9]) != membership):
                        return False, label + "_LOGIN_ROLE_OR_MEMBERSHIP"
                    # Constant, reviewed role names: never client-provided SQL.
                    cur.execute("SET LOCAL ROLE " + role_name)
                    cur.execute("SELECT current_user")
                    if cur.fetchone() != (role_name,):
                        return False, label + "_DELEGATED_ROLE"
                    cur.execute("""SELECT count(*), count(*) FILTER (WHERE c.relrowsecurity
                              AND c.relforcerowsecurity)
                          FROM pg_catalog.pg_class c
                          JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                          WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p')""")
                    if cur.fetchone() != (35, 35):
                        return False, label + "_FORCED_RLS_CATALOG"
        except Exception:
            # Never log an exception: a connection driver may embed a DSN.
            return False, label + "_TLS_CONNECT_OR_QUERY"
    return True, "BOTH_SEPARATE_REAL_ROLE_CONNECTIONS"
