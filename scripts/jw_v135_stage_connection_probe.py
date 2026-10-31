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


def _failure_code(exc: Exception) -> str:
    """Reduce psycopg failures to vetted labels; never disclose exception text."""
    code = getattr(exc, "sqlstate", None)
    if code in ("28P01", "28000"):
        return "AUTHENTICATION_REJECTED"
    if code == "42501":
        return "PG_ROLE_PERMISSION"
    if code == "3D000":
        return "PG_DATABASE_NOT_FOUND"
    # Match static substrings in memory; log ONLY a fixed label.
    detail = str(exc).lower()
    patterns = (
        ("password authentication failed", "AUTHENTICATION_REJECTED"),
        ("tenant or user not found", "POOLER_USER_REJECTED"),
        ("invalid user", "POOLER_USER_REJECTED"),
        ("could not translate host name", "DNS_RESOLUTION"),
        ("name or service not known", "DNS_RESOLUTION"),
        ("certificate verify failed", "TLS_CERTIFICATE"),
        ("certificate verify", "TLS_CERTIFICATE"),
        ("ssl certificate", "TLS_CERTIFICATE"),
        ("timeout expired", "NETWORK_TIMEOUT"),
        ("connection timed out", "NETWORK_TIMEOUT"),
        ("connection refused", "NETWORK_REFUSED"),
        ("server closed the connection unexpectedly", "SERVER_DISCONNECTED"),
        ("permission denied", "PG_ROLE_PERMISSION"),
        ("not permitted to set role", "PG_ROLE_PERMISSION"),
        ("no such host", "DNS_RESOLUTION"),
    )
    for needle, label in patterns:
        if needle in detail:
            return label
    return "PG_CONNECT_OR_QUERY_OTHER"


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
                    if cur.fetchone() != (40, 40):
                        return False, label + "_FORCED_RLS_CATALOG"
                    # The DEV approval added five immutable review tables.
                    # Require their complete exact set, all FORCE RLS; never
                    # silently treat a missing/unsafe table as an acceptable
                    # general schema count change.
                    cur.execute("""SELECT count(*), count(*) FILTER
                          (WHERE c.relrowsecurity AND c.relforcerowsecurity)
                        FROM pg_catalog.pg_class c
                        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                        WHERE n.nspname='jw_dev' AND c.relkind='r'
                        AND c.relname IN (
                          'review_signup_requests_v151',
                          'review_signup_nonces_v151',
                          'review_delivery_receipts_v151',
                          'review_delivery_nonces_v151',
                          'review_delivery_items_v151'
                        )""")
                    if cur.fetchone() != (5, 5):
                        return False, label + "_REVIEW_LEDGER_FORCED_RLS"
                    cur.execute("""SELECT rolcanlogin, rolbypassrls
                          FROM pg_catalog.pg_roles
                          WHERE rolname='jw_delivery_writer_v159'""")
                    if cur.fetchone() != (False, False):
                        return False, label + "_WRITER_ROLE_UNSAFE"
                    cur.execute("""SELECT
                        pg_catalog.has_table_privilege('jw_app_dev',
                           'jw_dev.review_delivery_receipts_v151','INSERT'),
                        pg_catalog.has_table_privilege('anon',
                           'jw_dev.review_delivery_receipts_v151','INSERT'),
                        pg_catalog.has_table_privilege('authenticated',
                           'jw_dev.review_delivery_receipts_v151','INSERT')""")
                    if cur.fetchone() != (False, False, False):
                        return False, label + "_REVIEW_DIRECT_WRITE_GRANT"
        except Exception as exc:
            # Never log raw exceptions: drivers may embed a connection URI.
            return False, label + "_" + _failure_code(exc)
    return True, "BOTH_SEPARATE_REAL_ROLE_CONNECTIONS"
