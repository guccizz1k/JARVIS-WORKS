"""V10.7 Render PG17 private-network, catalog-only least-privilege acceptance.

Offline until TWO separately provisioned restricted PostgreSQL login DSNs are
stored as Render secret environment values. This module NEVER serves HTTP,
never runs migrations, never reads business rows, never logs secrets and
does not use the Render database owner's credentials.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from psycopg import ProgrammingError
from psycopg.conninfo import conninfo_to_dict

from app.pg_full_shadow_v76 import EXPECTED_TABLES

ACK = "JW_V107_RENDER_PRIVATE_CATALOG_READ_ONLY"
EXPECTED_HOST = "dpg-dbeorinavr4c73bke6j0-a"
EXPECTED_DATABASE = "jw_isolated_stage_pg17_20261025"
EXPECTED_USERS = {"trade": "jw_trade_gateway_v90", "auth": "jw_auth_gateway_v90"}
STAGE_ROLES = {"trade": "jw_app_dev", "auth": "jw_auth_stage_v85"}
FIELDS = frozenset({"host", "port", "dbname", "user", "password", "sslmode", "connect_timeout"})
SCHEMA_SQL = """SELECT n.nspname,c.relname,c.relrowsecurity,c.relforcerowsecurity,
 c.relowner=pg_catalog.to_regrole(current_user)::oid OR
 pg_catalog.pg_has_role(current_user,c.relowner,'MEMBER') AS owner_role_access,
 CASE WHEN c.relname='payments' THEN
  pg_catalog.has_table_privilege(current_user,c.oid,'INSERT')
 ELSE FALSE END AS payment_insert
 FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p')
 ORDER BY c.relname"""
LOGIN_SQL = """SELECT session_user,current_user,r.rolcanlogin,r.rolinherit,
 r.rolsuper,r.rolbypassrls,r.rolcreaterole,r.rolcreatedb,r.rolreplication,
 current_setting('server_version_num')::integer/10000,
 current_setting('transaction_read_only'),
 (SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid())
 FROM pg_catalog.pg_roles r WHERE r.rolname=session_user"""


def valid_dsn(value: str, kind: str) -> bool:
    if kind not in EXPECTED_USERS or not isinstance(value, str):
        return False
    try:
        p = conninfo_to_dict(value)
        if not set(p).issubset(FIELDS):
            return False
        return (p.get("host") == EXPECTED_HOST
                and p.get("dbname") == EXPECTED_DATABASE
                and p.get("user") == EXPECTED_USERS[kind]
                and len(p.get("password", "")) >= 16
                and p.get("port", "5432") == "5432"
                and p.get("sslmode") in ("require", "verify-full")
                and 1 <= int(p.get("connect_timeout", "5")) <= 5)
    except (ValueError, TypeError, ProgrammingError):
        return False


def _inspection(connection: Any, kind: str) -> tuple[bool, str]:
    """Inspect two separate restricted raw logins in rollback-only transactions."""
    opposite = "auth" if kind == "trade" else "trade"
    try:
        with connection.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute(LOGIN_SQL)
            expected = (EXPECTED_USERS[kind], EXPECTED_USERS[kind],
                        True, False, False, False, False, False, False, 17, "on", True)
            if cur.fetchone() != expected:
                return False, "LOGIN_ATTRIBUTES_OR_TLS"
            cur.execute("""SELECT
              pg_catalog.pg_has_role(session_user,%s,'MEMBER'),
              pg_catalog.pg_has_role(session_user,%s,'SET'),
              pg_catalog.pg_has_role(session_user,%s,'MEMBER'),
              pg_catalog.pg_has_role(session_user,%s,'SET')""",
              (STAGE_ROLES[kind], STAGE_ROLES[kind],
               STAGE_ROLES[opposite], STAGE_ROLES[opposite]))
            if cur.fetchone() != (True, True, False, False):
                return False, "CROSS_ROLE_MEMBERSHIP"
            cur.execute("""SELECT EXISTS (
              SELECT 1 FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname IN ('jw_dev','public') AND c.relkind IN ('r','p')
              AND pg_catalog.has_table_privilege(session_user,c.oid,
              'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))""")
            if cur.fetchone() != (False,):
                return False, "RAW_TABLE_GRANT"
            cur.execute("SET LOCAL ROLE jw_app_dev" if kind == "trade"
                        else "SET LOCAL ROLE jw_auth_stage_v85")
            cur.execute("SELECT session_user,current_user")
            if cur.fetchone() != (EXPECTED_USERS[kind], STAGE_ROLES[kind]):
                return False, "STAGE_ROLE_DELEGATION"
            cur.execute(SCHEMA_SQL)
            rows = cur.fetchall()
            if (len(rows) != len(EXPECTED_TABLES)
                or {r[1] for r in rows} != EXPECTED_TABLES
                or any(len(r) != 6 or r[0] != "jw_dev"
                       or r[2] is not True or r[3] is not True
                       or r[4] is not False or r[5] is not False for r in rows)):
                return False, "SCHEMA_35_FORCE_RLS_OR_OWNER_MISMATCH"
            return True, "PASS"
    except Exception:
        return False, "CATALOG_QUERY_FAILED"
    finally:
        cleanup_failed = False
        try:
            connection.rollback()
        except Exception:
            cleanup_failed = True
        try:
            connection.close()
        except Exception:
            cleanup_failed = True
        if cleanup_failed:
            raise RuntimeError("DB_CONNECTION_CLEANUP_FAILED")


def check(*, env: Any = None, connector: Any = None) -> dict:
    e = os.environ if env is None else env
    verdict = {
        "decision": "BLOCKED",
        "scope": "RENDER_PRIVATE_PG17_CATALOG_ONLY",
        "read_only": True,
        "tenant_row_isolation": "NOT_RUN",
        "production_deployed": False,
        "external_db_exposure": False,
        "tls_hostname_verification": "NOT_ATTESTED",
    }
    if (e.get("JW_ENV") != "review"
        or e.get("JW_RENDER_PG_V107_ACK") != ACK
        or e.get("JW_RELEASE_APPROVED", "").lower() in ("true", "1", "yes")):
        return {**verdict, "reason": "REVIEW_MODE_NOT_APPROVED"}
    if any(k.startswith("PG") for k in e):
        return {**verdict, "reason": "AMBIENT_PG_CREDENTIALS"}
    trade = e.get("JW_RENDER_PG_TRADE_DSN", "")
    auth = e.get("JW_RENDER_PG_AUTH_DSN", "")
    if not trade or not auth:
        return {**verdict, "reason": "RESTRICTED_SECRET_DSNS_NOT_CONFIGURED"}
    if trade == auth or not valid_dsn(trade, "trade") or not valid_dsn(auth, "auth"):
        return {**verdict, "reason": "RESTRICTED_DSN_BOUNDARY_INVALID"}

    if connector is None:
        import psycopg
        def connector(dsn: str, *, kind: str):
            # Server requires encrypted TLS; Render's private connection does
            # NOT supply externally verifiable DNS identity. Never call this
            # 'verify-full'. That remains a separate deployment risk gate.
            return psycopg.connect(
                dsn, connect_timeout=5,
                options="-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000",
                application_name="jw_v107_render_catalog_only",
                gssencmode="disable",
            )

    result = {}
    for kind, dsn in (("trade", trade), ("auth", auth)):
        try:
            conn = connector(dsn, kind=kind)
        except Exception:
            return {**verdict, "reason": "PRIVATE_DB_CONNECTION_FAILED", "checked": result}
        try:
            success, reason = _inspection(conn, kind)
        except Exception:
            return {**verdict, "reason": "CONNECTION_CLEANUP_FAILED",
                    "checked": result}
        result[kind] = reason
        if not success:
            return {**verdict, "reason": reason, "checked": result}
    return {**verdict, "decision": "PASS", "reason": "TWO_ROLE_PG17_RLS_CATALOG_VERIFIED",
            "checked": result, "tls_transport": "ENCRYPTED", "tls_hostname_verification": "NOT_ATTESTED"}


def main() -> int:
    result = check()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["decision"] == "PASS" else 3


if __name__ == "__main__":
    sys.exit(main())
