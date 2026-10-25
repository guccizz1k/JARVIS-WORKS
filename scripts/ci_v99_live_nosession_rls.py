"""Actual Supabase no-session RLS denial, read-only and rollback-verified.

A missing session is NOT a substitute for adversarial valid A/B/C users.
No customer identifiers, rows, sensitive query results or credentials in logs.
"""
from __future__ import annotations
import json
import os
import secrets
from contextlib import closing
from scripts import ci_v97_supavisor_restricted_auth as gate

TABLES = ("customers", "quotes", "quote_items", "orders", "order_items",
          "invoices", "invoice_items", "payments",
          "messenger_connections", "messenger_messages")
ACK = "READ_ONLY_V99_NONSESSION_RLS"


class Denied(Exception):
    """Fixed, nonsensitive error code only."""


def validate_result(*, environ=None, connector=None) -> dict:
    env = os.environ if environ is None else environ
    base = {"decision":"BLOCKED","scope":"REAL_DB_UNKNOWN_SESSION_READONLY",
            "authenticated":False, "cross_tenant_abc":"NOT_VERIFIED",
            "writes":False,"rollback":"NOT_VERIFIED","tested_tables":0,
            "production_cutover":False}
    if env.get("JW_ENV") != "review" or env.get("JW_V99_RLS_ACK") != ACK:
        return {**base, "reason":"REVIEW_READONLY_OPT_IN_REQUIRED"}
    dsn = env.get("JW_V97_TRADE_DSN","")
    if not gate.trusted_ca() or not gate.valid_dsn(dsn,"trade"):
        return {**base,"reason":"TLS_OR_TRADE_DSN_MISSING"}
    if any(k.startswith("PG") for k in env) or (
        connector is None and any(k.startswith("PG") for k in os.environ)
    ):
        return {**base,"reason":"AMBIENT_LIBPQ_OVERRIDE"}
    if connector is None:
        import psycopg
        def connector(dsn):
            return psycopg.connect(
                dsn,sslmode="verify-full",sslrootcert=str(gate.CA),
                connect_timeout=5,gssencmode="disable",
                application_name="jw_v99_rls_no_session_readonly",
                options="-c default_transaction_read_only=on -c statement_timeout=5000 "
                        "-c lock_timeout=1000 -c idle_in_transaction_session_timeout=10000")
    reason = None
    completed = False
    rolled_back = False
    try:
        with closing(connector(dsn)) as connection:
            try:
                with connection.cursor() as cur:
                    cur.execute("SET TRANSACTION READ ONLY")
                    cur.execute("SELECT session_user, current_setting('server_version_num')::integer / 10000")
                    if cur.fetchone() != ("jw_trade_gateway_v90",17):
                        raise Denied("WRONG_LOGIN_OR_PG")
                    cur.execute("SET LOCAL ROLE jw_app_dev")
                    cur.execute("SELECT current_user")
                    if cur.fetchone() != ("jw_app_dev",):
                        raise Denied("STAGE_ROLE_NOT_APPLIED")
                    invalid_hash = secrets.token_hex(32)
                    cur.execute("SELECT pg_catalog.set_config('jw.session_hash', %s, true)",(invalid_hash,))
                    cur.execute("SELECT jw_dev.current_org_from_session()")
                    if cur.fetchone() != (None,):
                        raise Denied("INVALID_SESSION_BECAME_TENANT")
                    for table in TABLES:
                        # Identifiers are a private fixed tuple, never user input.
                        cur.execute("SELECT count(*) FROM jw_dev."+table)
                        if cur.fetchone() != (0,):
                            raise Denied("INVALID_SESSION_EXPOSED_ROWS")
                    completed = True
            except Denied as e:
                reason = str(e)
            except Exception:
                reason = "QUERY_OR_PERMISSION_FAILED"
            finally:
                try:
                    connection.rollback()
                    rolled_back = True
                except Exception:
                    reason = "ROLLBACK_FAILED"
    except Exception:
        reason = "CONNECT_OR_CLOSE_FAILED"
    if not completed or not rolled_back or reason:
        return {**base,"reason":reason or "PROBE_INCOMPLETE",
                "rollback":"PASS" if rolled_back else "NOT_VERIFIED"}
    return {**base, "decision":"PASS","reason":"MISSING_SESSION_CANNOT_SEE_ROWS",
            "authenticated":True, "tested_tables":len(TABLES),
            "rollback":"PASS"}


if __name__ == "__main__":
    print(json.dumps(validate_result(),sort_keys=True))
