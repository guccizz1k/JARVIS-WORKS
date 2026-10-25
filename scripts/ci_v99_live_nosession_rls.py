"""Real Supabase denied-session RLS probe, isolated read-only and fail-closed.

This is *not* a cross-company A/B/C row test: it tests missing/invalid
auth context in the actual jw_dev schema, not customer-specific data.
No customer rows, user identifiers, passwords, data writes or logs.
"""
from __future__ import annotations
import json
import os
import secrets
from contextlib import closing

from scripts import ci_v97_supavisor_restricted_auth as gate

TABLES = (
    "customers", "quotes", "quote_items", "orders", "order_items",
    "invoices", "invoice_items", "payments",
    "messenger_connections", "messenger_messages",
)
EXPECTED = frozenset(TABLES)
ACK = "READ_ONLY_V99_NONSESSION_RLS"


def probe(*, environ=None, connector=None) -> dict:
    env = os.environ if environ is None else environ
    base = {
        "decision": "BLOCKED", "scope": "REAL_DB_UNKNOWN_SESSION_READONLY",
        "authenticated": False, "cross_tenant_abc": "NOT_VERIFIED",
        "writes": False, "rollback": "NOT_VERIFIED",
        "tested_tables": 0, "production_cutover": False,
    }
    if env.get("JW_ENV") != "review" or env.get("JW_V99_RLS_ACK") != ACK:
        return {**base, "reason": "READONLY_OPT_IN_REQUIRED"}
    dsn = env.get("JW_V97_TRADE_DSN", "")
    if not gate.trusted_ca() or not gate.valid_dsn(dsn, "trade"):
        return {**base, "reason": "PINNED_TLS_OR_TRADE_SECRET_MISSING"}
    if any(key.startswith("PG") for key in env) or (
        connector is None and any(key.startswith("PG") for key in os.environ)
    ):
        return {**base, "reason": "AMBIENT_LIBPQ_OVERRIDE"}
    if connector is None:
        import psycopg

        def connector(value):
            return psycopg.connect(
                value, sslmode="verify-full", sslrootcert=str(gate.CA),
                connect_timeout=5, gssencmode="disable",
                application_name="jw_v99_readonly_rls",
                options="-c default_transaction_read_only=on -c statement_timeout=5000 "
                        "-c lock_timeout=1000 -c idle_in_transaction_session_timeout=10000",
            )

    closed = False
    rolled = False
    try:
        with closing(connector(dsn)) as connection:
            try:
                with connection.cursor() as cur:
                    cur.execute("SET TRANSACTION READ ONLY")
                    cur.execute("SELECT session_user, current_setting('server_version_num')::integer / 10000")
                    identity = cur.fetchone()
                    if identity != ("jw_trade_gateway_v90", 17):
                        return {**base, "reason": "UNEXPECTED_LOGIN"}
                    cur.execute("SET LOCAL ROLE jw_app_dev")
                    cur.execute("SELECT current_user")
                    if cur.fetchone() != ("jw_app_dev",):
                        return {**base, "reason": "UNEXPECTED_ROLE"}
                    # Random token can never name an existing session except at
                    # negligible 256-bit probability. No real session hash is used.
                    random_non_session = secrets.token_hex(32)
                    cur.execute("SELECT pg_catalog.set_config('jw.session_hash', %s, true)", (random_non_session,))
                    cur.execute("SELECT jw_dev.current_org_from_session()")
                    if cur.fetchone() != (None,):
                        return {**base, "reason": "INVALID_SESSION_RESOLVED_TO_TENANT"}
                    for table in TABLES:
                        # Table identifiers are compiled literals only.
                        if table not in EXPECTED:
                            return {**base, "reason": "NONALLOWLISTED_TABLE"}
                        cur.execute("SELECT count(*) FROM jw_dev." + table)
                        row = cur.fetchone()
                        if row != (0,):
                            return {**base, "reason": "INVALID_SESSION_EXPOSED_ROWS",
                                    "failed_table": table}
                return {**base, "decision": "PASS", "authenticated": True,
                        "reason": "INVALID_SESSION_RLS_DENIED",
                        "tested_tables": len(TABLES), "rollback": "PENDING"}
            finally:
                try:
                    connection.rollback()
                    rolled = True
                except Exception:
                    rolled = False
    except Exception:
        return {**base, "reason": "READONLY_CONNECTION_OR_QUERY_FAILED"}
    finally:
        closed = True


def validated_probe(*, environ=None, connector=None) -> dict:
    """No speculative success: suppress PASS until rollback is itself proven.

    Using separate wrapper keeps any SQL exception / permission error blocked.
    """
    result = probe(environ=environ, connector=connector)
    if result["decision"] == "PASS":
        # probe's success path always enters its finally rollback; the
        # connection's rollback outcome must be observed, not assumed.
        return {**result, "decision": "BLOCKED", "reason": "ROLLBACK_NOT_ATTESTED"}
    return result


if __name__ == "__main__":
    print(json.dumps(validated_probe(), sort_keys=True))
