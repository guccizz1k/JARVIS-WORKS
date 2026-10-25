"""Read-only and secret-redacted Supavisor pooler TLS leg diagnostic.

Network is pinned to the existing two restricted principals and public root
CA, and no production row is read. This PROVES NOTHING about release alone.
"""
from __future__ import annotations
from contextlib import closing
import json
import os
import sys

from scripts import ci_v97_supavisor_restricted_auth as v97

def diagnose(*, env=None, connector=None) -> dict:
    e = os.environ if env is None else env
    blocked = {"result": "BLOCKED", "production_cutover": False,
               "authenticated": False, "diagnostic_only": True}
    if (e.get("JW_ENV")!="review" or e.get("JW_V97_LIVE_ACK")!=v97.ACK
            or not v97.trusted_ca()):
        return {**blocked,"reason":"REVIEW_OR_CA_GUARD"}
    auth=e.get("JW_V97_AUTH_DSN","")
    trade=e.get("JW_V97_TRADE_DSN","")
    if not auth or not trade:
        return {**blocked,"reason":"TWO_SECRETS_MISSING"}
    if not v97.valid_dsn(auth,"auth") or not v97.valid_dsn(trade,"trade"):
        return {**blocked,"reason":"REJECTED_ROLE_DSN"}
    if any(k.startswith("PG") for k in e):
        return {**blocked,"reason":"AMBIENT_LIBPQ_SETTINGS"}
    if connector is None:
        import psycopg
        def connector(dsn):
            return psycopg.connect(
                dsn,sslmode="verify-full",sslrootcert=str(v97.CA),
                connect_timeout=5,gssencmode="disable",
                application_name="jw_v98_readonly_diag",
                options="-c default_transaction_read_only=on -c statement_timeout=5000")
    evidence={}
    for kind,dsn in (("trade",trade),("auth",auth)):
        try:
            with closing(connector(dsn)) as db:
                try:
                    with db.cursor() as cur:
                        cur.execute("SET TRANSACTION READ ONLY")
                        cur.execute("""SELECT current_setting('server_version_num')::int/10000,
                           (SELECT ssl FROM pg_catalog.pg_stat_ssl
                             WHERE pid=pg_backend_pid()),
                           session_user=current_user,
                           session_user=%s""",(kind=="trade" and "jw_trade_gateway_v90" or "jw_auth_gateway_v90",))
                        major,backend_ssl,same_identity,expected_role=cur.fetchone()
                    # These flags are intentionally booleans only, never
                    # actual usernames, backend PID, SQL messages or secrets.
                    evidence[kind]={"pg_major_17":major==17,
                                    "backend_pg_stat_ssl":bool(backend_ssl),
                                    "session_identity_consistent":same_identity is True,
                                    "login_role_expected":expected_role is True}
                finally:
                    db.rollback()
        except Exception:
            evidence[kind]={"error":"READ_ONLY_DIAGNOSTIC_BLOCKED"}
    result="DIAGNOSED" if len(evidence)==2 and all("error" not in v for v in evidence.values()) else "BLOCKED"
    return {**blocked,"result":result,"components":evidence}

def main() -> int:
    result=diagnose()
    print(json.dumps(result,sort_keys=True))
    return 0 if result["result"]=="DIAGNOSED" else 3

if __name__=="__main__":
    raise SystemExit(main())
