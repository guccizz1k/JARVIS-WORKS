#!/usr/bin/env python3
"""Real V9 ValidatedLegacyTx and verify-full TLS against a disposable PostgreSQL 17.
Runs the original 74-case HTTP scenario with the production registration/gateway.
Does not connect to Supabase or use real data.
"""
from __future__ import annotations
import json
import os
import secrets
import sys
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from fastapi import FastAPI
from app import pg_api_v84 as stage
from app import pg_cinema_legacy_api_v1 as legacy
from app import pg_cinema_register_v1 as trade
from app import pg_v90_integrated_entry as v90
from scripts import ci_cinema_pg_legacy_api_e2e_v223 as e2e

ROLE = "jw_ci_v223_tls_business"

class SyncedOrgs(dict):
    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if key == "value":
            os.environ[legacy.ORGS_ENV] = value

def must(ok, label):
    if not ok:
        raise AssertionError("FAIL_V223_VALIDATED_TLS_" + label)
    print("PASS_V223_VALIDATED_TLS_" + label)

def prepare():
    # Set up only inside the throw-away database already populated by e2e.main().
    # Four legacy ledger relations are required by the actual S4 collision guard.
    with psycopg.connect(dbname=e2e.DB, autocommit=True) as conn:
        for table in ("quotes", "orders", "invoices", "payments"):
            exists = conn.execute("SELECT to_regclass(%s)", ("jw_dev." + table,)).fetchone()[0]
            if exists is None:
                conn.execute(sql.SQL("CREATE TABLE jw_dev.{}(id text PRIMARY KEY, org_id text NOT NULL)").format(sql.Identifier(table)))
                conn.execute(sql.SQL("ALTER TABLE jw_dev.{} ENABLE ROW LEVEL SECURITY").format(sql.Identifier(table)))
                conn.execute(sql.SQL("ALTER TABLE jw_dev.{} FORCE ROW LEVEL SECURITY").format(sql.Identifier(table)))
                conn.execute(sql.SQL("CREATE POLICY s4_v223_tls_select ON jw_dev.{} FOR SELECT TO jw_app_dev USING (org_id=jw_dev.current_org_from_session())").format(sql.Identifier(table)))
            conn.execute(sql.SQL("GRANT SELECT ON jw_dev.{} TO jw_app_dev").format(sql.Identifier(table)))
    password = secrets.token_urlsafe(28)
    with psycopg.connect(dbname="postgres", autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD {}").format(sql.Identifier(ROLE), sql.Literal(password)))
        admin.execute(sql.SQL("GRANT jw_app_dev TO {} WITH INHERIT FALSE, SET TRUE").format(sql.Identifier(ROLE)))
        admin.execute(sql.SQL("GRANT jw_cinema_writer TO {} WITH INHERIT FALSE, SET TRUE").format(sql.Identifier(ROLE)))
    root = Path(os.environ["JW_PG_CI_TLS_CA"])
    must(root.is_file(), "TRUST_ROOT_EXISTS")
    dsn = make_conninfo("", host="localhost", port=os.environ.get("PGPORT", "5435"), dbname=e2e.DB,
                        user=ROLE, password=password, sslmode="verify-full",
                        sslrootcert=str(root), connect_timeout=5)
    os.environ.update({
        "JW_ENV": "dev",
        "JW_PG_STAGE_V84": "ISOLATED_DEV_READ_ONLY",
        "JW_PG_AUTH_V85": "ISOLATED_DEV_AUTH_ONLY",
        "JW_PG_MESSENGER_V90": "ISOLATED_DEV_MESSENGER_ONLY",
        "JW_PG_CINEMA_TRADE_V1": "ISOLATED_DEV_CINEMA_TRADE_ONLY",
        legacy.GATE_ENV: legacy.GATE_VALUE,
        "JW_V90_ALLOWED_ORIGINS": "https://testserver",
        "JW_PG_STAGE_DSN": dsn,
    })
    os.environ.pop("JW_INSECURE_LOCAL_DEV", None)
    must(stage.stage_enabled() and v90.v90_enabled() and trade.cinema_trade_enabled(), "PRODUCTION_GATES_ON")
    must(legacy.legacy_api_gate_on(), "LEGACY_CONTRACT_GATE_ON")
    with stage._connect() as conn:
        row = conn.execute("SELECT s.ssl,s.version,current_user,session_user FROM pg_stat_ssl s WHERE s.pid=pg_backend_pid()").fetchone()
        must(bool(row and row[0] and str(row[1]).startswith("TLSv1.")), "TLS_NEGOTIATED")
        must(row[2:] == (ROLE, ROLE), "SEPARATE_LOGIN_ROLE")
        roles = conn.execute("SELECT pg_has_role(session_user,'jw_app_dev','SET'), "
                             "pg_has_role(session_user,'jw_cinema_writer','SET'), "
                             "pg_has_role(session_user,'jw_cinema_owner','MEMBER'), "
                             "pg_has_role(session_user,'jw_auth_stage_v85','MEMBER')").fetchone()
        must(roles == (True, True, False, False), "ROLE_BOUNDARIES")
    # Check that the real stage._connect refuses untrusted roots and hostname mismatch.
    original = os.environ["JW_PG_STAGE_DSN"]
    try:
        os.environ["JW_PG_STAGE_DSN"] = make_conninfo(original, sslrootcert="/tmp/nonexistent-v223-ca.pem")
        try:
            with stage._connect():
                raise AssertionError("FAIL_V223_VALIDATED_TLS_UNTRUSTED_CERT_ACCEPTED")
        except psycopg.OperationalError:
            print("PASS_V223_VALIDATED_TLS_UNTRUSTED_CERT_REJECTED")
        os.environ["JW_PG_STAGE_DSN"] = make_conninfo(original, host="wrong.example.invalid", hostaddr="127.0.0.1")
        try:
            with stage._connect():
                raise AssertionError("FAIL_V223_VALIDATED_TLS_WRONG_HOST_ACCEPTED")
        except psycopg.OperationalError:
            print("PASS_V223_VALIDATED_TLS_WRONG_HOST_REJECTED")
    finally:
        os.environ["JW_PG_STAGE_DSN"] = original

def real_build_app():
    prepare()
    app = FastAPI()
    print("JW_V223_BEFORE_REGISTRATION", len(app.routes), len(app.router.routes), type(app).__name__, flush=True)
    must(trade.register_cinema_trade_v1(app), "TRADE_REGISTERED")
    print("JW_V223_AFTER_TRADE", len(app.routes), len(app.router.routes), flush=True)
    must(legacy.register_legacy_api_v1(app), "VALIDATED_LEGACY_REGISTERED")
    print("JW_V223_AFTER_LEGACY", len(app.routes), len(app.router.routes), flush=True)
    paths = {getattr(route, "path", "") for route in app.routes}
    print("JW_V223_REGISTERED_PATHS", json.dumps(sorted(paths)))
    must("/api/quotes" in paths and "/api/orders/from-quote" in paths, "LEGACY_PATHS_REGISTERED")
    return app

def main():
    if os.environ.get("JW_CINEMA_PG_DISPOSABLE") != "1" or os.environ.get("PGHOST") not in ("localhost", "127.0.0.1"):
        raise SystemExit("BLOCKED: DISPOSABLE PG17 LOOPBACK ONLY")
    if not os.environ.get("JW_PG_CI_TLS_CA"):
        raise SystemExit("BLOCKED: CA PEM REQUIRED")
    e2e.ORGS = SyncedOrgs(value="ci-a,ci-b")
    os.environ[legacy.ORGS_ENV] = e2e.ORGS["value"]
    e2e.build_app = real_build_app
    result = e2e.main()
    if result == 0:
        print(json.dumps({"result": "PASS_V223_REAL_VALIDATED_LEGACY_TX_TLS_PG17",
                          "http_checks": 74, "synthetic": True, "real_supabase": False}))
    return result

if __name__ == "__main__":
    sys.exit(main())
