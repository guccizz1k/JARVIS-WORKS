#!/usr/bin/env python3
"""Real SQLite + disposable PG17 cutover-front integration smoke test.

Uses the unchanged legacy FastAPI app, SQLite auth and CINEMA PG engine.
This is NOT a migration of real customers and NOT native PG V8.5 login QA.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import tempfile
from datetime import date
from pathlib import Path

import psycopg
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.testclient import TestClient

from scripts import ci_cinema_pg_sql_gate as gate
from app import pg_cinema_cutover_front_v223 as cut
from app import pg_cinema_legacy_api_v1 as pg_api

CHECKS = 0


def check(condition, label):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError("FAIL_V223_REALDB_FRONT_" + label)
    print("PASS_V223_REALDB_FRONT_" + label, flush=True)


def run() -> int:
    if (os.environ.get("JW_CINEMA_PG_DISPOSABLE") != "1"
            or os.environ.get("PGHOST") not in ("127.0.0.1", "localhost")):
        raise SystemExit("BLOCKED: disposable PG17 loopback only")
    gate.local_server_or_die()
    server = gate.Psql("postgres").sql("SHOW server_version_num").stdout.strip()
    if not server.isdigit() or int(server) < 170000:
        raise SystemExit("BLOCKED: disposable PostgreSQL 17 required")
    dbname = "jw_cutover_realdb_" + secrets.token_hex(4)
    admin = gate.Psql("postgres")
    if admin.sql("CREATE DATABASE " + dbname).returncode:
        raise SystemExit("BLOCKED: could not create disposable database")

    try:
        for role in ("jw_app_dev", "jw_auth_stage_v85", "anon", "authenticated", "service_role"):
            admin.sql(
                "DO $$ BEGIN IF NOT EXISTS "
                "(SELECT 1 FROM pg_roles WHERE rolname='" + role + "') "
                "THEN CREATE ROLE " + role + " NOLOGIN NOINHERIT NOBYPASSRLS; "
                "END IF; END $$"
            )
        psql = gate.Psql(dbname)
        for path in gate.BASE_FILES:
            if psql.file(path).returncode:
                raise AssertionError("FAIL_V223_REALDB_FRONT_BASE_SCHEMA")
        engine = psql.file(gate.ENGINE, single_transaction=True)
        if engine.returncode:
            raise AssertionError("FAIL_V223_REALDB_FRONT_ENGINE")
        for path in (
            "scripts/review/cinema_pg_v223_quote_two_person_proposal.sql",
            "scripts/review/cinema_pg_v223_terms_proposal.sql"
        ):
            if psql.file(path).returncode:
                raise AssertionError("FAIL_V223_REALDB_FRONT_MIGRATION_CANDIDATE")

        with tempfile.TemporaryDirectory(prefix="jw-cutover-realdb-") as work:
            os.environ["JARVIS_DB_PATH"] = str(Path(work) / "fresh-legacy.db")
            os.environ["JW_ENV"] = "test"
            os.environ.pop("DEMO_SEED", None)
            os.environ.pop("JW_INSECURE_LOCAL_DEV", None)
            from app import main as legacy

            def connect():
                return psycopg.connect(dbname=dbname, autocommit=False)

            pg = FastAPI(docs_url=None, openapi_url=None)
            # CI-only PG logout endpoint backed by a REAL disposable PG17 session
            # row. It tests cross-store session revocation; actual V8.5 role
            # delegation is separately covered in the integrated TLS gate.
            @pg.post("/api/pg-stage/v85/login")
            def pg_test_login(response: Response):
                # Issue a real __Host cookie through HTTP response, not a
                # manually inserted httpx cookie jar entry (which lacks the
                # correct host-only domain and Secure attributes).
                response.set_cookie(cut.UPSTREAM_COOKIE, pg_token,
                                    path="/", secure=True, httponly=True,
                                    samesite="strict")
                return {"csrf_token": pg_csrf}

            @pg.post("/api/pg-stage/v85/logout")
            def pg_test_logout(request: Request, response: Response):
                token = request.cookies.get(cut.UPSTREAM_COOKIE, "")
                csrf = request.headers.get("X-CSRF-Token", "")
                if len(token) < 30 or not csrf:
                    raise HTTPException(401, "PG session required")
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                with connect() as db:
                    row = db.execute(
                        "SELECT csrf_token FROM jw_dev.sessions WHERE token_hash=%s",
                        (token_hash,)
                    ).fetchone()
                    if not row or not hmac.compare_digest(str(row[0]), csrf):
                        raise HTTPException(403, "PG CSRF mismatch")
                    deleted = db.execute(
                        "DELETE FROM jw_dev.sessions WHERE token_hash=%s",
                        (token_hash,)
                    ).rowcount
                    if deleted != 1:
                        raise HTTPException(409, "PG session race detected")
                response.delete_cookie(cut.UPSTREAM_COOKIE, path="/", secure=True,
                                       httponly=True, samesite="strict")
                return {"ok": True}

            pg.include_router(pg_api.create_legacy_router(
                pg_api.WriterTx(connect), org_enabled=lambda org: org in enabled,
                today=lambda: date.today()
            ))
            enabled = set()

            def pg_user(request: Request):
                token = request.cookies.get(cut.UPSTREAM_COOKIE, "")
                if len(token) < 30:
                    raise HTTPException(401, "PG session missing")
                with connect() as db, db.transaction(), db.cursor() as cur:
                    cur.execute("SET LOCAL ROLE jw_cinema_writer")
                    cur.execute(
                        "SELECT set_config('jw.session_hash', %s, true)",
                        (hashlib.sha256(token.encode()).hexdigest(),)
                    )
                    cur.execute("SELECT actor_id, org_id, actor_role FROM jw_dev.stage_identity_v84()")
                    identity = cur.fetchone()
                    if not identity:
                        raise HTTPException(401, "PG session expired")
                    return cut.Identity(identity[1], identity[0], identity[2])

            def sqlite_user(request: Request):
                ident = legacy.current_user(request)
                return cut.Identity(ident["org_id"], ident["id"], ident["role"])

            app = cut.CutoverFront(
                legacy.app, pg, sqlite_user, pg_user, lambda: frozenset(enabled)
            )
            # Lifespan initializes the unchanged SQLite tables and original
            # business modules, without any live data or deployment.
            with TestClient(app, base_url="https://testserver") as c:
                with legacy.transaction() as db:
                    db.execute(
                        "INSERT INTO organizations VALUES(?,?,?)",
                        ("ci-a", "Company A", legacy.now())
                    )
                    db.execute(
                        "INSERT INTO users VALUES(?,?,?,?,?,?,?)",
                        ("ci-ua", "ci-a", "a@invalid.test",
                         legacy.hash_password("synthetic-only-password"),
                         "Synthetic Admin", "admin", legacy.now())
                    )

                login = c.post("/api/login", json={
                    "email": "a@invalid.test", "password": "synthetic-only-password"
                })
                check(login.status_code == 200, "REAL_SQLITE_LOGIN")
                check(cut.LEGACY_COOKIE in c.cookies, "LEGACY_COOKIE_VIRTUALIZED")
                check(cut.UPSTREAM_COOKIE not in c.cookies, "NO_COLLIDING_BROWSER_COOKIE")
                sqlite_csrf = login.json()["csrf_token"]

                old_customer = c.post("/api/customers", json={
                    "name": "Legacy Partner", "business_number": ""
                }, headers={"X-CSRF-Token": sqlite_csrf})
                check(old_customer.status_code == 201, "LEGACY_CUSTOMER_CREATED")
                old_id = old_customer.json()["id"]
                old_quote = c.post("/api/quotes", json={
                    "customer_id": old_id, "title": "Legacy Quote",
                    "vat_mode": "taxable",
                    "items": [{"name": "Widget", "quantity": 2, "unit_price": 100}]
                }, headers={"X-CSRF-Token": sqlite_csrf})
                check(old_quote.status_code == 201, "LEGACY_QUOTE_CREATED")
                legacy_id = old_quote.json()["id"]

                pg_token = secrets.token_urlsafe(40)
                pg_csrf = secrets.token_urlsafe(24)
                with psycopg.connect(dbname=dbname, autocommit=True) as db:
                    db.execute(
                        "INSERT INTO jw_dev.sessions"
                        "(id, token_hash, user_id, expires_at, csrf_token, created_at) "
                        "VALUES (%s,%s,'ci-ua',(now()+interval '1 hour')::text,%s,now()::text)",
                        ("ci-cutover", hashlib.sha256(pg_token.encode()).hexdigest(), pg_csrf)
                    )
                pg_login = c.post("/api/pg-stage/v85/login")
                check(pg_login.status_code == 200 and cut.PG_COOKIE in c.cookies
                      and cut.UPSTREAM_COOKIE not in c.cookies,
                      "PG_BROWSER_COOKIE_ISSUED_VIA_HTTP")
                enabled.add("ci-a")
                bad_csrf = c.post("/api/customers", json={
                    "name": "PG Partner", "business_number": "8111111111"
                }, headers={"X-CSRF-Token": sqlite_csrf})
                print("JW_V223_CSRF_PROBE", bad_csrf.status_code, bad_csrf.text[:240], flush=True)
                check(bad_csrf.status_code == 403, "PG_REJECTS_LEGACY_CSRF")

                pg_customer = c.post("/api/customers", json={
                    "name": "PG Partner", "business_number": "8111111111"
                }, headers={"X-JW-PG-CSRF": pg_csrf})
                check(pg_customer.status_code == 201, "REAL_PG_PARTNER_CREATED")
                new_customer_id = pg_customer.json().get("id", "")
                check(new_customer_id.startswith("pg_"), "PG_CUSTOMER_HOME_PREFIX")

                pg_quote = c.post("/api/quotes", json={
                    "customer_id": new_customer_id, "title": "PG Quote",
                    "vat_mode": "taxable",
                    "items": [{"name": "Widget", "quantity": 3, "unit_price": 100}]
                }, headers={"X-JW-PG-CSRF": pg_csrf})
                check(pg_quote.status_code == 201, "REAL_PG_QUOTE_CREATED")
                pg_id = pg_quote.json().get("id", "")
                check(pg_id.startswith("pg_"), "PG_QUOTE_HOME_PREFIX")

                merged = c.get("/api/quotes")
                check(merged.status_code == 200, "DUAL_HOME_READ")
                by_id = {row["id"]: row["source"] for row in merged.json()}
                check(by_id.get(legacy_id) == "legacy" and by_id.get(pg_id) == "pg",
                      "DUAL_HOME_SOURCE_TAGS")
                check(c.get("/api/quotes/" + legacy_id).status_code == 200,
                      "OLD_DOCUMENT_STAYS_SQLITE")
                check(c.get("/api/quotes/" + pg_id).status_code == 200,
                      "NEW_DOCUMENT_IN_PG")

                enabled.clear()
                off = c.get("/api/quotes")
                check(off.status_code == 200 and
                      all(row["id"] != pg_id for row in off.json()),
                      "FLAG_OFF_RESTORES_LEGACY_ONLY")
                check(c.get("/api/quotes/" + pg_id).status_code == 409,
                      "FLAG_OFF_REJECTS_PG_ID")
                enabled.add("ci-a")
                restored = c.get("/api/quotes")
                check(any(row["id"] == pg_id for row in restored.json()),
                      "FLAG_ON_RESTORES_PG_DATA")

                # The shared client cannot forge a PG identity of another
                # company and use it to reach this user's PG data.
                with psycopg.connect(dbname=dbname, autocommit=True) as db:
                    db.execute(
                        "UPDATE jw_dev.sessions SET user_id='ci-ub' WHERE id='ci-cutover'"
                    )
                forbidden = c.get("/api/quotes")
                check(forbidden.status_code == 403 and
                      forbidden.json().get("code") == "identity_mismatch",
                      "CROSS_ORG_SESSION_REJECTED")
                with psycopg.connect(dbname=dbname, autocommit=True) as db:
                    db.execute("UPDATE jw_dev.sessions SET user_id='ci-ua' WHERE id='ci-cutover'")

                with legacy.conn() as db:
                    saved_legacy = db.execute(
                        "SELECT count(*) FROM quotes WHERE id=?", (legacy_id,)
                    ).fetchone()[0]
                check(saved_legacy == 1, "SQLITE_ORIGINAL_RECORD_PRESERVED")
                with psycopg.connect(dbname=dbname) as db:
                    count = db.execute(
                        "SELECT count(*) FROM jw_dev.cinema_pg_quotes WHERE id=%s",
                        (pg_id[3:],)
                    ).fetchone()[0]
                check(count == 1, "PG_RECORD_PRESERVED")

                # Revoke both actual independent sessions through the front.
                # Missing PG CSRF and forged PG CSRF MUST NOT log out SQLite.
                legacy_token = c.cookies.get(cut.LEGACY_COOKIE)
                check(isinstance(legacy_token, str) and len(legacy_token) >= 30,
                      "SQLITE_COOKIE_PRESENT_BEFORE_DUAL_LOGOUT")
                get_attempt = c.get("/api/logout", headers={
                    "X-CSRF-Token": sqlite_csrf, "X-JW-PG-CSRF": pg_csrf
                })
                check(get_attempt.status_code == 405, "GET_LOGOUT_NEVER_REVOKES")
                head_attempt = c.head("/api/logout", headers={
                    "X-CSRF-Token": sqlite_csrf, "X-JW-PG-CSRF": pg_csrf
                })
                check(head_attempt.status_code == 405, "HEAD_LOGOUT_NEVER_REVOKES")
                no_pg_csrf = c.post("/api/logout", headers={
                    "X-CSRF-Token": sqlite_csrf
                })
                check(no_pg_csrf.status_code == 409, "DUAL_LOGOUT_REQUIRES_PG_CSRF")
                wrong_pg_csrf = c.post("/api/logout", headers={
                    "X-CSRF-Token": sqlite_csrf, "X-JW-PG-CSRF": "forged"
                })
                check(wrong_pg_csrf.status_code == 403, "DUAL_LOGOUT_REJECTS_FORGED_PG_CSRF")
                out = c.post("/api/logout", headers={
                    "X-CSRF-Token": sqlite_csrf, "X-JW-PG-CSRF": pg_csrf
                })
                check(out.status_code == 200 and out.json().get("ok") is True,
                      "BOTH_REALDB_SESSIONS_LOGOUT_SUCCEEDED")
                with legacy.conn() as db:
                    sqlite_sessions = db.execute(
                        "SELECT count(*) FROM sessions WHERE token_hash=?",
                        (hashlib.sha256(legacy_token.encode()).hexdigest(),)
                    ).fetchone()[0]
                check(sqlite_sessions == 0, "REAL_SQLITE_SESSION_ROW_REVOKED")
                with connect() as db:
                    pg_sessions = db.execute(
                        "SELECT count(*) FROM jw_dev.sessions WHERE token_hash=%s",
                        (hashlib.sha256(pg_token.encode()).hexdigest(),)
                    ).fetchone()[0]
                check(pg_sessions == 0, "REAL_PG17_SESSION_ROW_REVOKED")
                check(cut.LEGACY_COOKIE not in c.cookies and cut.PG_COOKIE not in c.cookies,
                      "BOTH_BROWSER_COOKIES_CLEARED")
            print(
                "PASS_V223_REAL_SQLITE_PG17_CUTOVER_FRONT "
                f"checks={CHECKS} failures=0 synthetic_only=true",
                flush=True
            )
            return 0
    finally:
        admin.sql("DROP DATABASE IF EXISTS " + dbname + " WITH (FORCE)")


if __name__ == "__main__":
    raise SystemExit(run())
