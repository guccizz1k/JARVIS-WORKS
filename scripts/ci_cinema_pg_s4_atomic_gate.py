#!/usr/bin/env python3
"""S4 two-ledger atomic claim/trigger gate. STRICT DISPOSABLE PG17 ONLY.

This gate never connects to Supabase/Render, never reads secrets or customer data.
It creates and drops one isolated local PostgreSQL database. psql + Python stdlib.
A finished PASS covers multi-connection concurrency; NOT a migrated DB or a
reconciliation of historical production business records.
"""
from __future__ import annotations

import json
import os
import re
import runpy
import secrets
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
old_gate = runpy.run_path(str(ROOT / "scripts/ci_cinema_pg_sql_gate.py"))
Psql = old_gate["Psql"]
BASE_FILES = old_gate["BASE_FILES"]
NOTICE = old_gate["NOTICE"]
ADDITION = "scripts/review/cinema_pg_s4_atomic_gate.sql"
CHECKS = "scripts/review/cinema_pg_s4_atomic_gate_test.sql"
ENGINE = "scripts/review/cinema_pg_write_engine.sql"


def demand_disposable_local() -> None:
    if os.environ.get("JW_CINEMA_PG_DISPOSABLE") != "1":
        raise SystemExit("BLOCKED: JW_CINEMA_PG_DISPOSABLE=1 required")
    if os.environ.get("PGHOST") not in ("127.0.0.1", "localhost", "::1") and not os.environ.get("PGHOST", "").startswith("/"):
        raise SystemExit("BLOCKED: local socket/loopback only")
    if not os.environ.get("PGUSER") or not os.environ.get("PGPASSWORD"):
        raise SystemExit("BLOCKED: disposable local DB role/password needed")
    if not subprocess.run(["psql", "--version"], capture_output=True, text=True).returncode == 0:
        raise SystemExit("BLOCKED: psql client missing")


def ensure_ok(proc: subprocess.CompletedProcess, step: str) -> None:
    if proc.returncode:
        raise RuntimeError(step + " failed: " + proc.stderr.strip()[-600:])


def create_synthetic_schema(db: Psql) -> None:
    sql = [
        "CREATE TABLE jw_dev.orders(id text PRIMARY KEY,org_id text NOT NULL)",
        "CREATE TABLE jw_dev.invoices(id text PRIMARY KEY,org_id text NOT NULL)",
        "CREATE TABLE jw_dev.payments(id text PRIMARY KEY,org_id text NOT NULL)",
    ]
    for t in ("orders", "invoices", "payments"):
        sql.extend([
            f"ALTER TABLE jw_dev.{t} ENABLE ROW LEVEL SECURITY",
            f"ALTER TABLE jw_dev.{t} FORCE ROW LEVEL SECURITY",
            f"GRANT SELECT ON jw_dev.{t} TO jw_app_dev",
            f"CREATE POLICY s4_tenant_select ON jw_dev.{t} FOR SELECT TO jw_app_dev "
            "USING(org_id=jw_dev.current_org_from_session())",
        ])
    ensure_ok(db.sql(*sql), "synthetic legacy fixture")


def quote_insert(org: str, suffix: str, cinema: bool) -> str:
    if cinema:
        return (f"INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,vat_mode,created_by) "
                f"VALUES('s4-race-{suffix}','{org}','TS4-{suffix}','s4-part-{org}','Synthetic','draft','exempt','ci-ua')")
    return (f"INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at) "
            f"VALUES('s4-race-{suffix}','{org}','s4-customer-{org}','Synthetic','Q-S4-{suffix}',"
            f"'Synthetic','draft','exempt',now()::text,now()::text)")


def wait_for_claim_lock(db: Psql, held: subprocess.Popen, duration: float = 5.0) -> bool:
    until = time.monotonic() + duration
    while time.monotonic() < until:
        if held.poll() is not None:
            return False
        q = db.sql(
            "SELECT count(*) FROM pg_locks l WHERE l.relation='jw_dev.cinema_pg_ledger_claims'::regclass "
            "AND l.mode='RowExclusiveLock' AND l.granted AND l.pid<>pg_backend_pid()"
        )
        if q.returncode == 0 and q.stdout.strip() not in ("", "0"):
            return True
        time.sleep(0.08)
    return False


def race_case(db: Psql, record, org: str, first_cinema: bool, commit: bool, suffix: str):
    # The first database transaction reserves a claim and holds its unique row
    # lock for 4 seconds. The second server session must block and time out.
    a_sql = quote_insert(org, suffix + "a", first_cinema)
    b_sql = quote_insert(org, suffix + "b", not first_cinema)
    dbname = db.dbname
    admin = Psql(dbname)
    cmd, env = admin._cmd("-A", "-t", "-c",
                          "BEGIN; " + a_sql + "; SELECT pg_sleep(4); "
                          + ("COMMIT;" if commit else "ROLLBACK;"))
    process = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        held = wait_for_claim_lock(db, process)
        if not held:
            record(f"G5.S4R.{suffix}01_first_writer_row_lock", False,
                   "could not observe first transaction claim lock")
            return
        record(f"G5.S4R.{suffix}01_first_writer_row_lock", True)

        denied = db.sql("SET lock_timeout='700ms'", b_sql)
        locked = denied.returncode != 0 and "lock timeout" in denied.stderr.lower()
        record(f"G5.S4R.{suffix}02_second_writer_blocked", locked,
               denied.stderr.strip()[:140])
        output, err = process.communicate(timeout=9)
        record(f"G5.S4R.{suffix}03_first_transaction_finished",
               process.returncode == 0, err[-130:])

        retry = db.sql(b_sql)
        if commit:
            blocked = retry.returncode != 0 and "S4 tenant ledger already reserved" in retry.stderr
            record(f"G5.S4R.{suffix}04_conflicting_commit_fails_closed", blocked,
                   retry.stderr.strip()[-130:])
        else:
            allowed = retry.returncode == 0
            record(f"G5.S4R.{suffix}04_rollback_releases_claim_for_other_ledger", allowed,
                   retry.stderr.strip()[-130:])
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=3)


def concurrency_checks(db: Psql, record) -> None:
    # Entirely fabricated organizations and customer/partner identities.
    for org in ("ci-f", "ci-g", "ci-h"):
        ensure_ok(db.sql(
            f"INSERT INTO jw_dev.organizations(id,name,created_at) VALUES('{org}','Synthetic {org}',now()::text)",
            f"INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES('s4-customer-{org}','{org}','Synthetic',now()::text)",
            f"INSERT INTO jw_dev.cinema_pg_partners(id,org_id,name,created_by) VALUES('s4-part-{org}','{org}','Synthetic','ci-ua')",
        ), "race fixtures for " + org)
    race_case(db, record, "ci-f", first_cinema=False, commit=True, suffix="F")
    race_case(db, record, "ci-g", first_cinema=True, commit=True, suffix="G")
    race_case(db, record, "ci-h", first_cinema=False, commit=False, suffix="H")


def main() -> int:
    demand_disposable_local()
    dbname = "jw_cinema_s4_gate_" + secrets.token_hex(4)
    admin = Psql("postgres")
    results = []
    def record(name: str, ok: bool, detail: str = ""):
        results.append({"name": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    try:
        ensure_ok(admin.sql(f"CREATE DATABASE {dbname}"), "create isolated db")
        db = Psql(dbname)
        for role in ("jw_app_dev", "jw_auth_stage_v85", "anon", "authenticated", "service_role"):
            ensure_ok(admin.sql(f"DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='{role}') "
                                f"THEN CREATE ROLE {role} NOLOGIN NOINHERIT NOBYPASSRLS; END IF; END $$"),
                      "disposable synthetic roles")
        for path in BASE_FILES:
            ensure_ok(db.file(path), "ephemeral base "+path)
        create_synthetic_schema(db)
        ensure_ok(db.file(ENGINE, single_transaction=True), "original CINEMA engine")
        ensure_ok(db.file(ADDITION, single_transaction=True), "S4 atomic extension")
        r = db.file(CHECKS)
        ensure_ok(r, "S4 SQL evidence")
        for name, status, detail in NOTICE.findall(r.stderr):
            record(name, status == "PASS", detail)
        if len(results) != 20:
            record("G5.S4A.00_expected_20_SQL_checks", False, f"observed={len(results)}")
        concurrency_checks(db, record)
        # Every listed test name is unique; a broken parser must not fake PASS.
        names = [x["name"] for x in results]
        duplicates = [x for x, n in Counter(names).items() if n > 1]
        fails = [x for x in results if x["status"] != "PASS"]
        overall = "PASS" if len(results) >= 32 and not fails and not duplicates else "FAIL"
        report = {"overall": overall, "total": len(results), "failed": fails,
                  "duplicate_names": duplicates, "tests": results,
                  "limitations": ["Disposable PG17 only", "No existing real ledger migrations",
                                  "No mounted HTTP auth or browser E2E", "No historical v92 ledger mapping",
                                  "No Supabase dev/prod mutation"]}
        Path("jw-cinema-s4-atomic-pg17.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
        print(f"{overall}: {len(results)-len(fails)}/{len(results)} S4 atomic tests; "
              f"failures={len(fails)} duplicates={duplicates}")
        for bad in fails:
            print("FAIL:", bad["name"], bad["detail"][:250])
        return 0 if overall == "PASS" else 1
    finally:
        ensure_ok(admin.sql(f"DROP DATABASE IF EXISTS {dbname} WITH (FORCE)"),
                  "delete disposable S4 database")


if __name__ == "__main__":
    sys.exit(main())
