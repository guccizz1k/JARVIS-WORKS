#!/usr/bin/env python3
"""Actual PG17 source-linked approval audit on an isolated disposable database.

NO remote database, no existing customer records, no secrets, no production
migration. Supabase migration remains BLOCKED, this is NOT an HTTPS E2E pass.
"""
from __future__ import annotations

import json
import os
import re
import runpy
import secrets
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
g = runpy.run_path(str(ROOT / "scripts/ci_cinema_pg_sql_gate.py"))
Psql = g["Psql"]
BASE_FILES = g["BASE_FILES"]
ENGINE = "scripts/review/cinema_pg_write_engine.sql"
REVIEW = "scripts/review/cinema_pg_s4_reviewed_links_gate.sql"
TESTS = "scripts/review/cinema_pg_s4_reviewed_links_test.sql"
NOTICE = g["NOTICE"]
OUT = ROOT / "jw-cinema-s4-reviewed-pg17.json"


def main() -> int:
    # Even if CI variables are spoofed, the SQL has a second independent
    # superuser + database-name guard and will refuse persistent databases.
    host = os.environ.get("PGHOST", "")
    if (os.environ.get("JW_CINEMA_PG_DISPOSABLE") != "1"
        or host not in ("127.0.0.1", "::1", "localhost")
        or not os.environ.get("PGUSER") or not os.environ.get("PGPASSWORD")):
        raise SystemExit("BLOCKED: local disposable PG17 service only")
    ver = subprocess.run(["psql", "--version"],capture_output=True,text=True,check=True)
    dbname = "jw_cinema_s4_link_" + secrets.token_hex(4)
    admin = Psql("postgres")
    def require_ok(p, step):
        if p.returncode:
            raise RuntimeError(step+": "+p.stderr[-600:].replace(os.environ["PGPASSWORD"],"[MASKED]"))
    created=False
    try:
        require_ok(admin.sql(f"CREATE DATABASE {dbname}"),"isolated database creation")
        created=True
        db = Psql(dbname)
        for role in ("jw_app_dev", "jw_auth_stage_v85", "anon", "authenticated", "service_role"):
            require_ok(admin.sql(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') "
                f"THEN CREATE ROLE {role} NOLOGIN NOINHERIT NOBYPASSRLS; END IF; END $$"),
                "synthetic role fixture")
        for path in BASE_FILES:
            require_ok(db.file(path),"base fixture "+path)
        require_ok(db.file(ENGINE,single_transaction=True),"original CINEMA SQL")
        require_ok(db.file(REVIEW,single_transaction=True),"server-authenticated link approval extension")
        p=db.file(TESTS)
        require_ok(p,"reviewed links test script")
        tests=[{"name":name,"status":status,"detail":detail}
               for name,status,detail in NOTICE.findall(p.stderr)
               if name.startswith("S4L.")]
        expected={f"S4L.{n:02d}" for n in range(1,23)}
        observed={x["name"].split("_",1)[0] for x in tests}
        dup=[k for k,v in Counter(x["name"] for x in tests).items() if v>1]
        failures=[x for x in tests if x["status"]!="PASS"]
        # Gaps/extra names and duplicated names are fatal even if all other
        # SQL check notices claim PASS.
        overall=("PASS" if len(tests)==22 and observed==expected
                 and not failures and not dup else "FAIL")
        report={"overall":overall,"actual_pg17":True,"tests":len(tests),
                "passed":len(tests)-len(failures),"failures":failures,
                "expected":sorted(expected),"observed":sorted(observed),
                "duplicate":dup,"scope":"synthetic disposable DB only",
                "not_proven":["Supabase development DB permanent ACL/RLS",
                              "real reviewer enterprise identity/provider MFA",
                              "real HTTPS complete trade flow",
                              "migration coexistence with legacy-claims lock"]}
        OUT.write_text(json.dumps(report,indent=2,ensure_ascii=False))
        print(f"{overall}: {len(tests)-len(failures)}/{len(tests)} S4 reviewed-link SQL tests;"
              f" missing={len(expected-observed)} extra={len(observed-expected)} duplicates={len(dup)}")
        for x in failures:
            print("FAIL:",x["name"],x["detail"][:120])
        return 0 if overall=="PASS" else 1
    finally:
        if created:
            require_ok(admin.sql(f"DROP DATABASE IF EXISTS {dbname} WITH (FORCE)"),
                       "disposable audit database cleanup")


if __name__=="__main__":
    sys.exit(main())
