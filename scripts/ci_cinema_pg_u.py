#!/usr/bin/env python3
"""Live, read-only verification of the approved temporary backup role.

Uses operator-owned local secrets from Codespaces, never prints credentials.
Does not create roles, update source data, or start a backup. This is NOT DR PASS.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import stat
import sys

# Supports direct invocation from the repo-root Codespaces terminal.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ci_cinema_pg_q import CREDS, ROLE, decode_salt, make_verifier
from scripts.ci_cinema_pg_s import CERT_FILE, HOST, PORT, load_dashboard_ca
from scripts.pg_backup_v223 import evaluate_source_privileges, fetch_role_facts

PROJECT_REF = "rvymwwzclagvljnofyss"
EXPECTED_TABLES = 65   # post-A/B/C live schema (issue #140); 62 was the pre-A/B count


def read_password_file(path: Path = CREDS) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or symlinked credential file")
    st = path.stat()
    if st.st_uid != os.getuid() or st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("credential file permissions unsafe")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if set(obj) != {"role", "password", "verifier"} or obj["role"] != ROLE:
        raise ValueError("unexpected credential format")
    if not secrets.compare_digest(obj["verifier"],
                                  make_verifier(obj["password"], decode_salt(obj["verifier"]))):
        raise ValueError("password does not match locally stored SCRAM verifier")
    return obj["password"]


def check_connection(conn) -> tuple[bool, list[str]]:
    from scripts.pg_backup_v223 import ROLE_FACT_KEYS
    with conn.transaction():
        conn.execute("SET TRANSACTION READ ONLY")
        row = conn.execute(
            "SELECT current_user, session_user, current_database(), "
            "current_setting('server_version_num')::integer, "
            "current_setting('transaction_read_only')"
        ).fetchone()
        if (not row or row[0] != ROLE or row[1] != ROLE
                or row[2] != "postgres" or row[3] < 170000 or row[4] != "on"):
            return False, ["identity_or_readonly"]
        facts = fetch_role_facts(conn, "jw_dev")
        violations = evaluate_source_privileges(facts)
        if facts.get("tables") != EXPECTED_TABLES:
            violations.append("business_table_count_changed")
        return not violations, violations


def main() -> int:
    if os.environ.get("CODESPACES") != "true":
        print("BLOCKED: use the approved Codespace only")
        return 2
    try:
        import psycopg
        password = read_password_file()
        load_dashboard_ca()
        # Pin host and identity, require the dashboard's trusted CA certificate.
        with psycopg.connect(
            host=HOST, port=PORT, dbname="postgres",
            user=f"{ROLE}.{PROJECT_REF}", password=password,
            sslmode="verify-full", sslrootcert=str(CERT_FILE),
            connect_timeout=8,
        ) as conn:
            valid, failures = check_connection(conn)
        if not valid:
            print("BLOCKED: source role does not meet the expected identity/privileges: "
                  + ",".join(sorted(set(failures))))
            return 2
        print("PASS: live session-pooler login as jw_backup_ro using SCRAM and verify-full")
        print("PASS: PostgreSQL 17+; read-only transaction; source privileges fail-closed checks")
        print("PASS: 65 expected jw_dev tables; no write permission; no other role assumption")
        print("SOURCE_AUTH_ONLY_PASS: no backup, restore, C reconfiguration or business data access")
        return 0
    except Exception as exc:
        # Database connection exceptions often embed a DSN; only the class is safe.
        print("BLOCKED: live read-only login or guard failed [" + type(exc).__name__ + "]")
        print("NO_CREDENTIALS_PRINTED_NO_DB_CHANGES")
        return 2


if __name__ == "__main__":
    sys.exit(main())
