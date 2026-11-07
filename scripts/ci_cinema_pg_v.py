#!/usr/bin/env python3
"""Isolate network-vs-login faults using verified TLS and libpq/psql.

Reads only the existing locally protected credential and dashboard CA.
Never prints passwords, SCRAM verifier, conninfo, SQL error text, or customer data.
Never changes source DB, role grants or existing restore target.
"""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.ci_cinema_pg_s import CERT_FILE, HOST, PORT, load_dashboard_ca, verify_tls
from scripts.ci_cinema_pg_u import PROJECT_REF, ROLE, read_password_file


def classify_failure(message: str) -> str:
    s = message.lower()
    if "password authentication failed" in s:
        return "AUTH_PASSWORD_REJECTED"
    if "tenant or user not found" in s or "unknown tenant" in s or "invalid tenant" in s:
        return "POOLER_TENANT_OR_USER_REJECTED"
    if "too many connections" in s or "remaining connection slots" in s:
        return "POOL_LIMIT_REACHED"
    if "certificate verify failed" in s or "certificate" in s and "verify" in s:
        return "TLS_VERIFICATION_FAILED"
    if "timeout" in s or "timed out" in s:
        return "PSQL_CONNECTION_TIMEOUT"
    if "could not translate host" in s or "name resolution" in s:
        return "DNS_FAILURE"
    return "PSQL_OTHER_CONNECTION_ERROR"


def probe_login() -> str:
    import shutil
    if shutil.which("psql") is None:
        return "PSQL_CLIENT_UNAVAILABLE"
    password = read_password_file()
    load_dashboard_ca()
    # No login attempt unless the trusted dashboard CA verifies this exact host.
    if verify_tls(CERT_FILE.read_bytes()) != "CA_CHAIN_AND_HOST_VERIFIED":
        return "TLS_NOT_VERIFIED"
    env = dict(os.environ)
    env.update({
        "PGPASSWORD": password, "PGSSLMODE": "verify-full",
        "PGSSLROOTCERT": str(CERT_FILE), "PGCONNECT_TIMEOUT": "20",
        "PGHOST": HOST, "PGPORT": str(PORT), "PGDATABASE": "postgres",
        "PGUSER": ROLE + "." + PROJECT_REF,
    })
    # -w: fail instead of prompting; --no-psqlrc (-X); user-visible data never printed.
    cmd = ["psql", "-X", "-w", "-A", "-t", "-F", "|", "-v", "ON_ERROR_STOP=1",
           "-c", "SELECT current_user, session_user, current_database(), current_setting('server_version_num')"]
    try:
        result = subprocess.run(cmd, env=env, text=True, capture_output=True,
                                timeout=25, check=False)
    except subprocess.TimeoutExpired:
        return "PSQL_PROCESS_TIMEOUT"
    except OSError:
        return "PSQL_CANNOT_EXECUTE"
    if result.returncode != 0:
        return classify_failure(result.stderr)
    parts = result.stdout.strip().split("|")
    if len(parts) != 4 or parts[:3] != [ROLE, ROLE, "postgres"] or not parts[3].isdigit():
        return "SOURCE_ROLE_OR_DB_IDENTITY_MISMATCH"
    if int(parts[3]) < 170000:
        return "POSTGRES_VERSION_TOO_OLD"
    return "PSQL_LIVE_LOGIN_OK"


def main() -> int:
    if os.environ.get("CODESPACES") != "true":
        print("BLOCKED: approved Codespaces only")
        return 2
    try:
        category = probe_login()
    except Exception as exc:
        category = "LOCAL_PREFLIGHT_" + type(exc).__name__
    print("SOURCE_PSQL_DIAGNOSTIC=" + category)
    print("NO_PASSWORD_OR_DATA_PRINTED_NO_DB_CHANGES")
    if category == "PSQL_LIVE_LOGIN_OK":
        print("SOURCE_AUTH_NETWORK_ONLY_PASS: separate permissions check and DR still required")
        return 0
    print("SOURCE_AUTH_BLOCKED: do not perform backup or schema changes")
    return 2


if __name__ == "__main__":
    sys.exit(main())
