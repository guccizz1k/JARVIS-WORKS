"""J6/J5: prove dump -> isolated restore -> checksums on CI-only PG17.

Data is entirely synthetic, produced by ci_v90_postgres_browser. Never connect
to user Supabase or alter original DB. Rejected environments exit without writes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
import time
from typing import Any

SOURCE_DB = "postgres"
RESTORE_NAME = re.compile(r"^jw_j6_restore_[0-9a-f]{10}$")
IMAGE = "postgres:17"


def allowed_connection(guard: str, dsn: str) -> bool:
    if guard != "ONLY_EPHEMERAL_LOCAL_DATABASE":
        return False
    try:
        from psycopg.conninfo import conninfo_to_dict
        parts = conninfo_to_dict(dsn)
    except Exception:
        return False
    return (
        parts.get("host") == "127.0.0.1"
        and parts.get("user") == "postgres"
        and parts.get("dbname") == SOURCE_DB
        and bool(parts.get("password"))
    )


def verify_server(connection: Any) -> None:
    with connection.cursor() as cur:
        cur.execute("SELECT current_user,current_database(),current_setting('server_version_num')::integer/10000")
        if cur.fetchone() != ("postgres", SOURCE_DB, 17):
            raise RuntimeError("Expected fresh ephemeral PostgreSQL 17 admin database")
        cur.execute("SELECT datname FROM pg_database WHERE NOT datistemplate AND datname <> %s", (SOURCE_DB,))
        if cur.fetchall():
            raise RuntimeError("Shared cluster detected: foreign database found")
        cur.execute("SELECT rolname FROM pg_roles WHERE rolname NOT LIKE 'pg_%' AND rolname NOT IN "
                    "('postgres','jw_app_dev','jw_auth_stage_v85','jw_ci_trade','jw_ci_auth',"
                    "'anon','authenticated','service_role')")
        if cur.fetchall():
            raise RuntimeError("Shared cluster detected: unknown login/role")
        cur.execute("SELECT count(*) FROM jw_dev.messenger_messages")
        if cur.fetchone()[0] < 3:
            raise RuntimeError("Real browser + RPC concurrency evidence not found")


def snapshot(connection: Any) -> dict[str, Any]:
    """Stable DB fingerprint, including duplicate preservation and FORCED RLS."""
    queries = {
        "orgs": "SELECT id,name FROM jw_dev.organizations ORDER BY id",
        "users": "SELECT id,org_id FROM jw_dev.users ORDER BY id",
        "sessions": "SELECT id,user_id,token_hash FROM jw_dev.sessions ORDER BY id",
        "companies": "SELECT org_id,business_number FROM jw_dev.messenger_companies ORDER BY org_id",
        "chats": "SELECT id,org_a,org_b,status FROM jw_dev.messenger_connections ORDER BY id",
        "messages": "SELECT id,connection_id,sender_org,body,request_id,message_seq FROM jw_dev.messenger_messages ORDER BY message_seq,id",
        "edits": "SELECT id,message_id,version,edited_at FROM jw_dev.messenger_edits ORDER BY id",
        "attachments": "SELECT message_id,content_hash,size_bytes FROM jw_dev.messenger_attachments ORDER BY message_id",
        "forced_rls": "SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jw_dev' AND c.relkind='r' ORDER BY c.relname",
        "rpcs": "SELECT proname,md5(pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='jw_dev' ORDER BY proname",
    }
    result: dict[str, Any] = {}
    with connection.cursor() as cur:
        for name, query in queries.items():
            cur.execute(query)
            rows = cur.fetchall()
            if name == "forced_rls":
                if not rows or any(not row[1] or not row[2] for row in rows):
                    raise AssertionError("Database lost FORCE RLS")
            if name == "rpcs" and not any(row[0] == "v90_send_text" for row in rows):
                raise AssertionError("Messenger RPC missing")
            raw = json.dumps(rows, sort_keys=True, separators=(",", ":"), default=str).encode()
            result[name] = {"count": len(rows), "sha256": hashlib.sha256(raw).hexdigest()}
    return result


def run_docker(*args: str, timeout: int = 30, env: dict[str,str] | None = None) -> str:
    cmd = ["docker", *args]
    result = subprocess.run(cmd, check=True, text=True, capture_output=True,
                            timeout=timeout, env=env)
    return result.stdout.strip()


def validate_container_id(value: str) -> str:
    matches = value.splitlines()
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", matches[0]):
        raise RuntimeError("Expected exactly one ephemeral postgres:17 Docker container")
    return matches[0]


def verify_dump_restored() -> None:
    guard = os.environ.get("JW_PG_CI_ALLOW", "")
    dsn = os.environ.get("JW_PG_CI_ROOT_DSN", "")
    if not allowed_connection(guard, dsn):
        raise RuntimeError("BLOCKED: only fresh localhost PG17 test service is allowed")

    import psycopg
    from psycopg.conninfo import make_conninfo, conninfo_to_dict
    opts = conninfo_to_dict(dsn)
    child_env = os.environ.copy()
    child_env["PGPASSWORD"] = opts["password"]
    db_name = "jw_j6_restore_" + secrets.token_hex(5)
    dump_path = "/tmp/" + db_name + ".dump"
    if not RESTORE_NAME.fullmatch(db_name):
        raise RuntimeError("Unsafe temporary DB name")
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        verify_server(conn)
        baseline = snapshot(conn)
    cid = validate_container_id(run_docker(
        "ps", "--filter", "ancestor=postgres:17", "--format", "{{.ID}}", timeout=10))
    # A second barrier against applying this script to the wrong container.
    image = run_docker("inspect", "--format", "{{.Config.Image}}", cid, timeout=10)
    if image != IMAGE:
        raise RuntimeError("Wrong postgres Docker image")
    created = False
    passed = False
    started = time.monotonic()
    try:
        run_docker("exec", "-e", "PGPASSWORD", cid, "pg_dump",
                   "-U", "postgres", "-h", "127.0.0.1",
                   "-d", SOURCE_DB, "--format=custom", "--file", dump_path,
                   timeout=40, env=child_env)
        run_docker("exec", "-e", "PGPASSWORD", cid, "createdb",
                   "-U", "postgres", "-h", "127.0.0.1", db_name,
                   timeout=15, env=child_env)
        created = True
        run_docker("exec", "-e", "PGPASSWORD", cid, "pg_restore",
                   "-U", "postgres", "-h", "127.0.0.1", "-d", db_name,
                   "--no-owner", "--exit-on-error", dump_path,
                   timeout=45, env=child_env)
        restored_dsn = make_conninfo(dsn, dbname=db_name)
        with psycopg.connect(restored_dsn, connect_timeout=5) as conn:
            restored = snapshot(conn)
        if restored != baseline:
            delta = sorted(k for k in baseline if baseline[k] != restored.get(k))
            raise AssertionError("Restore fidelity mismatch: " + ",".join(delta))
        elapsed = round(time.monotonic() - started, 3)
        print("PASS: J6 actual PG17 pg_dump/custom pg_restore; "
              "10 independent row/schema/RPC fingerprints identical; all RLS forced.")
        print(f"MEASURED: ephemeral restore plus verify elapsed {elapsed}s; "
              "this is NOT production RTO/RPO")
        passed = True
    finally:
        cleanup_error = None
        if created:
            try:
                run_docker("exec", "-e", "PGPASSWORD", cid, "dropdb", "--if-exists",
                           "-U", "postgres", "-h", "127.0.0.1", db_name,
                           timeout=15, env=child_env)
            except Exception as exc:
                cleanup_error = type(exc).__name__
        try:
            run_docker("exec", cid, "rm", "-f", dump_path, timeout=10)
        except Exception as exc:
            cleanup_error = cleanup_error or type(exc).__name__
        if cleanup_error:
            raise RuntimeError("Ephemeral restore cleanup failed: " + cleanup_error)
        # Confirm original source DB was not mutated by backup/restore rehearsal.
        with psycopg.connect(dsn, connect_timeout=5) as conn:
            if snapshot(conn) != baseline:
                raise AssertionError("Source database changed during backup/restore")
        if passed:
            print("PASS: ephemeral restored DB and backup file cleaned; original source unchanged")


def main() -> int:
    try:
        verify_dump_restored()
        return 0
    except Exception as exc:
        print(f"FAIL/BLOCKED: {type(exc).__name__}: {str(exc)[:180]}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
