"""J1–J6 V9.1: real PostgreSQL 17 verify-full TLS + independent gateway role drill.

ONLY an isolated Docker postgres:17 instance bound to 127.0.0.1. The CA and
server certificates are generated for synthetic localhost and destroyed in
finally. This does NOT validate the real Supabase CA or production RTO.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

from app.pg_connection_gate_v87 import check_two_connections
from app.pg_live_dryrun_v88 import live_gate_v88

CI_GUARD = "ONLY_EPHEMERAL_LOCAL_DATABASE"
PG_IMAGE = "postgres:17"
PORT = "55432"


def safe_environment(value: str, mode: str) -> bool:
    return value == CI_GUARD and mode == "review"


def run_command(args: list[str], *, timeout: int = 20) -> str:
    output = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=True)
    return output.stdout.strip()


def build_local_certificates(folder: Path) -> Path:
    if not all(shutil.which(name) for name in ("openssl", "docker")):
        raise RuntimeError("Both OpenSSL and Docker are mandatory")
    ca = folder / "ca.crt"
    root_key = folder / "ca.key"
    cert = folder / "server.crt"
    key = folder / "server.key"
    req = folder / "server.csr"
    extension = folder / "san.cnf"
    extension.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
    run_command(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1",
                 "-subj","/CN=JW ephemeral CI only","-keyout",str(root_key),"-out",str(ca)])
    run_command(["openssl","req","-new","-newkey","rsa:2048","-nodes",
                 "-subj","/CN=localhost","-keyout",str(key),"-out",str(req)])
    run_command(["openssl","x509","-req","-in",str(req),"-CA",str(ca),"-CAkey",
                 str(root_key),"-CAcreateserial","-out",str(cert),
                 "-days","1","-sha256","-extfile",str(extension)])
    # postgres:17 official Docker image uses UID 999.
    key.chmod(0o600)
    os.chown(key,999,999)
    folder.chmod(0o755)
    return ca


BOOTSTRAP = """
CREATE ROLE jw_app_dev NOLOGIN NOINHERIT NOBYPASSRLS;
CREATE ROLE jw_auth_stage_v85 NOLOGIN NOINHERIT NOBYPASSRLS;
CREATE ROLE jw_trade_gateway_v90 LOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD 'synthetic-trade-password';
CREATE ROLE jw_auth_gateway_v90 LOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD 'synthetic-auth-password';
GRANT jw_app_dev TO jw_trade_gateway_v90 WITH INHERIT FALSE, SET TRUE;
GRANT jw_auth_stage_v85 TO jw_auth_gateway_v90 WITH INHERIT FALSE, SET TRUE;
CREATE SCHEMA jw_dev;
REVOKE ALL ON SCHEMA jw_dev FROM PUBLIC;
GRANT USAGE ON SCHEMA jw_dev TO jw_app_dev,jw_auth_stage_v85;
CREATE TABLE jw_dev.users (id text PRIMARY KEY);
CREATE TABLE jw_dev.sessions (id text PRIMARY KEY);
CREATE TABLE jw_dev.customers (id text PRIMARY KEY);
CREATE TABLE jw_dev.payments (id text PRIMARY KEY);
ALTER TABLE jw_dev.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.users FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.customers FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.payments FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA jw_dev FROM PUBLIC;
GRANT SELECT ON jw_dev.customers TO jw_app_dev;
CREATE FUNCTION jw_dev.v85_auth_candidate(text) RETURNS text
LANGUAGE SQL SECURITY INVOKER SET search_path=pg_catalog AS 'SELECT NULL::text';
CREATE FUNCTION jw_dev.record_payment_v83(text,bigint,date,text,text) RETURNS text
LANGUAGE SQL SECURITY INVOKER SET search_path=pg_catalog AS 'SELECT NULL::text';
REVOKE ALL ON FUNCTION jw_dev.v85_auth_candidate(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION jw_dev.record_payment_v83(text,bigint,date,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION jw_dev.v85_auth_candidate(text) TO jw_auth_stage_v85;
GRANT EXECUTE ON FUNCTION jw_dev.record_payment_v83(text,bigint,date,text,text) TO jw_app_dev;
"""


def run() -> int:
    if not safe_environment(os.getenv("JW_PG_CI_ALLOW",""),os.getenv("JW_ENV","")):
        raise RuntimeError("BLOCKED: never run outside ephemeral PG17 review CI")
    import psycopg
    container = "jw-v91-pgssl-" + secrets.token_hex(4)
    with tempfile.TemporaryDirectory(prefix="jw-v91-verify-full-") as tmp:
        folder=Path(tmp)
        ca=build_local_certificates(folder)
        password="synthetic-ephemeral-superuser"
        launched=False
        try:
            run_command(["docker","run","-d","--name",container,"--rm",
                         "-e","POSTGRES_USER=postgres","-e","POSTGRES_PASSWORD="+password,
                         "-e","POSTGRES_DB=postgres",
                         "-p","127.0.0.1:"+PORT+":5432",
                         "-v",str(folder)+":/jw-tls:ro",
                         PG_IMAGE,"-c","ssl=on",
                         "-c","ssl_cert_file=/jw-tls/server.crt",
                         "-c","ssl_key_file=/jw-tls/server.key"],timeout=30)
            launched=True
            def dsn(login: str,pw: str,cert: Path =ca)->str:
                return ("host=127.0.0.1 port="+PORT+" dbname=postgres user="+login
                        +" password="+pw+" sslmode=verify-full sslrootcert="+str(cert))
            admin=dsn("postgres",password)
            last_failure=""
            for attempt in range(50):
                try:
                    with psycopg.connect(admin,connect_timeout=1) as db:
                        with db.cursor() as cur:
                            cur.execute("SELECT current_setting('server_version_num')::integer/10000")
                            if cur.fetchone()[0]!=17:raise RuntimeError("Unexpected PostgreSQL version")
                    break
                except psycopg.OperationalError as exc:
                    last_failure=type(exc).__name__
                    time.sleep(.2)
            else:
                raise RuntimeError("TLS PostgreSQL container never became ready: "+last_failure)

            with psycopg.connect(admin,autocommit=True) as db:
                db.execute(BOOTSTRAP)
                rows=db.execute("""SELECT rolname,rolcanlogin,rolsuper,rolbypassrls FROM pg_roles
                                   WHERE rolname IN ('jw_trade_gateway_v90','jw_auth_gateway_v90')
                                   ORDER BY rolname""").fetchall()
                if len(rows)!=2 or not all(x[1] and not x[2] and not x[3] for x in rows):
                    raise AssertionError("Gateway principal not least privileged")

            env={
                "JW_PG_V87_CONNECT_GATE":"ISOLATED_DEV_ONLY",
                "JW_PG_V88_LIVE_GATE":"ISOLATED_DEV_ONLY",
                "JW_ENV":"dev",
                "JW_PG_AUTH_STAGE_DSN":dsn("jw_auth_gateway_v90","synthetic-auth-password"),
                "JW_PG_STAGE_DSN":dsn("jw_trade_gateway_v90","synthetic-trade-password")
            }
            preflight=check_two_connections(env=env)
            if preflight.get("result")!="PASS":
                raise AssertionError("Actual TLS gateway preflight rejected: "+str(preflight))
            locks=live_gate_v88(env=env)
            if locks.get("result")!="PASS" or locks.get("payment_race_e2e")!="NOT_RUN":
                raise AssertionError("Real PG transaction-only lock test failed")

            bad_ca = folder / "bad-root.crt"
            # Valid PEM CA file, but never matches generated server chain.
            run_command(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1",
                         "-subj","/CN=Unrelated CA","-keyout",str(folder/"bad.key"),
                         "-out",str(bad_ca)])
            invalid=dict(env)
            invalid["JW_PG_AUTH_STAGE_DSN"]=dsn("jw_auth_gateway_v90","synthetic-auth-password",bad_ca)
            if check_two_connections(env=invalid).get("result")!="BLOCKED":
                raise AssertionError("Wrong certificate authority unexpectedly trusted")

            reversed_roles=dict(env)
            reversed_roles["JW_PG_AUTH_STAGE_DSN"]=env["JW_PG_STAGE_DSN"]
            reversed_roles["JW_PG_STAGE_DSN"]=env["JW_PG_AUTH_STAGE_DSN"]
            if check_two_connections(env=reversed_roles).get("result")!="BLOCKED":
                raise AssertionError("Wrong backend login separation accepted")

            print("PASS: actual PostgreSQL 17 SSL verify-full with ephemeral CA and SAN, two LOGIN gateway roles, no cross-role privileges")
            print("PASS: real V8.7 and V8.8 SQL gates, separate PG backend lock contention and transaction rollback")
            print("PASS: wrong CA chain rejected; swapped authentication/business role rejected")
            print("LIMIT: ephemeral self-signed CA and synthetic schema, not Supabase trusted CA or full financial DB")
            return 0
        finally:
            if launched:
                try:
                    run_command(["docker","rm","-f",container],timeout=20)
                except Exception as e:
                    raise RuntimeError("Failed to destroy isolated TLS database: "+type(e).__name__) from None


if __name__=="__main__":
    raise SystemExit(run())
