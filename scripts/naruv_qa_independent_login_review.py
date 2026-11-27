"""Independent hosted login review. No existing role, schema or row changes.
Run only from an authorized terminal with QA admin password entered via TTY.
"""
import base64
import getpass
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import signal
import sys
import time
import warnings

HOST = "aws-0-ap-northeast-2.pooler.supabase.com"
REF = "scvqtsyxkqddoorcaiqr"
CA_BLOB = "3d693669b23c340c57a3457bdc8b6fefe1806cc5"
STAGES = ("jw_auth_stage_v85", "jw_app_dev", "naruv_native_stage")
ORIGINALS = ("naruv_v85_cutover_ci", "jw_ci_trade", "naruv_ci_ingest")
def require(ok, code):
    if not ok:
        raise RuntimeError(code)

def check_ca(path):
    data = Path(path).read_bytes()
    require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == CA_BLOB, "CA_PIN")

def scram_verifier(password):
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac('sha256', password.encode('ascii'), salt, 4096)
    client = hmac.digest(salted,b'Client Key','sha256')
    stored = hashlib.sha256(client).digest()
    server = hmac.digest(salted,b'Server Key','sha256')
    enc = lambda b: base64.b64encode(b).decode('ascii')
    return 'SCRAM-SHA-256$4096:'+enc(salt)+'$'+enc(stored)+':'+enc(server)

def run(ca):
    import psycopg
    from psycopg import sql
    from psycopg.types.json import Jsonb
    check_ca(ca)
    require(sys.stdin.isatty(), "INTERACTIVE_TTY_REQUIRED")
    for k in list(os.environ):
        if k.startswith("PG"):
            os.environ.pop(k, None)
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        admin_pw = getpass.getpass("Isolated QA database password (hidden): ")
    require(bool(admin_pw), "NO_PASSWORD")
    names = tuple("naruv_qa_tmp_" + secrets.token_hex(8) + "_" + k for k in ("auth","trade","ingest"))
    passwords = tuple(secrets.token_urlsafe(48) for _ in names)
    def connect(role, pw):
        c = psycopg.connect(host=HOST, port=5432, dbname="postgres", user=role+"."+REF,
            password=pw, sslmode="verify-full", sslrootcert=str(Path(ca).resolve()),
            gssencmode="disable", connect_timeout=8, application_name="naruv_qa_independent_review",
            autocommit=True)
        try:
            require(c.info.host == HOST and c.info.port == 5432 and
                    c.info.get_parameters().get("sslmode") == "verify-full" and
                    c.info.get_parameters().get("sslrootcert") == str(Path(ca).resolve()), "TLS_PARAMS")
            require(c.execute("SELECT session_user,current_user,current_setting('server_version_num')::int/10000").fetchone()
                    == (role,role,17), "IDENTITY_OR_VERSION")
            c.execute("SET statement_timeout='10s'")
            c.execute("SET lock_timeout='3s'")
            c.execute("SET idle_in_transaction_session_timeout='30s'")
            c.execute("SET idle_session_timeout='60s'")
            return c
        except BaseException:
            c.close()
            raise
    def baseline(c):
        require(c.execute("SELECT count(*) FROM naruv_qa_probe.fixture").fetchone()==(2,), "QA_MARKER")
        require(c.execute("""SELECT count(*) FROM pg_authid WHERE rolname=ANY(%s)
            AND NOT rolcanlogin AND rolpassword IS NULL AND rolvaliduntil IS NULL AND rolconnlimit=-1
            AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole
            AND NOT rolcreatedb AND NOT rolreplication""",(list(ORIGINALS),)).fetchone()==(3,), "ORIGINAL_ROLE_DRIFT")
    def denied(c, statement, args=(), codes=("42501",)):
        try:
            with c.transaction():
                c.execute(statement,args)
        except psycopg.Error as e:
            require(e.sqlstate in codes, "UNEXPECTED_DENIAL_SQLSTATE")
        else:
            raise RuntimeError("UNEXPECTED_ACCEPTANCE")
    prepared = False
    failure = None
    cleanup = False
    try:
        with connect("postgres",admin_pw) as a:
            baseline(a)
            require(a.execute("SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)",(list(names),)).fetchone()==(0,), "NAME_COLLISION")
            prepared = True
            with a.transaction():
                expiry = a.execute("SELECT clock_timestamp()+interval '1 hour'").fetchone()[0]
                for n,p,s in zip(names,passwords,STAGES):
                    a.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION CONNECTION LIMIT 4 PASSWORD {} VALID UNTIL {}").format(sql.Identifier(n),sql.Literal(scram_verifier(p)),sql.Literal(expiry)))
                    a.execute(sql.SQL("ALTER ROLE {} SET statement_timeout TO '10s'").format(sql.Identifier(n)))
                    a.execute(sql.SQL("ALTER ROLE {} SET idle_in_transaction_session_timeout TO '30s'").format(sql.Identifier(n)))
                    a.execute(sql.SQL("ALTER ROLE {} SET idle_session_timeout TO '60s'").format(sql.Identifier(n)))
                    a.execute(sql.SQL("GRANT {} TO {} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE").format(sql.Identifier(s),sql.Identifier(n)))
                require(a.execute("""SELECT count(*) FROM pg_authid WHERE rolname=ANY(%s)
                    AND rolcanlogin AND rolpassword LIKE 'SCRAM-SHA-256$%%' AND rolvaliduntil>clock_timestamp()
                    AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole
                    AND NOT rolcreatedb AND NOT rolreplication AND rolconnlimit=4""",(list(names),)).fetchone()==(3,), "ROLE_FLAGS")
            print("TEMP_ROLE_COMMIT_PASS 3 names="+",".join(names),flush=True)
        for n,p,s in zip(names,passwords,STAGES):
            with connect(n,p) as c:
                with c.transaction(force_rollback=True):
                    c.execute("SET TRANSACTION READ ONLY")
                    require(c.execute("SELECT pg_has_role(session_user,%s,'SET'),pg_has_role(session_user,%s,'USAGE')",(s,s)).fetchone()==(True,False),"ROLE_MEMBERSHIP")
                    for other in STAGES:
                        if other!=s:
                            denied(c,sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(other)))
                    denied(c,"SELECT 1 FROM naruv_trade.documents LIMIT 1")
                    c.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(s)))
                    require(c.execute("SELECT current_user,session_user").fetchone()==(s,n),"SET_ROLE")
                    denied(c,"SELECT 1 FROM naruv_trade.documents LIMIT 1")
                    if s=="jw_app_dev":
                        denied(c,"SELECT naruv_trade.command(%s,%s,%s,%s,true,%s)",
                               ("qa-invalid","qa-invalid","open",Jsonb({}),"missing-session"))
                    elif s=="naruv_native_stage":
                        denied(c,"SELECT naruv_native_review.read_source(%s,%s,%s)",("qa-invalid","item","missing-session"))
                    else:
                        denied(c,"SELECT naruv_native_review.read_source(%s,%s,%s)",("qa-invalid","item","missing-session"))
                print("INDEPENDENT_LOGIN_ROLE_BOUNDARY_PASS "+s,flush=True)
    except BaseException as e:
        failure = type(e).__name__ + ":" + (str(e) if type(e) is RuntimeError else str(getattr(e,"sqlstate",None) or "REDACTED"))
    finally:
        if prepared:
            # Reconnect independently; disable and remove only this run's random roles.
            for _ in range(3):
                try:
                    with connect("postgres",admin_pw) as a:
                        baseline(a)
                        for n in names:
                            if a.execute("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)",(n,)).fetchone()[0]:
                                a.execute(sql.SQL("ALTER ROLE {} NOLOGIN PASSWORD NULL").format(sql.Identifier(n)))
                        a.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=ANY(%s) AND pid<>pg_backend_pid()", (list(names),))
                        require(a.execute("SELECT count(*) FROM pg_stat_activity WHERE usename=ANY(%s)",(list(names),)).fetchone()==(0,), "ACTIVE_SESSIONS")
                        for n in names:
                            a.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(n)))
                        require(a.execute("SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)",(list(names),)).fetchone()==(0,), "RESIDUAL_ROLES")
                        baseline(a)
                    cleanup=True
                    break
                except BaseException:
                    time.sleep(2)
            print("TEMP_ROLE_CLEANUP_PASS" if cleanup else "TEMP_ROLE_CLEANUP_BLOCKED",flush=True)
    if cleanup:
        for n,p in zip(names,passwords):
            try:
                with connect(n,p):
                    failure = "POST_CLEANUP_LOGIN_ACCEPTED"
            except psycopg.Error as e:
                if e.sqlstate not in ("28000","28P01"):
                    # A generic network/proxy failure is not proof of rejection.
                    failure = failure or "POST_CLEANUP_LOGIN_DENIAL_UNPROVEN"
            except BaseException:
                failure = failure or "POST_CLEANUP_LOGIN_DENIAL_UNPROVEN"
    if failure or not cleanup:
        print("HOSTED_LOGIN_REVIEW_BLOCKED "+(failure or "CLEANUP_UNPROVEN"),flush=True)
        return 1
    print("HOSTED_LOGIN_REVIEW_PASS; ERP_WORKLOAD_NOT_RUN; PRODUCTION_AUTHORIZED_FALSE",flush=True)
    return 0

def interrupt(*_):
    raise KeyboardInterrupt()

if __name__=="__main__":
    if len(sys.argv)!=2:
        raise SystemExit("Usage: python3 script.py /path/to/pinned-ca.crt")
    signal.signal(signal.SIGTERM, interrupt)
    try:
        raise SystemExit(run(sys.argv[1]))
    except ImportError:
        raise SystemExit("BLOCKED: psycopg not installed; no role change")
    except (OSError,RuntimeError,getpass.GetPassWarning) as e:
        raise SystemExit("BLOCKED: preflight failed; no role change")
